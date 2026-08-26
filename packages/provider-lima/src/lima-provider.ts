import {
  failClosed,
  silentLogger,
  YashikiError,
  type CreateNodeInput,
  type ExecInput,
  type ExecResult,
  type Logger,
  type MountSpec,
  type NodeInspection,
  type NodeLifecycleStatus,
  type NodeProvider,
  type NodeRef,
  type ProcessPort,
  type ProcessResult,
  type SecretGuard,
  assertSafeArgv,
  noopSecretGuard,
} from "@meidoya-yashiki/yashiki-core";

export type LimaProviderOptions = {
  process: ProcessPort;
  limactlPath?: string;
  template?: string;
  commandTimeoutMs?: number;
  logger?: Logger;
  /**
   * Optional: lets diagnostics quote limactl's stderr without becoming a leak
   * path. The guest write path already keeps secret material off argv and out
   * of the guest script, so this only covers the case where the guest itself
   * echoes something back.
   */
  secretGuard?: SecretGuard;
};

type LimaInstance = {
  name: string;
  status: string;
  cpus?: number;
  memory?: number | string;
  disk?: number | string;
};

const BYTES_PER_MIB = 1024 * 1024;
const BYTES_PER_GIB = 1024 * 1024 * 1024;
const LIST_FORMAT =
  '{{printf "{\\"name\\":%q,\\"status\\":%q,\\"cpus\\":%d,\\"memory\\":%d,\\"disk\\":%d}" .Name .Status .CPUs .Memory .Disk}}';

function toNumber(value: number | string | undefined): number | null {
  if (value === undefined) return null;
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function mapStatus(status: string): NodeLifecycleStatus {
  switch (status.toLowerCase()) {
    case "running":
      return "running";
    case "stopped":
      return "stopped";
    default:
      // Broken/Installing/unknown are never treated as a usable state.
      return "unknown";
  }
}

function parseInstances(stdout: string): LimaInstance[] {
  const trimmed = stdout.trim();
  if (trimmed === "") return [];

  const instances: LimaInstance[] = [];
  // `limactl list --json` emits one JSON object per line.
  for (const line of trimmed.split("\n")) {
    const text = line.trim();
    if (text === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      failClosed("limactl list", "output is not valid JSON");
    }
    const list = Array.isArray(parsed) ? parsed : [parsed];
    for (const entry of list) {
      if (typeof entry !== "object" || entry === null) failClosed("limactl list", "instance entry is not an object");
      const record = entry as Record<string, unknown>;
      if (typeof record["name"] !== "string" || typeof record["status"] !== "string") {
        failClosed("limactl list", "instance entry is missing name/status");
      }
      instances.push(record as unknown as LimaInstance);
    }
  }
  return instances;
}

/**
 * The mount stanza of the instance definition, as a yq expression for
 * `limactl create --set`.
 *
 * `--mount` was the wrong instrument, and using it made the entire target
 * validation decorative: `limactl --mount` accepts `<host_path>[:w]` and
 * NOTHING ELSE (limactl 2.1.1: "Directories to mount, suffix ':w' for
 * writable"). The guest mount point is settable only in the instance YAML, so
 * `--mount=${source}:${...}` mounted every declared path at its HOST path
 * inside the guest, `verifyMounts` then asked `mountpoint -q <target>` about a
 * directory that did not exist, and no node with a mount could provision.
 * Meanwhile absolute-path, `..` and overlap validation were all asserted about
 * a string the runtime never consumed.
 *
 * `.mounts = [...]` also REPLACES the template's own mounts, which is the
 * behaviour the mount policy assumes: the default Lima template mounts the
 * whole host home read-only, which is precisely what
 * `MOUNT_POLICY_VIOLATION: mounting the entire host home directory` exists to
 * refuse. Declared mounts are the only mounts.
 */
export function mountsExpression(mounts: readonly MountSpec[]): string {
  const entries = mounts.map((mount) => ({
    location: mount.source,
    mountPoint: mount.target,
    writable: mount.writable,
  }));
  // The paths are validated upstream to carry no quote, backslash or control
  // character, and JSON is a subset of the yq expression syntax for literals.
  return `--set=.mounts = ${JSON.stringify(entries)}`;
}

export class LimaProvider implements NodeProvider {
  readonly #process: ProcessPort;
  readonly #limactl: string;
  readonly #template: string;
  readonly #timeoutMs: number;
  readonly #logger: Logger;
  readonly #guard: SecretGuard;

  constructor(options: LimaProviderOptions) {
    this.#process = options.process;
    this.#limactl = options.limactlPath ?? "limactl";
    this.#template = options.template ?? "template://default";
    this.#timeoutMs = options.commandTimeoutMs ?? 15 * 60 * 1000;
    this.#logger = options.logger ?? silentLogger;
    this.#guard = options.secretGuard ?? noopSecretGuard;
  }

  /**
   * limactl's stderr is untrusted text that ends up in an error message and so
   * on the operator's terminal. It is quoted only if the guard says it carries
   * no credential value; otherwise the diagnosis is dropped, not the failure.
   */
  #safeStderr(text: string): string {
    const trimmed = text.trim();
    if (trimmed === "") return "";
    try {
      this.#guard.assertClean("limactl:stderr", trimmed);
    } catch {
      return "[stderr withheld: it contained a credential value]";
    }
    return trimmed;
  }

  async create(input: CreateNodeInput): Promise<NodeRef> {
    const ref: NodeRef = { name: input.name, provider: "lima" };
    const existing = await this.inspect(ref);
    if (existing.status !== "absent") {
      // Idempotent: an existing instance is reconciled, never recreated.
      await this.applyResourceConfig(ref, input);
      return ref;
    }

    await this.#limactlRun([
      "create",
      "--tty=false",
      `--name=${input.name}`,
      `--cpus=${input.cpus}`,
      `--memory=${input.memoryMiB / 1024}`,
      `--disk=${input.diskGiB}`,
      mountsExpression(input.mounts),
      this.#template,
    ]);

    const created = await this.inspect(ref);
    if (created.status === "absent") {
      throw new YashikiError("VERIFICATION_FAILED", `lima instance '${input.name}' is absent after create`, {
        node: input.name,
      });
    }
    if (created.status === "unknown") {
      failClosed(`lima create ${input.name}`, "instance status could not be determined after create");
    }

    await this.applyResourceConfig(ref, input);
    return ref;
  }

  async start(node: NodeRef): Promise<void> {
    const before = await this.inspect(node);
    if (before.status === "absent") {
      throw new YashikiError("NOT_FOUND", `lima instance '${node.name}' does not exist`, { node: node.name });
    }
    if (before.status === "running") return;

    await this.#limactlRun(["start", "--tty=false", node.name]);
    await this.#requireStatus(node, "running", "start");
  }

  async stop(node: NodeRef): Promise<void> {
    const before = await this.inspect(node);
    if (before.status === "absent" || before.status === "stopped") return;

    await this.#limactlRun(["stop", node.name]);
    await this.#requireStatus(node, "stopped", "stop");
  }

  async inspect(node: NodeRef): Promise<NodeInspection> {
    // Lima 2.1.1's full JSON includes the complete instance config. A large
    // provisioned cloud-init document exceeds its internal bufio.Scanner and
    // makes *every* list fail, including inspection of an unrelated new VM.
    // Ask its Go-template renderer for exactly the five fields we consume.
    const result = await this.#limactlRun(["list", "--format", LIST_FORMAT], { allowFailure: true });
    if (result.exitCode !== 0) {
      failClosed(`lima list`, `limactl exited with ${String(result.exitCode)}: ${this.#safeStderr(result.stderr)}`);
    }

    const matches = parseInstances(result.stdout).filter((instance) => instance.name === node.name);
    if (matches.length > 1) {
      failClosed(`lima list ${node.name}`, "limactl reported the instance name more than once");
    }

    const instance = matches[0];
    if (instance === undefined) {
      return { ref: node, status: "absent", cpus: null, memoryMiB: null, diskGiB: null, mounts: [] };
    }

    const memoryBytes = toNumber(instance.memory);
    const diskBytes = toNumber(instance.disk);
    return {
      ref: node,
      status: mapStatus(instance.status),
      cpus: toNumber(instance.cpus),
      memoryMiB: memoryBytes === null ? null : Math.round(memoryBytes / BYTES_PER_MIB),
      diskGiB: diskBytes === null ? null : Math.round(diskBytes / BYTES_PER_GIB),
      mounts: [],
    };
  }

  async exec(node: NodeRef, input: ExecInput): Promise<ExecResult> {
    assertSafeArgv(input.argv);
    const argv = [
      "shell",
      ...(input.cwd === undefined ? [] : [`--workdir=${input.cwd}`]),
      node.name,
      "--",
      ...input.argv,
    ];

    const result = await this.#limactlRun(argv, {
      allowFailure: true,
      ...(input.stdin === undefined ? {} : { stdin: input.stdin }),
      ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
    });

    if (result.timedOut) {
      failClosed(`guest exec on ${node.name}`, "the command timed out and its effect is unknown");
    }
    if (result.exitCode === null) {
      failClosed(`guest exec on ${node.name}`, `process terminated by signal ${result.signal ?? "unknown"}`);
    }

    return {
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      timedOut: false,
      truncated: result.truncated,
    };
  }

  async destroy(node: NodeRef): Promise<void> {
    const before = await this.inspect(node);
    if (before.status === "absent") return;

    await this.#limactlRun(["delete", "--force", node.name]);
    await this.#requireStatus(node, "absent", "destroy");
  }

  /**
   * Resizing requires a stopped instance in Lima. Every applied value is read
   * back and compared exactly; a partial apply is an error, not a warning.
   */
  async applyResourceConfig(node: NodeRef, desired: CreateNodeInput): Promise<void> {
    const before = await this.inspect(node);
    if (before.status === "unknown") {
      failClosed(`lima inspect ${node.name}`, "instance status could not be determined before applying config");
    }

    const needsChange =
      (before.cpus !== null && before.cpus !== desired.cpus) ||
      (before.memoryMiB !== null && before.memoryMiB !== desired.memoryMiB) ||
      (before.diskGiB !== null && before.diskGiB < desired.diskGiB);

    if (needsChange) {
      if (before.status === "running") await this.stop(node);
      await this.#limactlRun([
        "edit",
        `--cpus=${desired.cpus}`,
        `--memory=${desired.memoryMiB / 1024}`,
        `--disk=${desired.diskGiB}`,
        node.name,
      ]);
    }

    const after = await this.inspect(node);
    // Disk was in the doc comment's "every applied value is read back" and in
    // the `needsChange` test, but not in the read-back — so a disk that limactl
    // accepted and did not grow was reported as a verified apply.
    if (after.cpus === null || after.memoryMiB === null || after.diskGiB === null) {
      failClosed(`lima edit ${node.name}`, "resource configuration could not be read back");
    }
    if (after.cpus !== desired.cpus || after.memoryMiB !== desired.memoryMiB || after.diskGiB < desired.diskGiB) {
      throw new YashikiError("VERIFICATION_FAILED", `lima instance '${node.name}' did not accept the resource config`, {
        expectedCpus: desired.cpus,
        actualCpus: after.cpus,
        expectedMemoryMiB: desired.memoryMiB,
        actualMemoryMiB: after.memoryMiB,
        expectedDiskGiB: desired.diskGiB,
        actualDiskGiB: after.diskGiB,
      });
    }

    this.#logger.log("debug", "resource config verified", { node: node.name });
  }

  /**
   * Exact read-back for mounts: the guest is asked whether each target is a
   * mount point and whether its writability matches the declaration.
   */
  async verifyMounts(node: NodeRef, mounts: readonly MountSpec[]): Promise<void> {
    for (const mount of mounts) {
      const mounted = await this.exec(node, { argv: ["mountpoint", "-q", mount.target] });
      if (mounted.exitCode !== 0) {
        throw new YashikiError("VERIFICATION_FAILED", `guest path '${mount.target}' is not a mount point`, {
          node: node.name,
          target: mount.target,
        });
      }

      const writable = await this.exec(node, { argv: ["test", "-w", mount.target] });
      const isWritable = writable.exitCode === 0;
      if (isWritable !== mount.writable) {
        throw new YashikiError("VERIFICATION_FAILED", `mount '${mount.target}' writability does not match config`, {
          node: node.name,
          target: mount.target,
          expectedWritable: mount.writable,
          actualWritable: isWritable,
        });
      }
    }
  }

  async #requireStatus(node: NodeRef, expected: NodeLifecycleStatus, operation: string): Promise<void> {
    const after = await this.inspect(node);
    if (after.status === "unknown") {
      failClosed(`lima ${operation} ${node.name}`, "instance status could not be determined after the operation");
    }
    if (after.status !== expected) {
      throw new YashikiError("VERIFICATION_FAILED", `lima ${operation} did not leave '${node.name}' ${expected}`, {
        node: node.name,
        expected,
        actual: after.status,
      });
    }
  }

  async #limactlRun(
    args: readonly string[],
    options: { allowFailure?: boolean; stdin?: string; timeoutMs?: number } = {},
  ): Promise<ProcessResult> {
    const result = await this.#process.run({
      argv: [this.#limactl, ...args],
      timeoutMs: options.timeoutMs ?? this.#timeoutMs,
      ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
    });

    if (options.allowFailure !== true) {
      if (result.timedOut) {
        failClosed(`limactl ${args[0] ?? ""}`, "the command timed out and its effect is unknown");
      }
      if (result.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", `limactl ${args[0] ?? ""} failed: ${this.#safeStderr(result.stderr)}`, {
          exitCode: result.exitCode ?? -1,
        });
      }
    }
    return result;
  }
}
