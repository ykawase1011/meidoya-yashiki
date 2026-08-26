import {
  assertSafeArgv,
  failClosed,
  validateMounts,
  YashikiError,
  type CreateNodeInput,
  type ExecInput,
  type ExecResult,
  type NodeInspection,
  type NodeProvider,
  type NodeRef,
  type ProcessPort,
} from "@meidoya-yashiki/yashiki-core";

/**
 * Service control for a node running directly on the host: launchd on darwin,
 * systemd --user on linux. Injected so tests never touch a real service manager.
 */
export interface HostServicePort {
  isInstalled(nodeName: string): Promise<boolean>;
  isRunning(nodeName: string): Promise<boolean>;
  start(nodeName: string): Promise<void>;
  stop(nodeName: string): Promise<void>;
  remove(nodeName: string): Promise<void>;
}

export type NativeProviderOptions = {
  process: ProcessPort;
  service: HostServicePort;
  commandTimeoutMs?: number;
};

/**
 * A native node has no VM boundary: there is nothing to create, resize or mount.
 * The provider therefore only manages the service and runs commands locally,
 * and it rejects any mount request outright (11 section 8).
 */
export class NativeProvider implements NodeProvider {
  readonly #process: ProcessPort;
  readonly #service: HostServicePort;
  readonly #timeoutMs: number;

  constructor(options: NativeProviderOptions) {
    this.#process = options.process;
    this.#service = options.service;
    this.#timeoutMs = options.commandTimeoutMs ?? 5 * 60 * 1000;
  }

  async create(input: CreateNodeInput): Promise<NodeRef> {
    validateMounts(input.mounts, { homeDir: "/" }, "native");
    return { name: input.name, provider: "native" };
  }

  async start(node: NodeRef): Promise<void> {
    await this.#requireInstalled(node);
    if (await this.#service.isRunning(node.name)) return;

    await this.#service.start(node.name);
    if (!(await this.#service.isRunning(node.name))) {
      throw new YashikiError("VERIFICATION_FAILED", `native node '${node.name}' did not start`, { node: node.name });
    }
  }

  async stop(node: NodeRef): Promise<void> {
    if (!(await this.#service.isInstalled(node.name))) return;
    if (!(await this.#service.isRunning(node.name))) return;

    await this.#service.stop(node.name);
    if (await this.#service.isRunning(node.name)) {
      throw new YashikiError("VERIFICATION_FAILED", `native node '${node.name}' did not stop`, { node: node.name });
    }
  }

  async inspect(node: NodeRef): Promise<NodeInspection> {
    if (!(await this.#service.isInstalled(node.name))) {
      return { ref: node, status: "absent", cpus: null, memoryMiB: null, diskGiB: null, mounts: [] };
    }
    return {
      ref: node,
      status: (await this.#service.isRunning(node.name)) ? "running" : "stopped",
      // Host resources are not owned by Yashiki, so they are reported as unknown
      // rather than guessed from the machine.
      cpus: null,
      memoryMiB: null,
      diskGiB: null,
      mounts: [],
    };
  }

  async exec(node: NodeRef, input: ExecInput): Promise<ExecResult> {
    assertSafeArgv(input.argv);
    const result = await this.#process.run({
      argv: input.argv,
      timeoutMs: input.timeoutMs ?? this.#timeoutMs,
      ...(input.stdin === undefined ? {} : { stdin: input.stdin }),
    });

    if (result.timedOut) {
      failClosed(`native exec on ${node.name}`, "the command timed out and its effect is unknown");
    }
    if (result.exitCode === null) {
      failClosed(`native exec on ${node.name}`, `process terminated by signal ${result.signal ?? "unknown"}`);
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
    await this.stop(node);
    await this.#service.remove(node.name);
    if (await this.#service.isInstalled(node.name)) {
      throw new YashikiError("VERIFICATION_FAILED", `native node '${node.name}' service was not removed`, {
        node: node.name,
      });
    }
  }

  async #requireInstalled(node: NodeRef): Promise<void> {
    if (!(await this.#service.isInstalled(node.name))) {
      throw new YashikiError("NOT_FOUND", `native node '${node.name}' has no installed service`, { node: node.name });
    }
  }
}

export function createFakeHostServicePort(): HostServicePort & { installed: Set<string>; running: Set<string> } {
  const installed = new Set<string>();
  const running = new Set<string>();
  return {
    installed,
    running,
    isInstalled: async (name) => installed.has(name),
    isRunning: async (name) => running.has(name),
    start: async (name) => {
      running.add(name);
    },
    stop: async (name) => {
      running.delete(name);
    },
    remove: async (name) => {
      running.delete(name);
      installed.delete(name);
    },
  };
}
