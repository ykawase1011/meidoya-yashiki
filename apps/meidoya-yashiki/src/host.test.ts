import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  fixedClock,
  isYashikiError,
  type DesiredNodeConfig,
  type ExecInput,
  type ExecResult,
  type NodeProvider,
  type NodeRef,
  type ProcessPort,
  type ProcessRequest,
  type ProcessResult,
} from "@meidoya-yashiki/yashiki-core";
import {
  NODE_BINARY_PATH,
  NODE_CONFIG_PATH,
  createGuestSystemDependencies,
  createGuestInstallPort,
  createGuestRegistrationVerifier,
  createHostSecretSource,
  createSystemdServicePort,
  renderNodeConfig,
  renderNodeConfigYaml,
  serviceUnit,
} from "./host.js";

const here = dirname(fileURLToPath(import.meta.url));

const config: DesiredNodeConfig = {
  name: "work-grammarxiv",
  provider: "lima",
  profile: "lima-trusted",
  platform: "linux",
  arch: "arm64",
  cpus: 8,
  memoryMiB: 16384,
  diskGiB: 100,
  mounts: [{ source: "/Users/tester/Workspace/Repositories/GrammarXiv", target: "/workspace/GrammarXiv", writable: true }],
  credentials: [
    { provider: "codex", sourceRef: "keychain:codex", guestPath: "/home/meidoya/.codex/auth.json", mode: 0o600, owner: "meidoya", optional: false },
  ],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: "a".repeat(64) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: ["shell"],
};

/**
 * A NodeProvider whose `exec` understands exactly the shell idioms host.ts
 * uses to write and read guest files, backed by an in-memory filesystem. Good
 * enough to exercise createSystemdServicePort / createGuestRegistrationVerifier
 * without a real guest.
 */
function fakeProvider(): { provider: NodeProvider; files: Map<string, string> } {
  const files = new Map<string, string>();

  const provider: NodeProvider = {
    create: async (input) => ({ name: input.name, provider: "lima" }),
    start: async () => undefined,
    stop: async () => undefined,
    inspect: async (node) => ({ ref: node, status: "running", cpus: null, memoryMiB: null, diskGiB: null, mounts: [] }),
    destroy: async () => undefined,
    exec: async (_node: NodeRef, input: ExecInput): Promise<ExecResult> => {
      const argv = input.argv;
      const effectiveArgv = argv[0] === "sudo" ? argv.slice(1) : argv;
      if (effectiveArgv[0] === "cat" && effectiveArgv.length === 2) {
        const path = effectiveArgv[1] as string;
        const content = files.get(path);
        return content === undefined
          ? { exitCode: 1, stdout: "", stderr: "no such file", timedOut: false, truncated: false }
          : { exitCode: 0, stdout: content, stderr: "", timedOut: false, truncated: false };
      }
      // Every write in host.ts is `sudo sh -c '<script>' sh <path>` with the
      // content on stdin; the target path is always the last argv entry.
      if (argv.includes("sh") && argv.includes("-c")) {
        const path = argv[argv.length - 1] as string;
        files.set(path, input.stdin ?? "");
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
      }
      return { exitCode: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    },
  };

  return { provider, files };
}

describe("node launch interface (Defect 1)", () => {
  it("renders an ExecStart line that invokes --config, never the removed --node-id/--control-plane flags", () => {
    const unit = serviceUnit(config);
    expect(unit).toContain(`ExecStart=/usr/local/bin/meidoya-node --config ${NODE_CONFIG_PATH}`);
    expect(unit).not.toContain("--node-id");
    expect(unit).not.toContain("--control-plane");
    expect(unit).not.toContain("--task-queue");
  });

  it("runs the service as the dedicated account and passes only credential file paths", () => {
    const unit = serviceUnit({
      ...config,
      credentials: [
        ...config.credentials,
        {
          provider: "claude",
          sourceRef: "sops:/host/claude.yaml#token",
          guestPath: "/home/meidoya/.claude/setup.token",
          mode: 0o600,
          owner: "meidoya",
          optional: false,
        },
        {
          provider: "node-registration",
          sourceRef: "private-file:/host/node.token",
          guestPath: "/home/meidoya/.config/meidoya-node/registration.token",
          mode: 0o600,
          owner: "meidoya",
          optional: false,
        },
      ],
      modelEnvironment: {
        MEIDOYA_MODEL_CLAUDE_STANDARD: "sonnet",
        MEIDOYA_MODEL_CODEX_STANDARD: "gpt-5.6-sol",
      },
    });

    expect(unit).toContain("User=meidoya\nGroup=meidoya");
    expect(unit).toContain("Environment=HOME=/home/meidoya");
    expect(unit).toContain("Environment=CODEX_HOME=/home/meidoya/.codex");
    expect(unit).toContain(
      "Environment=MEIDOYA_NODE_TOKEN_FILE=/home/meidoya/.config/meidoya-node/registration.token",
    );
    expect(unit).toContain("Environment=MEIDOYA_CLAUDE_TOKEN_FILE=/home/meidoya/.claude/setup.token");
    expect(unit).toContain("Environment=MEIDOYA_MODEL_CODEX_STANDARD=gpt-5.6-sol");
    expect(unit).not.toContain("sops:/host/claude.yaml#token");
    expect(unit).not.toContain("private-file:/host/node.token");
  });

  it("writes a node config file to the guest before installing the service unit", async () => {
    const { provider, files } = fakeProvider();
    const service = createSystemdServicePort(provider);

    await service.install({ name: config.name, provider: "lima" }, config);

    expect(files.get(NODE_CONFIG_PATH)).toBe(renderNodeConfigYaml(config));
    expect(files.get("/etc/systemd/system/meidoya-node.service")).toBe(serviceUnit(config));
  });

  it("renders a config that satisfies the meidoya NodeConfigSchema shape (schema_version, node.id, node.control_plane, filesystem.allowed_roots)", () => {
    const rendered = renderNodeConfig(config) as {
      schema_version: number;
      node: { id: string; profile: string; control_plane: string; max_concurrency: number };
      filesystem: { allowed_roots: string[]; allow_home_fallback: boolean };
      workspaces: Record<string, unknown>;
    };

    expect(rendered.schema_version).toBe(1);
    expect(rendered.node.id).toBe(config.name);
    expect(rendered.node.profile).toBe(config.profile);
    expect(rendered.node.control_plane).toBe(config.controlPlane.endpoint);
    expect(rendered.node.max_concurrency).toBe(config.maxConcurrency);
    expect(rendered.filesystem.allowed_roots).toContain("/workspace/GrammarXiv");
    expect(rendered.filesystem.allow_home_fallback).toBe(false);
    expect(Object.keys(rendered.workspaces).length).toBeGreaterThan(0);
  });

  it(
    "the ExecStart invocation is accepted by the REAL meidoya-node argument parser (the crash-loop regression test)",
    () => {
      const repoRoot = resolve(here, "../../../..");
      const meidoyaRoot = resolve(repoRoot, "..", "meidoya");
      const binary = join(meidoyaRoot, "apps", "meidoya-node", "dist", "main.js");

      if (!existsSync(binary)) {
        // CI for meidoya-yashiki alone does not have the meidoya repository
        // built alongside it; skip cleanly rather than fail on an absent sibling.
        return;
      }

      const dir = mkdtempSync(join(tmpdir(), "meidoya-node-config-"));
      try {
        const configPath = join(dir, "node.yaml");
        writeFileSync(configPath, renderNodeConfigYaml(config), "utf8");

        // Same ExecStart argv Yashiki writes into the systemd unit, minus the
        // binary path itself, plus --help so the daemon parses its args and
        // exits immediately instead of trying to connect to Temporal/Control
        // Plane.
        const unitArgv = ["--config", configPath, "--help"];
        const result = spawnSync(process.execPath, [binary, ...unitArgv], { encoding: "utf8" });

        expect(result.stderr).not.toContain("Unknown option");
        expect(result.status).toBe(0);
        expect(result.stdout).toContain("meidoya-node");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it("the REAL parser rejects the old --node-id/--control-plane/--task-queue flags (proves this is a real regression test, not a restatement)", () => {
    const repoRoot = resolve(here, "../../../..");
    const meidoyaRoot = resolve(repoRoot, "..", "meidoya");
    const binary = join(meidoyaRoot, "apps", "meidoya-node", "dist", "main.js");

    if (!existsSync(binary)) return;

    const oldArgv = ["--node-id", config.name, "--control-plane", config.controlPlane.endpoint, "--task-queue", config.controlPlane.taskQueue];
    const result = spawnSync(process.execPath, [binary, ...oldArgv], { encoding: "utf8" });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Unknown option");
  });
});

describe("guest runtime account", () => {
  it("creates the meidoya account even when every package is already installed", async () => {
    const commands: readonly string[][] = [];
    const mutableCommands = commands as string[][];
    const provider: NodeProvider = {
      create: async (input) => ({ name: input.name, provider: "lima" }),
      start: async () => undefined,
      stop: async () => undefined,
      inspect: async (node) => ({ ref: node, status: "running", cpus: null, memoryMiB: null, diskGiB: null, mounts: [] }),
      destroy: async () => undefined,
      exec: async (_node, input) => {
        mutableCommands.push([...input.argv]);
        return {
          exitCode: 0,
          stdout: input.argv[0] === "dpkg-query" ? "install ok installed" : "",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    };

    const result = await createGuestSystemDependencies(provider).ensure(
      { name: config.name, provider: "lima" },
      ["curl", "git"],
    );

    expect(result.missing).toEqual([]);
    expect(commands.some((argv) => argv.join(" ").includes("useradd --system"))).toBe(true);
    expect(commands.some((argv) => argv.includes("apt-get"))).toBe(false);
  });
});

/**
 * Defect 20e. The environment allowlist stopped `sops` from finding its key,
 * and the resulting non-zero exit was reported as "credential not available on
 * the host" — a NOT_FOUND for a credential that was exactly where it belonged.
 */
/**
 * The node artifact is BINARY and `ProcessRequest.stdin` is a `string` written
 * at Node's default utf8 encoding, so the two need an encoding between them
 * that survives the trip. The old one — latin1 in, utf8 out — did not.
 */
describe("the rendered node config", () => {
  it("keeps every declared workspace when two targets share a basename", () => {
    // The id was the target's BASENAME, so `/workspace/a/repo` and
    // `/workspace/b/repo` were both `repo` and the second silently replaced the
    // first: a declared, mounted project invisible to the node, with nothing
    // anywhere saying so.
    const rendered = renderNodeConfig({
      ...config,
      mounts: [
        { source: "/Users/tester/a/repo", target: "/workspace/a/repo", writable: true },
        { source: "/Users/tester/b/repo", target: "/workspace/b/repo", writable: true },
      ],
    }) as { workspaces: Record<string, { projects: Record<string, { path: string }> }> };

    const paths = Object.values(rendered.workspaces).map((workspace) => Object.values(workspace.projects)[0]?.path);
    expect(Object.keys(rendered.workspaces)).toHaveLength(2);
    expect(paths.sort()).toEqual(["/workspace/a/repo", "/workspace/b/repo"]);
  });

  it("still uses the plain basename when it is unambiguous", () => {
    const rendered = renderNodeConfig(config) as { workspaces: Record<string, unknown> };
    expect(Object.keys(rendered.workspaces)).toEqual(["GrammarXiv"]);
  });

  it("never grants guest-full to a node that does not run inside a Lima guest", () => {
    const rendered = renderNodeConfig({
      ...config,
      provider: "native",
      profile: "lima-trusted",
      mounts: [],
    }) as { filesystem: { mode: string } };
    expect(rendered.filesystem.mode).toBe("allowed-roots");
  });
});

describe("the node artifact on the way to the guest", () => {
  /** A guest that decodes what it is given, the way `base64 -d` would. */
  function binaryGuest(): { provider: NodeProvider; installed: Uint8Array | null } {
    let installedChunks: Buffer[] | null = null;
    const provider: NodeProvider = {
      create: async (input) => ({ name: input.name, provider: "lima" }),
      start: async () => undefined,
      stop: async () => undefined,
      inspect: async (node) => ({ ref: node, status: "running", cpus: null, memoryMiB: null, diskGiB: null, mounts: [] }),
      destroy: async () => undefined,
      exec: async (_node: NodeRef, input: ExecInput): Promise<ExecResult> => {
        // `sudo sh -c SCRIPT ...` and `sh -c SCRIPT ...` put the script at
        // different indices; the guest cares about the script, not the index.
        const script = input.argv.join(" ");
        // The stdin the port produced is what the wire actually carries: a
        // JS string, encoded to bytes at utf8 exactly as `child.stdin.end`
        // would encode it.
        const wire = Buffer.from(input.stdin ?? "", "utf8");
        if (script.includes(": >")) {
          installedChunks = [];
          return { exitCode: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
        }
        if (script.includes("base64 -d")) {
          const decoded = Buffer.from(wire.toString("utf8"), "base64");
          installedChunks?.push(decoded);
          return { exitCode: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
        }
        if (script.includes("sha256sum")) {
          const digest =
            installedChunks === null ? "" : createHash("sha256").update(Buffer.concat(installedChunks)).digest("hex");
          return installedChunks === null
            ? { exitCode: 1, stdout: "", stderr: "", timedOut: false, truncated: false }
            : { exitCode: 0, stdout: `${digest}  ${NODE_BINARY_PATH}\n`, stderr: "", timedOut: false, truncated: false };
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
      },
    };
    return {
      provider,
      get installed() {
        return installedChunks === null ? null : new Uint8Array(Buffer.concat(installedChunks));
      },
    };
  }

  it("delivers every byte of a binary artifact unchanged", async () => {
    // An ELF header and a run of high bytes: latin1-in/utf8-out turned this
    // 10-byte header into 13 bytes on the guest, and the receipt attested the
    // uncorrupted host digest anyway.
    const artifact = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0xff, 0xc3, 0x80, 0x90, 0xfe]);
    const guest = binaryGuest();

    await createGuestInstallPort(guest.provider).installArtifact({ name: config.name, provider: "lima" }, artifact);

    expect(guest.installed).toEqual(artifact);
  });

  it("preserves an artifact across multiple bounded transfer chunks", async () => {
    const artifact = new Uint8Array(8 * 1024 * 1024 + 3);
    artifact[0] = 0x7f;
    artifact[artifact.length - 1] = 0xfe;
    const guest = binaryGuest();

    await createGuestInstallPort(guest.provider).installArtifact(
      { name: config.name, provider: "lima" },
      artifact,
    );

    const installed = guest.installed;
    expect(installed).not.toBeNull();
    expect(installed).toHaveLength(artifact.length);
    expect(createHash("sha256").update(installed ?? new Uint8Array()).digest("hex")).toBe(
      createHash("sha256").update(artifact).digest("hex"),
    );
  });

  it("hashes the artifact where it landed, on the guest", async () => {
    const artifact = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0xff, 0xfe]);
    const guest = binaryGuest();
    const port = createGuestInstallPort(guest.provider);
    const node = { name: config.name, provider: "lima" as const };

    expect(await port.digestArtifact(node)).toBeNull();
    await port.installArtifact(node, artifact);
    expect(await port.digestArtifact(node)).toBe(createHash("sha256").update(artifact).digest("hex"));
  });
});

describe("host credential sources", () => {
  /** An obvious dummy; only its presence in stdout is ever used. */
  const DUMMY_VALUE = "dummy-not-a-real-credential-value";

  function recordingPort(result: Partial<ProcessResult> = {}): ProcessPort & {
    readonly requests: ProcessRequest[];
  } {
    const requests: ProcessRequest[] = [];
    return {
      requests,
      async run(request) {
        requests.push(request);
        return {
          exitCode: 0,
          signal: null,
          stdout: `${DUMMY_VALUE}\n`,
          stderr: "",
          timedOut: false,
          truncated: false,
          ...result,
        };
      },
    };
  }

  it("lets a sops source inherit the locators it needs to find a key", async () => {
    const port = recordingPort();
    await createHostSecretSource(port).read("sops:/Users/dummy/secrets/claude.yaml");

    const inherited = port.requests[0]?.inheritEnv ?? [];
    expect(port.requests[0]?.argv[0]).toBe("sops");
    expect(inherited).toContain("SOPS_AGE_KEY_FILE");
    expect(inherited).toContain("GNUPGHOME");
    expect(inherited).toContain("AWS_PROFILE");
    // Locators only: a key VALUE is never forwarded to a child.
    expect(inherited).not.toContain("SOPS_AGE_KEY");
    expect(inherited).not.toContain("AWS_SECRET_ACCESS_KEY");
  });

  it("gives the keychain source no extra environment at all", async () => {
    const port = recordingPort();
    await createHostSecretSource(port).read("keychain:meidoya/claude-dummy");
    expect(port.requests[0]?.inheritEnv ?? []).toEqual([]);
  });

  it("reads a private file through a fixed validation script", async () => {
    const port = recordingPort();
    await createHostSecretSource(port).read("private-file:/Users/dummy/.codex/auth.json");

    expect(port.requests[0]?.argv[0]).toBe("sh");
    expect(port.requests[0]?.argv.at(-1)).toBe("/Users/dummy/.codex/auth.json");
    expect(port.requests[0]?.argv.join(" ")).not.toContain(DUMMY_VALUE);
  });

  it("extracts only the Claude token from a Hermes SOPS document", async () => {
    const port = recordingPort();
    await createHostSecretSource(port).read(
      "hermes-sops:/Users/dummy/HermesFleet/secrets/projects/example.sops.yaml#claude.code_oauth_token",
    );

    const argv = port.requests[0]?.argv ?? [];
    expect(argv[0]).toBe("sh");
    expect(argv.at(-1)).toBe("/Users/dummy/HermesFleet/secrets/projects/example.sops.yaml");
    expect(argv.join(" ")).toContain("hermes-sops-age");
    expect(argv.join(" ")).not.toContain(DUMMY_VALUE);
  });

  it("refuses any other Hermes SOPS selector", async () => {
    await expect(
      createHostSecretSource(recordingPort()).read(
        "hermes-sops:/Users/dummy/example.sops.yaml#other.bot_token",
      ),
    ).rejects.toThrowError(/claude\.code_oauth_token/);
  });

  it("reports a key sops could not reach as a configuration failure, not as a missing credential", async () => {
    // 128 is sops' CouldNotRecoverDataKey: the file is right there, the key is not.
    const port = recordingPort({ exitCode: 128, stdout: "" });
    const source = createHostSecretSource(port);

    await expect(source.read("sops:/Users/dummy/secrets/claude.yaml")).rejects.toThrowError(/CONFIG_INVALID/);
    try {
      await source.read("sops:/Users/dummy/secrets/claude.yaml");
    } catch (error) {
      if (!isYashikiError(error, "CONFIG_INVALID")) throw error;
      expect(error.code).not.toBe("NOT_FOUND");
      expect(error.message).toContain("key material");
      expect(error.message).toContain("SOPS_AGE_KEY_FILE");
      expect(error.details).toEqual({ sourceRef: "sops:/Users/dummy/secrets/claude.yaml", exitCode: 128 });
      return;
    }
    throw new Error("expected a refusal");
  });

  it("still reports a genuinely absent sops secret as absent", async () => {
    // Exit 2 is CouldNotReadInputFile: there is no such secret to read.
    const port = recordingPort({ exitCode: 2, stdout: "" });
    expect(await createHostSecretSource(port).read("sops:/Users/dummy/secrets/absent.yaml")).toBeNull();
  });

  it("returns the value a working source printed, with the trailing newline removed", async () => {
    const port = recordingPort();
    expect(await createHostSecretSource(port).read("keychain:meidoya/claude-dummy")).toBe(DUMMY_VALUE);
  });
});

describe("heartbeat timestamp handling (Defect 2)", () => {
  it("computes a small heartbeatAgeMs for a fresh epoch-millisecond lastHeartbeatAt", async () => {
    const { provider, files } = fakeProvider();
    const now = "2026-08-17T12:00:00.000Z";
    const clock = fixedClock(now);
    const fiveSecondsAgo = Date.parse(now) - 5_000;

    files.set(
      "/var/lib/meidoya-node/registration.json",
      JSON.stringify({ registered: true, protocolVersion: 1, lastHeartbeatAt: fiveSecondsAgo }),
    );

    const verifier = createGuestRegistrationVerifier(provider, clock);
    const status = await verifier.check({ name: config.name, provider: "lima" }, config);

    expect(status.registered).toBe(true);
    expect(status.heartbeatAgeMs).toBe(5_000);
  });

  it("computes a large heartbeatAgeMs for a stale epoch-millisecond lastHeartbeatAt", async () => {
    const { provider, files } = fakeProvider();
    const now = "2026-08-17T12:00:00.000Z";
    const clock = fixedClock(now);
    const oneHourAgo = Date.parse(now) - 60 * 60_000;

    files.set(
      "/var/lib/meidoya-node/registration.json",
      JSON.stringify({ registered: true, protocolVersion: 1, lastHeartbeatAt: oneHourAgo }),
    );

    const verifier = createGuestRegistrationVerifier(provider, clock);
    const status = await verifier.check({ name: config.name, provider: "lima" }, config);

    expect(status.heartbeatAgeMs).toBe(60 * 60_000);
  });

  it("never reports null for a valid epoch-ms heartbeat (the permanent-FAIL regression)", async () => {
    const { provider, files } = fakeProvider();
    files.set(
      "/var/lib/meidoya-node/registration.json",
      JSON.stringify({ registered: true, protocolVersion: 1, lastHeartbeatAt: Date.now() }),
    );

    const verifier = createGuestRegistrationVerifier(provider);
    const status = await verifier.check({ name: config.name, provider: "lima" }, config);

    expect(status.heartbeatAgeMs).not.toBeNull();
  });
});
