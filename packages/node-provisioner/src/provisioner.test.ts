import { describe, expect, it } from "vitest";
import {
  createInMemoryNodeLock,
  fixedClock,
  isYashikiError,
  type DesiredNodeConfig,
  type ExecResult,
  type NodeInspection,
  type NodeProvider,
} from "@meidoya-yashiki/yashiki-core";
import { BundleInstaller, type ArtifactSourcePort, type GuestInstallPort } from "@meidoya-yashiki/node-bundle";
import { CredentialMaterializer, type GuestCredentialPort } from "@meidoya-yashiki/credentials";
import { createInMemoryReceiptStore, sha256Hex } from "@meidoya-yashiki/receipts";
import type { NodeInstallReceipt } from "@meidoya-yashiki/node-protocol-client";
import { NodeProvisioner, PROVISION_STEPS, type ProvisionerOptions } from "./provisioner.js";
import type { NodeServicePort, RegistrationVerifierPort, SystemDependencyPort } from "./ports.js";

const clock = fixedClock("2026-01-01T00:00:00.000Z");
const HOME = "/Users/tester";
const SECRET = "sk-live-CODEX-secret-value";

const ARTIFACT = new TextEncoder().encode("meidoya-node-0.1.0");
const ARTIFACT_SHA256 = sha256Hex(ARTIFACT);
const MANIFEST_TEXT = JSON.stringify({
  product: "meidoya-node",
  version: "0.1.0",
  protocolVersion: 1,
  artifacts: [{ platform: "linux", arch: "arm64", sha256: ARTIFACT_SHA256 }],
});

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
    {
      provider: "codex",
      sourceRef: "keychain:codex",
      guestPath: "/home/meidoya/.codex/auth.json",
      mode: 0o600,
      owner: "meidoya",
      optional: false,
    },
  ],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: sha256Hex(MANIFEST_TEXT) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: ["shell"],
};

type Harness = {
  options: ProvisionerOptions;
  provisioner: NodeProvisioner;
  state: {
    created: string[];
    started: string[];
    credentialsWritten: string[];
    serviceInstalled: boolean;
    serviceRunning: boolean;
    systemPackages: string[];
    guestReceipt: NodeInstallReceipt | null;
    guestArtifact: Uint8Array | null;
  };
};

function harness(overrides: Partial<ProvisionerOptions> = {}, inspection?: Partial<NodeInspection>): Harness {
  const state = {
    created: [] as string[],
    started: [] as string[],
    credentialsWritten: [] as string[],
    serviceInstalled: false,
    serviceRunning: false,
    systemPackages: [] as string[],
    guestReceipt: null as NodeInstallReceipt | null,
    guestArtifact: null as Uint8Array | null,
  };
  let exists = false;
  let running = false;

  const provider: NodeProvider = {
    create: async (input) => {
      state.created.push(input.name);
      exists = true;
      return { name: input.name, provider: "lima" };
    },
    start: async (node) => {
      state.started.push(node.name);
      running = true;
    },
    stop: async () => {
      running = false;
    },
    inspect: async (node): Promise<NodeInspection> => ({
      ref: node,
      status: exists ? (running ? "running" : "stopped") : "absent",
      cpus: exists ? config.cpus : null,
      memoryMiB: exists ? config.memoryMiB : null,
      diskGiB: exists ? config.diskGiB : null,
      mounts: [],
      ...inspection,
    }),
    exec: async (): Promise<ExecResult> => ({ exitCode: 0, stdout: "", stderr: "", timedOut: false, truncated: false }),
    destroy: async () => {
      exists = false;
    },
  };

  const source: ArtifactSourcePort = {
    fetchManifest: async () => MANIFEST_TEXT,
    fetchArtifact: async () => ARTIFACT,
  };

  const guestInstall: GuestInstallPort = {
    installArtifact: async (_node, bytes) => {
      state.guestArtifact = bytes;
    },
    digestArtifact: async () => (state.guestArtifact === null ? null : sha256Hex(state.guestArtifact)),
    writeReceipt: async (_node, receipt) => {
      state.guestReceipt = receipt;
    },
    readReceipt: async () => state.guestReceipt,
  };

  const guestCredentials: GuestCredentialPort = {
    writeSecret: async (_node, path) => {
      state.credentialsWritten.push(path);
    },
    stat: async (_node, path) => ({
      exists: state.credentialsWritten.includes(path),
      isSymlink: false,
      owner: "meidoya",
      mode: 0o600,
      sha256: sha256Hex(SECRET),
    }),
    remove: async () => undefined,
  };

  const systemDeps: SystemDependencyPort = {
    ensure: async (_node, packages) => {
      state.systemPackages.push(...packages);
      return { missing: [] };
    },
  };

  const service: NodeServicePort = {
    install: async () => {
      state.serviceInstalled = true;
    },
    start: async () => {
      state.serviceRunning = true;
    },
    state: async () => (state.serviceRunning ? "running" : state.serviceInstalled ? "installed" : "absent"),
  };

  const registration: RegistrationVerifierPort = {
    check: async () => ({ registered: true, protocolVersion: 1, heartbeatAgeMs: 1_000 }),
  };

  const receipts = createInMemoryReceiptStore();

  const options: ProvisionerOptions = {
    provider,
    bundle: new BundleInstaller({ source, guest: guestInstall, receipts, clock }),
    credentials: new CredentialMaterializer({
      source: { read: async () => SECRET },
      guest: guestCredentials,
      receipts,
      clock,
    }),
    systemDeps,
    service,
    registration,
    receipts,
    lock: createInMemoryNodeLock(clock),
    homeDir: HOME,
    clock,
    ...overrides,
  };

  return { options, provisioner: new NodeProvisioner(options), state };
}

describe("NodeProvisioner", () => {
  it("runs the lifecycle in the documented order", async () => {
    const { provisioner, state } = harness();
    const result = await provisioner.provision(config, "run-1");

    expect(result.completedSteps).toEqual([...PROVISION_STEPS]);
    expect(state.created).toEqual(["work-grammarxiv"]);
    expect(state.credentialsWritten).toEqual(["/home/meidoya/.codex/auth.json"]);
    expect(state.serviceRunning).toBe(true);
    expect(result.installedVersion).toBe("0.1.0");
  });

  it("writes a provisioning receipt that lists the executed steps", async () => {
    const { provisioner, options } = harness();
    const result = await provisioner.provision(config, "run-1");

    const receipt = options.receipts.latest("provisioning", "work-grammarxiv");
    // The receipt is the record of the run, so it lists every step of it — the
    // one writing it included. This assertion used to encode the divergence
    // (`PROVISION_STEPS.slice(0, -1)`), which made a receipt that disagreed
    // with the `completedSteps` returned two lines later look intended.
    expect(receipt?.payload["steps"]).toEqual([...PROVISION_STEPS]);
    expect(receipt?.payload["steps"]).toEqual(result.completedSteps);
    expect(receipt?.payload["artifactSha256"]).toBe(ARTIFACT_SHA256);
    expect(options.receipts.verify()).toBeUndefined();
  });

  it("is idempotent: reprovision re-runs every step without reinstalling", async () => {
    const { provisioner, state } = harness();
    await provisioner.provision(config, "run-1");
    const second = await provisioner.reprovision(config, "run-2");

    expect(second.completedSteps).toEqual([...PROVISION_STEPS]);
    expect(second.changed).toBe(false);
    expect(state.created).toEqual(["work-grammarxiv"]);
  });

  it("installs the vendor sandbox dependencies by default", async () => {
    const { provisioner, state } = harness();
    await provisioner.provision(config, "run-1");
    expect(state.systemPackages).toEqual(["curl", "git", "ca-certificates", "bubblewrap", "socat"]);
  });

  it("refuses to provision a node that is already locked", async () => {
    const { provisioner, options, state } = harness();
    options.lock.acquire("work-grammarxiv", "other-run", 60_000);

    try {
      await provisioner.provision(config, "run-1");
    } catch (error) {
      expect(isYashikiError(error, "NODE_LOCKED")).toBe(true);
      expect(state.created).toEqual([]);
      return;
    }
    throw new Error("expected the node lock to block provisioning");
  });

  it("releases the node lock even when a step fails", async () => {
    const { provisioner, options } = harness({
      systemDeps: { ensure: async () => ({ missing: ["git"] }) },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/VERIFICATION_FAILED/);
    expect(options.lock.isHeld("work-grammarxiv")).toBe(false);
  });

  it("rejects a desired config that mounts the host home before touching the provider", async () => {
    const { provisioner, state } = harness();

    await expect(
      provisioner.provision({ ...config, mounts: [{ source: HOME, target: "/host", writable: true }] }, "run-1"),
    ).rejects.toThrowError(/MOUNT_POLICY_VIOLATION/);
    expect(state.created).toEqual([]);
  });

  it("fails closed when the provider cannot determine the node state", async () => {
    const { provisioner, state } = harness({}, { status: "unknown" });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/AMBIGUOUS_RESULT/);
    expect(state.created).toEqual([]);
  });

  it("aborts before credentials when the artifact checksum does not match", async () => {
    const receipts = createInMemoryReceiptStore();
    const base = harness();
    const provisioner = new NodeProvisioner({
      ...base.options,
      receipts,
      bundle: new BundleInstaller({
        source: {
          fetchManifest: async () => MANIFEST_TEXT,
          fetchArtifact: async () => new TextEncoder().encode("trojan"),
        },
        guest: {
          installArtifact: async () => {
            throw new Error("the artifact must never be installed");
          },
          digestArtifact: async () => null,
          writeReceipt: async () => undefined,
          readReceipt: async () => null,
        },
        receipts,
        clock,
      }),
    });

    try {
      await provisioner.provision(config, "run-1");
    } catch (error) {
      expect(isYashikiError(error, "CHECKSUM_MISMATCH")).toBe(true);
      expect(base.state.credentialsWritten).toEqual([]);
      expect(receipts.list({ kind: "install" })).toHaveLength(0);
      return;
    }
    throw new Error("expected the checksum mismatch to abort provisioning");
  });

  it("fails closed when the service state cannot be determined", async () => {
    const { provisioner } = harness({
      service: { install: async () => undefined, start: async () => undefined, state: async () => null },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("fails closed when the Control Plane view is incomplete", async () => {
    const { provisioner } = harness({
      registration: { check: async () => ({ registered: true, protocolVersion: 1, heartbeatAgeMs: null }) },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("fails when the node registers with the wrong protocol version", async () => {
    const { provisioner } = harness({
      registration: { check: async () => ({ registered: true, protocolVersion: 2, heartbeatAgeMs: 100 }) },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/PROTOCOL_MISMATCH/);
  });

  it("fails when the heartbeat is stale", async () => {
    const { provisioner } = harness({
      registration: { check: async () => ({ registered: true, protocolVersion: 1, heartbeatAgeMs: 10 * 60_000 }) },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  it("fails when the heartbeat is dated in the future", async () => {
    // Only staleness was ever asserted, so a guest clock a day fast reported
    // `ok` — the more wrong the clock, the fresher the dead node looked.
    const { provisioner } = harness({
      registration: { check: async () => ({ registered: true, protocolVersion: 1, heartbeatAgeMs: -86_400_000 }) },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  it("refuses to start a node whose installed artifact is not the pinned one", async () => {
    // `assertStartAllowed` was wired into step 10 and enforced by nothing:
    // replacing the call with `void installed;` left all thirteen tests green,
    // so the Phase-6 DoD rested entirely on the function's own unit tests. Here
    // the guest swaps its receipt between the install and the start.
    const base = harness();
    const receipts = createInMemoryReceiptStore();
    let stored: NodeInstallReceipt | null = null;
    let reads = 0;

    const swapped: GuestInstallPort = {
      installArtifact: async () => undefined,
      digestArtifact: async () => ARTIFACT_SHA256,
      writeReceipt: async (_node, receipt) => {
        stored = receipt;
      },
      // The install's own two reads see the truth; by the time step 10 asks,
      // the guest reports a different artifact.
      readReceipt: async () => {
        reads += 1;
        return reads > 2 && stored !== null ? { ...stored, artifactSha256: "b".repeat(64) } : stored;
      },
    };

    const provisioner = new NodeProvisioner({
      ...base.options,
      bundle: new BundleInstaller({
        source: { fetchManifest: async () => MANIFEST_TEXT, fetchArtifact: async () => ARTIFACT },
        guest: swapped,
        receipts,
        clock,
      }),
      receipts,
    });

    try {
      await provisioner.provision(config, "run-1");
    } catch (error) {
      expect(isYashikiError(error, "ARTIFACT_MISMATCH")).toBe(true);
      expect(base.state.serviceRunning).toBe(false);
      return;
    }
    throw new Error("expected the artifact mismatch to refuse the start");
  });

  it("applies the resource config before reading it back", async () => {
    // Step 4 is called "apply-resource-and-mount-config" and only ever
    // verified, so raising `cpus` in config.yaml made every reprovision throw
    // VERIFICATION_FAILED for good: nothing could make the node match.
    const applied: number[] = [];
    let cpus = 2;
    const base = harness({}, {});
    const provisioner = new NodeProvisioner({
      ...base.options,
      provider: {
        ...base.options.provider,
        inspect: async (node) => ({
          ref: node,
          status: "running" as const,
          cpus,
          memoryMiB: config.memoryMiB,
          diskGiB: config.diskGiB,
          mounts: [],
        }),
      },
      applyResourceConfig: async (_node, desired) => {
        applied.push(desired.cpus);
        cpus = desired.cpus;
      },
    });

    const result = await provisioner.provision(config, "run-1");
    expect(applied).toEqual([config.cpus]);
    expect(result.completedSteps).toContain("apply-resource-and-mount-config");
  });

  it("propagates a mount read-back failure", async () => {
    const { provisioner } = harness({
      verifyMounts: async () => {
        throw new Error("VERIFICATION_FAILED: mount is missing");
      },
    });

    await expect(provisioner.provision(config, "run-1")).rejects.toThrowError(/VERIFICATION_FAILED/);
  });
});
