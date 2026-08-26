import { describe, expect, it } from "vitest";
import { createSecretGuard, isYashikiError, type DesiredNodeConfig } from "@meidoya-yashiki/yashiki-core";
import { renderDoctorReport, runDoctor, type DoctorProbes } from "./doctor.js";

const SECRET = "sk-live-CLAUDE-secret-value";
const ARTIFACT_SHA256 = "a".repeat(64);

const config: DesiredNodeConfig = {
  name: "work-grammarxiv",
  provider: "lima",
  profile: "lima-trusted",
  platform: "linux",
  arch: "arm64",
  cpus: 8,
  memoryMiB: 16384,
  diskGiB: 100,
  mounts: [{ source: "/Users/tester/Workspace/x", target: "/workspace/x", writable: true }],
  credentials: [
    {
      provider: "claude",
      sourceRef: "keychain:claude",
      guestPath: "/home/meidoya/.claude/token",
      mode: 0o600,
      owner: "meidoya",
      optional: false,
    },
  ],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: "b".repeat(64) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: [],
};

function probes(overrides: Partial<DoctorProbes> = {}): DoctorProbes {
  return {
    providerVersion: async () => "1.0.0",
    inspect: async () => ({
      ref: { name: config.name, provider: "lima" },
      status: "running",
      cpus: config.cpus,
      memoryMiB: config.memoryMiB,
      diskGiB: config.diskGiB,
      mounts: [],
    }),
    installedReceipt: async () => ({
      product: "meidoya-node",
      version: "0.1.0",
      protocolVersion: 1,
      artifactSha256: ARTIFACT_SHA256,
      installedAt: "2026-01-01T00:00:00.000Z",
    }),
    expectedArtifactSha256: async () => ARTIFACT_SHA256,
    serviceState: async () => "running",
    registration: async () => ({ registered: true, protocolVersion: 1, heartbeatAgeMs: 500 }),
    taskQueuePoller: async () => ({ polling: true, queue: config.controlPlane.taskQueue }),
    runtimeReadiness: async (runtime) => ({ ready: true, detail: `${runtime} CLI available` }),
    mountState: async () => ({ mounted: true, writable: true }),
    credentialState: async () => ({
      exists: true,
      isSymlink: false,
      owner: "meidoya",
      mode: 0o600,
      sha256: "c".repeat(64),
    }),
    ...overrides,
  };
}

describe("doctor", () => {
  it("covers every check from the design", async () => {
    const report = await runDoctor(config, { probes: probes() });

    expect(report.status).toBe("ok");
    expect(report.checks.map((check) => check.id)).toEqual([
      "provider-version",
      "provider-registry",
      "node-artifact",
      "node-service",
      "control-plane-registration",
      "task-queue-poller",
      "codex-runtime",
      "claude-runtime",
      "mount:/workspace/x",
      "credential:claude",
    ]);
  });

  it("fails a heartbeat dated in the future rather than calling it fresh", async () => {
    // Only staleness was ever checked, so `-86_400_000` — a guest clock a day
    // fast, or a forged registration.json — reported `ok`: the more wrong the
    // clock, the healthier the dead node looked.
    const report = await runDoctor(config, {
      probes: probes({
        registration: async () => ({ registered: true, protocolVersion: 1, heartbeatAgeMs: -86_400_000 }),
      }),
    });

    const check = report.checks.find((entry) => entry.id === "control-plane-registration");
    expect(check?.status).toBe("fail");
    expect(check?.detail).toContain("in the future");
    expect(report.status).toBe("fail");
  });

  it("reports credential presence only, never the value", async () => {
    const guard = createSecretGuard([SECRET]);
    const report = await runDoctor(config, { probes: probes(), secretGuard: guard });

    const credential = report.checks.find((check) => check.id === "credential:claude");
    expect(credential?.status).toBe("ok");
    expect(credential?.detail).toBe("present, owner meidoya, mode 0600");

    const rendered = renderDoctorReport(report, guard);
    expect(rendered).not.toContain(SECRET);
    expect(rendered).toContain("Credential claude: present");
  });

  it("refuses to render a report that would leak a credential value", () => {
    const guard = createSecretGuard([SECRET]);
    try {
      renderDoctorReport(
        {
          nodeName: "work-grammarxiv",
          status: "ok",
          checks: [{ id: "credential:claude", title: "Credential claude", status: "ok", detail: SECRET }],
        },
        guard,
      );
    } catch (error) {
      expect(isYashikiError(error, "CREDENTIAL_UNSAFE")).toBe(true);
      return;
    }
    throw new Error("expected the renderer to refuse the leaking report");
  });

  it("refuses to build a report whose probe detail leaks a credential value", async () => {
    const guard = createSecretGuard([SECRET]);
    await expect(
      runDoctor(config, {
        probes: probes({ runtimeReadiness: async () => ({ ready: true, detail: `token ${SECRET}` }) }),
        secretGuard: guard,
      }),
    ).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
  });

  it("reports owner, mode and symlink problems", async () => {
    const symlinked = await runDoctor(config, {
      probes: probes({
        credentialState: async () => ({
          exists: true,
          isSymlink: true,
          owner: "meidoya",
          mode: 0o600,
          sha256: "c".repeat(64),
        }),
      }),
    });
    expect(symlinked.checks.at(-1)).toMatchObject({ status: "fail", detail: "present but the path is a symlink" });

    const wrongMode = await runDoctor(config, {
      probes: probes({
        credentialState: async () => ({
          exists: true,
          isSymlink: false,
          owner: "root",
          mode: 0o644,
          sha256: "c".repeat(64),
        }),
      }),
    });
    expect(wrongMode.checks.at(-1)?.status).toBe("fail");
    expect(wrongMode.checks.at(-1)?.detail).toContain("owner root mode 0644");
  });

  it("fails on artifact drift, registry drift and a missing mount", async () => {
    const drifted = await runDoctor(config, {
      probes: probes({
        inspect: async () => ({
          ref: { name: config.name, provider: "lima" },
          status: "running",
          cpus: 2,
          memoryMiB: 2048,
          diskGiB: 20,
          mounts: [],
        }),
        installedReceipt: async () => ({
          product: "meidoya-node",
          version: "0.0.9",
          protocolVersion: 1,
          artifactSha256: "d".repeat(64),
          installedAt: "2026-01-01T00:00:00.000Z",
        }),
        mountState: async () => ({ mounted: false, writable: false }),
      }),
    });

    expect(drifted.status).toBe("fail");
    expect(drifted.checks.find((check) => check.id === "provider-registry")?.status).toBe("fail");
    expect(drifted.checks.find((check) => check.id === "node-artifact")?.status).toBe("fail");
    expect(drifted.checks.find((check) => check.id === "mount:/workspace/x")?.status).toBe("fail");
  });

  it("treats an undeterminable state as a failure, not a pass", async () => {
    const report = await runDoctor(config, {
      probes: probes({
        providerVersion: async () => null,
        serviceState: async () => null,
        taskQueuePoller: async () => null,
        mountState: async () => null,
      }),
    });

    expect(report.status).toBe("fail");
    for (const id of ["provider-version", "node-service", "task-queue-poller", "mount:/workspace/x"]) {
      expect(report.checks.find((check) => check.id === id)?.status).toBe("fail");
    }
  });
});
