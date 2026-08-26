import {
  noopSecretGuard,
  type CredentialRequirement,
  type DesiredNodeConfig,
  type MountSpec,
  type NodeInspection,
  type SecretGuard,
} from "@meidoya-yashiki/yashiki-core";
import type { NodeInstallReceipt } from "@meidoya-yashiki/node-protocol-client";
import type { GuestFileStat } from "@meidoya-yashiki/credentials";

export type CheckStatus = "ok" | "warn" | "fail" | "skipped";

export type DoctorCheck = {
  id: string;
  title: string;
  status: CheckStatus;
  detail: string;
};

export type DoctorReport = {
  nodeName: string;
  checks: readonly DoctorCheck[];
  status: CheckStatus;
};

export type DoctorServiceState = "absent" | "installed" | "running" | null;

export type DoctorRegistration = {
  registered: boolean;
  protocolVersion: number | null;
  heartbeatAgeMs: number | null;
};

export type MountObservation = { mounted: boolean; writable: boolean } | null;

/** Everything Doctor observes. All injected: no Lima, network or Keychain in tests. */
export interface DoctorProbes {
  providerVersion(): Promise<string | null>;
  inspect(): Promise<NodeInspection>;
  installedReceipt(): Promise<NodeInstallReceipt | null>;
  expectedArtifactSha256(): Promise<string | null>;
  serviceState(): Promise<DoctorServiceState>;
  registration(): Promise<DoctorRegistration>;
  taskQueuePoller(): Promise<{ polling: boolean; queue: string } | null>;
  runtimeReadiness(runtime: "codex" | "claude"): Promise<{ ready: boolean; detail: string }>;
  mountState(mount: MountSpec): Promise<MountObservation>;
  /** Presence and file attributes only. Implementations never read the value. */
  credentialState(requirement: CredentialRequirement): Promise<GuestFileStat>;
}

export type DoctorOptions = {
  probes: DoctorProbes;
  maxHeartbeatAgeMs?: number;
  secretGuard?: SecretGuard;
};

function formatMode(mode: number): string {
  return `0${mode.toString(8).padStart(3, "0")}`;
}

function worst(checks: readonly DoctorCheck[]): CheckStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.some((check) => check.status === "warn")) return "warn";
  if (checks.every((check) => check.status === "skipped")) return "skipped";
  return "ok";
}

export async function runDoctor(config: DesiredNodeConfig, options: DoctorOptions): Promise<DoctorReport> {
  const probes = options.probes;
  const guard = options.secretGuard ?? noopSecretGuard;
  const checks: DoctorCheck[] = [];
  const add = (id: string, title: string, status: CheckStatus, detail: string): void => {
    // Nothing reaches a Doctor line without passing the secret guard.
    guard.assertClean(`doctor:${id}`, detail);
    checks.push({ id, title, status, detail });
  };

  const version = await probes.providerVersion();
  add(
    "provider-version",
    "Provider version",
    version === null ? "fail" : "ok",
    version === null ? `${config.provider} provider is not available on this host` : `${config.provider} ${version}`,
  );

  const inspection = await probes.inspect();
  if (inspection.status === "absent") {
    add("provider-registry", "Provider registry matches desired config", "fail", "node does not exist");
  } else if (inspection.status === "unknown") {
    add("provider-registry", "Provider registry matches desired config", "fail", "node state could not be determined");
  } else {
    const drift: string[] = [];
    if (inspection.cpus !== null && inspection.cpus !== config.cpus) {
      drift.push(`cpus ${inspection.cpus} != ${config.cpus}`);
    }
    if (inspection.memoryMiB !== null && inspection.memoryMiB !== config.memoryMiB) {
      drift.push(`memory ${inspection.memoryMiB}MiB != ${config.memoryMiB}MiB`);
    }
    if (inspection.diskGiB !== null && inspection.diskGiB < config.diskGiB) {
      drift.push(`disk ${inspection.diskGiB}GiB < ${config.diskGiB}GiB`);
    }
    add(
      "provider-registry",
      "Provider registry matches desired config",
      drift.length === 0 ? "ok" : "fail",
      drift.length === 0 ? `${inspection.status}, resources match` : drift.join("; "),
    );
  }

  const installed = await probes.installedReceipt();
  const expectedSha = await probes.expectedArtifactSha256();
  if (installed === null) {
    add("node-artifact", "Node artifact checksum and receipt", "fail", "no install receipt on the node");
  } else if (expectedSha === null) {
    add("node-artifact", "Node artifact checksum and receipt", "fail", "pinned release manifest is unavailable");
  } else if (installed.version !== config.bundle.version || installed.artifactSha256 !== expectedSha) {
    add(
      "node-artifact",
      "Node artifact checksum and receipt",
      "fail",
      `installed ${installed.version} does not match the pinned ${config.bundle.version}`,
    );
  } else if (installed.protocolVersion !== config.bundle.protocolVersion) {
    add(
      "node-artifact",
      "Node artifact checksum and receipt",
      "fail",
      `protocol ${installed.protocolVersion} does not match the pinned ${config.bundle.protocolVersion}`,
    );
  } else {
    add("node-artifact", "Node artifact checksum and receipt", "ok", `${installed.version} (checksum verified)`);
  }

  const serviceState = await probes.serviceState();
  add(
    "node-service",
    "Node service active",
    serviceState === "running" ? "ok" : "fail",
    serviceState === null ? "service state could not be determined" : `service is ${serviceState}`,
  );

  const registration = await probes.registration();
  const maxAge = options.maxHeartbeatAgeMs ?? 60_000;
  if (!registration.registered) {
    add("control-plane-registration", "Control Plane registration", "fail", "node is not registered");
  } else if (registration.heartbeatAgeMs === null || registration.protocolVersion === null) {
    add("control-plane-registration", "Control Plane registration", "fail", "Control Plane view is incomplete");
  } else if (registration.protocolVersion !== config.bundle.protocolVersion) {
    add(
      "control-plane-registration",
      "Control Plane registration",
      "fail",
      `registered protocol ${registration.protocolVersion} != pinned ${config.bundle.protocolVersion}`,
    );
  } else if (registration.heartbeatAgeMs < 0) {
    // Only staleness was ever checked, so a heartbeat dated in the FUTURE — a
    // wrong guest clock, or a `registration.json` that says so — read as `ok`
    // and the further into the future it was, the healthier it looked.
    add(
      "control-plane-registration",
      "Control Plane registration",
      "fail",
      `heartbeat is dated ${Math.abs(registration.heartbeatAgeMs)}ms in the future; the node clock or its registration record is wrong`,
    );
  } else {
    add(
      "control-plane-registration",
      "Control Plane registration",
      registration.heartbeatAgeMs > maxAge ? "warn" : "ok",
      `heartbeat ${registration.heartbeatAgeMs}ms ago`,
    );
  }

  const poller = await probes.taskQueuePoller();
  add(
    "task-queue-poller",
    "Temporal task queue poller",
    poller === null ? "fail" : poller.polling ? "ok" : "fail",
    poller === null ? "poller state could not be determined" : `${poller.queue}: ${poller.polling ? "polling" : "idle"}`,
  );

  for (const runtime of ["codex", "claude"] as const) {
    const readiness = await probes.runtimeReadiness(runtime);
    add(`${runtime}-runtime`, `${runtime} runtime readiness`, readiness.ready ? "ok" : "fail", readiness.detail);
  }

  if (config.mounts.length === 0) {
    add("workspace-mounts", "Workspace paths and mounts", "skipped", "no mounts declared");
  } else {
    for (const mount of config.mounts) {
      const observed = await probes.mountState(mount);
      if (observed === null) {
        add(`mount:${mount.target}`, `Mount ${mount.target}`, "fail", "mount state could not be determined");
      } else if (!observed.mounted) {
        add(`mount:${mount.target}`, `Mount ${mount.target}`, "fail", "target is not a mount point");
      } else if (observed.writable !== mount.writable) {
        add(
          `mount:${mount.target}`,
          `Mount ${mount.target}`,
          "fail",
          `writable=${observed.writable}, expected ${mount.writable}`,
        );
      } else {
        add(`mount:${mount.target}`, `Mount ${mount.target}`, "ok", `${mount.writable ? "rw" : "ro"} from host`);
      }
    }
  }

  for (const requirement of config.credentials) {
    const stat = await probes.credentialState(requirement);
    const id = `credential:${requirement.provider}`;
    const title = `Credential ${requirement.provider}`;

    // Presence only. No value, no digest, no length (11 section 9).
    if (!stat.exists) {
      add(id, title, requirement.optional ? "warn" : "fail", "not present");
      continue;
    }
    if (stat.isSymlink) {
      add(id, title, "fail", "present but the path is a symlink");
      continue;
    }
    if (stat.owner !== requirement.owner || stat.mode !== requirement.mode) {
      add(
        id,
        title,
        "fail",
        `present with owner ${stat.owner} mode ${formatMode(stat.mode)}, expected owner ${requirement.owner} mode ${formatMode(requirement.mode)}`,
      );
      continue;
    }
    add(id, title, "ok", `present, owner ${stat.owner}, mode ${formatMode(stat.mode)}`);
  }

  return { nodeName: config.name, checks, status: worst(checks) };
}

const SYMBOL: Record<CheckStatus, string> = { ok: "ok  ", warn: "warn", fail: "FAIL", skipped: "skip" };

export function renderDoctorReport(report: DoctorReport, guard: SecretGuard = noopSecretGuard): string {
  const lines = [
    `doctor ${report.nodeName}: ${report.status}`,
    ...report.checks.map((check) => `  [${SYMBOL[check.status]}] ${check.title}: ${check.detail}`),
  ];
  const text = lines.join("\n");
  guard.assertClean("doctor:render", text);
  return text;
}
