import {
  failClosed,
  silentLogger,
  systemClock,
  validateDesiredNodeConfig,
  YashikiError,
  type Clock,
  type DesiredNodeConfig,
  type Logger,
  type NodeLock,
  type NodeProvider,
  type NodeRef,
} from "@meidoya-yashiki/yashiki-core";
import { assertStartAllowed, type BundleInstaller, type VerifiedArtifact } from "@meidoya-yashiki/node-bundle";
import type { CredentialMaterializer } from "@meidoya-yashiki/credentials";
import type { ReceiptStore } from "@meidoya-yashiki/receipts";
import type { NodeServicePort, RegistrationVerifierPort, SystemDependencyPort } from "./ports.js";

/** 11-yashiki-design.md section 5, in order. */
export const PROVISION_STEPS = [
  "validate-desired-config",
  "acquire-node-lock",
  "create-or-inspect-vm",
  "apply-resource-and-mount-config",
  "install-system-dependencies",
  "download-pinned-artifact",
  "verify-checksum",
  "materialize-credentials",
  "install-service",
  "start-node",
  "verify-registration",
  "write-receipt",
] as const;

export type ProvisionStep = (typeof PROVISION_STEPS)[number];

export type ProvisionKind = "provision" | "reprovision" | "upgrade";

export type ProvisionResult = {
  nodeName: string;
  kind: ProvisionKind;
  completedSteps: readonly ProvisionStep[];
  installedVersion: string;
  changed: boolean;
};

export type MountVerifier = (node: NodeRef, config: DesiredNodeConfig) => Promise<void>;

/**
 * Provider-specific resource APPLY (LimaProvider.applyResourceConfig in the
 * MVP).
 *
 * Step 4 is called "apply-resource-and-mount-config" and only ever verified:
 * `NodeProvider` has no resize operation, so raising `cpus` in config.yaml made
 * `reprovision` throw VERIFICATION_FAILED permanently — the step that exists to
 * converge on the desired config could not converge on anything.
 */
export type ResourceApplier = (node: NodeRef, config: DesiredNodeConfig) => Promise<void>;

export type ProvisionerOptions = {
  provider: NodeProvider;
  bundle: BundleInstaller;
  credentials: CredentialMaterializer;
  systemDeps: SystemDependencyPort;
  service: NodeServicePort;
  registration: RegistrationVerifierPort;
  receipts: ReceiptStore;
  lock: NodeLock;
  homeDir: string;
  /** Provider-specific mount read-back (LimaProvider.verifyMounts in the MVP). */
  verifyMounts?: MountVerifier;
  /** Provider-specific resource apply, run before the read-back below. */
  applyResourceConfig?: ResourceApplier;
  systemPackages?: readonly string[];
  lockTtlMs?: number;
  maxHeartbeatAgeMs?: number;
  registrationWaitMs?: number;
  clock?: Clock;
  logger?: Logger;
};

const DEFAULT_SYSTEM_PACKAGES = ["curl", "git", "ca-certificates", "bubblewrap", "socat"];

export class NodeProvisioner {
  readonly #options: ProvisionerOptions;
  readonly #clock: Clock;
  readonly #logger: Logger;

  constructor(options: ProvisionerOptions) {
    this.#options = options;
    this.#clock = options.clock ?? systemClock;
    this.#logger = options.logger ?? silentLogger;
  }

  provision(config: DesiredNodeConfig, holder: string): Promise<ProvisionResult> {
    return this.#run(config, "provision", holder);
  }

  /** Re-runs the full lifecycle against an existing node. Idempotent. */
  reprovision(config: DesiredNodeConfig, holder: string): Promise<ProvisionResult> {
    return this.#run(config, "reprovision", holder);
  }

  upgrade(config: DesiredNodeConfig, holder: string): Promise<ProvisionResult> {
    return this.#run(config, "upgrade", holder);
  }

  async #run(input: DesiredNodeConfig, kind: ProvisionKind, holder: string): Promise<ProvisionResult> {
    const completed: ProvisionStep[] = [];
    const step = <T>(name: ProvisionStep, body: () => Promise<T>): Promise<T> =>
      body().then((value) => {
        completed.push(name);
        this.#logger.log("debug", "provision step completed", { node: input.name, step: name });
        return value;
      });

    // 1. validate desired config
    const config = await step("validate-desired-config", async () =>
      validateDesiredNodeConfig(input, this.#options.homeDir),
    );

    // 2. acquire node lock
    const lock = await step("acquire-node-lock", async () =>
      this.#options.lock.acquire(config.name, holder, this.#options.lockTtlMs ?? 30 * 60 * 1000),
    );

    try {
      const ref: NodeRef = { name: config.name, provider: config.provider };

      // 3. create or inspect VM
      await step("create-or-inspect-vm", async () => {
        const inspection = await this.#options.provider.inspect(ref);
        if (inspection.status === "unknown") {
          failClosed(`inspect ${config.name}`, "the provider could not determine the node state");
        }
        if (inspection.status === "absent") {
          await this.#options.provider.create({
            name: config.name,
            cpus: config.cpus,
            memoryMiB: config.memoryMiB,
            diskGiB: config.diskGiB,
            mounts: config.mounts,
          });
        }
      });

      // 4. apply resource and mount config
      await step("apply-resource-and-mount-config", async () => {
        // Apply, THEN read back. Without the apply this step could only ever
        // report that the node did not match, and never make it match.
        if (this.#options.applyResourceConfig !== undefined) {
          await this.#options.applyResourceConfig(ref, config);
        }
        const inspection = await this.#options.provider.inspect(ref);
        if (inspection.status === "absent") {
          throw new YashikiError("VERIFICATION_FAILED", `node '${config.name}' is absent after create`, {
            node: config.name,
          });
        }
        if (inspection.cpus !== null && inspection.cpus !== config.cpus) {
          throw new YashikiError("VERIFICATION_FAILED", "cpu count does not match the desired config", {
            node: config.name,
            expected: config.cpus,
            actual: inspection.cpus,
          });
        }
        if (inspection.memoryMiB !== null && inspection.memoryMiB !== config.memoryMiB) {
          throw new YashikiError("VERIFICATION_FAILED", "memory does not match the desired config", {
            node: config.name,
            expected: config.memoryMiB,
            actual: inspection.memoryMiB,
          });
        }
        if (inspection.status !== "running") await this.#options.provider.start(ref);
        if (this.#options.verifyMounts !== undefined) await this.#options.verifyMounts(ref, config);
      });

      // 5. install system dependencies
      await step("install-system-dependencies", async () => {
        const packages = this.#options.systemPackages ?? DEFAULT_SYSTEM_PACKAGES;
        const { missing } = await this.#options.systemDeps.ensure(ref, packages);
        if (missing.length > 0) {
          throw new YashikiError("VERIFICATION_FAILED", `system dependencies are still missing after install`, {
            node: config.name,
            missing: missing.join(","),
          });
        }
      });

      // 6. download pinned artifact
      const verified: VerifiedArtifact = await step("download-pinned-artifact", async () =>
        this.#options.bundle.resolve(config),
      );

      // 7. verify checksum (again, immediately before anything is written)
      const installOutcome = await step("verify-checksum", async () =>
        this.#options.bundle.installVerified(ref, config, verified),
      );

      // 8. materialize credentials
      await step("materialize-credentials", async () => this.#options.credentials.sync(ref, config));

      // 9. install launchd/systemd service
      await step("install-service", async () => {
        await this.#options.service.install(ref, config);
        const state = await this.#options.service.state(ref);
        if (state === null) failClosed(`service install on ${config.name}`, "service state is unknown");
        if (state === "absent") {
          throw new YashikiError("VERIFICATION_FAILED", "node service is absent after install", {
            node: config.name,
          });
        }
      });

      // 10. start node — refused outright on artifact/protocol mismatch
      await step("start-node", async () => {
        const installed = await this.#options.bundle.readInstalled(ref);
        assertStartAllowed(installed, config, verified.artifactSha256);

        await this.#options.service.start(ref);
        const state = await this.#options.service.state(ref);
        if (state === null) failClosed(`service start on ${config.name}`, "service state is unknown");
        if (state !== "running") {
          throw new YashikiError("VERIFICATION_FAILED", "node service did not reach the running state", {
            node: config.name,
            actual: state,
          });
        }
      });

      // 11. verify registration / heartbeat
      await step("verify-registration", async () => {
        const deadline = Date.now() + (this.#options.registrationWaitMs ?? 0);
        let status = await this.#options.registration.check(ref, config);
        while (
          (!status.registered || status.heartbeatAgeMs === null || status.protocolVersion === null) &&
          Date.now() < deadline
        ) {
          await new Promise((resolve) => setTimeout(resolve, 500));
          status = await this.#options.registration.check(ref, config);
        }
        if (status.heartbeatAgeMs === null || status.protocolVersion === null) {
          failClosed(`registration check for ${config.name}`, "the Control Plane view is incomplete");
        }
        if (!status.registered) {
          throw new YashikiError("VERIFICATION_FAILED", "node did not register with the Control Plane", {
            node: config.name,
          });
        }
        if (status.protocolVersion !== config.bundle.protocolVersion) {
          throw new YashikiError("PROTOCOL_MISMATCH", "registered protocol version does not match the pin", {
            node: config.name,
            registered: status.protocolVersion,
            pinned: config.bundle.protocolVersion,
          });
        }
        const maxAge = this.#options.maxHeartbeatAgeMs ?? 60_000;
        // An age is a duration since something happened, so it cannot be
        // negative. Only the upper bound was checked, which made
        // `heartbeatAgeMs: -86_400_000` — a guest clock a day fast, or a
        // `registration.json` written to say so — the freshest heartbeat this
        // check has ever seen. A dead node looked alive by being wrong enough.
        if (status.heartbeatAgeMs < 0) {
          throw new YashikiError("VERIFICATION_FAILED", "node heartbeat is dated in the future", {
            node: config.name,
            heartbeatAgeMs: status.heartbeatAgeMs,
          });
        }
        if (status.heartbeatAgeMs > maxAge) {
          throw new YashikiError("VERIFICATION_FAILED", "node heartbeat is stale", {
            node: config.name,
            heartbeatAgeMs: status.heartbeatAgeMs,
          });
        }
      });

      // 12. write receipt
      await step("write-receipt", async () => {
        this.#options.receipts.append({
          kind: "provisioning",
          nodeName: config.name,
          createdAt: this.#clock.now().toISOString(),
          payload: {
            kind,
            provider: config.provider,
            profile: config.profile,
            cpus: config.cpus,
            memoryMiB: config.memoryMiB,
            diskGiB: config.diskGiB,
            mountTargets: config.mounts.map((mount) => mount.target),
            credentialProviders: config.credentials.map((credential) => credential.provider),
            nodeVersion: installOutcome.receipt.version,
            artifactSha256: installOutcome.receipt.artifactSha256,
            protocolVersion: installOutcome.receipt.protocolVersion,
            // The snapshot is taken INSIDE the write-receipt body, so `completed`
            // does not yet contain the step doing the writing. A receipt that
            // under-reports the work it is the record of is a receipt that
            // disagrees with `ProvisionResult.completedSteps` returned two lines
            // later; the last step is named explicitly rather than omitted.
            steps: [...completed, "write-receipt"],
          },
        });
      });

      return {
        nodeName: config.name,
        kind,
        completedSteps: completed,
        installedVersion: installOutcome.receipt.version,
        changed: installOutcome.installed,
      };
    } finally {
      lock.release();
    }
  }
}
