import { mkdir, readFile } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  createNodeProcessPort,
  createSecretGuard,
  findNode,
  parseYashikiConfig,
  resolveYashikiPaths,
  systemClock,
  validateDesiredNodeConfig,
  YashikiError,
  formatMiB,
  type Clock,
  type DesiredNodeConfig,
  type Logger,
  type MutableSecretGuard,
  type NodeRef,
  type ProcessPort,
  type SecretGuard,
  type YashikiConfig,
} from "@meidoya-yashiki/yashiki-core";
import { LimaProvider } from "@meidoya-yashiki/provider-lima";
import { assertStartAllowed, BundleInstaller } from "@meidoya-yashiki/node-bundle";
import { CredentialMaterializer, createExecGuestCredentialPort } from "@meidoya-yashiki/credentials";
import { NodeProvisioner } from "@meidoya-yashiki/node-provisioner";
import { renderDoctorReport, runDoctor, type DoctorProbes } from "@meidoya-yashiki/doctor";
import { runBackup, type BackupItem, type BackupSinkPort } from "@meidoya-yashiki/backup";
import type { ReceiptStore } from "@meidoya-yashiki/receipts";
import {
  createSqliteNodeLock,
  createSqliteReceiptStore,
  migrate,
  migrations,
  openDatabase,
  upsertNode,
  recordProviderState,
} from "@meidoya-yashiki/store-sqlite";
import type { CliRuntime, CreateOverrides } from "./cli.js";
import {
  createGuestInstallPort,
  createGuestRegistrationVerifier,
  createGuestSystemDependencies,
  createHostSecretSource,
  createLocalArtifactSource,
  createSystemdServicePort,
} from "./host.js";

export type RuntimeEnvironment = {
  homeDir: string;
  xdgConfigHome?: string | undefined;
  xdgDataHome?: string | undefined;
  clock?: Clock | undefined;
  logger?: Logger | undefined;
  /**
   * The single seam to the host. Injected so the wiring in this file — which is
   * where the secret guard is created and where every command decides whether
   * to populate it — is testable without limactl, a VM or a real Keychain.
   */
  processPort?: ProcessPort | undefined;
  /**
   * The guard every store, provider, child process and report inside this
   * runtime shares. Injected so `main.ts` can put the process's stderr logger
   * behind the SAME guard without having to construct the runtime first — the
   * logger is a constructor argument, so a runtime-owned guard could never
   * reach it.
   */
  secretGuard?: MutableSecretGuard | undefined;
};

async function loadConfig(env: RuntimeEnvironment): Promise<YashikiConfig> {
  const paths = resolveYashikiPaths(env);
  let text: string;
  try {
    text = await readFile(paths.configFile, "utf8");
  } catch {
    throw new YashikiError("NOT_FOUND", `no config at ${paths.configFile}`, { path: paths.configFile });
  }
  return parseYashikiConfig(text, env);
}

function applyOverrides(config: DesiredNodeConfig, overrides: CreateOverrides, homeDir: string): DesiredNodeConfig {
  return validateDesiredNodeConfig(
    {
      ...config,
      ...(overrides.provider === undefined ? {} : { provider: overrides.provider }),
      ...(overrides.cpus === undefined ? {} : { cpus: overrides.cpus }),
      ...(overrides.memoryMiB === undefined ? {} : { memoryMiB: overrides.memoryMiB }),
      ...(overrides.diskGiB === undefined ? {} : { diskGiB: overrides.diskGiB }),
    },
    homeDir,
  );
}

/**
 * The CLI runtime plus the secret guard it shares with every store, provider
 * and report inside it, so `main.ts` can put the terminal behind the same
 * guard as the database.
 */
export type AppRuntime = CliRuntime & {
  readonly secretGuard: SecretGuard;
  /**
   * The single host seam every command in this runtime shares.
   *
   * Exposed because this file is the ONLY place the real port is ever
   * constructed, and the guard it is constructed with is the only thing between
   * a credential and the host process table. Without a handle on it, dropping
   * `{ secretGuard }` from that construction changed nothing any test could see.
   */
  readonly processPort: ProcessPort;
};

/**
 * The archive sink, exported so it can be driven by the real `runBackup` in a
 * test rather than re-implemented next to it.
 *
 * The archive is a file on disk, mode 0600, that a human will later open, and
 * the receipt log that records it has no delete path — so a value that reaches
 * it reaches it permanently. It is guarded on the exact bytes, not on the
 * objects they came from.
 *
 * This scan is the SECOND one those bytes get, and deliberately not the load
 * bearing one: `collectBackupItems` scans each item on its own budget first, so
 * a pathological item cannot spend the allowance that would have found a value
 * in a different item.
 */
export function createBackupArchiveSink(options: {
  backupDir: string;
  clock: Clock;
  secretGuard: SecretGuard;
}): BackupSinkPort {
  return {
    write: async (nodeName, entries) => {
      const stamp = options.clock.now().toISOString().replace(/[:.]/g, "-");
      const archiveRef = path.join(options.backupDir, `${stamp}.json`);
      const body = JSON.stringify({ nodeName, entries }, null, 2);
      options.secretGuard.assertClean("backup:archive", body);
      await writeFile(archiveRef, body, { mode: 0o600 });
      return { archiveRef };
    },
  };
}

/**
 * What a backup collects, and the one place this system decides that an
 * INCOMPLETE SCAN IS NOT A PASS.
 *
 * `sensitive: false` used to be hard-coded on all three items, which made
 * `planBackup`'s encryption gate unreachable in production and meant every
 * receipt that got past an incomplete append-time scan was archived in
 * plaintext. That is what turned a guard that fails open on its own bounds — a
 * tolerable, reported degradation for terminal output — into a credential on
 * disk: 2.6 KB of gzip padding in front of the log blinded decompression, the
 * archive was written anyway, and one `Buffer.from(run, "base64")` plus
 * `gunzipSync` got the value back out of a file that is never deleted.
 *
 * Now each item is scanned on its OWN budget and allowances, and an item whose
 * scan did not finish is marked sensitive. With no encryption port configured
 * that means `planBackup` EXCLUDES it and says so in the manifest and on the
 * terminal; with one, it is encrypted. Either way the bytes the guard could not
 * clear do not become a plaintext file.
 *
 * The cost of being wrong in this direction is a backup missing an entry, with
 * a printed reason. The cost of being wrong in the other direction is a
 * permanent plaintext credential. Those are not comparable.
 */
export function collectBackupItems(
  config: DesiredNodeConfig,
  receipts: ReceiptStore,
  secretGuard: SecretGuard,
): BackupItem[] {
  const item = (id: string, kind: BackupItem["kind"], content: string): BackupItem => {
    const incomplete = secretGuard.assertClean(`backup:item:${id}`, content);
    return incomplete === null
      ? { id, kind, content, sensitive: false }
      : { id, kind, content, sensitive: true, sensitiveReason: "item the credential guard could not fully scan" };
  };

  return [
    item("desired-config", "desired-config", JSON.stringify(config)),
    item("install-receipts", "install-receipt", JSON.stringify(receipts.list({ kind: "install", nodeName: config.name }))),
    item(
      "credential-receipts",
      "credential-receipt",
      JSON.stringify(receipts.list({ kind: "credential", nodeName: config.name })),
    ),
  ];
}

export function createRuntime(env: RuntimeEnvironment): AppRuntime {
  const clock = env.clock ?? systemClock;
  const paths = resolveYashikiPaths(env);
  const secretGuard = env.secretGuard ?? createSecretGuard();
  // The real host port goes behind the guard too: argv is world-readable in
  // `ps`, and a child's environment is readable by everything it spawns.
  const processPort = env.processPort ?? createNodeProcessPort({ secretGuard });

  const open = async (name: string, overrides: CreateOverrides = {}) => {
    const config = applyOverrides(findNode(await loadConfig(env), name), overrides, env.homeDir);
    if (config.provider !== "lima") {
      throw new YashikiError("CONFIG_INVALID", "the CLI wires the Lima provider only in the MVP", {
        node: name,
        provider: config.provider,
      });
    }

    await mkdir(paths.dataDir, { recursive: true });
    const db = openDatabase(paths.databaseFile);
    migrate(db, migrations);
    upsertNode(db, config, clock);

    const receipts = createSqliteReceiptStore(db, { secretGuard });
    const provider = new LimaProvider({
      process: processPort,
      secretGuard,
      ...(env.logger === undefined ? {} : { logger: env.logger }),
    });
    const ref: NodeRef = { name: config.name, provider: config.provider };

    const bundle = new BundleInstaller({
      source: createLocalArtifactSource(paths.artifactsDir),
      guest: createGuestInstallPort(provider),
      receipts,
      clock,
    });

    const credentials = new CredentialMaterializer({
      source: createHostSecretSource(processPort),
      guest: createExecGuestCredentialPort(provider),
      receipts,
      clock,
      secretGuard,
      ...(env.logger === undefined ? {} : { logger: env.logger }),
    });

    const provisioner = new NodeProvisioner({
      provider,
      bundle,
      credentials,
      systemDeps: createGuestSystemDependencies(provider),
      service: createSystemdServicePort(provider),
      registration: createGuestRegistrationVerifier(provider, clock),
      receipts,
      lock: createSqliteNodeLock(db, clock),
      homeDir: env.homeDir,
      verifyMounts: (node, desired) => provider.verifyMounts(node, desired.mounts),
      applyResourceConfig: (node, desired) =>
        provider.applyResourceConfig(node, {
          name: desired.name,
          cpus: desired.cpus,
          memoryMiB: desired.memoryMiB,
          diskGiB: desired.diskGiB,
          mounts: desired.mounts,
        }),
      registrationWaitMs: 120_000,
      clock,
      ...(env.logger === undefined ? {} : { logger: env.logger }),
    });

    return { config, db, receipts, provider, ref, bundle, credentials, provisioner };
  };

  const holder = `cli-${process.pid}`;

  return {
    secretGuard,
    processPort,

    async create(name, overrides) {
      const { config, provisioner } = await open(name, overrides);
      const result = await provisioner.provision(config, holder);
      return [
        `created node ${config.name} (${config.provider}, ${config.cpus} vCPU, ${formatMiB(config.memoryMiB)}, ${config.diskGiB}GiB disk)`,
        `meidoya-node ${result.installedVersion} installed and registered`,
        `mounts: ${config.mounts.length === 0 ? "none" : config.mounts.map((mount) => `${mount.target}${mount.writable ? " (rw)" : " (ro)"}`).join(", ")}`,
      ];
    },

    async start(name) {
      const { config, provider, ref, bundle } = await open(name);
      // Artifact mismatch refuses the start outright (Phase 6 DoD).
      const verified = await bundle.resolve(config);
      assertStartAllowed(await bundle.readInstalled(ref), config, verified.artifactSha256);

      await provider.start(ref);
      return [`started ${config.name}`];
    },

    async stop(name) {
      const { config, provider, ref } = await open(name);
      await provider.stop(ref);
      return [`stopped ${config.name}`];
    },

    async status(name) {
      const { config, provider, ref, db, receipts, credentials } = await open(name);
      // Read-only commands never call `sync`, so nothing else would ever teach
      // this process's guard which values are in flight (defect 8b).
      await credentials.primeGuard(ref, config);
      const inspection = await provider.inspect(ref);
      recordProviderState(db, inspection, clock);

      const install = receipts.latest("install", config.name);
      const provisioning = receipts.latest("provisioning", config.name);
      return [
        `${config.name}: ${inspection.status}`,
        `  provider   ${config.provider} (${config.profile})`,
        `  resources  ${inspection.cpus ?? config.cpus} vCPU, ${formatMiB(inspection.memoryMiB ?? config.memoryMiB)}, ${inspection.diskGiB ?? config.diskGiB}GiB disk`,
        `  node       ${install?.payload["version"] ?? "not installed"} (protocol ${config.bundle.protocolVersion})`,
        `  mounts     ${config.mounts.length === 0 ? "none" : config.mounts.map((mount) => mount.target).join(", ")}`,
        `  last run   ${provisioning?.createdAt ?? "never"}`,
      ];
    },

    async doctor(name) {
      const { config, provider, ref, bundle, db, credentials } = await open(name);
      // Doctor is the human-readable sink 11 section 9 singles out, and it is
      // the one path that never materializes a credential — so the guard has to
      // be told what to look for before the first check is rendered (defect 8b).
      await credentials.primeGuard(ref, config);
      const guestCredentials = createExecGuestCredentialPort(provider);
      const service = createSystemdServicePort(provider);
      const registration = createGuestRegistrationVerifier(provider, clock);

      const probes: DoctorProbes = {
        providerVersion: async () => {
          const result = await processPort.run({ argv: ["limactl", "--version"], timeoutMs: 30_000 });
          return result.exitCode === 0 ? result.stdout.trim() : null;
        },
        inspect: () => provider.inspect(ref),
        installedReceipt: () => bundle.readInstalled(ref),
        expectedArtifactSha256: async () => (await bundle.resolve(config)).artifactSha256,
        serviceState: () => service.state(ref),
        registration: () => registration.check(ref, config),
        taskQueuePoller: async () => {
          const result = await provider.exec(ref, {
            argv: ["sudo", "cat", "/var/lib/meidoya-node/poller.json"],
          });
          if (result.exitCode !== 0) return null;
          try {
            const parsed = JSON.parse(result.stdout) as { polling?: unknown; queue?: unknown };
            return typeof parsed.polling === "boolean" && typeof parsed.queue === "string"
              ? { polling: parsed.polling, queue: parsed.queue }
              : null;
          } catch {
            return null;
          }
        },
        runtimeReadiness: async (runtime) => {
          const result = await provider.exec(ref, {
            argv: ["sudo", "-u", "meidoya", "/usr/local/bin/meidoya-node", "--runtime-probe", runtime],
          });
          return {
            ready: result.exitCode === 0,
            detail: result.exitCode === 0 ? `${runtime} available` : `${runtime} not found`,
          };
        },
        mountState: async (mount) => {
          const mounted = await provider.exec(ref, { argv: ["mountpoint", "-q", mount.target] });
          if (mounted.exitCode !== 0) return { mounted: false, writable: false };
          const writable = await provider.exec(ref, { argv: ["test", "-w", mount.target] });
          return { mounted: true, writable: writable.exitCode === 0 };
        },
        credentialState: (requirement) => guestCredentials.stat(ref, requirement.guestPath),
      };

      const report = await runDoctor(config, { probes, secretGuard });
      db.close();
      return renderDoctorReport(report, secretGuard).split("\n");
    },

    async upgrade(name) {
      const { config, provisioner } = await open(name);
      const result = await provisioner.upgrade(config, holder);
      return [
        `upgraded ${config.name} to meidoya-node ${result.installedVersion}`,
        result.changed ? "artifact replaced" : "artifact already matched the pin",
      ];
    },

    async reprovision(name) {
      const { config, provisioner } = await open(name);
      const result = await provisioner.reprovision(config, holder);
      return [`reprovisioned ${config.name} (${result.completedSteps.length} steps verified)`];
    },

    async backup(name) {
      const { config, receipts, ref, credentials } = await open(name);
      await credentials.primeGuard(ref, config);
      const backupDir = path.join(paths.dataDir, "backups", config.name);
      await mkdir(backupDir, { recursive: true });

      const manifest = await runBackup(config, {
        source: { collect: async () => collectBackupItems(config, receipts, secretGuard) },
        sink: createBackupArchiveSink({ backupDir, clock, secretGuard }),
        receipts,
        clock,
      });

      return [
        `backed up ${config.name} to ${manifest.archiveRef}`,
        `  entries  ${manifest.entries.map((entry) => entry.id).join(", ")}`,
        `  excluded ${manifest.excluded.length === 0 ? "none" : manifest.excluded.map((entry) => `${entry.id} (${entry.reason})`).join(", ")}`,
      ];
    },
  };
}
