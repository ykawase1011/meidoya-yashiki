import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  CREDENTIAL_SOURCE_ENV_NAMES,
  failClosed,
  systemClock,
  YashikiError,
  type Clock,
  type DesiredNodeConfig,
  type NodeProvider,
  type NodeRef,
  type ProcessPort,
} from "@meidoya-yashiki/yashiki-core";
import type { ArtifactSourcePort, GuestInstallPort } from "@meidoya-yashiki/node-bundle";
import type { SecretSourcePort } from "@meidoya-yashiki/credentials";
import type { NodeInstallReceipt } from "@meidoya-yashiki/node-protocol-client";
import type {
  NodeServicePort,
  RegistrationVerifierPort,
  ServiceState,
  SystemDependencyPort,
} from "@meidoya-yashiki/node-provisioner";

const NODE_BINARY_PATH = "/usr/local/bin/meidoya-node";
const NODE_STATE_DIR = "/var/lib/meidoya-node";
const RECEIPT_PATH = `${NODE_STATE_DIR}/receipt.json`;
const REGISTRATION_PATH = `${NODE_STATE_DIR}/registration.json`;
const SERVICE_UNIT_PATH = "/etc/systemd/system/meidoya-node.service";
/**
 * meidoya-node's launch interface is `--config <node.yaml>` only
 * (apps/meidoya-node/src/main.ts in the meidoya repository, `allowPositionals:
 * false`). Node identity and the control-plane address are config-file
 * concerns, not CLI flags: that keeps them out of the process listing and
 * matches docs/design/node.example.yaml. Yashiki is therefore responsible for
 * materializing that file on the guest before starting the service; it must
 * never invent CLI flags the daemon does not parse.
 */
const NODE_CONFIG_PATH = `${NODE_STATE_DIR}/node.yaml`;

/**
 * Release artifacts are staged locally under the Yashiki data directory. Yashiki
 * never downloads during provisioning: the bytes are placed there deliberately
 * and then pinned by checksum.
 */
export function createLocalArtifactSource(artifactsDir: string): ArtifactSourcePort {
  return {
    fetchManifest: async (version) => readFile(path.join(artifactsDir, version, "manifest.json"), "utf8"),
    fetchArtifact: async (artifact, version) =>
      readFile(path.join(artifactsDir, version, `meidoya-node-${artifact.platform}-${artifact.arch}`)),
  };
}

/**
 * sops exit codes that mean "I could not get at my key material", as opposed to
 * "there is no such secret" (sops/cmd/sops/codes/codes.go).
 *
 * The difference matters to an operator: a missing key is a locked keyring, an
 * unset `SOPS_AGE_KEY_FILE` or an AWS profile that is not in the environment
 * this process forwards — and none of those is fixed by looking for a secret
 * that is, in fact, right where it was configured to be.
 */
const SOPS_KEY_UNAVAILABLE_EXIT_CODES: readonly number[] = [
  24, // ErrorDecryptingMac
  25, // ErrorDecryptingTree
  111, // NoEncryptionKeyFound
  128, // CouldNotRecoverDataKey
];

const PRIVATE_FILE_SCRIPT = [
  "set -eu",
  '[ -e "$1" ] || exit 2',
  '[ -f "$1" ] && [ ! -L "$1" ] || exit 91',
  'owner=$(stat -f "%u" "$1" 2>/dev/null || stat -c "%u" "$1")',
  '[ "$owner" = "$(id -u)" ] || exit 91',
  'mode=$(stat -f "%OLp" "$1" 2>/dev/null || stat -c "%a" "$1")',
  'case "$mode" in *[!0-7]*|"") exit 91;; esac',
  'group_other="${mode#${mode%??}}"',
  '[ "$group_other" = "00" ] || exit 91',
  'cat "$1"',
].join("; ");

const HERMES_SOPS_SCRIPT = [
  "set -eu",
  'SOPS_AGE_KEY=$(/usr/bin/security find-generic-password -s hermes-sops-age -a default -w)',
  '[ -n "$SOPS_AGE_KEY" ]',
  "export SOPS_AGE_KEY",
  'exec sops --decrypt --extract "[\\"claude\\"][\\"code_oauth_token\\"]" "$1"',
].join("; ");

function sourceCommand(sourceRef: string): {
  readonly scheme: "keychain" | "sops" | "private-file" | "hermes-sops";
  readonly argv: readonly string[];
} {
  const colon = sourceRef.indexOf(":");
  const scheme = sourceRef.slice(0, colon);
  const rest = colon < 0 ? "" : sourceRef.slice(colon + 1);
  if (scheme === "keychain") return { scheme, argv: ["security", "find-generic-password", "-s", rest, "-w"] };
  if (scheme === "sops") return { scheme, argv: ["sops", "-d", rest] };
  if (scheme === "private-file") {
    if (!rest.startsWith("/") || rest.includes("\0")) {
      throw new YashikiError("CONFIG_INVALID", "private-file source must name an absolute path", { sourceRef });
    }
    return { scheme, argv: ["sh", "-c", PRIVATE_FILE_SCRIPT, "sh", rest] };
  }
  if (scheme === "hermes-sops") {
    const suffix = "#claude.code_oauth_token";
    if (!rest.endsWith(suffix)) {
      throw new YashikiError("CONFIG_INVALID", "hermes-sops source must select claude.code_oauth_token", { sourceRef });
    }
    const document = rest.slice(0, -suffix.length);
    if (!document.startsWith("/") || document.includes("\0")) {
      throw new YashikiError("CONFIG_INVALID", "hermes-sops source must name an absolute document path", { sourceRef });
    }
    return { scheme, argv: ["sh", "-c", HERMES_SOPS_SCRIPT, "sh", document] };
  }
  throw new YashikiError("CONFIG_INVALID", `unsupported credential source scheme '${scheme}'`, { sourceRef });
}

/**
 * Host secret source. `security` and `sops` print the value on stdout; the value
 * is never a command-line argument.
 *
 * A tool is given the base child environment plus the LOCATORS its scheme needs
 * (`CREDENTIAL_SOURCE_ENV_NAMES`), never a credential from this process's own
 * environment.
 */
export function createHostSecretSource(processPort: ProcessPort): SecretSourcePort {
  return {
    async read(sourceRef) {
      const command = sourceCommand(sourceRef);

      const inheritEnv = CREDENTIAL_SOURCE_ENV_NAMES[command.scheme] ?? [];
      const result = await processPort.run({ argv: command.argv, timeoutMs: 30_000, inheritEnv });
      if (result.timedOut) failClosed(`read credential from ${command.scheme}`, "the host secret tool timed out");

      if (command.scheme === "private-file" && result.exitCode === 91) {
        throw new YashikiError("CONFIG_INVALID", "private-file source is not a private regular file owned by this user", {
          sourceRef,
        });
      }

      // A key that cannot be reached is a configuration failure with a name, not
      // an absent credential. Reporting it as NOT_FOUND sent operators looking
      // for a secret that was never missing.
      if (command.scheme === "sops" && result.exitCode !== null && SOPS_KEY_UNAVAILABLE_EXIT_CODES.includes(result.exitCode)) {
        throw new YashikiError(
          "CONFIG_INVALID",
          `sops could not reach the key material for '${sourceRef}'. Children inherit only ${inheritEnv.join(", ")} ` +
            "from this process's environment, so a key located by any other variable — or held in " +
            "AWS_SECRET_ACCESS_KEY rather than an AWS profile — is not visible to sops here.",
          { sourceRef, exitCode: result.exitCode },
        );
      }
      if (command.scheme === "hermes-sops" && result.exitCode !== 0) {
        throw new YashikiError("CONFIG_INVALID", "Hermes SOPS credential could not be decrypted", {
          sourceRef,
          exitCode: result.exitCode ?? "signal",
        });
      }
      if (result.exitCode !== 0) return null;

      const value = result.stdout.replace(/\n$/, "");
      return value === "" ? null : value;
    },
  };
}

async function guestExec(
  provider: NodeProvider,
  node: NodeRef,
  argv: readonly string[],
  stdin?: string,
): Promise<{ exitCode: number; stdout: string }> {
  const result = await provider.exec(node, stdin === undefined ? { argv } : { argv, stdin });
  return { exitCode: result.exitCode, stdout: result.stdout };
}

export function createGuestSystemDependencies(provider: NodeProvider): SystemDependencyPort {
  const missingOf = async (node: NodeRef, packages: readonly string[]): Promise<string[]> => {
    const missing: string[] = [];
    for (const name of packages) {
      const probe = await guestExec(provider, node, ["dpkg-query", "-W", "-f=${Status}", name]);
      if (probe.exitCode !== 0 || probe.stdout.trim() !== "install ok installed") missing.push(name);
    }
    return missing;
  };

  return {
    async ensure(node, packages) {
      const missing = await missingOf(node, packages);
      if (missing.length > 0) {
        await guestExec(provider, node, ["sudo", "apt-get", "update", "-y"]);
        await guestExec(provider, node, ["sudo", "apt-get", "install", "-y", ...missing]);
      }

      const user = await guestExec(provider, node, [
        "sudo",
        "sh",
        "-c",
        'set -e; id -u meidoya >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/meidoya --shell /usr/sbin/nologin meidoya; id -u meidoya >/dev/null',
      ]);
      if (user.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest could not create the meidoya runtime user", {
          node: node.name,
        });
      }
      const sandbox = await guestExec(provider, node, [
        "sudo",
        "sh",
        "-c",
        'set -e; if sysctl -n kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then printf "%s\\n" "kernel.apparmor_restrict_unprivileged_userns=0" > /etc/sysctl.d/90-meidoya-codex-sandbox.conf; sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0; fi',
      ]);
      if (sandbox.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest could not enable the isolated Codex user namespace", {
          node: node.name,
        });
      }
      return { missing: await missingOf(node, packages) };
    },
  };
}

export function createGuestInstallPort(provider: NodeProvider): GuestInstallPort {
  return {
    /**
     * The node artifact is a BINARY, and `ProcessRequest.stdin` is a `string`
     * written with Node's default utf8 encoding. Handing it
     * `Buffer.from(bytes).toString("binary")` — latin1 — turned every byte
     * >= 0x80 into two on the way out: a 10-byte ELF header arrived as 13. The
     * artifact was pinned, checksum-verified and then installed mangled and
     * non-executable, while the receipt attested the uncorrupted host-side
     * digest and Doctor printed "checksum verified".
     *
     * base64 is ASCII, so it survives the string channel exactly, and the guest
     * decodes it back to the original bytes.
     */
    async installArtifact(node, bytes) {
      const prepare = await guestExec(
        provider,
        node,
        [
          "sudo",
          "sh",
          "-c",
          'set -e; mkdir -p "$(dirname "$1")"; : > "$1.new"; chmod 0600 "$1.new"',
          "sh",
          NODE_BINARY_PATH,
        ],
      );
      if (prepare.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest refused the node artifact write", { node: node.name });
      }

      const chunkBytes = 8 * 1024 * 1024;
      for (let offset = 0; offset < bytes.byteLength; offset += chunkBytes) {
        const chunk = bytes.subarray(offset, Math.min(offset + chunkBytes, bytes.byteLength));
        const append = await guestExec(
          provider,
          node,
          ["sudo", "sh", "-c", 'set -e; base64 -d >> "$1.new"', "sh", NODE_BINARY_PATH],
          Buffer.from(chunk).toString("base64"),
        );
        if (append.exitCode !== 0) {
          throw new YashikiError("PROVIDER_FAILED", "guest refused a node artifact chunk", {
            node: node.name,
            offset,
          });
        }
      }

      const commit = await guestExec(provider, node, [
        "sudo",
        "sh",
        "-c",
        'set -e; chmod 0755 "$1.new"; mv "$1.new" "$1"',
        "sh",
        NODE_BINARY_PATH,
      ]);
      if (commit.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest refused to commit the node artifact", { node: node.name });
      }
    },

    /** Hashed where the bytes are, by the guest, after the write. */
    async digestArtifact(node) {
      const digest = await guestExec(provider, node, [
        ...(node.provider === "lima" ? ["sudo"] : []),
        "sh",
        "-c",
        'sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"',
        "sh",
        NODE_BINARY_PATH,
      ]);
      if (digest.exitCode !== 0) return null;
      const sha256 = digest.stdout.trim().split(/\s+/)[0];
      return sha256 !== undefined && /^[0-9a-f]{64}$/.test(sha256) ? sha256 : null;
    },

    async writeReceipt(node, receipt) {
      const write = await guestExec(
        provider,
        node,
        ["sudo", "sh", "-c", 'set -e; mkdir -p "$(dirname "$1")"; cat > "$1"; chmod 0444 "$1"', "sh", RECEIPT_PATH],
        JSON.stringify(receipt),
      );
      if (write.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest refused the install receipt write", { node: node.name });
      }
    },

    async readReceipt(node) {
      const read = await guestExec(
        provider,
        node,
        node.provider === "lima" ? ["sudo", "cat", RECEIPT_PATH] : ["cat", RECEIPT_PATH],
      );
      if (read.exitCode !== 0) return null;
      try {
        return JSON.parse(read.stdout) as NodeInstallReceipt;
      } catch {
        failClosed(`read install receipt on ${node.name}`, "the guest receipt is not valid JSON");
      }
    },
  };
}

/**
 * Renders the node.yaml consumed by `loadNodeConfig` / `NodeConfigSchema` in
 * the meidoya repository (packages/execution-native/src/config.ts). JSON is a
 * strict subset of YAML 1.2, so `js-yaml`'s parser (used on the other side)
 * accepts this output byte-for-byte; that sidesteps hand-rolled YAML escaping
 * for values Yashiki already validates elsewhere (node name, mount paths).
 *
 * `node.control_plane` carries the Meidoya node RPC endpoint, while
 * `node.temporal.address` carries the independently configured Temporal
 * endpoint. Lima commonly reaches both through `host.lima.internal`, but the
 * ports and protocols remain separate contracts.
 */
export function renderNodeConfig(config: DesiredNodeConfig): Record<string, unknown> {
  const allowedRoots =
    config.mounts.length > 0 ? [...new Set(config.mounts.map((mount) => mount.target))] : [NODE_STATE_DIR];

  // A workspace id was the target's BASENAME, so `/workspace/a/repo` and
  // `/workspace/b/repo` were both `repo` and the second silently overwrote the
  // first: a declared, mounted project invisible to the node, with nothing
  // anywhere saying so. A colliding basename falls back to the full path, which
  // is unique by construction (overlapping targets are already rejected).
  const segmentsOf = (target: string): string[] => target.split("/").filter((segment) => segment !== "");
  const basenameCounts = new Map<string, number>();
  for (const mount of config.mounts) {
    const base = segmentsOf(mount.target).at(-1) ?? mount.target;
    basenameCounts.set(base, (basenameCounts.get(base) ?? 0) + 1);
  }

  const workspaces: Record<string, unknown> = {};
  for (const mount of config.mounts) {
    const segments = segmentsOf(mount.target);
    const base = segments.at(-1) ?? mount.target;
    const id = (basenameCounts.get(base) ?? 0) > 1 ? segments.join("-") : base;
    workspaces[id] = { projects: { [id]: { path: mount.target } } };
  }

  const runtimes: Record<string, unknown> = {};
  for (const credential of config.credentials) {
    if (credential.provider === "codex" || credential.provider === "claude") {
      runtimes[credential.provider] = { enabled: true, mode: "cli", auth: `${credential.provider}-subscription` };
    }
  }

  return {
    schema_version: 1,
    node: {
      id: config.name,
      profile: config.profile,
      control_plane: config.controlPlane.endpoint,
      temporal: {
        address: config.controlPlane.temporalAddress,
        namespace: "default",
        task_queue: config.controlPlane.taskQueue,
      },
      max_concurrency: config.maxConcurrency,
    },
    workspaces,
    filesystem: {
      allowed_roots: allowedRoots,
      allow_home_fallback: false,
      // `guest-full` means "this filesystem is the guest's, not the host's", so
      // it is only ever correct inside a Lima guest. The profile alone used to
      // decide it, and nothing stopped a `native` node — a process running
      // directly on the operator's machine — from declaring `lima-trusted`.
      // config.ts now refuses that pairing; this repeats the condition rather
      // than trusting a single declaration to carry it.
      mode: config.provider === "lima" && config.profile === "lima-trusted" ? "guest-full" : "allowed-roots",
    },
    runtimes,
    capabilities: [...config.capabilities],
    network: { policy: "restricted", allowed_domains: [] },
  };
}

export function renderNodeConfigYaml(config: DesiredNodeConfig): string {
  return `${JSON.stringify(renderNodeConfig(config), null, 2)}\n`;
}

export function serviceUnit(config: DesiredNodeConfig): string {
  const credentialEnvironment = config.credentials.flatMap((credential) => {
    if (credential.provider === "node-registration") {
      return [`Environment=MEIDOYA_NODE_TOKEN_FILE=${credential.guestPath}`];
    }
    if (credential.provider === "claude") {
      return [`Environment=MEIDOYA_CLAUDE_TOKEN_FILE=${credential.guestPath}`];
    }
    return [];
  });
  const modelEnvironment = Object.entries(config.modelEnvironment)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `Environment=${key}=${value}`);
  const environment = [
    "Environment=HOME=/home/meidoya",
    "Environment=CODEX_HOME=/home/meidoya/.codex",
    ...credentialEnvironment,
    ...modelEnvironment,
  ].join("\n");

  return `[Unit]
Description=meidoya-node (${config.name})
After=network-online.target

[Service]
User=meidoya
Group=meidoya
WorkingDirectory=${NODE_STATE_DIR}
${environment}
ExecStart=${NODE_BINARY_PATH} --config ${NODE_CONFIG_PATH}
Restart=on-failure
StateDirectory=meidoya-node
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`;
}

export function createSystemdServicePort(provider: NodeProvider): NodeServicePort {
  return {
    async install(node, config) {
      const configWrite = await guestExec(
        provider,
        node,
        [
          "sudo",
          "sh",
          "-c",
          'set -e; mkdir -p "$(dirname "$1")"; cat > "$1.new"; chmod 0644 "$1.new"; mv "$1.new" "$1"',
          "sh",
          NODE_CONFIG_PATH,
        ],
        renderNodeConfigYaml(config),
      );
      if (configWrite.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest refused the node config write", { node: node.name });
      }

      const write = await guestExec(
        provider,
        node,
        ["sudo", "sh", "-c", 'set -e; cat > "$1"; systemctl daemon-reload; systemctl enable meidoya-node', "sh", SERVICE_UNIT_PATH],
        serviceUnit(config),
      );
      if (write.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest refused the service unit install", { node: node.name });
      }
    },

    async start(node) {
      const started = await guestExec(provider, node, ["sudo", "systemctl", "restart", "meidoya-node"]);
      if (started.exitCode !== 0) {
        throw new YashikiError("PROVIDER_FAILED", "guest could not restart the meidoya-node service", {
          node: node.name,
        });
      }
    },

    async state(node): Promise<ServiceState | null> {
      const exists = await guestExec(provider, node, ["test", "-f", SERVICE_UNIT_PATH]);
      if (exists.exitCode !== 0) return "absent";

      const active = await guestExec(provider, node, ["systemctl", "is-active", "meidoya-node"]);
      const text = active.stdout.trim();
      if (text === "active") return "running";
      if (text === "inactive" || text === "failed" || text === "activating") return "installed";
      // Anything else is not understood; the caller must fail closed.
      return null;
    },
  };
}

/**
 * Reads the Control Plane's view as the node itself recorded it. Yashiki only
 * observes registration; it never issues work to the node.
 */
export function createGuestRegistrationVerifier(
  provider: NodeProvider,
  clock: Clock = systemClock,
): RegistrationVerifierPort {
  return {
    async check(node) {
      const read = await guestExec(
        provider,
        node,
        node.provider === "lima" ? ["sudo", "cat", REGISTRATION_PATH] : ["cat", REGISTRATION_PATH],
      );
      if (read.exitCode !== 0) {
        return { registered: false, protocolVersion: null, heartbeatAgeMs: null };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(read.stdout);
      } catch {
        failClosed(`registration check on ${node.name}`, "the guest registration file is not valid JSON");
      }

      const record = parsed as Record<string, unknown>;
      // `lastHeartbeatAt` is an epoch-millisecond NUMBER on the wire
      // (apps/meidoyad/src/api.ts `lastHeartbeatAt: number`, backed by the
      // `execution_nodes.last_heartbeat_at INTEGER` column) — never an ISO
      // string, so it must not go through `Date.parse`.
      const heartbeatAt = typeof record["lastHeartbeatAt"] === "number" ? record["lastHeartbeatAt"] : NaN;
      return {
        registered: record["registered"] === true,
        protocolVersion: typeof record["protocolVersion"] === "number" ? record["protocolVersion"] : null,
        heartbeatAgeMs: Number.isFinite(heartbeatAt) ? clock.now().getTime() - heartbeatAt : null,
      };
    },
  };
}

export { NODE_BINARY_PATH, NODE_CONFIG_PATH, RECEIPT_PATH, REGISTRATION_PATH, SERVICE_UNIT_PATH };
