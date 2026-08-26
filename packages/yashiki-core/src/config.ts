import path from "node:path";
import { parse as parseYaml } from "yaml";
import { YashikiError } from "./errors.js";
import { validateMounts } from "./mount-policy.js";
import { resolveYashikiPaths, type PathEnvironment } from "./paths.js";
import { parseSizeToGiB, parseSizeToMiB } from "./size.js";
import type {
  ControlPlaneBinding,
  CredentialProviderId,
  CredentialRequirement,
  DesiredNodeConfig,
  MountSpec,
  NodeBundlePin,
  ProviderKind,
  YashikiConfig,
} from "./types.js";
import type { NodeArchitecture, NodePlatform, NodeProfile } from "@meidoya-yashiki/node-protocol-client";

const NODE_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

const PROVIDERS: readonly ProviderKind[] = ["lima", "native"];
const PROFILES: readonly NodeProfile[] = ["mac-restricted", "linux-restricted", "lima-trusted"];
const PLATFORMS: readonly NodePlatform[] = ["darwin", "linux"];
const ARCHES: readonly NodeArchitecture[] = ["arm64", "x64"];
const CREDENTIAL_PROVIDERS: readonly CredentialProviderId[] = [
  "codex",
  "claude",
  "node-registration",
  "github",
];

type Raw = Record<string, unknown>;

function invalid(message: string, field: string): never {
  throw new YashikiError("CONFIG_INVALID", message, { field });
}

function asRecord(value: unknown, field: string): Raw {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${field} must be a mapping`, field);
  }
  return value as Raw;
}

function asArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) invalid(`${field} must be a list`, field);
  return value;
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") invalid(`${field} must be a non-empty string`, field);
  return value.trim();
}

function asInt(value: unknown, field: string, min: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min) {
    invalid(`${field} must be an integer >= ${min}`, field);
  }
  return value;
}

function asBool(value: unknown, field: string, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "boolean") invalid(`${field} must be a boolean`, field);
  return value;
}

function asEnum<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  const text = asString(value, field);
  if (!(allowed as readonly string[]).includes(text)) {
    invalid(`${field} must be one of: ${allowed.join(", ")}`, field);
  }
  return text as T;
}

function asStringList(value: unknown, field: string): string[] {
  if (value === undefined || value === null) return [];
  return asArray(value, field).map((entry, index) => asString(entry, `${field}[${index}]`));
}

const MODEL_ENV_NAME = /^MEIDOYA_MODEL_(CODEX|CLAUDE)_(HIGH|STANDARD|ECONOMY)$/;
const MODEL_ENV_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:/+-]*$/;

function parseModelEnvironment(value: unknown, field: string): Record<string, string> {
  if (value === undefined || value === null) return {};
  const raw = asRecord(value, field);
  const result: Record<string, string> = {};
  for (const [name, candidate] of Object.entries(raw)) {
    if (!MODEL_ENV_NAME.test(name)) invalid(`${field} contains unsupported variable '${name}'`, field);
    const model = asString(candidate, `${field}.${name}`);
    if (!MODEL_ENV_VALUE.test(model)) invalid(`${field}.${name} contains unsafe characters`, `${field}.${name}`);
    result[name] = model;
  }
  return result;
}

/**
 * A credential file mode, and the one place YAML's number syntax is refused
 * outright.
 *
 * YAML 1.2 has no leading-zero octal literal, so an unquoted `mode: 0400` is
 * the DECIMAL number 400. Accepting a number here meant 400 passed the
 * `0..0o777` bound and was re-rendered as octal at write time: `0400` became
 * `0620`, a group-writable secret; `0500` became `0764`. The failure was
 * inverted — the common modes (`0600`, `0644` -> decimal 600/644) exceeded the
 * bound and produced a clear error, while precisely the MORE RESTRICTIVE
 * intents passed silently and landed looser. There is no spelling of a number
 * here that is safe to guess at, so a number is an error with the fix in it.
 *
 * The floor is separate and independent: a credential file must grant nothing
 * to group or other, whatever the operator wrote.
 */
function parseMode(value: unknown, field: string): number {
  if (typeof value === "number") {
    invalid(
      `${field} must be a QUOTED octal string such as "0600": YAML has no leading-zero octal, ` +
        `so an unquoted ${String(value)} is the decimal number ${String(value)}, not a POSIX mode`,
      field,
    );
  }
  const text = asString(value, field);
  if (!/^0?[0-7]{3}$/.test(text)) invalid(`${field} must be an octal mode such as "0600"`, field);
  const mode = Number.parseInt(text, 8);
  if ((mode & 0o077) !== 0) {
    invalid(
      `${field} is ${text}, which grants group or other access to a credential file; ` +
        `it must be one of "0400", "0600", "0700" and the like`,
      field,
    );
  }
  return mode;
}

function parseBundle(value: unknown, field: string): NodeBundlePin {
  const raw = asRecord(value, field);
  const manifestSha256 = asString(raw["manifest_sha256"], `${field}.manifest_sha256`).toLowerCase();
  if (!SHA256_PATTERN.test(manifestSha256)) {
    invalid(`${field}.manifest_sha256 must be a 64-character hex sha256`, `${field}.manifest_sha256`);
  }
  return {
    version: asString(raw["version"], `${field}.version`),
    protocolVersion: asInt(raw["protocol_version"], `${field}.protocol_version`, 1),
    manifestSha256,
  };
}

function parseControlPlane(value: unknown, field: string): ControlPlaneBinding {
  const raw = asRecord(value, field);
  return {
    endpoint: asString(raw["endpoint"], `${field}.endpoint`),
    temporalAddress: asString(raw["temporal_address"], `${field}.temporal_address`),
    taskQueue: asString(raw["task_queue"], `${field}.task_queue`),
  };
}

function parseMount(value: unknown, field: string): MountSpec {
  const raw = asRecord(value, field);
  return {
    source: asString(raw["source"], `${field}.source`),
    target: asString(raw["target"], `${field}.target`),
    writable: asBool(raw["writable"], `${field}.writable`, false),
  };
}

/**
 * The guest destination of one credential, in ONE spelling.
 *
 * "One file and one receipt per provider" (11 section 7) was enforced by
 * comparing raw strings, so `/x/a.key`, `/x//a.key`, `/x/./a.key` and
 * `/x/b/../a.key` were four distinct paths to two providers and one file on the
 * guest: last writer wins, both receipts claim success, and the surviving file
 * carries the other provider's mode and owner. `..` was accepted outright, so a
 * declaration could also escape the directory it appears to name. The mount
 * policy has rejected `..` since the beginning; credentials get the same rule.
 */
function parseGuestPath(value: unknown, field: string): string {
  const raw = asString(value, field);
  if (!raw.startsWith("/")) invalid(`${field} must be absolute`, field);
  if (raw.split("/").includes("..")) invalid(`${field} must not contain '..' segments`, field);
  const normalized = path.posix.normalize(raw);
  const guestPath = normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
  if (guestPath === "/") invalid(`${field} must name a file, not the guest root`, field);
  return guestPath;
}

function parseCredential(value: unknown, field: string): CredentialRequirement {
  const raw = asRecord(value, field);
  const guestPath = parseGuestPath(raw["guest_path"], `${field}.guest_path`);
  return {
    provider: asEnum(raw["provider"], `${field}.provider`, CREDENTIAL_PROVIDERS),
    sourceRef: asString(raw["source_ref"], `${field}.source_ref`),
    guestPath,
    mode: parseMode(raw["mode"] ?? "0600", `${field}.mode`),
    owner: asString(raw["owner"], `${field}.owner`),
    optional: asBool(raw["optional"], `${field}.optional`, false),
  };
}

/**
 * The profile a node gets when it does not name one.
 *
 * `mac-restricted` used to be the default for every non-lima provider
 * regardless of the platform the node runs on, which is how a linux node ended
 * up declaring the macOS confinement profile.
 */
function defaultProfile(provider: ProviderKind, platform: NodePlatform): NodeProfile {
  if (provider === "lima") return "lima-trusted";
  return platform === "darwin" ? "mac-restricted" : "linux-restricted";
}

function assertCredentialInvariant(credentials: readonly CredentialRequirement[], field: string): void {
  const seenProviders = new Set<CredentialProviderId>();
  const seenPaths = new Set<string>();
  for (const credential of credentials) {
    // 11 section 7: separate file and separate receipt per provider.
    if (seenProviders.has(credential.provider)) {
      invalid(`${field} declares '${credential.provider}' twice`, field);
    }
    if (seenPaths.has(credential.guestPath)) {
      invalid(`${field} reuses guest path '${credential.guestPath}' across providers`, field);
    }
    seenProviders.add(credential.provider);
    seenPaths.add(credential.guestPath);
  }
}

function parseNode(
  name: string,
  value: unknown,
  defaultBundle: NodeBundlePin,
  homeDir: string,
): DesiredNodeConfig {
  const field = `nodes.${name}`;
  const raw = asRecord(value, field);
  const provider = asEnum(raw["provider"], `${field}.provider`, PROVIDERS);
  const credentials = asArray(raw["credentials"] ?? [], `${field}.credentials`).map((entry, index) =>
    parseCredential(entry, `${field}.credentials[${index}]`),
  );

  assertCredentialInvariant(credentials, `${field}.credentials`);

  const platform = asEnum(raw["platform"] ?? "linux", `${field}.platform`, PLATFORMS);
  const config: DesiredNodeConfig = {
    name,
    provider,
    profile: asEnum(raw["profile"] ?? defaultProfile(provider, platform), `${field}.profile`, PROFILES),
    platform,
    arch: asEnum(raw["arch"] ?? "arm64", `${field}.arch`, ARCHES),
    cpus: asInt(raw["cpus"] ?? 4, `${field}.cpus`, 1),
    memoryMiB: parseSizeToMiB((raw["memory"] ?? "8GiB") as string | number, `${field}.memory`),
    diskGiB: parseSizeToGiB((raw["disk"] ?? "60GiB") as string | number, `${field}.disk`),
    mounts: validateMounts(
      asArray(raw["mounts"] ?? [], `${field}.mounts`).map((entry, index) =>
        parseMount(entry, `${field}.mounts[${index}]`),
      ),
      { homeDir },
      provider,
    ),
    credentials,
    bundle: raw["node_bundle"] === undefined ? defaultBundle : parseBundle(raw["node_bundle"], `${field}.node_bundle`),
    controlPlane: parseControlPlane(raw["control_plane"], `${field}.control_plane`),
    modelEnvironment: parseModelEnvironment(raw["model_environment"], `${field}.model_environment`),
    maxConcurrency: asInt(raw["max_concurrency"] ?? 4, `${field}.max_concurrency`, 1),
    capabilities: asStringList(raw["capabilities"], `${field}.capabilities`),
  };

  return validateDesiredNodeConfig(config, homeDir);
}

/**
 * Revalidates an already-materialized desired configuration. This is the first
 * step of the provisioning lifecycle (11 section 5), so it must be callable
 * without re-reading the config file.
 */
export function validateDesiredNodeConfig(config: DesiredNodeConfig, homeDir: string): DesiredNodeConfig {
  if (!NODE_NAME_PATTERN.test(config.name)) {
    invalid(
      `node name '${config.name}' must match ${NODE_NAME_PATTERN.source}`,
      `nodes.${config.name}`,
    );
  }
  // The profile is not decoration: `renderNodeConfig` turns `lima-trusted` into
  // `filesystem.mode: guest-full`, so a node that declares it while running
  // somewhere other than inside a Lima guest would hand the host filesystem to
  // the daemon. The rule was enforced in one direction only (lima => trusted);
  // it is an equivalence, and both halves are checked here.
  const profileField = `nodes.${config.name}.profile`;
  if (config.provider === "lima" && config.profile !== "lima-trusted") {
    invalid(`nodes.${config.name}.profile must be 'lima-trusted' for the lima provider`, profileField);
  }
  if (config.provider !== "lima" && config.profile === "lima-trusted") {
    invalid(
      `nodes.${config.name}.profile 'lima-trusted' means the node runs inside a Lima guest; ` +
        `provider '${config.provider}' runs on the host, so it must not claim it`,
      profileField,
    );
  }
  if (config.profile === "mac-restricted" && config.platform !== "darwin") {
    invalid(`nodes.${config.name}.profile 'mac-restricted' requires platform 'darwin'`, profileField);
  }
  if (config.profile === "linux-restricted" && config.platform !== "linux") {
    invalid(`nodes.${config.name}.profile 'linux-restricted' requires platform 'linux'`, profileField);
  }
  const expectedTaskQueue = `meidoya/node/${config.name}`;
  if (config.controlPlane.taskQueue !== expectedTaskQueue) {
    invalid(
      `nodes.${config.name}.control_plane.task_queue must be '${expectedTaskQueue}'`,
      `nodes.${config.name}.control_plane.task_queue`,
    );
  }
  assertCredentialInvariant(config.credentials, `nodes.${config.name}.credentials`);
  const mounts = validateMounts(config.mounts, { homeDir }, config.provider);
  return { ...config, mounts };
}

export function parseYashikiConfig(text: string, env: PathEnvironment): YashikiConfig {
  let document: unknown;
  try {
    document = parseYaml(text);
  } catch (error) {
    invalid(`config.yaml is not valid YAML: ${(error as Error).message}`, "config.yaml");
  }

  const raw = asRecord(document, "config.yaml");
  const schemaVersion = asInt(raw["schema_version"], "schema_version", 1);
  if (schemaVersion !== 1) invalid("schema_version must be 1", "schema_version");

  const defaultBundle = parseBundle(raw["node_bundle"], "node_bundle");
  const nodesRaw = asRecord(raw["nodes"] ?? {}, "nodes");
  const nodes = Object.entries(nodesRaw).map(([name, value]) =>
    parseNode(name, value, defaultBundle, env.homeDir),
  );

  return {
    schemaVersion: 1,
    paths: resolveYashikiPaths(env),
    defaultBundle,
    nodes,
  };
}

export function findNode(config: YashikiConfig, name: string): DesiredNodeConfig {
  const node = config.nodes.find((candidate) => candidate.name === name);
  if (node === undefined) {
    throw new YashikiError("NOT_FOUND", `node '${name}' is not declared in config.yaml`, { node: name });
  }
  return node;
}
