import type { NodeArchitecture, NodePlatform, NodeProfile } from "@meidoya-yashiki/node-protocol-client";

export type ProviderKind = "lima" | "native";

export type MountSpec = {
  source: string;
  target: string;
  writable: boolean;
};

export type CredentialProviderId = "codex" | "claude" | "node-registration" | "github";

/**
 * A credential requirement never carries the value itself, only where to read
 * it from on the host and where it must land in the guest (11 section 7).
 */
export type CredentialRequirement = {
  provider: CredentialProviderId;
  /** Opaque host reference resolved by an injected SecretSourcePort (Keychain/SOPS). */
  sourceRef: string;
  guestPath: string;
  /** POSIX mode, e.g. 0o600. */
  mode: number;
  owner: string;
  optional: boolean;
};

export type NodeBundlePin = {
  version: string;
  protocolVersion: number;
  manifestSha256: string;
};

export type ControlPlaneBinding = {
  endpoint: string;
  temporalAddress: string;
  taskQueue: string;
};

export type DesiredNodeConfig = {
  name: string;
  provider: ProviderKind;
  profile: NodeProfile;
  platform: NodePlatform;
  arch: NodeArchitecture;
  cpus: number;
  memoryMiB: number;
  diskGiB: number;
  mounts: readonly MountSpec[];
  credentials: readonly CredentialRequirement[];
  bundle: NodeBundlePin;
  controlPlane: ControlPlaneBinding;
  modelEnvironment: Readonly<Record<string, string>>;
  maxConcurrency: number;
  capabilities: readonly string[];
};

export type YashikiPaths = {
  configFile: string;
  dataDir: string;
  databaseFile: string;
  artifactsDir: string;
  locksDir: string;
};

export type YashikiConfig = {
  schemaVersion: 1;
  paths: YashikiPaths;
  defaultBundle: NodeBundlePin;
  nodes: readonly DesiredNodeConfig[];
};
