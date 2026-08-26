import type { NodeArchitecture, NodePlatform } from "./node.js";

/** Mirrors `@meidoya/node-manifest`. */
export type ReleaseArtifact = {
  platform: NodePlatform;
  arch: NodeArchitecture;
  sha256: string;
  url?: string;
};

export type NodeReleaseManifest = {
  product: "meidoya-node";
  version: string;
  protocolVersion: number;
  artifacts: ReleaseArtifact[];
};

export type NodeInstallReceipt = {
  product: "meidoya-node";
  version: string;
  protocolVersion: number;
  artifactSha256: string;
  installedAt: string;
};
