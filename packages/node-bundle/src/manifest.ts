import { YashikiError, type NodeBundlePin } from "@meidoya-yashiki/yashiki-core";
import { NODE_PROTOCOL_VERSION, type NodeArchitecture, type NodePlatform, type NodeReleaseManifest, type ReleaseArtifact } from "@meidoya-yashiki/node-protocol-client";
import { sha256Hex } from "@meidoya-yashiki/receipts";

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function invalid(message: string): never {
  throw new YashikiError("ARTIFACT_MISMATCH", message, {});
}

export function parseReleaseManifest(text: string): NodeReleaseManifest {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    invalid("release manifest is not valid JSON");
  }
  if (typeof document !== "object" || document === null) invalid("release manifest is not an object");

  const raw = document as Record<string, unknown>;
  if (raw["product"] !== "meidoya-node") invalid("release manifest is not a meidoya-node manifest");
  if (typeof raw["version"] !== "string") invalid("release manifest has no version");
  if (typeof raw["protocolVersion"] !== "number") invalid("release manifest has no protocolVersion");
  if (!Array.isArray(raw["artifacts"])) invalid("release manifest has no artifacts");

  const artifacts = raw["artifacts"].map((entry): ReleaseArtifact => {
    if (typeof entry !== "object" || entry === null) invalid("release manifest artifact is not an object");
    const record = entry as Record<string, unknown>;
    const sha256 = typeof record["sha256"] === "string" ? record["sha256"].toLowerCase() : "";
    if (!SHA256_PATTERN.test(sha256)) invalid("release manifest artifact has no valid sha256");
    if (record["platform"] !== "darwin" && record["platform"] !== "linux") invalid("artifact platform is invalid");
    if (record["arch"] !== "arm64" && record["arch"] !== "x64") invalid("artifact arch is invalid");
    return {
      platform: record["platform"],
      arch: record["arch"],
      sha256,
      ...(typeof record["url"] === "string" ? { url: record["url"] } : {}),
    };
  });

  return {
    product: "meidoya-node",
    version: raw["version"],
    protocolVersion: raw["protocolVersion"],
    artifacts,
  };
}

/**
 * Yashiki pins the manifest itself, not just the artifact: the manifest bytes
 * must hash to the pinned value before any artifact inside it is trusted
 * (03-repository-boundaries.md section 4.2).
 */
export function resolvePinnedManifest(manifestText: string, pin: NodeBundlePin): NodeReleaseManifest {
  const actual = sha256Hex(manifestText);
  if (actual !== pin.manifestSha256) {
    throw new YashikiError("CHECKSUM_MISMATCH", "release manifest sha256 does not match the pinned value", {
      expected: pin.manifestSha256,
      actual,
    });
  }

  const manifest = parseReleaseManifest(manifestText);
  if (manifest.version !== pin.version) {
    throw new YashikiError("ARTIFACT_MISMATCH", "release manifest version does not match the pinned version", {
      expected: pin.version,
      actual: manifest.version,
    });
  }
  assertProtocolCompatible(manifest.protocolVersion, pin.protocolVersion);
  return manifest;
}

export function assertProtocolCompatible(manifestProtocolVersion: number, pinnedProtocolVersion: number): void {
  if (pinnedProtocolVersion !== NODE_PROTOCOL_VERSION) {
    throw new YashikiError("PROTOCOL_MISMATCH", "pinned protocol version is not supported by this Yashiki build", {
      pinned: pinnedProtocolVersion,
      supported: NODE_PROTOCOL_VERSION,
    });
  }
  if (manifestProtocolVersion !== NODE_PROTOCOL_VERSION) {
    throw new YashikiError("PROTOCOL_MISMATCH", "release manifest speaks a different node protocol version", {
      manifest: manifestProtocolVersion,
      supported: NODE_PROTOCOL_VERSION,
    });
  }
}

export function selectArtifact(
  manifest: NodeReleaseManifest,
  platform: NodePlatform,
  arch: NodeArchitecture,
): ReleaseArtifact {
  const matches = manifest.artifacts.filter(
    (artifact) => artifact.platform === platform && artifact.arch === arch,
  );
  if (matches.length === 0) {
    throw new YashikiError("ARTIFACT_MISMATCH", `release ${manifest.version} has no ${platform}/${arch} artifact`, {
      platform,
      arch,
    });
  }
  if (matches.length > 1) {
    throw new YashikiError("ARTIFACT_MISMATCH", `release ${manifest.version} declares ${platform}/${arch} twice`, {
      platform,
      arch,
    });
  }
  return matches[0] as ReleaseArtifact;
}

/** Verifies bytes BEFORE they are written anywhere in the guest. */
export function verifyArtifactChecksum(bytes: Uint8Array, expectedSha256: string): string {
  const actual = sha256Hex(bytes);
  if (actual !== expectedSha256.toLowerCase()) {
    throw new YashikiError("CHECKSUM_MISMATCH", "node artifact sha256 does not match the release manifest", {
      expected: expectedSha256,
      actual,
    });
  }
  return actual;
}
