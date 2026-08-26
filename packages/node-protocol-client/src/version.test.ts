import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { NODE_PROTOCOL_VERSION } from "./version.js";
import type { NodeInstallReceipt, NodeRegistration, NodeReleaseManifest } from "./index.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("vendored node protocol contract", () => {
  it("pins the node protocol version to 1", () => {
    // A drift here means the vendored mirror no longer matches the published
    // contract; the mirror must be re-synced (or replaced) deliberately.
    expect(NODE_PROTOCOL_VERSION).toBe(1);
  });

  it("declares the mirror provenance in the package header", () => {
    const header = readFileSync(join(here, "index.ts"), "utf8");
    expect(header).toContain("@meidoya/node-protocol");
    expect(header).toContain("NODE_PROTOCOL_VERSION = 1");
    expect(header).toContain("replaced by the published package");
  });

  it("keeps the manifest and registration shapes structurally stable", () => {
    const manifest: NodeReleaseManifest = {
      product: "meidoya-node",
      version: "0.1.0",
      protocolVersion: NODE_PROTOCOL_VERSION,
      artifacts: [{ platform: "linux", arch: "arm64", sha256: "a".repeat(64) }],
    };
    const registration: NodeRegistration = {
      nodeId: "work-grammarxiv",
      nodeVersion: "0.1.0",
      protocolVersion: NODE_PROTOCOL_VERSION,
      platform: "linux",
      arch: "arm64",
      profile: "lima-trusted",
      capabilities: ["shell"],
      workspaceBindings: ["work-grammarxiv"],
      maxConcurrency: 4,
    };
    const receipt: NodeInstallReceipt = {
      product: "meidoya-node",
      version: "0.1.0",
      protocolVersion: NODE_PROTOCOL_VERSION,
      artifactSha256: "a".repeat(64),
      installedAt: "2026-01-01T00:00:00.000Z",
    };

    expect(manifest.artifacts[0]?.platform).toBe("linux");
    expect(registration.profile).toBe("lima-trusted");
    expect(receipt.product).toBe("meidoya-node");
  });
});
