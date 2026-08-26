import { describe, expect, it } from "vitest";
import { fixedClock, isYashikiError, type DesiredNodeConfig, type NodeRef } from "@meidoya-yashiki/yashiki-core";
import { createInMemoryReceiptStore, sha256Hex } from "@meidoya-yashiki/receipts";
import type { NodeInstallReceipt } from "@meidoya-yashiki/node-protocol-client";
import { assertStartAllowed, BundleInstaller, type ArtifactSourcePort, type GuestInstallPort } from "./installer.js";
import { resolvePinnedManifest, selectArtifact, verifyArtifactChecksum } from "./manifest.js";

const ARTIFACT_BYTES = new TextEncoder().encode("meidoya-node-0.1.0-linux-arm64");
const ARTIFACT_SHA256 = sha256Hex(ARTIFACT_BYTES);

const MANIFEST_TEXT = JSON.stringify({
  product: "meidoya-node",
  version: "0.1.0",
  protocolVersion: 1,
  artifacts: [{ platform: "linux", arch: "arm64", sha256: ARTIFACT_SHA256 }],
});
const MANIFEST_SHA256 = sha256Hex(MANIFEST_TEXT);

const node: NodeRef = { name: "work-grammarxiv", provider: "lima" };

const config: DesiredNodeConfig = {
  name: "work-grammarxiv",
  provider: "lima",
  profile: "lima-trusted",
  platform: "linux",
  arch: "arm64",
  cpus: 8,
  memoryMiB: 16384,
  diskGiB: 100,
  mounts: [],
  credentials: [],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: MANIFEST_SHA256 },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: [],
};

/**
 * A guest that holds the artifact BYTES as well as the receipt, and hashes the
 * bytes it holds.
 *
 * That distinction is the whole point: the receipt is a claim about the binary
 * and the digest is the binary, and a fake that only ever kept the receipt made
 * "the guest agrees" unfalsifiable.
 */
function fakeGuest(): GuestInstallPort & {
  installedBytes: Uint8Array[];
  receipt: NodeInstallReceipt | null;
  onGuest: Uint8Array | null;
} {
  const state = {
    installedBytes: [] as Uint8Array[],
    receipt: null as NodeInstallReceipt | null,
    onGuest: null as Uint8Array | null,
    installArtifact: async (_node: NodeRef, bytes: Uint8Array) => {
      state.installedBytes.push(bytes);
      state.onGuest = bytes;
    },
    digestArtifact: async () => (state.onGuest === null ? null : sha256Hex(state.onGuest)),
    writeReceipt: async (_node: NodeRef, receipt: NodeInstallReceipt) => {
      state.receipt = receipt;
    },
    readReceipt: async () => state.receipt,
  };
  return state;
}

function fakeSource(overrides: Partial<ArtifactSourcePort> = {}): ArtifactSourcePort {
  return {
    fetchManifest: async () => MANIFEST_TEXT,
    fetchArtifact: async () => ARTIFACT_BYTES,
    ...overrides,
  };
}

function makeInstaller(source: ArtifactSourcePort, guest: GuestInstallPort): BundleInstaller {
  return new BundleInstaller({
    source,
    guest,
    receipts: createInMemoryReceiptStore(),
    clock: fixedClock("2026-01-01T00:00:00.000Z"),
  });
}

describe("release manifest pinning", () => {
  it("resolves a manifest whose bytes match the pin", () => {
    const manifest = resolvePinnedManifest(MANIFEST_TEXT, config.bundle);
    expect(selectArtifact(manifest, "linux", "arm64").sha256).toBe(ARTIFACT_SHA256);
  });

  it("rejects a manifest whose bytes do not match the pin", () => {
    expect(() => resolvePinnedManifest(`${MANIFEST_TEXT} `, config.bundle)).toThrowError(/CHECKSUM_MISMATCH/);
  });

  it("rejects a manifest that speaks another protocol version", () => {
    const text = JSON.stringify({
      product: "meidoya-node",
      version: "0.1.0",
      protocolVersion: 2,
      artifacts: [{ platform: "linux", arch: "arm64", sha256: ARTIFACT_SHA256 }],
    });
    expect(() =>
      resolvePinnedManifest(text, { ...config.bundle, manifestSha256: sha256Hex(text) }),
    ).toThrowError(/PROTOCOL_MISMATCH/);
  });

  it("rejects a missing platform/arch artifact", () => {
    const manifest = resolvePinnedManifest(MANIFEST_TEXT, config.bundle);
    expect(() => selectArtifact(manifest, "darwin", "arm64")).toThrowError(/ARTIFACT_MISMATCH/);
  });

  it("refuses bytes whose checksum does not match", () => {
    expect(() => verifyArtifactChecksum(new TextEncoder().encode("tampered"), ARTIFACT_SHA256)).toThrowError(
      /CHECKSUM_MISMATCH/,
    );
  });
});

describe("BundleInstaller", () => {
  it("installs the verified artifact and records a receipt", async () => {
    const guest = fakeGuest();
    const outcome = await makeInstaller(fakeSource(), guest).install(node, config);

    expect(outcome.installed).toBe(true);
    expect(outcome.receipt.artifactSha256).toBe(ARTIFACT_SHA256);
    expect(guest.installedBytes).toHaveLength(1);
  });

  it("is idempotent when the guest already has the pinned artifact", async () => {
    const guest = fakeGuest();
    const installer = makeInstaller(fakeSource(), guest);
    await installer.install(node, config);
    const second = await installer.install(node, config);

    expect(second.installed).toBe(false);
    expect(guest.installedBytes).toHaveLength(1);
  });

  it("refuses to install artifact bytes whose checksum does not match, before writing anything", async () => {
    const guest = fakeGuest();
    const source = fakeSource({ fetchArtifact: async () => new TextEncoder().encode("trojan") });

    try {
      await makeInstaller(source, guest).install(node, config);
    } catch (error) {
      expect(isYashikiError(error, "CHECKSUM_MISMATCH")).toBe(true);
      expect(guest.installedBytes).toHaveLength(0);
      expect(guest.receipt).toBeNull();
      return;
    }
    throw new Error("expected the checksum mismatch to abort the install");
  });

  it("refuses an artifact that did not arrive on the guest intact", async () => {
    // The transport that carried the bytes as latin1 through a utf8 stdin
    // delivered exactly this: a longer, different file. Nothing hashed the
    // bytes on the guest, so the receipt attested the uncorrupted HOST digest
    // and every layer above — assertStartAllowed, Doctor's "checksum verified"
    // — agreed with it.
    const guest = fakeGuest();
    const mangling: GuestInstallPort = {
      ...guest,
      installArtifact: async (ref, bytes) => {
        await guest.installArtifact(ref, new Uint8Array([...bytes, 0xc3, 0xbf]));
      },
    };

    try {
      await makeInstaller(fakeSource(), mangling).install(node, config);
    } catch (error) {
      expect(isYashikiError(error, "CHECKSUM_MISMATCH")).toBe(true);
      expect(guest.receipt).toBeNull();
      return;
    }
    throw new Error("expected the corrupted guest artifact to be refused");
  });

  it("fails closed when the artifact on the guest cannot be hashed", async () => {
    const guest = fakeGuest();
    const blind: GuestInstallPort = { ...guest, digestArtifact: async () => null };
    await expect(makeInstaller(fakeSource(), blind).install(node, config)).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("reinstalls when the receipt matches but the binary behind it does not", async () => {
    // Root on the guest swaps /usr/local/bin/meidoya-node and leaves
    // receipt.json alone. Trusting the receipt alone made that a no-op install
    // reported as twelve completed steps.
    const guest = fakeGuest();
    const installer = makeInstaller(fakeSource(), guest);
    await installer.install(node, config);

    guest.onGuest = new TextEncoder().encode("a different binary entirely");
    const second = await installer.install(node, config);

    expect(second.installed).toBe(true);
    expect(guest.installedBytes).toHaveLength(2);
    expect(guest.onGuest).toEqual(ARTIFACT_BYTES);
  });

  it("fails closed when the guest receipt cannot be read back", async () => {
    const guest = fakeGuest();
    const broken: GuestInstallPort = { ...guest, readReceipt: async () => null };
    await expect(makeInstaller(fakeSource(), broken).install(node, config)).rejects.toThrowError(
      /VERIFICATION_FAILED/,
    );
  });
});

describe("assertStartAllowed", () => {
  const good: NodeInstallReceipt = {
    product: "meidoya-node",
    version: "0.1.0",
    protocolVersion: 1,
    artifactSha256: ARTIFACT_SHA256,
    installedAt: "2026-01-01T00:00:00.000Z",
  };

  it("allows a node whose artifact matches the pin", () => {
    expect(() => assertStartAllowed(good, config, ARTIFACT_SHA256)).not.toThrow();
  });

  it("refuses to start a node with no receipt", () => {
    expect(() => assertStartAllowed(null, config, ARTIFACT_SHA256)).toThrowError(/ARTIFACT_MISMATCH/);
  });

  it("refuses to start a node whose version does not match the pin", () => {
    expect(() => assertStartAllowed({ ...good, version: "0.2.0" }, config, ARTIFACT_SHA256)).toThrowError(
      /ARTIFACT_MISMATCH/,
    );
  });

  it("refuses to start a node whose artifact checksum does not match the pin", () => {
    expect(() => assertStartAllowed({ ...good, artifactSha256: "b".repeat(64) }, config, ARTIFACT_SHA256)).toThrowError(
      /ARTIFACT_MISMATCH/,
    );
  });

  it("refuses to start a node speaking a different protocol version", () => {
    expect(() => assertStartAllowed({ ...good, protocolVersion: 2 }, config, ARTIFACT_SHA256)).toThrowError(
      /PROTOCOL_MISMATCH/,
    );
  });
});
