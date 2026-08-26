import {
  failClosed,
  systemClock,
  YashikiError,
  type Clock,
  type DesiredNodeConfig,
  type NodeRef,
} from "@meidoya-yashiki/yashiki-core";
import type { NodeInstallReceipt, ReleaseArtifact } from "@meidoya-yashiki/node-protocol-client";
import type { ReceiptStore } from "@meidoya-yashiki/receipts";
import { resolvePinnedManifest, selectArtifact, verifyArtifactChecksum } from "./manifest.js";

/** Where release bytes come from. Injected so tests never touch the network. */
export interface ArtifactSourcePort {
  fetchManifest(version: string): Promise<string>;
  fetchArtifact(artifact: ReleaseArtifact, version: string): Promise<Uint8Array>;
}

/** Where verified bytes go. Injected so tests never touch a guest. */
export interface GuestInstallPort {
  installArtifact(node: NodeRef, bytes: Uint8Array): Promise<void>;
  /**
   * sha256 of the artifact AS IT EXISTS ON THE GUEST, or null when it is absent
   * or cannot be hashed.
   *
   * Until this existed the integrity chain terminated on the host: the checksum
   * was verified before the write, the receipt carried the HOST-side digest,
   * `assertStartAllowed` compared the receipt against that same host digest and
   * Doctor printed "checksum verified" — while nothing ever hashed the bytes
   * actually on the guest. A transport that mangled them (and one did) or a root
   * user swapping the binary and leaving `receipt.json` alone produced a green
   * report at every layer.
   */
  digestArtifact(node: NodeRef): Promise<string | null>;
  writeReceipt(node: NodeRef, receipt: NodeInstallReceipt): Promise<void>;
  readReceipt(node: NodeRef): Promise<NodeInstallReceipt | null>;
}

export type BundleInstallerOptions = {
  source: ArtifactSourcePort;
  guest: GuestInstallPort;
  receipts: ReceiptStore;
  clock?: Clock;
};

export type InstallOutcome = {
  installed: boolean;
  receipt: NodeInstallReceipt;
};

export type VerifiedArtifact = {
  version: string;
  protocolVersion: number;
  artifactSha256: string;
  bytes: Uint8Array;
};

export class BundleInstaller {
  readonly #source: ArtifactSourcePort;
  readonly #guest: GuestInstallPort;
  readonly #receipts: ReceiptStore;
  readonly #clock: Clock;

  constructor(options: BundleInstallerOptions) {
    this.#source = options.source;
    this.#guest = options.guest;
    this.#receipts = options.receipts;
    this.#clock = options.clock ?? systemClock;
  }

  /**
   * Downloads the pinned manifest and artifact and verifies the checksum. No
   * byte reaches the guest before this resolves.
   */
  async resolve(config: DesiredNodeConfig): Promise<VerifiedArtifact> {
    const manifestText = await this.#source.fetchManifest(config.bundle.version);
    const manifest = resolvePinnedManifest(manifestText, config.bundle);
    const artifact = selectArtifact(manifest, config.platform, config.arch);

    const bytes = await this.#source.fetchArtifact(artifact, manifest.version);
    const artifactSha256 = verifyArtifactChecksum(bytes, artifact.sha256);

    return { version: manifest.version, protocolVersion: manifest.protocolVersion, artifactSha256, bytes };
  }

  async readInstalled(node: NodeRef): Promise<NodeInstallReceipt | null> {
    return this.#guest.readReceipt(node);
  }

  /**
   * Verifies the checksum BEFORE installing and records an install receipt.
   * Re-running with an already matching receipt is a no-op (11 section 5:
   * idempotent and re-runnable).
   */
  async install(node: NodeRef, config: DesiredNodeConfig): Promise<InstallOutcome> {
    return this.installVerified(node, config, await this.resolve(config));
  }

  async installVerified(
    node: NodeRef,
    config: DesiredNodeConfig,
    verified: VerifiedArtifact,
  ): Promise<InstallOutcome> {
    // Re-verify the bytes we are about to write; a caller may have held them.
    const artifactSha256 = verifyArtifactChecksum(verified.bytes, verified.artifactSha256);

    const existing = await this.#guest.readReceipt(node);
    if (
      existing !== null &&
      existing.version === verified.version &&
      existing.artifactSha256 === artifactSha256 &&
      existing.protocolVersion === verified.protocolVersion &&
      // The receipt is a claim ABOUT the binary, not the binary. Skipping the
      // install on the receipt alone meant anything with root on the guest
      // could swap /usr/local/bin/meidoya-node and leave receipt.json in place.
      (await this.#guest.digestArtifact(node)) === artifactSha256
    ) {
      return { installed: false, receipt: existing };
    }

    await this.#guest.installArtifact(node, verified.bytes);

    // The bytes on the guest, hashed on the guest. A transport that corrupts
    // them fails here instead of being attested as correct by a receipt that
    // only ever repeated the host's own digest.
    const onGuest = await this.#guest.digestArtifact(node);
    if (onGuest === null) {
      failClosed(`install ${config.name}`, "the installed artifact could not be hashed on the guest");
    }
    if (onGuest !== artifactSha256) {
      throw new YashikiError(
        "CHECKSUM_MISMATCH",
        "the artifact on the guest does not hash to the verified release checksum",
        { node: node.name, expected: artifactSha256, actual: onGuest },
      );
    }

    const receipt: NodeInstallReceipt = {
      product: "meidoya-node",
      version: verified.version,
      protocolVersion: verified.protocolVersion,
      artifactSha256,
      installedAt: this.#clock.now().toISOString(),
    };
    await this.#guest.writeReceipt(node, receipt);

    const readBack = await this.#guest.readReceipt(node);
    if (readBack === null) {
      throw new YashikiError("VERIFICATION_FAILED", "install receipt could not be read back from the guest", {
        node: node.name,
      });
    }
    assertReceiptMatches(readBack, receipt);

    this.#receipts.append({
      kind: "install",
      nodeName: node.name,
      createdAt: receipt.installedAt,
      payload: {
        product: receipt.product,
        version: receipt.version,
        protocolVersion: receipt.protocolVersion,
        artifactSha256: receipt.artifactSha256,
        manifestSha256: config.bundle.manifestSha256,
        platform: config.platform,
        arch: config.arch,
      },
    });

    return { installed: true, receipt };
  }
}

function assertReceiptMatches(actual: NodeInstallReceipt, expected: NodeInstallReceipt): void {
  if (
    actual.version !== expected.version ||
    actual.artifactSha256 !== expected.artifactSha256 ||
    actual.protocolVersion !== expected.protocolVersion
  ) {
    throw new YashikiError("ARTIFACT_MISMATCH", "the guest receipt does not match what was just installed", {
      expectedVersion: expected.version,
      actualVersion: actual.version,
    });
  }
}

/**
 * Phase 6 DoD: a node whose installed artifact does not match the pinned bundle
 * must be refused a start, not started and reconciled later.
 */
export function assertStartAllowed(
  installed: NodeInstallReceipt | null,
  config: DesiredNodeConfig,
  expectedArtifactSha256: string,
): void {
  if (installed === null) {
    throw new YashikiError("ARTIFACT_MISMATCH", `node '${config.name}' has no install receipt; refusing to start`, {
      node: config.name,
    });
  }
  if (installed.product !== "meidoya-node") {
    throw new YashikiError("ARTIFACT_MISMATCH", `node '${config.name}' has a foreign install receipt`, {
      node: config.name,
      product: installed.product,
    });
  }
  if (installed.version !== config.bundle.version) {
    throw new YashikiError("ARTIFACT_MISMATCH", `node '${config.name}' runs ${installed.version}, pinned ${config.bundle.version}; refusing to start`, {
      node: config.name,
      installed: installed.version,
      pinned: config.bundle.version,
    });
  }
  if (installed.artifactSha256 !== expectedArtifactSha256) {
    throw new YashikiError("ARTIFACT_MISMATCH", `node '${config.name}' artifact checksum does not match the pinned release; refusing to start`, {
      node: config.name,
    });
  }
  if (installed.protocolVersion !== config.bundle.protocolVersion) {
    throw new YashikiError("PROTOCOL_MISMATCH", `node '${config.name}' speaks protocol ${installed.protocolVersion}, pinned ${config.bundle.protocolVersion}; refusing to start`, {
      node: config.name,
      installed: installed.protocolVersion,
      pinned: config.bundle.protocolVersion,
    });
  }
}
