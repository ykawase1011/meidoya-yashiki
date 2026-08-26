import {
  createSecretGuard,
  silentLogger,
  systemClock,
  YashikiError,
  type Clock,
  type CredentialProviderId,
  type CredentialRequirement,
  type DesiredNodeConfig,
  type Logger,
  type MutableSecretGuard,
  type NodeRef,
} from "@meidoya-yashiki/yashiki-core";
import { sha256Hex, type ReceiptStore } from "@meidoya-yashiki/receipts";
import type { CredentialOutcome, GuestCredentialPort, SecretSourcePort } from "./ports.js";

export type CredentialMaterializerOptions = {
  source: SecretSourcePort;
  guest: GuestCredentialPort;
  receipts: ReceiptStore;
  clock?: Clock;
  logger?: Logger;
  secretGuard?: MutableSecretGuard;
};

function formatMode(mode: number): string {
  return `0${mode.toString(8).padStart(3, "0")}`;
}

/**
 * A salted digest so a receipt can detect drift without being an oracle for a
 * low-entropy secret. It is never the secret and never reversible in practice.
 */
function fingerprint(nodeName: string, provider: CredentialProviderId, value: string): string {
  return sha256Hex(`meidoya-yashiki/credential/${nodeName}/${provider}\n${value}`);
}

export class CredentialMaterializer {
  readonly #source: SecretSourcePort;
  readonly #guest: GuestCredentialPort;
  readonly #receipts: ReceiptStore;
  readonly #clock: Clock;
  readonly #logger: Logger;
  readonly #guard: MutableSecretGuard;

  constructor(options: CredentialMaterializerOptions) {
    this.#source = options.source;
    this.#guest = options.guest;
    this.#receipts = options.receipts;
    this.#clock = options.clock ?? systemClock;
    this.#logger = options.logger ?? silentLogger;
    this.#guard = options.secretGuard ?? createSecretGuard();
  }

  /**
   * Materializes every declared credential. Sync never revokes: removing a
   * credential from the host is a separate, explicit operation (11 section 7).
   */
  async sync(node: NodeRef, config: DesiredNodeConfig): Promise<CredentialOutcome[]> {
    const outcomes: CredentialOutcome[] = [];
    for (const requirement of config.credentials) {
      outcomes.push(await this.#syncOne(node, requirement));
    }
    return outcomes;
  }

  /**
   * Teaches the secret guard the values this node declares, without writing,
   * verifying or recording anything.
   *
   * Read-only commands (doctor, status, backup) render credential-adjacent
   * output but never call `sync`, and every CLI invocation is a fresh process —
   * so without this the guard those commands share is empty and its
   * `assertClean` is a no-op on the one human-readable sink 11 section 9 cares
   * about. Returns how many values are now guarded so a caller can tell a
   * populated guard from a blind one.
   *
   * A value that cannot be read (locked Keychain, missing entry) is skipped:
   * doctor's job is to diagnose exactly that situation, so it must still run.
   * Doctor's real protection is structural — no probe ever reads a credential
   * file's contents — and this only backs it up.
   */
  async primeGuard(node: NodeRef, config: DesiredNodeConfig): Promise<number> {
    for (const requirement of config.credentials) {
      let value: string | null;
      try {
        value = await this.#source.read(requirement.sourceRef);
      } catch {
        value = null;
      }
      if (value === null || value === "") {
        this.#logger.log("debug", "credential not readable on the host; the guard cannot cover it", {
          node: node.name,
          provider: requirement.provider,
        });
        continue;
      }
      this.#guard.remember(value);
    }
    return this.#guard.size;
  }

  async revoke(node: NodeRef, requirement: CredentialRequirement): Promise<CredentialOutcome> {
    await this.#guest.remove(node, requirement.guestPath);

    const stat = await this.#guest.stat(node, requirement.guestPath);
    if (stat.exists) {
      throw new YashikiError("VERIFICATION_FAILED", "credential file still exists after revoke", {
        node: node.name,
        provider: requirement.provider,
        guestPath: requirement.guestPath,
      });
    }

    this.#appendReceipt(node, requirement, "revoke", null);
    this.#logger.log("info", "credential revoked", { node: node.name, provider: requirement.provider });
    return {
      provider: requirement.provider,
      operation: "revoke",
      guestPath: requirement.guestPath,
      changed: true,
      skipped: false,
    };
  }

  async #syncOne(node: NodeRef, requirement: CredentialRequirement): Promise<CredentialOutcome> {
    const value = await this.#source.read(requirement.sourceRef);
    if (value === null || value === "") {
      if (requirement.optional) {
        this.#logger.log("info", "optional credential is absent on the host", {
          node: node.name,
          provider: requirement.provider,
        });
        return {
          provider: requirement.provider,
          operation: "sync",
          guestPath: requirement.guestPath,
          changed: false,
          skipped: true,
        };
      }
      throw new YashikiError("NOT_FOUND", `credential '${requirement.provider}' is not available on the host`, {
        node: node.name,
        provider: requirement.provider,
        sourceRef: requirement.sourceRef,
      });
    }

    // From here on the value is known to every sink guard in this process.
    this.#guard.remember(value);

    const digest = sha256Hex(value);
    const before = await this.#guest.stat(node, requirement.guestPath);
    const alreadyCorrect =
      before.exists &&
      !before.isSymlink &&
      before.sha256 === digest &&
      before.owner === requirement.owner &&
      before.mode === requirement.mode;

    if (!alreadyCorrect) {
      if (before.exists && before.isSymlink) {
        // Never follow: a symlink at the destination could redirect the write.
        throw new YashikiError("CREDENTIAL_UNSAFE", "credential destination is a symlink", {
          node: node.name,
          provider: requirement.provider,
          guestPath: requirement.guestPath,
        });
      }
      await this.#guest.writeSecret(node, requirement.guestPath, value, {
        mode: requirement.mode,
        owner: requirement.owner,
      });
    }

    const after = await this.#guest.stat(node, requirement.guestPath);
    this.#assertGuestState(node, requirement, after, digest);

    this.#appendReceipt(node, requirement, "sync", fingerprint(node.name, requirement.provider, value));
    this.#logger.log("info", "credential materialized", {
      node: node.name,
      provider: requirement.provider,
      guestPath: requirement.guestPath,
      mode: formatMode(requirement.mode),
    });

    return {
      provider: requirement.provider,
      operation: "sync",
      guestPath: requirement.guestPath,
      changed: !alreadyCorrect,
      skipped: false,
    };
  }

  #assertGuestState(
    node: NodeRef,
    requirement: CredentialRequirement,
    stat: { exists: boolean; isSymlink: boolean; owner: string; mode: number; sha256: string },
    expectedDigest: string,
  ): void {
    const fail = (reason: string, details: Record<string, string | number | boolean>): never => {
      throw new YashikiError("CREDENTIAL_UNSAFE", reason, {
        node: node.name,
        provider: requirement.provider,
        guestPath: requirement.guestPath,
        ...details,
      });
    };

    if (!stat.exists) fail("credential file is missing after write", {});
    if (stat.isSymlink) fail("credential file is a symlink after write", {});
    if (stat.owner !== requirement.owner) {
      fail("credential file owner does not match the requirement", {
        expected: requirement.owner,
        actual: stat.owner,
      });
    }
    if (stat.mode !== requirement.mode) {
      fail("credential file mode does not match the requirement", {
        expected: formatMode(requirement.mode),
        actual: formatMode(stat.mode),
      });
    }
    if (stat.sha256 !== expectedDigest) {
      // Digests only; the value itself is never part of the comparison output.
      fail("credential file content does not match the host secret", {});
    }
  }

  #appendReceipt(
    node: NodeRef,
    requirement: CredentialRequirement,
    operation: "sync" | "revoke",
    valueFingerprint: string | null,
  ): void {
    // Separate receipt per provider (11 section 7); no value, only metadata.
    this.#receipts.append({
      kind: "credential",
      nodeName: node.name,
      createdAt: this.#clock.now().toISOString(),
      payload: {
        provider: requirement.provider,
        operation,
        sourceRef: requirement.sourceRef,
        guestPath: requirement.guestPath,
        owner: requirement.owner,
        mode: formatMode(requirement.mode),
        valueFingerprint,
      },
    });
  }
}
