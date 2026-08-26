import { systemClock, YashikiError, type Clock } from "@meidoya-yashiki/yashiki-core";
import { sha256Hex, type ReceiptStore } from "@meidoya-yashiki/receipts";
import type { BackupEntry, BackupManifest } from "@meidoya-yashiki/backup";

/** Content-addressed store: entries are addressed by the sha256 of their bytes. */
export interface ContentAddressedStorePort {
  get(sha256: string): Promise<string | null>;
}

/**
 * The store view of a backup archive.
 *
 * A backup writes entries keyed by ID and recovery reads them keyed by
 * SHA256 — two halves of one round trip that had never been connected to each
 * other, so no archive this system produces could be fed to the function that
 * consumes one. This is the adapter, and `recovery.test.ts` drives it with the
 * output of the real `planBackup` rather than a hand-built fixture.
 *
 * Content that does not hash to its own address is not served: `recover`
 * re-checks anyway, and a store that hands back the wrong bytes should say
 * "missing" rather than "here you go".
 */
export function createArchiveContentStore(entries: readonly BackupEntry[]): ContentAddressedStorePort {
  const byDigest = new Map<string, string>();
  for (const entry of entries) {
    if (sha256Hex(entry.content) === entry.sha256) byDigest.set(entry.sha256, entry.content);
  }
  return { get: async (sha256) => byDigest.get(sha256) ?? null };
}

export interface RestoreTargetPort {
  apply(entryId: string, content: string): Promise<void>;
  /** Digest of what is actually there now, or null when it cannot be read. */
  observe(entryId: string): Promise<string | null>;
}

/**
 * Unwraps an entry the backup encrypted. The counterpart of
 * `backup`'s `EncryptionPort`.
 *
 * Without one, `entry.encrypted` — set by `planBackup`, carried in the manifest,
 * never read here — meant an encrypted entry was restored as raw CIPHERTEXT and
 * reported `succeeded`, because the postcondition compared the target against
 * `sha256(ciphertext)`: the check validated the wrong content by construction
 * and could not have failed. A "successful" restore installed an unusable
 * credential.
 */
export interface DecryptionPort {
  decrypt(ciphertext: string): Promise<string>;
}

export type JournalEntry = {
  sequence: number;
  entryId: string;
  state: "intent" | "applied" | "verified" | "halted";
  sha256: string;
  detail?: string;
};

export type RecoveryOutcome = {
  nodeName: string;
  status: "succeeded" | "recovery_required";
  restored: readonly string[];
  journal: readonly JournalEntry[];
  haltedReason: string | null;
};

export type RecoveryOptions = {
  cas: ContentAddressedStorePort;
  target: RestoreTargetPort;
  receipts: ReceiptStore;
  /** Required to restore any entry the manifest marks `encrypted`. */
  decryption?: DecryptionPort;
  clock?: Clock;
};

/**
 * Journal-driven restore. Every entry is written only after its bytes are
 * content-verified, and the postcondition is checked by reading the target
 * back. Any ambiguity halts with RECOVERY_REQUIRED instead of guessing
 * (11-yashiki-design.md section 10).
 */
export async function recover(manifest: BackupManifest, options: RecoveryOptions): Promise<RecoveryOutcome> {
  const clock = options.clock ?? systemClock;
  const journal: JournalEntry[] = [];
  const restored: string[] = [];
  /** Everything written to the target, verified or not — what a halt leaves behind. */
  const applied: string[] = [];
  let sequence = 0;

  const record = (entry: Omit<JournalEntry, "sequence">): void => {
    journal.push({ sequence: sequence++, ...entry });
  };

  const halt = (entryId: string, sha256: string, why: string): RecoveryOutcome => {
    // There is no rollback: entries already applied stay applied, and a halt
    // mid-manifest leaves a MIXTURE of restored and live state. That was true
    // before and invisible — the reason named only the entry that failed — so
    // an operator reading the receipt could not tell a no-op halt from a
    // half-restored node. The count goes in the reason, where they will read it.
    const reason =
      applied.length === 0
        ? why
        : `${why}; ${String(applied.length)} ${applied.length === 1 ? "entry has" : "entries have"} ` +
          `already been applied and are NOT rolled back (${applied.join(", ")})`;
    record({ entryId, state: "halted", sha256, detail: reason });
    const outcome: RecoveryOutcome = {
      nodeName: manifest.nodeName,
      status: "recovery_required",
      restored,
      journal,
      haltedReason: reason,
    };
    appendReceipt(options.receipts, manifest, outcome, clock);
    return outcome;
  };

  for (const entry of manifest.entries) {
    record({ entryId: entry.id, state: "intent", sha256: entry.sha256 });

    const content = await options.cas.get(entry.sha256);
    if (content === null) {
      return halt(entry.id, entry.sha256, `content ${entry.sha256} is missing from the store`);
    }
    if (sha256Hex(content) !== entry.sha256) {
      return halt(entry.id, entry.sha256, `content ${entry.sha256} does not hash to its address`);
    }

    // The address covers the bytes as ARCHIVED. For an encrypted entry those
    // are ciphertext, so what gets applied — and what the postcondition must be
    // compared against — is the plaintext behind it.
    let plaintext = content;
    if (entry.encrypted) {
      if (options.decryption === undefined) {
        return halt(
          entry.id,
          entry.sha256,
          `entry '${entry.id}' is encrypted and no decryption port is configured; ` +
            `restoring it verbatim would install ciphertext`,
        );
      }
      try {
        plaintext = await options.decryption.decrypt(content);
      } catch (error) {
        return halt(entry.id, entry.sha256, `entry '${entry.id}' could not be decrypted: ${(error as Error).message}`);
      }
      if (plaintext === content) {
        return halt(entry.id, entry.sha256, `the decryption port returned the ciphertext of '${entry.id}' unchanged`);
      }
    }
    const expected = entry.encrypted ? sha256Hex(plaintext) : entry.sha256;

    await options.target.apply(entry.id, plaintext);
    applied.push(entry.id);
    record({ entryId: entry.id, state: "applied", sha256: entry.sha256 });

    const observed = await options.target.observe(entry.id);
    if (observed === null) {
      return halt(entry.id, entry.sha256, `postcondition for '${entry.id}' could not be observed`);
    }
    if (observed !== expected) {
      return halt(entry.id, entry.sha256, `postcondition for '${entry.id}' does not match the backup`);
    }

    record({ entryId: entry.id, state: "verified", sha256: entry.sha256 });
    restored.push(entry.id);
  }

  const outcome: RecoveryOutcome = {
    nodeName: manifest.nodeName,
    status: "succeeded",
    restored,
    journal,
    haltedReason: null,
  };
  appendReceipt(options.receipts, manifest, outcome, clock);
  return outcome;
}

function appendReceipt(
  receipts: ReceiptStore,
  manifest: BackupManifest,
  outcome: RecoveryOutcome,
  clock: Clock,
): void {
  receipts.append({
    kind: "recovery",
    nodeName: manifest.nodeName,
    createdAt: clock.now().toISOString(),
    payload: {
      archiveRef: manifest.archiveRef,
      status: outcome.status,
      restored: [...outcome.restored],
      haltedReason: outcome.haltedReason,
      journal: outcome.journal.map((entry) => ({ ...entry, detail: entry.detail ?? null })),
    },
  });
}

/** Turns a halted recovery into an error for callers that cannot continue. */
export function assertRecovered(outcome: RecoveryOutcome): void {
  if (outcome.status === "recovery_required") {
    throw new YashikiError("RECOVERY_REQUIRED", outcome.haltedReason ?? "recovery halted on an ambiguous outcome", {
      node: outcome.nodeName,
      restored: outcome.restored.length,
    });
  }
}
