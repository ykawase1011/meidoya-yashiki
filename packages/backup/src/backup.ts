import { systemClock, YashikiError, type Clock, type DesiredNodeConfig } from "@meidoya-yashiki/yashiki-core";
import { sha256Hex, type ReceiptStore } from "@meidoya-yashiki/receipts";

/** 11-yashiki-design.md section 10. */
export const BACKUP_ITEM_KINDS = [
  "desired-config",
  "install-receipt",
  "credential-receipt",
  "node-state",
  "workspace-metadata",
  "credential-document",
] as const;

export type BackupItemKind = (typeof BACKUP_ITEM_KINDS)[number];

export type BackupItem = {
  id: string;
  kind: BackupItemKind;
  content: string;
  /**
   * True when the content is (or may contain) plaintext credential material.
   *
   * "May contain" is the operative half, and it is not only a statement about
   * where the bytes came from. An item whose credential scan could not finish —
   * `SecretGuard.assertClean` returned an `IncompleteScan` — is sensitive too:
   * the guard did not clear it, and an uncleared item that is archived anyway is
   * a permanent plaintext file with nobody's word behind it. See
   * `collectBackupItems` in the CLI runtime.
   */
  sensitive: boolean;
  /** Why, for the exclusion line an operator reads. Defaults to the plaintext-sink wording. */
  sensitiveReason?: string;
};

export type BackupEntry = {
  id: string;
  kind: BackupItemKind;
  sha256: string;
  encrypted: boolean;
  content: string;
};

export type BackupExclusion = {
  id: string;
  kind: BackupItemKind;
  reason: string;
};

export type BackupPlan = {
  entries: readonly BackupEntry[];
  excluded: readonly BackupExclusion[];
};

export type BackupManifest = {
  nodeName: string;
  createdAt: string;
  archiveRef: string;
  entries: readonly Omit<BackupEntry, "content">[];
  excluded: readonly BackupExclusion[];
};

export interface BackupSourcePort {
  collect(config: DesiredNodeConfig): Promise<readonly BackupItem[]>;
}

export interface EncryptionPort {
  encrypt(plaintext: string): Promise<string>;
}

export interface BackupSinkPort {
  /** Stores the entry bytes and returns a reference to the resulting archive. */
  write(nodeName: string, entries: readonly BackupEntry[]): Promise<{ archiveRef: string }>;
}

export type BackupOptions = {
  source: BackupSourcePort;
  sink: BackupSinkPort;
  receipts: ReceiptStore;
  encryption?: EncryptionPort;
  clock?: Clock;
};

/**
 * Plaintext credential sinks are excluded by default; they are only included
 * when an encryption port is available to wrap them (11 section 10).
 */
export async function planBackup(
  items: readonly BackupItem[],
  encryption?: EncryptionPort,
): Promise<BackupPlan> {
  const entries: BackupEntry[] = [];
  const excluded: BackupExclusion[] = [];

  for (const item of items) {
    if (!item.sensitive) {
      entries.push({ id: item.id, kind: item.kind, sha256: sha256Hex(item.content), encrypted: false, content: item.content });
      continue;
    }
    if (encryption === undefined) {
      excluded.push({
        id: item.id,
        kind: item.kind,
        reason: `${item.sensitiveReason ?? "plaintext credential sink"} excluded: no encryption port configured`,
      });
      continue;
    }
    const ciphertext = await encryption.encrypt(item.content);
    // `"anything".includes("")` is true, so a zero-length sensitive item — an
    // empty receipt list, a credential file that is not there yet — aborted the
    // WHOLE backup with CREDENTIAL_UNSAFE, a security refusal reporting an
    // encryption port that had done nothing wrong. There is no plaintext to
    // find in an empty string.
    if (item.content !== "" && ciphertext.includes(item.content)) {
      throw new YashikiError("CREDENTIAL_UNSAFE", "the encryption port returned the plaintext unchanged", {
        item: item.id,
      });
    }
    entries.push({ id: item.id, kind: item.kind, sha256: sha256Hex(ciphertext), encrypted: true, content: ciphertext });
  }

  return { entries, excluded };
}

export async function runBackup(config: DesiredNodeConfig, options: BackupOptions): Promise<BackupManifest> {
  const clock = options.clock ?? systemClock;
  const items = await options.source.collect(config);
  const plan = await planBackup(items, options.encryption);
  const { archiveRef } = await options.sink.write(config.name, plan.entries);

  const manifest: BackupManifest = {
    nodeName: config.name,
    createdAt: clock.now().toISOString(),
    archiveRef,
    entries: plan.entries.map(({ id, kind, sha256, encrypted }) => ({ id, kind, sha256, encrypted })),
    excluded: plan.excluded,
  };

  options.receipts.append({
    kind: "backup",
    nodeName: config.name,
    createdAt: manifest.createdAt,
    payload: {
      archiveRef,
      entries: manifest.entries.map((entry) => ({ ...entry })),
      excluded: manifest.excluded.map((entry) => ({ ...entry })),
    },
  });

  return manifest;
}
