import { describe, expect, it } from "vitest";
import { fixedClock, isYashikiError } from "@meidoya-yashiki/yashiki-core";
import { createInMemoryReceiptStore, sha256Hex } from "@meidoya-yashiki/receipts";
import { planBackup, type BackupItem, type BackupManifest } from "@meidoya-yashiki/backup";
import {
  assertRecovered,
  createArchiveContentStore,
  recover,
  type ContentAddressedStorePort,
  type RestoreTargetPort,
} from "./recovery.js";

const clock = fixedClock("2026-01-01T00:00:00.000Z");

const CONFIG_CONTENT = '{"name":"work-grammarxiv"}';
const RECEIPT_CONTENT = '{"version":"0.1.0"}';

const manifest: BackupManifest = {
  nodeName: "work-grammarxiv",
  createdAt: "2026-01-01T00:00:00.000Z",
  archiveRef: "cas://archive-1",
  entries: [
    { id: "config", kind: "desired-config", sha256: sha256Hex(CONFIG_CONTENT), encrypted: false },
    { id: "install", kind: "install-receipt", sha256: sha256Hex(RECEIPT_CONTENT), encrypted: false },
  ],
  excluded: [],
};

function cas(overrides: Record<string, string | null> = {}): ContentAddressedStorePort {
  const store: Record<string, string> = {
    [sha256Hex(CONFIG_CONTENT)]: CONFIG_CONTENT,
    [sha256Hex(RECEIPT_CONTENT)]: RECEIPT_CONTENT,
  };
  return { get: async (sha) => (sha in overrides ? overrides[sha] ?? null : store[sha] ?? null) };
}

function target(): RestoreTargetPort & { applied: Record<string, string> } {
  const applied: Record<string, string> = {};
  return {
    applied,
    apply: async (id, content) => {
      applied[id] = content;
    },
    observe: async (id) => {
      const content = applied[id];
      return content === undefined ? null : sha256Hex(content);
    },
  };
}

describe("recovery", () => {
  it("restores every entry and journals intent, apply and verify", async () => {
    const receipts = createInMemoryReceiptStore();
    const outcome = await recover(manifest, { cas: cas(), target: target(), receipts, clock });

    expect(outcome.status).toBe("succeeded");
    expect(outcome.restored).toEqual(["config", "install"]);
    expect(outcome.journal.map((entry) => entry.state)).toEqual([
      "intent",
      "applied",
      "verified",
      "intent",
      "applied",
      "verified",
    ]);
    expect(() => assertRecovered(outcome)).not.toThrow();
    expect(receipts.latest("recovery", "work-grammarxiv")?.payload["status"]).toBe("succeeded");
  });

  it("halts with RECOVERY_REQUIRED when content is missing from the store", async () => {
    const receipts = createInMemoryReceiptStore();
    const outcome = await recover(manifest, {
      cas: cas({ [sha256Hex(CONFIG_CONTENT)]: null }),
      target: target(),
      receipts,
      clock,
    });

    expect(outcome.status).toBe("recovery_required");
    expect(outcome.restored).toEqual([]);
    expect(outcome.haltedReason).toContain("missing from the store");
    expect(outcome.journal.at(-1)?.state).toBe("halted");

    try {
      assertRecovered(outcome);
    } catch (error) {
      expect(isYashikiError(error, "RECOVERY_REQUIRED")).toBe(true);
      return;
    }
    throw new Error("expected assertRecovered to throw");
  });

  it("halts when stored content does not hash to its address", async () => {
    const outcome = await recover(manifest, {
      cas: cas({ [sha256Hex(CONFIG_CONTENT)]: "tampered" }),
      target: target(),
      receipts: createInMemoryReceiptStore(),
      clock,
    });

    expect(outcome.status).toBe("recovery_required");
    expect(outcome.haltedReason).toContain("does not hash to its address");
  });

  it("halts rather than guessing when the postcondition cannot be observed", async () => {
    const blind: RestoreTargetPort = { apply: async () => undefined, observe: async () => null };
    const outcome = await recover(manifest, {
      cas: cas(),
      target: blind,
      receipts: createInMemoryReceiptStore(),
      clock,
    });

    expect(outcome.status).toBe("recovery_required");
    expect(outcome.haltedReason).toContain("could not be observed");
  });

  it("halts when the postcondition does not match the backup", async () => {
    const wrong: RestoreTargetPort = {
      apply: async () => undefined,
      observe: async () => sha256Hex("something else"),
    };
    const outcome = await recover(manifest, {
      cas: cas(),
      target: wrong,
      receipts: createInMemoryReceiptStore(),
      clock,
    });

    expect(outcome.status).toBe("recovery_required");
    expect(outcome.haltedReason).toContain("does not match the backup");
  });

  it("applies nothing when the FIRST entry fails", async () => {
    const restoreTarget = target();
    const outcome = await recover(manifest, {
      cas: cas({ [sha256Hex(CONFIG_CONTENT)]: null }),
      target: restoreTarget,
      receipts: createInMemoryReceiptStore(),
      clock,
    });

    expect(outcome.status).toBe("recovery_required");
    expect(Object.keys(restoreTarget.applied)).toEqual([]);
  });

  /**
   * This test used to be called "stops at the failing entry and leaves the
   * remainder untouched" and only ever failed on the FIRST entry — so it
   * asserted `applied === []` and gave the impression partial application could
   * not happen. It can, there is no rollback, and the honest thing is to say so
   * where an operator reads it.
   */
  it("says so when a halt leaves the node half restored", async () => {
    const restoreTarget = target();
    const outcome = await recover(manifest, {
      cas: cas({ [sha256Hex(RECEIPT_CONTENT)]: null }),
      target: restoreTarget,
      receipts: createInMemoryReceiptStore(),
      clock,
    });

    expect(outcome.status).toBe("recovery_required");
    // The first entry really is on the node, and stays there.
    expect(Object.keys(restoreTarget.applied)).toEqual(["config"]);
    expect(outcome.restored).toEqual(["config"]);
    expect(outcome.haltedReason).toContain("NOT rolled back");
    expect(outcome.haltedReason).toContain("config");
  });

  describe("an entry the backup encrypted", () => {
    // An obvious dummy, and its "ciphertext" is an obvious reversible stand-in.
    const PLAINTEXT = '{"token":"dummy-not-a-real-credential"}';
    const CIPHERTEXT = `enc(${PLAINTEXT})`;
    const decryption = {
      decrypt: async (text: string) => text.replace(/^enc\(/, "").replace(/\)$/, ""),
    };

    const encryptedManifest: BackupManifest = {
      ...manifest,
      entries: [{ id: "codex-auth", kind: "credential-document", sha256: sha256Hex(CIPHERTEXT), encrypted: true }],
    };

    const encryptedCas: ContentAddressedStorePort = {
      get: async (sha) => (sha === sha256Hex(CIPHERTEXT) ? CIPHERTEXT : null),
    };

    it("is decrypted before it is applied, and verified against the PLAINTEXT", async () => {
      // `entry.encrypted` was set by the backup, carried in the manifest and
      // never read: the ciphertext was restored verbatim and the postcondition
      // compared it against sha256(ciphertext) — a check that validated the
      // wrong content by construction and could not fail. The restore
      // "succeeded" and installed an unusable credential.
      const restoreTarget = target();
      const outcome = await recover(encryptedManifest, {
        cas: encryptedCas,
        target: restoreTarget,
        receipts: createInMemoryReceiptStore(),
        decryption,
        clock,
      });

      expect(outcome.status).toBe("succeeded");
      expect(restoreTarget.applied["codex-auth"]).toBe(PLAINTEXT);
    });

    it("halts rather than installing ciphertext when no decryption port is configured", async () => {
      const restoreTarget = target();
      const outcome = await recover(encryptedManifest, {
        cas: encryptedCas,
        target: restoreTarget,
        receipts: createInMemoryReceiptStore(),
        clock,
      });

      expect(outcome.status).toBe("recovery_required");
      expect(outcome.haltedReason).toContain("no decryption port");
      expect(restoreTarget.applied).toEqual({});
    });

    it("halts when the decryption port hands back what it was given", async () => {
      const outcome = await recover(encryptedManifest, {
        cas: encryptedCas,
        target: target(),
        receipts: createInMemoryReceiptStore(),
        decryption: { decrypt: async (text) => text },
        clock,
      });

      expect(outcome.status).toBe("recovery_required");
      expect(outcome.haltedReason).toContain("unchanged");
    });

    it("halts when decryption throws", async () => {
      const outcome = await recover(encryptedManifest, {
        cas: encryptedCas,
        target: target(),
        receipts: createInMemoryReceiptStore(),
        decryption: {
          decrypt: async () => {
            throw new Error("no key");
          },
        },
        clock,
      });

      expect(outcome.status).toBe("recovery_required");
      expect(outcome.haltedReason).toContain("could not be decrypted");
    });
  });

  /**
   * The two halves of one round trip, connected. A backup writes entries keyed
   * by ID and recovery reads them keyed by sha256, and nothing had ever fed one
   * to the other — so an archive this system produces could not be restored by
   * the function that exists to restore it.
   */
  describe("an archive this system actually produced", () => {
    // Obvious dummies; the "encryption" is a reversible stand-in, never a
    // cipher. It has to actually transform the bytes: `planBackup` refuses a
    // port whose output still contains the plaintext, which is the right
    // refusal and the reason a wrapper will not do here.
    const PLAINTEXT = '{"token":"dummy-not-a-real-credential"}';
    const encryption = { encrypt: async (text: string) => `enc:${Buffer.from(text, "utf8").toString("base64")}` };
    const decryption = {
      decrypt: async (text: string) => Buffer.from(text.replace(/^enc:/, ""), "base64").toString("utf8"),
    };

    const items: BackupItem[] = [
      { id: "config", kind: "desired-config", content: CONFIG_CONTENT, sensitive: false },
      { id: "codex-auth", kind: "credential-document", content: PLAINTEXT, sensitive: true },
    ];

    it("round-trips through planBackup and recover", async () => {
      const plan = await planBackup(items, encryption);
      const archived: BackupManifest = {
        nodeName: "work-grammarxiv",
        createdAt: "2026-01-01T00:00:00.000Z",
        archiveRef: "cas://archive-1",
        entries: plan.entries.map(({ id, kind, sha256, encrypted }) => ({ id, kind, sha256, encrypted })),
        excluded: plan.excluded,
      };

      const restoreTarget = target();
      const outcome = await recover(archived, {
        cas: createArchiveContentStore(plan.entries),
        target: restoreTarget,
        receipts: createInMemoryReceiptStore(),
        decryption,
        clock,
      });

      expect(outcome.status).toBe("succeeded");
      expect(restoreTarget.applied["config"]).toBe(CONFIG_CONTENT);
      // The credential comes back as the credential, not as its ciphertext.
      expect(restoreTarget.applied["codex-auth"]).toBe(PLAINTEXT);
    });

    it("halts on an archive whose entry does not hash to its address", async () => {
      const plan = await planBackup(items, encryption);
      const tampered = plan.entries.map((entry) => ({ ...entry, content: `${entry.content} ` }));
      const archived: BackupManifest = {
        nodeName: "work-grammarxiv",
        createdAt: "2026-01-01T00:00:00.000Z",
        archiveRef: "cas://archive-1",
        entries: plan.entries.map(({ id, kind, sha256, encrypted }) => ({ id, kind, sha256, encrypted })),
        excluded: [],
      };

      const outcome = await recover(archived, {
        cas: createArchiveContentStore(tampered),
        target: target(),
        receipts: createInMemoryReceiptStore(),
        decryption,
        clock,
      });

      expect(outcome.status).toBe("recovery_required");
      expect(outcome.haltedReason).toContain("missing from the store");
    });
  });
});
