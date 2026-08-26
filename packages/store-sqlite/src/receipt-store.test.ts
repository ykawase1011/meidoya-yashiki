import { describe, expect, it } from "vitest";
import { createSecretGuard, isYashikiError } from "@meidoya-yashiki/yashiki-core";
import { openMemoryDatabase } from "./db.js";
import { migrate } from "./migrate.js";
import { migrations } from "./migrations/index.js";
import { createSqliteReceiptStore } from "./receipt-store.js";
import { upsertNode } from "./registry.js";
import type { DesiredNodeConfig } from "@meidoya-yashiki/yashiki-core";

const NODE: DesiredNodeConfig = {
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
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: "a".repeat(64) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: [],
};

function setup() {
  const db = openMemoryDatabase();
  migrate(db, migrations);
  upsertNode(db, NODE);
  return { db, store: createSqliteReceiptStore(db) };
}

describe("sqlite receipt store", () => {
  it("appends a chained receipt and projects typed rows", () => {
    const { db, store } = setup();

    store.append({
      kind: "install",
      nodeName: NODE.name,
      createdAt: "2026-01-01T00:00:00.000Z",
      payload: { product: "meidoya-node", version: "0.1.0", protocolVersion: 1, artifactSha256: "a".repeat(64) },
    });
    store.append({
      kind: "credential",
      nodeName: NODE.name,
      createdAt: "2026-01-01T00:01:00.000Z",
      payload: {
        provider: "codex",
        operation: "sync",
        sourceRef: "keychain:codex",
        guestPath: "/home/meidoya/.codex/auth.json",
        owner: "meidoya",
        mode: "0600",
        valueFingerprint: "f".repeat(64),
      },
    });

    expect(store.list()).toHaveLength(2);
    expect(store.latest("install", NODE.name)?.payload["version"]).toBe("0.1.0");
    expect(() => store.verify()).not.toThrow();

    expect((db.prepare("SELECT COUNT(*) AS n FROM install_receipts").get() as { n: number }).n).toBe(1);
    expect(
      (db.prepare("SELECT credential_provider AS p FROM credential_receipts").get() as { p: string }).p,
    ).toBe("codex");
  });

  it("detects tampering through the chain", () => {
    const { db, store } = setup();
    store.append({
      kind: "install",
      nodeName: NODE.name,
      createdAt: "2026-01-01T00:00:00.000Z",
      payload: { product: "meidoya-node", version: "0.1.0", protocolVersion: 1, artifactSha256: "a".repeat(64) },
    });

    // Only a direct write around the triggers could do this; the chain catches it.
    db.exec("DROP TRIGGER receipts_no_update");
    db.prepare("UPDATE receipts SET payload_json = '{\"version\":\"9.9.9\"}'").run();

    expect(() => store.verify()).toThrowError(/RECEIPT_TAMPERED/);
  });

  /**
   * This is the SHIPPED store: `apps/meidoya-yashiki/src/runtime.ts` wires it
   * into every command. Its guard calls cover two disjoint halves of the row
   * (payload and envelope), and there is one test per half so that deleting
   * either call turns this file red. An unguarded write here is a credential in
   * a file on disk, so nothing about it may rest on the in-memory store's
   * coverage.
   */
  const INSTALL = {
    product: "meidoya-node",
    version: "0.1.0",
    protocolVersion: 1,
    artifactSha256: "a".repeat(64),
  } as const;

  function appendInstall(store: ReturnType<typeof setup>["store"], minute: number): void {
    store.append({
      kind: "install",
      nodeName: NODE.name,
      createdAt: `2026-01-01T00:0${String(minute)}:00.000Z`,
      payload: { ...INSTALL },
    });
  }

  /**
   * Defect C4. `verifyReceiptChain` walked forward from sequence 0 with no
   * anchor, so a truncated TAIL was invisible: after cutting a three-receipt
   * chain, `[r0, r1]`, `[r0]` and `[]` all passed. The store now records how
   * many receipts it appended, and the head hash, in `receipt_chain_head` —
   * outside the table being truncated.
   */
  describe("tail truncation", () => {
    function truncated(keep: number) {
      const { db, store } = setup();
      appendInstall(store, 0);
      appendInstall(store, 1);
      appendInstall(store, 2);
      // Only a write around the append-only triggers can do this — an export, a
      // backup or a restored file, which is exactly where `verify` is used.
      db.exec("DROP TRIGGER receipts_no_delete");
      db.prepare("DELETE FROM receipts WHERE sequence >= ?").run(keep);
      return { db, store };
    }

    for (const keep of [2, 1, 0]) {
      it(`detects a chain cut down to ${String(keep)} receipt(s)`, () => {
        const { store } = truncated(keep);
        expect(() => store.verify()).toThrowError(/RECEIPT_TAMPERED/);
      });
    }

    /**
     * The compounding half: `sequence` came from `COUNT(*)`, so deleting the
     * last receipt handed its sequence straight back to the next append and the
     * chain re-verified CLEAN — a receipt erased and replaced, with the
     * tamper-evidence reporting OK.
     */
    it("never reissues the sequence of a deleted receipt", () => {
      const { db, store } = truncated(2);
      expect(() =>
        store.append({
          kind: "install",
          nodeName: NODE.name,
          createdAt: "2026-01-01T09:00:00.000Z",
          payload: { ...INSTALL },
        }),
      ).toThrowError(/RECEIPT_TAMPERED/);
      expect((db.prepare("SELECT COUNT(*) AS n FROM receipts").get() as { n: number }).n).toBe(2);
    });

    it("keeps the head anchor from being rewound", () => {
      const { db, store } = setup();
      appendInstall(store, 0);
      expect(() => db.prepare("UPDATE receipt_chain_head SET next_sequence = 0 WHERE id = 0").run()).toThrowError(
        /must not rewind/,
      );
      expect(() => db.prepare("DELETE FROM receipt_chain_head").run()).toThrowError(/append-only/);
    });
  });

  /**
   * Defect C17. `text()` returned `""` and `integer()` returned `0` for a
   * missing or wrong-typed field, so a malformed payload satisfied every
   * `NOT NULL` and wrote a row recording nothing. An empty `artifact_sha256`
   * compares unequal to every real digest, so a drift check reading it fails
   * open.
   */
  describe("typed projection", () => {
    it("refuses an install receipt with no artifact digest instead of writing an empty one", () => {
      const { db, store } = setup();
      expect(() =>
        store.append({
          kind: "install",
          nodeName: NODE.name,
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { product: "meidoya-node", version: "0.1.0", protocolVersion: 1 },
        }),
      ).toThrowError(/artifactSha256/);
      expect((db.prepare("SELECT COUNT(*) AS n FROM install_receipts").get() as { n: number }).n).toBe(0);
    });

    it("refuses a wrong-typed protocol version instead of writing 0", () => {
      const { store } = setup();
      expect(() =>
        store.append({
          kind: "install",
          nodeName: NODE.name,
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { ...INSTALL, protocolVersion: "one" },
        }),
      ).toThrowError(/protocolVersion/);
    });

    /**
     * The projection insert and the chain row are ONE transaction: a projection
     * that fails must take the `receipts` row with it, or the log holds a
     * receipt no projection describes.
     */
    it("writes no chain row when the projection is rejected", () => {
      const { db, store } = setup();
      expect(() =>
        store.append({
          kind: "install",
          // A node that is not registered: the projection's foreign key rejects
          // it, the chain row must not survive.
          nodeName: "not-registered",
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { ...INSTALL },
        }),
      ).toThrow();
      expect((db.prepare("SELECT COUNT(*) AS n FROM receipts").get() as { n: number }).n).toBe(0);
      expect((db.prepare("SELECT next_sequence AS n FROM receipt_chain_head").get() as { n: number }).n).toBe(0);
    });

    it("keeps the credential_provider enumeration closed", () => {
      const { db } = setup();
      expect(() =>
        db
          .prepare(
            `INSERT INTO credential_receipts (content_hash, node_name, sequence, previous_hash,
               credential_provider, operation, source_ref, guest_path, guest_owner, guest_mode,
               materialized_at, body_json)
             VALUES ('h', @node, 0, NULL, 'not-a-provider', 'sync', 's', '/p', 'o', '0600', 't', '{}')`,
          )
          .run({ node: NODE.name }),
      ).toThrowError(/CHECK constraint failed/);
    });

    it("keeps receipt sequences unique", () => {
      const { db, store } = setup();
      appendInstall(store, 0);
      expect(() =>
        db
          .prepare(
            `INSERT INTO receipts (content_hash, sequence, previous_hash, kind, node_name, created_at, payload_json)
             VALUES ('other-hash', 0, NULL, 'health', @node, 't', '{}')`,
          )
          .run({ node: NODE.name }),
      ).toThrowError(/UNIQUE constraint failed/);
    });
  });

  /**
   * Both node-scoped read primitives ignored their `nodeName` argument and no
   * test bound either of them: deleting the predicate left the suite green.
   */
  describe("node-scoped reads", () => {
    function twoNodes() {
      const db = openMemoryDatabase();
      migrate(db, migrations);
      upsertNode(db, NODE);
      upsertNode(db, { ...NODE, name: "other-node" });
      const store = createSqliteReceiptStore(db);
      store.append({
        kind: "install",
        nodeName: NODE.name,
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { ...INSTALL, version: "0.1.0" },
      });
      store.append({
        kind: "install",
        nodeName: "other-node",
        createdAt: "2026-01-01T00:01:00.000Z",
        payload: { ...INSTALL, version: "9.9.9" },
      });
      return store;
    }

    it("latest() answers about the node it was asked about", () => {
      const store = twoNodes();
      expect(store.latest("install", NODE.name)?.payload["version"]).toBe("0.1.0");
      expect(store.latest("install", "other-node")?.payload["version"]).toBe("9.9.9");
      expect(store.latest("install", "absent-node")).toBeUndefined();
    });

    it("list() filters by node and by kind", () => {
      const store = twoNodes();
      expect(store.list({ nodeName: NODE.name })).toHaveLength(1);
      expect(store.list({ nodeName: "other-node" }).map((receipt) => receipt.nodeName)).toEqual(["other-node"]);
      expect(store.list({ kind: "credential" })).toHaveLength(0);
      expect(store.list()).toHaveLength(2);
    });
  });

  describe("secret guard", () => {
    // An obvious dummy, never printed by any assertion below.
    const SECRET = "dummy-not-a-real-credential-value";

    function guarded() {
      const db = openMemoryDatabase();
      migrate(db, migrations);
      upsertNode(db, NODE);
      return { db, store: createSqliteReceiptStore(db, { secretGuard: createSecretGuard([SECRET]) }) };
    }

    function persistedRows(db: ReturnType<typeof openMemoryDatabase>): number {
      return (db.prepare("SELECT COUNT(*) AS n FROM receipts").get() as { n: number }).n;
    }

    it("refuses a credential value in the receipt PAYLOAD", () => {
      const { db, store } = guarded();
      let refused = false;
      try {
        store.append({
          kind: "credential",
          nodeName: NODE.name,
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { provider: "codex", token: SECRET },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(persistedRows(db)).toBe(0);
    });

    it("refuses a credential value in the receipt ENVELOPE, which no payload guard sees", () => {
      const { db, store } = guarded();
      let refused = false;
      try {
        store.append({
          kind: "provisioning",
          nodeName: NODE.name,
          // A caller-controlled envelope field. Nothing in the payload leaks
          // here, so only the envelope guard can catch it.
          createdAt: `2026-01-01T00:00:00.000Z (${SECRET})`,
          payload: { step: "verify" },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(persistedRows(db)).toBe(0);
    });

    it("refuses an encoded credential value in the payload, not just the raw one", () => {
      const { db, store } = guarded();
      let refused = false;
      try {
        store.append({
          kind: "credential",
          nodeName: NODE.name,
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { provider: "codex", blob: `prefix${Buffer.from(SECRET, "utf8").toString("base64")}` },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(persistedRows(db)).toBe(0);
    });

    /**
     * Defect 18, on the shipped store. `payload_json` is now bound to the very
     * string the guard inspected; the old code guarded one `JSON.stringify` and
     * persisted a second, independent reading of the caller's object.
     */
    it("writes the exact bytes it guarded, even when the payload answers twice", () => {
      const { db, store } = guarded();
      let reads = 0;
      const payload = {} as Record<string, unknown>;
      Object.defineProperty(payload, "note", {
        enumerable: true,
        configurable: true,
        get: () => {
          reads += 1;
          return reads === 1 ? "nothing to see here" : SECRET;
        },
      });

      store.append({
        kind: "provisioning",
        nodeName: NODE.name,
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: payload as never,
      });

      expect(reads).toBe(1);
      const row = db.prepare("SELECT payload_json AS json FROM receipts").get() as { json: string };
      expect(row.json).toBe(JSON.stringify({ note: "nothing to see here" }));
      expect(row.json).not.toContain(SECRET);
      expect(() => store.verify()).not.toThrow();
    });

    /**
     * Defect 20d, on the shipped store. The payload snapshot left the ENVELOPE
     * unprotected: `node_name`, `created_at` and the `body_json` the typed
     * tables carry were all read a second time after the guard had approved the
     * first reading. A getter that answers with the credential on read two put
     * it in the database through a column no payload guard ever inspects.
     */
    it("writes the envelope it guarded, even when a field answers twice", () => {
      const { db, store } = guarded();
      let reads = 0;
      const input = {
        kind: "provisioning",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { step: "verify" },
      } as Record<string, unknown>;
      Object.defineProperty(input, "nodeName", {
        enumerable: true,
        configurable: true,
        get: () => {
          reads += 1;
          return reads === 1 ? NODE.name : SECRET;
        },
      });

      store.append(input as never);

      expect(reads).toBe(1);
      const row = db.prepare("SELECT node_name AS name FROM receipts").get() as { name: string };
      expect(row.name).toBe(NODE.name);
      expect(row.name).not.toContain(SECRET);
      expect(() => store.verify()).not.toThrow();
    });

    /**
     * Defect 19: a four-character credential occurs inside every ISO timestamp
     * this store writes. Matching it against the envelope would refuse every
     * receipt — after the credential had already been written to the guest.
     */
    it("does not become unwritable when the guarded value is four characters long", () => {
      const db = openMemoryDatabase();
      migrate(db, migrations);
      upsertNode(db, NODE);
      const store = createSqliteReceiptStore(db, { secretGuard: createSecretGuard(["2026"]) });

      store.append({
        kind: "credential",
        nodeName: NODE.name,
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: {
          provider: "codex",
          operation: "sync",
          sourceRef: "keychain:codex",
          guestPath: "/home/meidoya/.codex/auth.json",
          owner: "meidoya",
          mode: "0600",
          valueFingerprint: "b".repeat(64),
        },
      });
      expect((db.prepare("SELECT COUNT(*) AS n FROM receipts").get() as { n: number }).n).toBe(1);

      let refused = false;
      try {
        store.append({
          kind: "credential",
          nodeName: NODE.name,
          createdAt: "2026-01-01T00:01:00.000Z",
          payload: { provider: "codex", token: "2026" },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
    });

    /**
     * `assertClean`'s contract: a caller that PERSISTS what it scanned must
     * treat a non-null return as untrusted. This store discarded it. A receipt
     * is permanent and cannot be marked sensitive the way a backup item can, so
     * the only honest response is to refuse. Asserted here as well as on the
     * in-memory store: neither may rest on the other's coverage.
     */
    it("refuses bytes the guard could not finish scanning", () => {
      const db = openMemoryDatabase();
      migrate(db, migrations);
      upsertNode(db, NODE);
      const store = createSqliteReceiptStore(db, {
        secretGuard: {
          assertClean: () => ({
            sink: "receipt:payload",
            budgetExhausted: true,
            streamsSkipped: 0,
            streamsTruncated: 0,
            depthExhausted: false,
            runsTruncated: 0,
          }),
        },
      });

      let refused = false;
      try {
        store.append({ kind: "health", nodeName: NODE.name, createdAt: "t", payload: { detail: "x" } });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(persistedRows(db)).toBe(0);
    });

    it("still persists a receipt that carries only a fingerprint", () => {
      const { db, store } = guarded();
      store.append({
        kind: "credential",
        nodeName: NODE.name,
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: {
          provider: "codex",
          operation: "sync",
          sourceRef: "keychain:codex",
          guestPath: "/home/meidoya/.codex/auth.json",
          owner: "meidoya",
          mode: "0600",
          valueFingerprint: "f".repeat(64),
        },
      });
      expect(persistedRows(db)).toBe(1);
    });
  });
});
