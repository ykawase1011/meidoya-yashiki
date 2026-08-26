import { describe, expect, it } from "vitest";
import { fixedClock, isYashikiError, type DesiredNodeConfig } from "@meidoya-yashiki/yashiki-core";
import { openMemoryDatabase, type YashikiDatabase } from "./db.js";
import { migrate } from "./migrate.js";
import { migrations } from "./migrations/index.js";
import {
  createSqliteNodeLock,
  getNode,
  listNodes,
  recordHealthResults,
  recordProviderState,
  upsertNode,
} from "./registry.js";

const clock = fixedClock("2026-01-01T00:00:00.000Z");

const NODE: DesiredNodeConfig = {
  name: "work-grammarxiv",
  provider: "lima",
  profile: "lima-trusted",
  platform: "linux",
  arch: "arm64",
  cpus: 8,
  memoryMiB: 16384,
  diskGiB: 100,
  mounts: [{ source: "/Users/tester/Workspace/x", target: "/workspace/x", writable: true }],
  credentials: [],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: "a".repeat(64) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: ["shell"],
};

function freshDb(): YashikiDatabase {
  const db = openMemoryDatabase();
  migrate(db, migrations);
  return db;
}

describe("yashiki registry schema", () => {
  it("applies migrations idempotently", () => {
    const db = freshDb();
    migrate(db, migrations);
    const applied = (db.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get() as { n: number }).n;
    expect(applied).toBe(migrations.length);
  });

  it("contains only infrastructure tables", () => {
    const db = freshDb();
    const tables = (
      db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[]
    ).map((row) => row.name);

    expect(tables).toEqual([
      "backup_operations",
      "credential_receipts",
      "health_results",
      "install_receipts",
      "node_locks",
      "nodes",
      "provider_state",
      "provisioning_runs",
      "receipt_chain_head",
      "receipts",
      "recovery_operations",
      "schema_migrations",
      "schema_migrations_meta",
    ]);

    // 11 section 3: business-domain rows for the Control Plane are not stored here.
    for (const forbidden of ["tasks", "conversations", "messages", "workspaces", "human_gates", "notification_outbox"]) {
      expect(tables).not.toContain(forbidden);
    }
  });

  it("keeps receipts append-only at the storage layer", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    db.prepare(
      `INSERT INTO install_receipts (content_hash, node_name, sequence, previous_hash, product,
                                     node_version, protocol_version, artifact_sha256, installed_at, body_json)
       VALUES ('h1', 'work-grammarxiv', 0, NULL, 'meidoya-node', '0.1.0', 1, 'abc', '2026-01-01T00:00:00.000Z', '{}')`,
    ).run();

    expect(() =>
      db.prepare("UPDATE install_receipts SET node_version = '9.9.9' WHERE content_hash = 'h1'").run(),
    ).toThrowError(/append-only/);
    expect(() => db.prepare("DELETE FROM install_receipts WHERE content_hash = 'h1'").run()).toThrowError(
      /append-only/,
    );
  });

  it("round-trips the desired node config and provider state", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    upsertNode(db, { ...NODE, cpus: 12 }, clock);

    expect(getNode(db, "work-grammarxiv")?.cpus).toBe(12);
    expect(listNodes(db)).toHaveLength(1);
    expect((db.prepare("SELECT version FROM nodes WHERE name = ?").get("work-grammarxiv") as { version: number }).version).toBe(1);

    recordProviderState(
      db,
      {
        ref: { name: "work-grammarxiv", provider: "lima" },
        status: "running",
        cpus: 12,
        memoryMiB: 16384,
        diskGiB: 100,
        mounts: [],
      },
      clock,
    );
    expect(
      (db.prepare("SELECT status FROM provider_state WHERE node_name = ?").get("work-grammarxiv") as { status: string })
        .status,
    ).toBe("running");
  });
});

describe("node registry reads and writes", () => {
  /**
   * `getNode` ignored its `name` predicate and nothing noticed: deleting the
   * `WHERE` clause left the suite green, because every test had exactly one node
   * registered.
   */
  it("getNode answers about the node it was asked about", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    upsertNode(db, { ...NODE, name: "other-node", cpus: 2 }, clock);

    expect(getNode(db, "work-grammarxiv")?.cpus).toBe(8);
    expect(getNode(db, "other-node")?.cpus).toBe(2);
    expect(getNode(db, "absent-node")).toBeUndefined();
  });

  /**
   * Defect C17. `version = nodes.version + 1` was unconditional, and
   * `runtime.ts` calls `upsertNode` on EVERY command — so a read-only
   * `node status` bumped the desired-config version and anything reading that
   * number as "the operator changed something" was reading noise.
   */
  it("bumps the desired-config version only when the desired config changes", () => {
    const db = freshDb();
    const version = (): number =>
      (db.prepare("SELECT version FROM nodes WHERE name = ?").get(NODE.name) as { version: number }).version;

    upsertNode(db, NODE, clock);
    expect(version()).toBe(0);

    upsertNode(db, NODE, clock);
    upsertNode(db, NODE, clock);
    expect(version()).toBe(0);

    upsertNode(db, { ...NODE, cpus: 12 }, clock);
    expect(version()).toBe(1);
  });

  /**
   * Defect C17. `provider_state.provider` had no CHECK and nothing tying it to
   * `nodes.provider`, so a row could say a `lima` node had been observed as
   * `native` — a description of a machine that does not exist, which every
   * reconciliation reading it then draws conclusions from.
   */
  it("refuses provider state that disagrees with the node's provider", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);

    expect(() =>
      recordProviderState(
        db,
        {
          ref: { name: NODE.name, provider: "native" },
          status: "running",
          cpus: 8,
          memoryMiB: 16384,
          diskGiB: 100,
          mounts: [],
        },
        clock,
      ),
    ).toThrowError(/must match nodes.provider/);

    // Anything outside the enumeration disagrees with nodes.provider too, so
    // the same trigger is what refuses it.
    expect(() =>
      db
        .prepare(
          `INSERT INTO provider_state (node_name, provider, external_ref, status, observed_at)
           VALUES (?, 'not-a-provider', NULL, 'running', 0)`,
        )
        .run(NODE.name),
    ).toThrowError(/must match nodes.provider/);
  });

  it("refuses provider state edited to disagree after the fact", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    recordProviderState(
      db,
      { ref: { name: NODE.name, provider: "lima" }, status: "running", cpus: 8, memoryMiB: 16384, diskGiB: 100, mounts: [] },
      clock,
    );

    expect(() =>
      db.prepare("UPDATE provider_state SET provider = 'native' WHERE node_name = ?").run(NODE.name),
    ).toThrowError(/must match nodes.provider/);
  });
});

/**
 * Defect C17. The row id was `${nodeName}:${result.id}:${seconds}`: two runs in
 * the same second collided on the PRIMARY KEY and rolled back the WHOLE batch,
 * and `:` is legal in both halves, so node `a:b` + check `c` and node `a` +
 * check `b:c` produced the same key.
 */
describe("health results", () => {
  it("records two runs in the same second without losing either", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    const results = [{ id: "service", status: "ok", detail: "" }];

    recordHealthResults(db, NODE.name, results, clock);
    recordHealthResults(db, NODE.name, results, clock);

    expect((db.prepare("SELECT COUNT(*) AS n FROM health_results").get() as { n: number }).n).toBe(2);
  });

  it("does not let a colon in a name collide with a colon in a check id", () => {
    const db = freshDb();
    upsertNode(db, { ...NODE, name: "a:b" }, clock);
    upsertNode(db, { ...NODE, name: "a" }, clock);

    recordHealthResults(db, "a:b", [{ id: "c", status: "ok", detail: "" }], clock);
    recordHealthResults(db, "a", [{ id: "b:c", status: "ok", detail: "" }], clock);

    expect((db.prepare("SELECT COUNT(*) AS n FROM health_results").get() as { n: number }).n).toBe(2);
  });

  it("records every result in a batch or none of them", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    expect(() =>
      recordHealthResults(
        db,
        NODE.name,
        [
          { id: "service", status: "ok", detail: "" },
          { id: "heartbeat", status: "not-a-status", detail: "" },
        ],
        clock,
      ),
    ).toThrowError(/CHECK constraint failed/);
    expect((db.prepare("SELECT COUNT(*) AS n FROM health_results").get() as { n: number }).n).toBe(0);
  });
});

describe("sqlite node lock", () => {
  it("prevents concurrent provisioning of the same node", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    const lock = createSqliteNodeLock(db, clock);

    const held = lock.acquire("work-grammarxiv", "run-a", 60_000);
    expect(lock.isHeld("work-grammarxiv")).toBe(true);

    try {
      lock.acquire("work-grammarxiv", "run-b", 60_000);
      throw new Error("expected the second acquire to fail");
    } catch (error) {
      expect(isYashikiError(error, "NODE_LOCKED")).toBe(true);
    }

    held.release();
    expect(lock.isHeld("work-grammarxiv")).toBe(false);
    expect(() => lock.acquire("work-grammarxiv", "run-b", 60_000)).not.toThrow();
  });

  /**
   * Defect C18. The CLI's holder string is `cli-<pid>` and a PID is reused, so
   * fencing release on the HOLDER was no fence: run A acquires, its TTL
   * expires, run B acquires under an identical holder string, and A's
   * `finally { release() }` deleted B's LIVE lock mid-provision. Release is
   * fenced on a per-acquisition token instead.
   */
  it("does not let an expired run's release delete a later run's live lock", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);

    const runA = createSqliteNodeLock(db, fixedClock("2026-01-01T00:00:00.000Z")).acquire(
      "work-grammarxiv",
      "cli-4242",
      1_000,
    );

    // The same PID comes round again after A's lease has expired.
    const later = createSqliteNodeLock(db, fixedClock("2026-01-01T01:00:00.000Z"));
    const runB = later.acquire("work-grammarxiv", "cli-4242", 60_000);

    runA.release();

    expect(later.isHeld("work-grammarxiv")).toBe(true);
    expect(() => later.acquire("work-grammarxiv", "cli-9999", 60_000)).toThrowError(/NODE_LOCKED/);

    runB.release();
    expect(later.isHeld("work-grammarxiv")).toBe(false);
  });

  it("reclaims an expired lock", () => {
    const db = freshDb();
    upsertNode(db, NODE, clock);
    createSqliteNodeLock(db, fixedClock("2026-01-01T00:00:00.000Z")).acquire("work-grammarxiv", "stale", 1_000);

    const later = createSqliteNodeLock(db, fixedClock("2026-01-01T01:00:00.000Z"));
    expect(later.isHeld("work-grammarxiv")).toBe(false);
    expect(() => later.acquire("work-grammarxiv", "run-b", 60_000)).not.toThrow();
  });
});
