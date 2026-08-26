import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { openDatabase, openMemoryDatabase } from "./db.js";
import { migrate } from "./migrate.js";
import { migrations } from "./migrations/index.js";

const created: string[] = [];

function tempDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "yashiki-db-"));
  created.push(dir);
  return join(dir, "registry.sqlite");
}

afterEach(() => {
  while (created.length > 0) rmSync(created.pop() as string, { recursive: true, force: true });
});

/**
 * Nothing in this suite used to open a FILE-BACKED database, so every pragma
 * `openDatabase` sets was unverified: deleting all three left the suite green.
 * They are not decoration — WAL is what stops a reader blocking the writer
 * mid-provision, and `busy_timeout` is what makes a concurrent writer wait
 * rather than fail instantly.
 */
describe("openDatabase", () => {
  it("puts the file-backed registry in WAL mode", () => {
    const db = openDatabase(tempDbPath());
    try {
      expect(db.pragma("journal_mode", { simple: true })).toBe("wal");
    } finally {
      db.close();
    }
  });

  it("waits for a concurrent writer instead of failing instantly", () => {
    const db = openDatabase(tempDbPath());
    try {
      expect(db.pragma("busy_timeout", { simple: true })).toBe(5000);
    } finally {
      db.close();
    }
  });

  it("enforces foreign keys", () => {
    const path = tempDbPath();
    const db = openDatabase(path);
    try {
      expect(db.pragma("foreign_keys", { simple: true })).toBe(1);
      migrate(db, migrations);
      expect(() =>
        db
          .prepare(
            `INSERT INTO health_results (id, node_name, check_id, status, detail, checked_at)
             VALUES ('h', 'no-such-node', 'c', 'ok', '', 0)`,
          )
          .run(),
      ).toThrowError(/FOREIGN KEY/);
    } finally {
      db.close();
    }
  });
});

describe("openMemoryDatabase", () => {
  /**
   * Foreign keys are OFF by default in SQLite, so without this pragma every
   * `REFERENCES nodes(name)` in the schema is inert — including the one that
   * stops a receipt being projected for a node that does not exist.
   */
  it("enforces foreign keys", () => {
    const db = openMemoryDatabase();
    expect(db.pragma("foreign_keys", { simple: true })).toBe(1);
    migrate(db, migrations);
    expect(() =>
      db
        .prepare(
          `INSERT INTO health_results (id, node_name, check_id, status, detail, checked_at)
           VALUES ('h', 'no-such-node', 'c', 'ok', '', 0)`,
        )
        .run(),
    ).toThrowError(/FOREIGN KEY/);
  });
});
