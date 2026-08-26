import { describe, expect, it } from "vitest";
import { openMemoryDatabase, type YashikiDatabase } from "./db.js";
import { migrate, migrationChecksum, type Migration } from "./migrate.js";
import { migrations } from "./migrations/index.js";

function table(version: number, name: string): Migration {
  const sql = `CREATE TABLE t${String(version)} (id INTEGER PRIMARY KEY);`;
  return { version, name, checksum: migrationChecksum(version, name, sql), up: (db) => db.exec(sql) };
}

function applied(db: YashikiDatabase): number[] {
  return (db.prepare("SELECT version FROM schema_migrations ORDER BY version").all() as { version: number }[]).map(
    (row) => row.version,
  );
}

function tables(db: YashikiDatabase): string[] {
  return (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]).map(
    (row) => row.name,
  );
}

describe("migration runner", () => {
  it("applies and records every migration", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one"), table(2, "two")]);
    expect(applied(db)).toEqual([1, 2]);
    expect(tables(db)).toEqual(expect.arrayContaining(["t1", "t2"]));
  });

  it("is idempotent", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one")]);
    migrate(db, [table(1, "one")]);
    expect(applied(db)).toEqual([1]);
  });

  /**
   * Defect C5. `pending = version > MAX(version)` skipped a migration numbered
   * below the head FOREVER, with no error and no trace: apply [1, 3], then run
   * [1, 2, 3], and version 2 never ran while the ledger read [1, 3] and the
   * runner reported success.
   */
  it("refuses a ledger that skipped a version instead of silently leaving it unapplied", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one"), table(3, "three")]);
    expect(applied(db)).toEqual([1, 3]);

    expect(() => migrate(db, [table(1, "one"), table(2, "two"), table(3, "three")])).toThrowError(
      /not contiguous/,
    );
    expect(tables(db)).not.toContain("t2");
  });

  it("refuses a ledger row that was deleted below the head", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one"), table(2, "two"), table(3, "three")]);
    db.prepare("DELETE FROM schema_migrations WHERE version = 2").run();

    expect(() => migrate(db, [table(1, "one"), table(2, "two"), table(3, "three")])).toThrowError(
      /not contiguous/,
    );
  });

  /**
   * Defect C5. The SQL is read from `dist/migrations/*.sql`, so it genuinely can
   * drift; nothing recorded what had run, so rewriting an applied migration was
   * undetectable.
   */
  it("detects an already-applied migration whose SQL was rewritten", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one")]);

    const rewritten: Migration = {
      version: 1,
      name: "one",
      checksum: migrationChecksum(1, "one", "CREATE TABLE t1 (id INTEGER PRIMARY KEY, extra TEXT);"),
      up: (database) => database.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, extra TEXT);"),
    };
    expect(() => migrate(db, [rewritten])).toThrowError(/applied from different SQL/);
  });

  /** The recorded `name` was written on apply and never once compared back. */
  it("detects an already-applied migration that was renamed", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one")]);
    const sql = "CREATE TABLE t1 (id INTEGER PRIMARY KEY);";
    expect(() =>
      migrate(db, [{ version: 1, name: "renamed", checksum: migrationChecksum(1, "one", sql), up: () => undefined }]),
    ).toThrowError(/ledger name/);
  });

  it("refuses to run an older build against a newer schema", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one"), table(2, "two")]);
    expect(() => migrate(db, [table(1, "one")])).toThrowError(/newer than this build/);
  });

  /**
   * "NULL checksum means unknown, so skip it" was a self-service exemption:
   * dropping the column made `ensureChecksumColumn` re-add it all-NULL and the
   * runner forgot every hash it had recorded. The watermark, decided the first
   * time a checksumming runner sees the database, turns that into an error.
   */
  it("refuses a checksum that was erased after it had been recorded", () => {
    const db = openMemoryDatabase();
    migrate(db, [table(1, "one")]);
    db.prepare("UPDATE schema_migrations SET checksum = NULL WHERE version = 1").run();

    expect(() => migrate(db, [table(1, "one")])).toThrowError(/no recorded checksum/);
  });

  it("accepts a ledger written by the pre-checksum runner, once, and never again after that", () => {
    const db = openMemoryDatabase();
    // Exactly what the old runner left behind: no checksum column at all.
    db.exec(`
      CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);
      INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, 'one', 0);
      CREATE TABLE t1 (id INTEGER PRIMARY KEY);
    `);

    expect(() => migrate(db, [table(1, "one"), table(2, "two")])).not.toThrow();
    expect(applied(db)).toEqual([1, 2]);

    // Version 2 was applied WITH a checksum, so erasing that one is not history.
    db.prepare("UPDATE schema_migrations SET checksum = NULL WHERE version = 2").run();
    expect(() => migrate(db, [table(1, "one"), table(2, "two")])).toThrowError(/no recorded checksum/);
  });

  /**
   * One transaction for the whole run: a failure part way must leave the
   * database where it started, not at an intermediate version no build
   * corresponds to. Per-migration transactions committed version 1 and left the
   * ledger claiming it.
   */
  it("rolls the WHOLE run back when a later migration fails", () => {
    const db = openMemoryDatabase();
    const boom: Migration = {
      version: 2,
      name: "boom",
      checksum: "sha256:boom",
      up: () => {
        throw new Error("migration 2 exploded");
      },
    };

    expect(() => migrate(db, [table(1, "one"), boom])).toThrowError(/exploded/);
    expect(tables(db)).not.toContain("t1");
    expect(tables(db)).not.toContain("schema_migrations");
  });

  it("carries a checksum for every shipped migration", () => {
    for (const migration of migrations) expect(migration.checksum).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("detects a rewritten 0001_yashiki_registry.sql", () => {
    const db = openMemoryDatabase();
    migrate(db, migrations);
    const drifted = migrations.map((migration) => ({ ...migration, checksum: `${migration.checksum ?? ""}-drifted` }));
    expect(() => migrate(db, drifted)).toThrowError(/applied from different SQL/);
  });
});
