import { createHash } from "node:crypto";
import type { YashikiDatabase } from "./db.js";

export type Migration = {
  /** Monotonically increasing, e.g. 1, 2, 3. */
  version: number;
  name: string;
  /**
   * Hash of this migration's IDENTITY — `version|name|sql` — recorded in the
   * ledger on apply and re-checked on every later boot.
   *
   * The SQL is read from `dist/migrations/*.sql` at `up()` time, so it genuinely
   * can drift from what a database was built with: a rewritten file used to be
   * completely undetectable, because the ledger recorded only a number and a
   * name and never compared either back.
   *
   * Optional only so a test can hand-build a `Migration`; the real registry
   * always supplies one via `migrationChecksum`.
   */
  checksum?: string;
  up: (db: YashikiDatabase) => void;
};

/** Hash of a migration's identity tuple: version, ledger name and SQL. */
export function migrationChecksum(version: number, name: string, sql: string): string {
  return `sha256:${createHash("sha256").update(`${String(version)}|${name}|${sql}`).digest("hex")}`;
}

/** Ledger bookkeeping that belongs to the runner, not to a numbered migration. */
const META_TABLE = "schema_migrations_meta";
const PRE_CHECKSUM_WATERMARK = "pre_checksum_max_version";

export function migrationChecksumMismatchMessage(
  version: number,
  recordedName: string,
  recordedChecksum: string,
  currentChecksum: string,
): string {
  return (
    `migration ${String(version)} (${recordedName}) was applied from different SQL than this build carries: ` +
    `recorded ${recordedChecksum}, current ${currentChecksum}. An already-applied migration was edited in ` +
    `place; a migration must never be changed after it has run anywhere.`
  );
}

export function migrationNameMismatchMessage(
  version: number,
  recordedName: string,
  currentName: string,
): string {
  return (
    `migration ${String(version)} was applied under the ledger name '${recordedName}', but this build calls ` +
    `it '${currentName}'. The recorded name is evidence about which SQL ran; renaming a released migration ` +
    `destroys that evidence.`
  );
}

export function migrationMissingRowMessage(version: number, maxRecorded: number): string {
  return (
    `migration ledger is not contiguous: version ${String(version)} is not recorded, but version ` +
    `${String(maxRecorded)} is. A migration below the head is skipped forever and in silence. Restore the ` +
    `ledger or recreate the database.`
  );
}

export function migrationDowngradeMessage(maxRecorded: number, maxKnown: number): string {
  return (
    `database schema version ${String(maxRecorded)} is newer than this build, which carries ` +
    `${String(maxKnown)} migration(s). An older build against a newer schema reads and writes a shape it ` +
    `does not know; refusing to start.`
  );
}

export function migrationChecksumErasedMessage(version: number, watermark: number): string {
  return (
    `migration ${String(version)} has no recorded checksum, but this database was first seen by a ` +
    `checksumming runner at version ${String(watermark)}, so version ${String(version)} was applied WITH ` +
    `one. The checksum column has been dropped or cleared, which erases the only record of what ran.`
  );
}

/**
 * Adds the `checksum` column to a ledger created by the pre-checksum runner.
 * `CREATE TABLE IF NOT EXISTS` cannot widen an existing table, and this table is
 * the runner's own bookkeeping rather than a numbered migration.
 */
function ensureChecksumColumn(db: YashikiDatabase): void {
  const columns = db.prepare("PRAGMA table_info(schema_migrations)").all() as { name: string }[];
  if (!columns.some((column) => column.name === "checksum")) {
    db.exec("ALTER TABLE schema_migrations ADD COLUMN checksum TEXT");
  }
}

/**
 * The highest version this database may hold a NULL checksum for, decided ONCE
 * — the first time a checksumming runner opens it — and remembered thereafter.
 *
 * Without it, "NULL means unknown, so skip it" is a self-service exemption:
 * `ALTER TABLE schema_migrations DROP COLUMN checksum` makes
 * `ensureChecksumColumn` re-add it all-NULL, and the runner forgets every hash
 * it ever recorded. With it, a NULL at or below the watermark is genuinely
 * unverifiable history and a NULL above it is an erasure, which is loud.
 */
function preChecksumWatermark(db: YashikiDatabase): number {
  db.exec(`CREATE TABLE IF NOT EXISTS ${META_TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
  const existing = db.prepare(`SELECT value FROM ${META_TABLE} WHERE key = ?`).get(PRE_CHECKSUM_WATERMARK) as
    | { value: string }
    | undefined;
  if (existing !== undefined) return Number(existing.value);

  const observed =
    (
      db.prepare("SELECT MAX(version) AS v FROM schema_migrations WHERE checksum IS NULL").get() as {
        v: number | null;
      }
    ).v ?? 0;
  db.prepare(`INSERT INTO ${META_TABLE} (key, value) VALUES (?, ?)`).run(
    PRE_CHECKSUM_WATERMARK,
    String(observed),
  );
  return observed;
}

/**
 * Fails closed when the ledger and this build disagree about what was applied.
 *
 * Four separate things, because each is a distinct way the old runner was blind:
 *
 *   1. the identity hash of every checksummed row — a rewritten `.sql` file used
 *      to be undetectable;
 *   2. the recorded NAME — written on apply and never once compared back;
 *   3. that no NULL checksum appears above the pre-checksum watermark, so
 *      dropping the column is an error rather than an amnesty;
 *   4. that versions 1..MAX are all present. The runner used to apply everything
 *      above `MAX(version)`, so a ledger of `[1, 3]` skipped version 2 forever,
 *      with no error and no trace.
 */
function verifyLedger(db: YashikiDatabase, migrations: readonly Migration[], watermark: number): void {
  const applied = db.prepare("SELECT version, name, checksum FROM schema_migrations").all() as {
    version: number;
    name: string;
    checksum: string | null;
  }[];
  const byVersion = new Map(migrations.map((migration) => [migration.version, migration]));

  for (const row of applied) {
    if (row.checksum === null) {
      if (row.version > watermark) throw new Error(migrationChecksumErasedMessage(row.version, watermark));
      continue;
    }
    const migration = byVersion.get(row.version);
    if (migration === undefined) continue;
    if (migration.name !== row.name) {
      throw new Error(migrationNameMismatchMessage(row.version, row.name, migration.name));
    }
    if (migration.checksum === undefined || migration.checksum === row.checksum) continue;
    throw new Error(
      migrationChecksumMismatchMessage(row.version, row.name, row.checksum, migration.checksum),
    );
  }

  const recorded = new Set(applied.map((row) => row.version));
  const maxRecorded = applied.reduce((max, row) => Math.max(max, row.version), 0);
  for (let version = 1; version <= maxRecorded; version += 1) {
    if (!recorded.has(version)) throw new Error(migrationMissingRowMessage(version, maxRecorded));
  }

  const maxKnown = migrations.reduce((max, migration) => Math.max(max, migration.version), 0);
  if (maxRecorded > maxKnown) throw new Error(migrationDowngradeMessage(maxRecorded, maxKnown));
}

/**
 * Applies every migration this build carries that the ledger does not record,
 * in ascending order, inside ONE `BEGIN IMMEDIATE` transaction.
 *
 * PENDING IS "NOT RECORDED", NOT "ABOVE THE HEAD". Selecting `version >
 * MAX(version)` is what made a ledger of `[1, 3]` skip version 2 forever — no
 * error, no log line, and a database permanently missing a table. The
 * contiguity check in `verifyLedger` is what actually refuses that ledger, and
 * it is the one under test; this selection is the same statement said in the
 * form that cannot mean anything else, so that relaxing the check later does not
 * silently restore the skip.
 *
 * IMMEDIATE, and covering the ledger read, because a deferred `BEGIN` takes no
 * write lock until its first write: two processes both read the ledger under a
 * shared lock, both compute the same pending list, and the loser then either
 * re-applies a migration or dies on `database is locked` — SQLite will not run
 * the busy handler for a deferred transaction that has already read. Taking the
 * write lock BEFORE the read makes the loser wait, re-read a current ledger and
 * find nothing to do.
 *
 * ONE transaction for the whole run, not one per migration, so a failure part
 * way leaves the database exactly where it started rather than at an
 * intermediate version no build corresponds to.
 */
export function migrate(db: YashikiDatabase, migrations: readonly Migration[]): void {
  const run = db.transaction(() => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at INTEGER NOT NULL,
        checksum TEXT
      );
    `);
    ensureChecksumColumn(db);
    const watermark = preChecksumWatermark(db);
    verifyLedger(db, migrations, watermark);

    const recorded = new Set(
      (db.prepare("SELECT version FROM schema_migrations").all() as { version: number }[]).map(
        (row) => row.version,
      ),
    );
    const pending = [...migrations]
      .filter((migration) => !recorded.has(migration.version))
      .sort((a, b) => a.version - b.version);

    const record = db.prepare(
      "INSERT INTO schema_migrations (version, name, applied_at, checksum) VALUES (?, ?, unixepoch(), ?)",
    );
    for (const migration of pending) {
      migration.up(db);
      record.run(migration.version, migration.name, migration.checksum ?? null);
    }
  });
  run.immediate();
}
