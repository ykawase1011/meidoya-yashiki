import Database from "better-sqlite3";

export type YashikiDatabase = Database.Database;

/**
 * `PRAGMA` is a REQUEST, not a command: SQLite answers with the setting that is
 * actually in force and reports nothing when it declines. `journal_mode = WAL`
 * is refused outright on some filesystems (network mounts, and any read-only
 * open), and an unchecked call leaves a database that silently has none of the
 * concurrency properties every caller below assumes. So every pragma is read
 * back, and a database that will not take one is an error rather than a
 * surprise later.
 */
function applyPragma(db: YashikiDatabase, statement: string, name: string, expected: string | number): void {
  db.pragma(statement);
  const observed = db.pragma(name, { simple: true }) as string | number;
  if (observed !== expected) {
    throw new Error(
      `sqlite refused '${statement}': ${name} is ${String(observed)}, expected ${String(expected)}. ` +
        `The registry needs it; continuing would mean running without a guarantee this store assumes.`,
    );
  }
}

/**
 * `foreign_keys = ON` and `busy_timeout = 5000` restate what better-sqlite3
 * currently applies for us. They are stated anyway, and read back, because the
 * guarantees the schema rests on — every `REFERENCES nodes(name)`, and a
 * concurrent writer waiting rather than failing instantly — must not depend on
 * an unversioned default in a driver. Deleting either line therefore cannot turn
 * a test red today; `db.test.ts` asserts the EFFECTIVE settings, so a change on
 * either side is what goes red.
 */
/** Opens the Yashiki local registry (11 section 3). */
export function openDatabase(path: string): YashikiDatabase {
  const db = new Database(path);
  // WAL is ours: without it a reader (`node status`) blocks the writer
  // mid-provision. SQLite's default is `delete`.
  applyPragma(db, "journal_mode = WAL", "journal_mode", "wal");
  applyPragma(db, "foreign_keys = ON", "foreign_keys", 1);
  applyPragma(db, "busy_timeout = 5000", "busy_timeout", 5000);
  return db;
}

export function openMemoryDatabase(): YashikiDatabase {
  const db = new Database(":memory:");
  applyPragma(db, "foreign_keys = ON", "foreign_keys", 1);
  return db;
}
