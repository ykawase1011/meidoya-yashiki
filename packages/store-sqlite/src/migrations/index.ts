import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { migrationChecksum, type Migration } from "../migrate.js";

const here = dirname(fileURLToPath(import.meta.url));

function sql(file: string): string {
  return readFileSync(join(here, file), "utf8");
}

/**
 * The SQL is read from disk (`dist/migrations/` in a build), so it can drift
 * from the file this database was built with. Every migration therefore carries
 * the hash of `version|name|sql`, recorded in the ledger on apply and re-checked
 * on every later boot; see `migrate.ts`.
 *
 * The file is read ONCE, and both the hash and the SQL that `up()` executes come
 * from that single read — hashing one reading of a file and executing another is
 * a TOCTOU that makes the checksum attest to nothing.
 */
function fileMigration(version: number, name: string, file: string): Migration {
  const text = sql(file);
  return {
    version,
    name,
    checksum: migrationChecksum(version, name, text),
    up: (db) => db.exec(text),
  };
}

export const migrations: readonly Migration[] = [
  fileMigration(1, "yashiki_registry", "0001_yashiki_registry.sql"),
];
