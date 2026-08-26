import {
  lockedError,
  systemClock,
  YashikiError,
  type Clock,
  type DesiredNodeConfig,
  type NodeInspection,
  type NodeLock,
} from "@meidoya-yashiki/yashiki-core";
import { createHash, randomUUID } from "node:crypto";
import type { YashikiDatabase } from "./db.js";

function hashConfig(config: DesiredNodeConfig): string {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}

export type NodeRow = {
  name: string;
  provider: string;
  desired_config_json: string;
  desired_config_hash: string;
  version: number;
};

export function upsertNode(db: YashikiDatabase, config: DesiredNodeConfig, clock: Clock = systemClock): void {
  const now = Math.floor(clock.now().getTime() / 1000);
  // `version` is the version of the DESIRED CONFIG, so it moves when the config
  // does and not when somebody looks at it. `runtime.ts` calls this on EVERY
  // command, so the unconditional `nodes.version + 1` meant a read-only
  // `node status` bumped the desired-config version — anything reading that
  // number as "the operator changed something" was reading noise.
  db.prepare(
    `INSERT INTO nodes (name, provider, profile, platform, arch, cpus, memory_mib, disk_gib,
                        desired_config_json, desired_config_hash, version, created_at, updated_at)
     VALUES (@name, @provider, @profile, @platform, @arch, @cpus, @memory_mib, @disk_gib,
             @config_json, @config_hash, 0, @now, @now)
     ON CONFLICT (name) DO UPDATE SET
       provider = excluded.provider,
       profile = excluded.profile,
       platform = excluded.platform,
       arch = excluded.arch,
       cpus = excluded.cpus,
       memory_mib = excluded.memory_mib,
       disk_gib = excluded.disk_gib,
       desired_config_json = excluded.desired_config_json,
       desired_config_hash = excluded.desired_config_hash,
       version = CASE
         WHEN nodes.desired_config_hash = excluded.desired_config_hash THEN nodes.version
         ELSE nodes.version + 1
       END,
       updated_at = excluded.updated_at`,
  ).run({
    name: config.name,
    provider: config.provider,
    profile: config.profile,
    platform: config.platform,
    arch: config.arch,
    cpus: config.cpus,
    memory_mib: config.memoryMiB,
    disk_gib: config.diskGiB,
    config_json: JSON.stringify(config),
    config_hash: hashConfig(config),
    now,
  });
}

export function getNode(db: YashikiDatabase, name: string): DesiredNodeConfig | undefined {
  const row = db.prepare("SELECT desired_config_json FROM nodes WHERE name = ?").get(name) as
    | { desired_config_json: string }
    | undefined;
  return row === undefined ? undefined : (JSON.parse(row.desired_config_json) as DesiredNodeConfig);
}

export function listNodes(db: YashikiDatabase): DesiredNodeConfig[] {
  return (db.prepare("SELECT desired_config_json FROM nodes ORDER BY name").all() as {
    desired_config_json: string;
  }[]).map((row) => JSON.parse(row.desired_config_json) as DesiredNodeConfig);
}

export function recordProviderState(
  db: YashikiDatabase,
  inspection: NodeInspection,
  clock: Clock = systemClock,
): void {
  db.prepare(
    `INSERT INTO provider_state (node_name, provider, external_ref, status,
                                 observed_cpus, observed_memory_mib, observed_disk_gib, observed_at)
     VALUES (@node, @provider, @ref, @status, @cpus, @memory, @disk, @at)
     ON CONFLICT (node_name) DO UPDATE SET
       provider = excluded.provider,
       external_ref = excluded.external_ref,
       status = excluded.status,
       observed_cpus = excluded.observed_cpus,
       observed_memory_mib = excluded.observed_memory_mib,
       observed_disk_gib = excluded.observed_disk_gib,
       observed_at = excluded.observed_at`,
  ).run({
    node: inspection.ref.name,
    provider: inspection.ref.provider,
    ref: inspection.ref.name,
    status: inspection.status,
    cpus: inspection.cpus,
    memory: inspection.memoryMiB,
    disk: inspection.diskGiB,
    at: Math.floor(clock.now().getTime() / 1000),
  });
}

/**
 * Records one health run's results.
 *
 * The row id is a fresh UUID, not `node:check:seconds`. That key was two
 * separate bugs in one string: two runs within the same second collided on the
 * PRIMARY KEY and rolled back the WHOLE batch, so the faster a fleet was
 * checked the more of its results vanished; and `:` is legal in both a node name
 * and a check id, so node `a:b` + check `c` and node `a` + check `b:c` produced
 * the same key and one silently displaced the other. Nothing about a health
 * observation is a natural key — the same check on the same node at the same
 * second is a genuinely new observation, not a duplicate — so it gets a
 * synthetic one.
 */
export function recordHealthResults(
  db: YashikiDatabase,
  nodeName: string,
  results: readonly { id: string; status: string; detail: string }[],
  clock: Clock = systemClock,
): void {
  const at = Math.floor(clock.now().getTime() / 1000);
  const insert = db.prepare(
    "INSERT INTO health_results (id, node_name, check_id, status, detail, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
  );
  const run = db.transaction(() => {
    for (const result of results) {
      insert.run(randomUUID(), nodeName, result.id, result.status, result.detail, at);
    }
  });
  run.immediate();
}

/**
 * SQLite-backed node lock. The PRIMARY KEY on node_name is the mutual-exclusion
 * primitive: a second holder's INSERT conflicts instead of silently winning.
 *
 * FENCE TOKEN. Release is fenced on a token minted per ACQUISITION, not on the
 * holder string. The CLI's holder is `cli-<pid>` and a PID is reused, so
 * fencing on the holder was no fence at all: run A acquires, its TTL expires,
 * run B acquires under an identical holder string, and A's
 * `finally { release() }` deleted B's LIVE lock in the middle of B's
 * provisioning run. With a token, a stale handle's release matches nothing and
 * does nothing.
 */
export function createSqliteNodeLock(db: YashikiDatabase, clock: Clock = systemClock): NodeLock {
  const nowSeconds = (): number => Math.floor(clock.now().getTime() / 1000);

  const pruneExpired = (nodeName: string): void => {
    db.prepare("DELETE FROM node_locks WHERE node_name = ? AND expires_at <= ?").run(nodeName, nowSeconds());
  };

  return {
    isHeld(nodeName) {
      pruneExpired(nodeName);
      return db.prepare("SELECT 1 FROM node_locks WHERE node_name = ?").get(nodeName) !== undefined;
    },

    acquire(nodeName, holder, ttlMs) {
      const fence = randomUUID();
      // Prune and insert atomically: between a separate prune and insert, another
      // run can take the lock the prune just freed, and this one's INSERT then
      // fails with `NODE_LOCKED` naming a holder that did nothing wrong.
      const acquire = db.transaction((): { acquiredAt: number; expiresAt: number } => {
        pruneExpired(nodeName);
        const acquiredAt = nowSeconds();
        const expiresAt = acquiredAt + Math.ceil(ttlMs / 1000);
        const inserted = db
          .prepare(
            `INSERT INTO node_locks (node_name, holder, fence, acquired_at, expires_at)
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (node_name) DO NOTHING`,
          )
          .run(nodeName, holder, fence, acquiredAt, expiresAt);

        if (inserted.changes === 0) {
          const current = db.prepare("SELECT holder FROM node_locks WHERE node_name = ?").get(nodeName) as
            | { holder: string }
            | undefined;
          throw lockedError(nodeName, current?.holder ?? "unknown");
        }
        return { acquiredAt, expiresAt };
      });
      const { acquiredAt, expiresAt } = acquire.immediate();

      return {
        nodeName,
        holder,
        acquiredAt: new Date(acquiredAt * 1000).toISOString(),
        expiresAt: new Date(expiresAt * 1000).toISOString(),
        release: () => {
          // Fenced on the per-acquisition token: a handle can only ever delete
          // the lock it took, never a later holder's live one.
          db.prepare("DELETE FROM node_locks WHERE node_name = ? AND fence = ?").run(nodeName, fence);
        },
      };
    },
  };
}

export function assertNodeExists(db: YashikiDatabase, name: string): void {
  if (getNode(db, name) === undefined) {
    throw new YashikiError("NOT_FOUND", `node '${name}' is not registered`, { node: name });
  }
}
