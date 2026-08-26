import { YashikiError } from "./errors.js";
import type { Clock } from "./ports.js";

export type LockHandle = {
  nodeName: string;
  holder: string;
  acquiredAt: string;
  expiresAt: string;
  release(): void;
};

/** Prevents two provisioning runs from mutating the same node concurrently. */
export interface NodeLock {
  acquire(nodeName: string, holder: string, ttlMs: number): LockHandle;
  isHeld(nodeName: string): boolean;
}

export function lockedError(nodeName: string, holder: string): YashikiError {
  return new YashikiError("NODE_LOCKED", `node '${nodeName}' is locked by '${holder}'`, {
    node: nodeName,
    holder,
  });
}

/**
 * In-memory node lock.
 *
 * FENCE TOKEN. Release is fenced on a token minted per ACQUISITION, not on the
 * holder string. Holders are not unique — the CLI's is `cli-<pid>` and a PID is
 * reused — so comparing holders let a run whose TTL had expired delete the LIVE
 * lock a later run held under the same name, from its own `finally` block, in
 * the middle of that run's provisioning. A token is unique to one acquisition,
 * so a stale handle's release matches nothing.
 */
export function createInMemoryNodeLock(clock: Clock): NodeLock {
  const held = new Map<string, { holder: string; fence: string; expiresAtMs: number }>();
  let fences = 0;

  const prune = (nodeName: string): void => {
    const entry = held.get(nodeName);
    if (entry !== undefined && entry.expiresAtMs <= clock.now().getTime()) held.delete(nodeName);
  };

  return {
    isHeld(nodeName) {
      prune(nodeName);
      return held.has(nodeName);
    },

    acquire(nodeName, holder, ttlMs) {
      prune(nodeName);
      const existing = held.get(nodeName);
      if (existing !== undefined) throw lockedError(nodeName, existing.holder);

      const acquiredAt = clock.now();
      const expiresAtMs = acquiredAt.getTime() + ttlMs;
      fences += 1;
      const fence = `${String(fences)}`;
      held.set(nodeName, { holder, fence, expiresAtMs });

      return {
        nodeName,
        holder,
        acquiredAt: acquiredAt.toISOString(),
        expiresAt: new Date(expiresAtMs).toISOString(),
        release: () => {
          const current = held.get(nodeName);
          if (current?.fence === fence) held.delete(nodeName);
        },
      };
    },
  };
}
