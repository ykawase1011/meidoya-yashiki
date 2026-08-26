import { describe, expect, it } from "vitest";
import { isYashikiError } from "./errors.js";
import { createInMemoryNodeLock } from "./lock.js";
import { fixedClock, type Clock } from "./ports.js";

/** A clock the test moves by hand; the lock must read it on every call. */
function movableClock(startIso: string): Clock & { advance(ms: number): void } {
  let now = new Date(startIso).getTime();
  return {
    now: () => new Date(now),
    advance: (ms: number) => {
      now += ms;
    },
  };
}

/**
 * Every invariant here was unbound: deleting the mutual-exclusion check, the
 * expiry prune or the release fence each left the whole suite green.
 */
describe("in-memory node lock", () => {
  it("refuses a second holder while the lock is live", () => {
    const lock = createInMemoryNodeLock(fixedClock("2026-01-01T00:00:00.000Z"));
    lock.acquire("work-grammarxiv", "run-a", 60_000);

    expect(lock.isHeld("work-grammarxiv")).toBe(true);
    let refused = false;
    try {
      lock.acquire("work-grammarxiv", "run-b", 60_000);
    } catch (error) {
      refused = isYashikiError(error, "NODE_LOCKED");
    }
    expect(refused).toBe(true);
  });

  it("locks one node without locking another", () => {
    const lock = createInMemoryNodeLock(fixedClock("2026-01-01T00:00:00.000Z"));
    lock.acquire("node-a", "run-a", 60_000);
    expect(lock.isHeld("node-b")).toBe(false);
    expect(() => lock.acquire("node-b", "run-b", 60_000)).not.toThrow();
  });

  it("reclaims a lock whose TTL has expired", () => {
    const clock = movableClock("2026-01-01T00:00:00.000Z");
    const lock = createInMemoryNodeLock(clock);
    lock.acquire("work-grammarxiv", "run-a", 1_000);

    expect(lock.isHeld("work-grammarxiv")).toBe(true);
    clock.advance(1_000);
    expect(lock.isHeld("work-grammarxiv")).toBe(false);
    expect(() => lock.acquire("work-grammarxiv", "run-b", 60_000)).not.toThrow();
  });

  it("releases the lock it holds", () => {
    const lock = createInMemoryNodeLock(fixedClock("2026-01-01T00:00:00.000Z"));
    const held = lock.acquire("work-grammarxiv", "run-a", 60_000);
    held.release();
    expect(lock.isHeld("work-grammarxiv")).toBe(false);
  });

  /**
   * Defect C18. Release used to be fenced on the HOLDER string, and holders are
   * not unique — the CLI's is `cli-<pid>` and a PID is reused. Run A's TTL
   * expires, run B acquires under the identical holder string, and A's
   * `finally { release() }` deleted B's LIVE lock in the middle of B's
   * provisioning run.
   */
  it("does not let an expired run's release delete a later run's live lock", () => {
    const clock = movableClock("2026-01-01T00:00:00.000Z");
    const lock = createInMemoryNodeLock(clock);

    const runA = lock.acquire("work-grammarxiv", "cli-4242", 1_000);
    clock.advance(5_000);
    const runB = lock.acquire("work-grammarxiv", "cli-4242", 60_000);

    runA.release();

    expect(lock.isHeld("work-grammarxiv")).toBe(true);
    let refused = false;
    try {
      lock.acquire("work-grammarxiv", "cli-9999", 60_000);
    } catch (error) {
      refused = isYashikiError(error, "NODE_LOCKED");
    }
    expect(refused).toBe(true);

    runB.release();
    expect(lock.isHeld("work-grammarxiv")).toBe(false);
  });

  it("reports the holder that is actually in the way", () => {
    const lock = createInMemoryNodeLock(fixedClock("2026-01-01T00:00:00.000Z"));
    lock.acquire("work-grammarxiv", "run-a", 60_000);
    try {
      lock.acquire("work-grammarxiv", "run-b", 60_000);
      throw new Error("expected the second acquire to fail");
    } catch (error) {
      expect(isYashikiError(error, "NODE_LOCKED") && error.details["holder"]).toBe("run-a");
    }
  });
});
