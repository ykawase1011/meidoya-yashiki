import { noopSecretGuard, YashikiError, type SecretGuard } from "@meidoya-yashiki/yashiki-core";
import { canonicalize } from "./canonical.js";
import {
  sealReceipt,
  snapshotReceipt,
  verifyReceiptChain,
  type Receipt,
  type ReceiptInput,
  type ReceiptKind,
} from "./receipt.js";

export type ReceiptFilter = {
  kind?: ReceiptKind;
  nodeName?: string;
};

export interface ReceiptStore {
  append(input: ReceiptInput): Receipt;
  list(filter?: ReceiptFilter): readonly Receipt[];
  latest(kind: ReceiptKind, nodeName: string): Receipt | undefined;
  /**
   * Verifies the whole chain, including its length and head against whatever
   * anchor the store keeps independently of the receipts themselves. A store
   * that keeps none cannot detect a truncated tail; see `verifyReceiptChain`.
   */
  verify(): void;
}

/**
 * A receipt is permanent and cannot be re-scanned later, so bytes the guard
 * could not fully inspect are refused rather than recorded. The backup path can
 * mark an item sensitive and move on; there is no such fallback here — the only
 * choices are "write bytes nobody vouched for into an append-only log" and
 * "refuse".
 */
export function refuseIncompleteScan(guard: SecretGuard, context: string, text: string, region?: "payload" | "metadata"): void {
  const incomplete = guard.assertClean(context, text, region);
  if (incomplete === null) return;
  throw new YashikiError(
    "CREDENTIAL_UNSAFE",
    `the credential guard could not fully scan ${context}; a receipt is permanent, so it is refused rather ` +
      `than recorded (budget exhausted: ${String(incomplete.budgetExhausted)}, streams skipped: ` +
      `${String(incomplete.streamsSkipped)}, streams truncated: ${String(incomplete.streamsTruncated)}, ` +
      `decode rounds exhausted: ${String(incomplete.depthExhausted)}, runs cut by a window: ` +
      `${String(incomplete.runsTruncated)})`,
    { sink: context },
  );
}

export type ReceiptStoreOptions = {
  secretGuard?: SecretGuard;
};

/**
 * Append-only receipt log. There is deliberately no update or delete: a
 * correction is a new receipt, and the hash chain makes an out-of-band edit
 * detectable (Phase 0 DoD: immutable receipt format).
 */
export function createInMemoryReceiptStore(options: ReceiptStoreOptions = {}): ReceiptStore {
  const guard = options.secretGuard ?? noopSecretGuard;
  const receipts: Receipt[] = [];
  // High-water marks, never derived from `receipts.length`: a sequence freed by
  // a removed receipt must never be handed out again, or an erased receipt can
  // be replaced by another one and the chain still verifies. See
  // `receipt_chain_head` in the sqlite schema for the same rule with teeth.
  let appended = 0;
  let headHash: string | null = null;


  return {
    append(input) {
      const sequence = appended;
      const previousHash = headHash;
      // Same split as the sqlite store (packages/store-sqlite): payload and
      // envelope are guarded separately so neither call is a subset of the
      // other, and both stores refuse on exactly the same inputs.
      //
      // The input is read ONCE, here — envelope fields included — and the
      // receipt is sealed from that same read: guarding one view of an object
      // and persisting another is a TOCTOU a `toJSON` or a getter walks
      // straight through, in `kind`/`nodeName`/`createdAt` exactly as much as
      // in the payload.
      const snapshot = snapshotReceipt(input);
      refuseIncompleteScan(guard, "receipt:payload", snapshot.payloadJson);
      refuseIncompleteScan(
        guard,
        "receipt:envelope",
        canonicalize({
          kind: snapshot.kind,
          nodeName: snapshot.nodeName,
          createdAt: snapshot.createdAt,
          sequence,
          previousHash,
        }),
        // Chain links, sequence and an ISO timestamp are structure this store
        // generated. Matching a four-character credential against them would
        // refuse every receipt ever written; see SHORT VALUES on `SecretGuard`.
        "metadata",
      );

      const receipt = sealReceipt(input, previousHash, sequence, snapshot);
      receipts.push(receipt);
      appended += 1;
      headHash = receipt.contentHash;
      return receipt;
    },

    list(filter) {
      return receipts.filter(
        (receipt) =>
          (filter?.kind === undefined || receipt.kind === filter.kind) &&
          (filter?.nodeName === undefined || receipt.nodeName === filter.nodeName),
      );
    },

    latest(kind, nodeName) {
      for (let index = receipts.length - 1; index >= 0; index -= 1) {
        const receipt = receipts[index];
        if (receipt !== undefined && receipt.kind === kind && receipt.nodeName === nodeName) return receipt;
      }
      return undefined;
    },

    verify() {
      // `headHash` is a record of what was APPENDED, tracked as the chain grew,
      // rather than a restatement of whatever the array currently holds. Nothing
      // outside this closure can shorten the array, so the distinction cannot
      // bite here — it bites in the sqlite store, and both stores state the
      // chain's guarantee the same way on purpose.
      verifyReceiptChain(receipts, { headHash });
    },
  };
}

export function requireReceipt(store: ReceiptStore, kind: ReceiptKind, nodeName: string): Receipt {
  const receipt = store.latest(kind, nodeName);
  if (receipt === undefined) {
    throw new YashikiError("NOT_FOUND", `no ${kind} receipt recorded for node '${nodeName}'`, {
      node: nodeName,
      kind,
    });
  }
  return receipt;
}
