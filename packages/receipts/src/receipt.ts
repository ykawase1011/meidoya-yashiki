import { YashikiError } from "@meidoya-yashiki/yashiki-core";
import { canonicalize, contentHash, deepFreeze, type JsonObject } from "./canonical.js";

export const RECEIPT_KINDS = [
  "install",
  "credential",
  "provisioning",
  "health",
  "backup",
  "recovery",
] as const;

export type ReceiptKind = (typeof RECEIPT_KINDS)[number];

export type ReceiptInput = {
  kind: ReceiptKind;
  nodeName: string;
  createdAt: string;
  payload: JsonObject;
};

export type Receipt = ReceiptInput & {
  /** sha256 over the canonical body plus the previous receipt hash. */
  contentHash: string;
  previousHash: string | null;
  sequence: number;
};

/**
 * A whole receipt input read exactly once, as the values that will be stored.
 *
 * A `ReceiptInput` is an object the caller still owns. Reading a field for the
 * secret guard and then reading it AGAIN to seal the receipt reads it twice,
 * and the two reads are not required to agree: a getter, a `toJSON` or a Proxy
 * can hand benign text to the guard and the credential to the store.
 *
 * This covers the ENVELOPE as well as the payload. `kind`, `nodeName` and
 * `createdAt` are caller-controlled too, and they land in `node_name`,
 * `created_at` and `body_json` — so a getter that answers differently on its
 * second read used to put a credential in the database through fields the
 * payload snapshot never touched. Every field is read here, once, and both the
 * guarded bytes and the sealed receipt are derived from these reads alone.
 *
 * A `ReceiptSnapshot` is structurally a `ReceiptInput`, so it can be passed
 * anywhere one is expected — but its fields are plain data.
 */
export type ReceiptSnapshot = {
  readonly kind: ReceiptKind;
  readonly nodeName: string;
  readonly createdAt: string;
  /** Inert data parsed back out of `payloadJson`; no accessors, no `toJSON`. */
  readonly payload: JsonObject;
  /** The exact JSON a sink should guard and persist. */
  readonly payloadJson: string;
};

export function snapshotReceipt(input: ReceiptInput): ReceiptSnapshot {
  // Each field is touched exactly once, and only the results are used below.
  const kind = input.kind;
  const nodeName = input.nodeName;
  const createdAt = input.createdAt;
  const payloadJson = JSON.stringify(input.payload);
  return { kind, nodeName, createdAt, payloadJson, payload: JSON.parse(payloadJson) as JsonObject };
}

export function receiptBody(input: ReceiptInput, previousHash: string | null, sequence: number): JsonObject {
  return {
    kind: input.kind,
    nodeName: input.nodeName,
    createdAt: input.createdAt,
    sequence,
    previousHash,
    payload: input.payload,
  };
}

/**
 * Seals a receipt from ONE read of the input. `snapshot` is threaded in by the
 * stores so the values the secret guard inspected — envelope and payload alike
 * — are the values that get hashed and stored; see `ReceiptSnapshot`. Nothing
 * below reads `input` again.
 */
export function sealReceipt(
  input: ReceiptInput,
  previousHash: string | null,
  sequence: number,
  snapshot: ReceiptSnapshot = snapshotReceipt(input),
): Receipt {
  const payload = deepFreeze(snapshot.payload);
  const sealed = {
    kind: snapshot.kind,
    nodeName: snapshot.nodeName,
    createdAt: snapshot.createdAt,
    payload,
  };
  const receipt: Receipt = {
    ...sealed,
    previousHash,
    sequence,
    contentHash: contentHash(receiptBody(sealed, previousHash, sequence)),
  };
  return deepFreeze(receipt);
}

export function verifyReceipt(receipt: Receipt): boolean {
  const expected = contentHash(
    receiptBody(
      { kind: receipt.kind, nodeName: receipt.nodeName, createdAt: receipt.createdAt, payload: receipt.payload },
      receipt.previousHash,
      receipt.sequence,
    ),
  );
  return expected === receipt.contentHash;
}

/**
 * What a chain cannot prove about itself.
 *
 * `headHash` is the content hash of the last receipt appended — recorded as the
 * chain grew and held somewhere the receipts themselves are not, so that
 * removing receipts cannot also remove the record of them. In the sqlite store
 * that is the `receipt_chain_head` row; an exported or restored chain must carry
 * one alongside it.
 *
 * ONE FIELD, deliberately. A count was carried here too and was pure
 * redundancy: `sequence` is inside the hashed body and the walk requires it to
 * be contiguous from 0, so the head hash already pins the length — a chain one
 * receipt shorter ends on a different hash, and an empty one ends on `null`.
 * A field no input can make fail is a field no test can bind.
 */
export type ReceiptChainAnchor = {
  headHash: string | null;
};

/** The anchor a chain currently claims for itself; persist or export alongside it. */
export function receiptChainAnchor(receipts: readonly Receipt[]): ReceiptChainAnchor {
  return { headHash: receipts[receipts.length - 1]?.contentHash ?? null };
}

/**
 * Append-only chain check.
 *
 * WITHOUT an `anchor` this detects any edit, any reorder, any insertion, and any
 * removal EXCEPT the removal of a suffix. That exception is not a detail: after
 * truncating a three-receipt chain, `[r0, r1]`, `[r0]` and `[]` each pass, and
 * they pass because a prefix of a valid chain is a valid chain — no forward walk
 * from sequence 0 can tell one from a chain that was always that long. This
 * function used to claim "any edit, reorder or deletion", which was false in
 * exactly the case where the deletion is the easiest to perform.
 *
 * WITH an `anchor` — the head hash, recorded independently as the chain grew —
 * the tail is covered too, and the guarantee is the one the doc-comment used to
 * claim.
 *
 * The in-process append-only triggers do not help here: this is public API, run
 * over receipts read from exports, backups and restored database files where no
 * trigger applies.
 */
export function verifyReceiptChain(receipts: readonly Receipt[], anchor?: ReceiptChainAnchor): void {
  let previousHash: string | null = null;
  let expectedSequence = 0;

  for (const receipt of receipts) {
    if (receipt.sequence !== expectedSequence) {
      throw new YashikiError("RECEIPT_TAMPERED", "receipt sequence is not contiguous", {
        expected: expectedSequence,
        actual: receipt.sequence,
      });
    }
    if (receipt.previousHash !== previousHash) {
      throw new YashikiError("RECEIPT_TAMPERED", "receipt chain link does not match the previous receipt", {
        sequence: receipt.sequence,
      });
    }
    if (!verifyReceipt(receipt)) {
      throw new YashikiError("RECEIPT_TAMPERED", "receipt content hash does not match its body", {
        sequence: receipt.sequence,
      });
    }
    previousHash = receipt.contentHash;
    expectedSequence += 1;
  }

  if (anchor === undefined) return;

  if (previousHash !== anchor.headHash) {
    throw new YashikiError("RECEIPT_TAMPERED", "receipt chain head does not match the recorded head", {
      sequence: expectedSequence - 1,
    });
  }
}

export function renderReceipt(receipt: Receipt): string {
  return canonicalize(receiptBody(receipt, receipt.previousHash, receipt.sequence));
}
