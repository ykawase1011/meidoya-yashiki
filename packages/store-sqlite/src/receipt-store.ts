import { noopSecretGuard, YashikiError, type SecretGuard } from "@meidoya-yashiki/yashiki-core";
import {
  canonicalize,
  deepFreeze,
  refuseIncompleteScan,
  sealReceipt,
  snapshotReceipt,
  verifyReceiptChain,
  type JsonObject,
  type Receipt,
  type ReceiptChainAnchor,
  type ReceiptFilter,
  type ReceiptKind,
  type ReceiptStore,
} from "@meidoya-yashiki/receipts";
import type { YashikiDatabase } from "./db.js";

type ChainHead = { next_sequence: number; head_hash: string | null };

/**
 * The chain's independently-kept anchor: how many receipts were appended, and
 * the hash of the last one. Held in its own table, protected by triggers against
 * being rewound or deleted, so that removing receipts does not also remove the
 * record that they existed.
 */
function readChainHead(db: YashikiDatabase): ChainHead {
  const head = db.prepare("SELECT next_sequence, head_hash FROM receipt_chain_head WHERE id = 0").get() as
    | ChainHead
    | undefined;
  if (head === undefined) {
    throw new YashikiError(
      "RECEIPT_TAMPERED",
      "the receipt chain head anchor is missing; without it a truncated chain is indistinguishable from a short one",
    );
  }
  return head;
}

/**
 * The anchor and the table must describe the same chain. They only disagree if
 * rows were removed behind the append-only triggers — a restored or hand-edited
 * database file — and appending onto that would extend a chain the store never
 * recorded.
 */
function assertChainHeadMatchesTable(db: YashikiDatabase, head: ChainHead): void {
  const observed = db.prepare("SELECT COUNT(*) AS n, MAX(sequence) AS max FROM receipts").get() as {
    n: number;
    max: number | null;
  };
  const expectedMax = head.next_sequence === 0 ? null : head.next_sequence - 1;
  if (observed.n !== head.next_sequence || observed.max !== expectedMax) {
    throw new YashikiError("RECEIPT_TAMPERED", "the receipts table disagrees with the recorded chain head", {
      recorded: head.next_sequence,
      rows: observed.n,
    });
  }
}

type ReceiptRow = {
  content_hash: string;
  sequence: number;
  previous_hash: string | null;
  kind: ReceiptKind;
  node_name: string;
  created_at: string;
  payload_json: string;
};

function toReceipt(row: ReceiptRow): Receipt {
  return deepFreeze({
    kind: row.kind,
    nodeName: row.node_name,
    createdAt: row.created_at,
    payload: JSON.parse(row.payload_json) as JsonObject,
    previousHash: row.previous_hash,
    sequence: row.sequence,
    contentHash: row.content_hash,
  });
}

/**
 * A projected column is EVIDENCE, so a missing or wrong-typed field is refused
 * rather than defaulted.
 *
 * These used to return `""` and `0`, which satisfied every `NOT NULL` and wrote
 * `{product: '', protocol_version: 0, artifact_sha256: ''}` for a malformed
 * payload. An empty `artifact_sha256` compares unequal to every real digest, so
 * a drift check reading it FAILS OPEN: it reports a mismatch it cannot explain,
 * or — worse, wherever the comparison is "is this the artifact we recorded" —
 * silently answers about a row that records nothing at all.
 */
function text(kind: ReceiptKind, payload: JsonObject, key: string): string {
  const value = payload[key];
  if (typeof value !== "string" || value === "") {
    throw new YashikiError(
      "VERIFICATION_FAILED",
      `a ${kind} receipt must carry a non-empty string '${key}'; it is projected into a column other ` +
        `checks compare against, and a defaulted value there fails open`,
      { kind, field: key },
    );
  }
  return value;
}

function integer(kind: ReceiptKind, payload: JsonObject, key: string): number {
  const value = payload[key];
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new YashikiError(
      "VERIFICATION_FAILED",
      `a ${kind} receipt must carry an integer '${key}'; it is projected into a column other checks ` +
        `compare against, and a defaulted value there fails open`,
      { kind, field: key },
    );
  }
  return value;
}

/** Optional projected column: absent is `null`, present-but-wrong-typed is refused. */
function optionalText(kind: ReceiptKind, payload: JsonObject, key: string): string | null {
  const value = payload[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new YashikiError(
      "VERIFICATION_FAILED",
      `a ${kind} receipt's '${key}' must be a string when present`,
      { kind, field: key },
    );
  }
  return value;
}

/**
 * Append-only receipt store backed by the local registry. There is no update or
 * delete path here or in SQL: the table triggers reject both.
 */
export function createSqliteReceiptStore(
  db: YashikiDatabase,
  options: { secretGuard?: SecretGuard } = {},
): ReceiptStore {
  const guard = options.secretGuard ?? noopSecretGuard;

  const insertReceipt = db.prepare(
    `INSERT INTO receipts (content_hash, sequence, previous_hash, kind, node_name, created_at, payload_json)
     VALUES (@contentHash, @sequence, @previousHash, @kind, @nodeName, @createdAt, @payloadJson)`,
  );
  const insertInstall = db.prepare(
    `INSERT INTO install_receipts (content_hash, node_name, sequence, previous_hash, product, node_version,
                                   protocol_version, artifact_sha256, installed_at, body_json)
     VALUES (@contentHash, @nodeName, @sequence, @previousHash, @product, @version, @protocolVersion,
             @artifactSha256, @createdAt, @payloadJson)`,
  );
  const insertCredential = db.prepare(
    `INSERT INTO credential_receipts (content_hash, node_name, sequence, previous_hash, credential_provider,
                                      operation, source_ref, guest_path, guest_owner, guest_mode,
                                      value_fingerprint, materialized_at, body_json)
     VALUES (@contentHash, @nodeName, @sequence, @previousHash, @provider, @operation, @sourceRef, @guestPath,
             @owner, @mode, @valueFingerprint, @createdAt, @payloadJson)`,
  );

  const advanceChainHead = db.prepare(
    "UPDATE receipt_chain_head SET next_sequence = @next, head_hash = @head WHERE id = 0 AND next_sequence = @previous",
  );

  return {
    append(input) {
      // EVERYTHING is inside one transaction — the anchor read included. Reading
      // the head outside it and writing inside is a race in which two appends
      // both read the same sequence; `immediate` takes the write lock before the
      // read, so the loser waits and re-reads rather than duplicating a link.
      const run = db.transaction((): Receipt => {
        // The sequence and the chain link come from the HEAD ANCHOR, not from
        // the receipts table. `COUNT(*)` (and `MAX(sequence) + 1` equally)
        // handed a deleted row's sequence straight back to the next append:
        // delete the last receipt, append another, and the chain verified clean
        // — a receipt erased and replaced, with the tamper-evidence reporting
        // OK. `next_sequence` only ever increases, so a freed sequence is never
        // reissued.
        const head = readChainHead(db);
        const sequence = head.next_sequence;
        const previousHash = head.head_hash;

        // The anchor and the table must agree before anything is written: if
        // they do not, rows have been removed behind the triggers and this store
        // would be appending onto a chain that is no longer the one it recorded.
        assertChainHeadMatchesTable(db, head);

        // Two guard calls over two DISJOINT halves of the row. Guarding the whole
        // canonical body once would make any second call a subset of the first —
        // redundant, therefore impossible to write a failing test for, therefore
        // free to rot. Split this way each call is the only thing standing
        // between its half of the row and the database.
        //   - payload: the caller's data, stored verbatim in `payload_json` and
        //     projected into the typed columns.
        //   - envelope: kind, node name, timestamp and chain links, which the
        //     caller also controls and which no payload guard ever sees.
        //
        // The input is read ONCE, into `snapshot`, and the guarded bytes are
        // literally the values bound to the columns: guarding one view of a
        // caller's object and persisting another is a TOCTOU that a `toJSON` or
        // a getter walks straight through. That applies to `kind`, `nodeName`
        // and `createdAt` as much as to the payload — they are bound to
        // `node_name`, `created_at` and `body_json`.
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
        const payloadJson = snapshot.payloadJson;

        const common = {
          contentHash: receipt.contentHash,
          sequence,
          previousHash,
          kind: receipt.kind,
          nodeName: receipt.nodeName,
          createdAt: receipt.createdAt,
          payloadJson,
        };

        // The chain row, the typed projection AND the head anchor all move in this
        // one transaction. A projection that fails — a node that is not
        // registered, a payload missing a projected field — must take the
        // `receipts` row with it, or the log holds a receipt no projection
        // describes; and the anchor must advance in the same commit as the row it
        // describes, or a crash between them loses the record either way.
        insertReceipt.run(common);
        if (receipt.kind === "install") {
          insertInstall.run({
            ...common,
            product: text(receipt.kind, receipt.payload, "product"),
            version: text(receipt.kind, receipt.payload, "version"),
            protocolVersion: integer(receipt.kind, receipt.payload, "protocolVersion"),
            artifactSha256: text(receipt.kind, receipt.payload, "artifactSha256"),
          });
        }
        if (receipt.kind === "credential") {
          insertCredential.run({
            ...common,
            provider: text(receipt.kind, receipt.payload, "provider"),
            operation: text(receipt.kind, receipt.payload, "operation"),
            sourceRef: text(receipt.kind, receipt.payload, "sourceRef"),
            guestPath: text(receipt.kind, receipt.payload, "guestPath"),
            owner: text(receipt.kind, receipt.payload, "owner"),
            mode: text(receipt.kind, receipt.payload, "mode"),
            valueFingerprint: optionalText(receipt.kind, receipt.payload, "valueFingerprint"),
          });
        }
        advanceChainHead.run({ next: sequence + 1, head: receipt.contentHash, previous: sequence });

        return receipt;
      });
      return run.immediate();
    },

    list(filter?: ReceiptFilter) {
      const rows = db
        .prepare(
          `SELECT * FROM receipts
           WHERE (@kind IS NULL OR kind = @kind) AND (@nodeName IS NULL OR node_name = @nodeName)
           ORDER BY sequence`,
        )
        .all({ kind: filter?.kind ?? null, nodeName: filter?.nodeName ?? null }) as ReceiptRow[];
      return rows.map(toReceipt);
    },

    latest(kind, nodeName) {
      const row = db
        .prepare("SELECT * FROM receipts WHERE kind = ? AND node_name = ? ORDER BY sequence DESC LIMIT 1")
        .get(kind, nodeName) as ReceiptRow | undefined;
      return row === undefined ? undefined : toReceipt(row);
    },

    verify() {
      const rows = db.prepare("SELECT * FROM receipts ORDER BY sequence").all() as ReceiptRow[];
      const head = readChainHead(db);
      // The anchor is what makes a truncated TAIL visible. Without it `[r0, r1]`,
      // `[r0]` and `[]` are each an internally consistent chain, and no forward
      // walk can tell any of them from a chain that was always that short.
      const anchor: ReceiptChainAnchor = { headHash: head.head_hash };
      verifyReceiptChain(rows.map(toReceipt), anchor);
    },
  };
}
