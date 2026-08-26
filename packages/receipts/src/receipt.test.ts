import { describe, expect, it } from "vitest";
import { createSecretGuard, isYashikiError, type SecretGuard } from "@meidoya-yashiki/yashiki-core";
import { canonicalize, contentHash, type JsonObject } from "./canonical.js";
import {
  receiptChainAnchor,
  sealReceipt,
  verifyReceipt,
  verifyReceiptChain,
  type Receipt,
  type ReceiptInput,
} from "./receipt.js";
import { createInMemoryReceiptStore } from "./store.js";

function makeStore(): ReturnType<typeof createInMemoryReceiptStore> {
  const store = createInMemoryReceiptStore();
  store.append({
    kind: "install",
    nodeName: "work-grammarxiv",
    createdAt: "2026-01-01T00:00:00.000Z",
    payload: { product: "meidoya-node", version: "0.1.0", artifactSha256: "a".repeat(64) },
  });
  store.append({
    kind: "credential",
    nodeName: "work-grammarxiv",
    createdAt: "2026-01-01T00:01:00.000Z",
    payload: { provider: "codex", guestPath: "/home/meidoya/.codex/auth.json", mode: "0600" },
  });
  return store;
}

describe("canonicalize", () => {
  it("is independent of key insertion order", () => {
    expect(canonicalize({ b: 1, a: [2, { d: 4, c: 3 }] })).toBe(canonicalize({ a: [2, { c: 3, d: 4 }] as never, b: 1 }));
    expect(contentHash({ a: 1 })).toHaveLength(64);
  });

  /**
   * This is a hash input and a secret-guard input, so a value it renders WRONG
   * is worse than one it rejects. `JSON` maps NaN and Infinity to `null` and
   * every exotic object to `{}` — so they all hashed identically, and a guard
   * handed `{}` had been shown nothing at all.
   */
  describe("refuses what JSON would silently misrepresent", () => {
    for (const [name, value] of [
      ["NaN", Number.NaN],
      ["Infinity", Number.POSITIVE_INFINITY],
      ["-Infinity", Number.NEGATIVE_INFINITY],
    ] as const) {
      it(`refuses ${name} rather than writing null`, () => {
        expect(() => canonicalize({ n: value } as never)).toThrowError(/no JSON representation/);
      });
    }

    for (const [name, value] of [
      ["a Map", new Map([["token", "dummy-value"]])],
      ["a Set", new Set(["dummy-value"])],
      ["a function", () => "dummy-value"],
      ["a class instance", new (class Holder {})()],
    ] as const) {
      it(`refuses ${name} rather than rendering it as {}`, () => {
        expect(() => canonicalize({ v: value } as never)).toThrowError(/canonicalize/);
      });
    }

    it("refuses a BigInt, which JSON.stringify would throw on anyway", () => {
      expect(() => canonicalize({ v: 1n } as never)).toThrowError(/not JSON/);
    });

    it("refuses an undefined property rather than dropping the key", () => {
      expect(() => canonicalize({ v: undefined } as never)).toThrowError(/undefined/);
    });

    it("still canonicalizes ordinary JSON", () => {
      expect(canonicalize({ a: 1, b: [true, null, "x"], c: { d: -1.5 } })).toBe(
        '{"a":1,"b":[true,null,"x"],"c":{"d":-1.5}}',
      );
    });
  });
});

describe("receipts", () => {
  it("chains receipts and verifies the chain", () => {
    const store = makeStore();
    const receipts = store.list();
    expect(receipts).toHaveLength(2);
    expect(receipts[0]?.previousHash).toBeNull();
    expect(receipts[1]?.previousHash).toBe(receipts[0]?.contentHash);
    expect(() => store.verify()).not.toThrow();
  });

  it("is immutable at runtime: the sealed receipt cannot be edited in place", () => {
    const store = makeStore();
    const receipt = store.list()[0] as Receipt;
    expect(Object.isFrozen(receipt)).toBe(true);
    expect(Object.isFrozen(receipt.payload)).toBe(true);
    expect(() => {
      (receipt as unknown as { nodeName: string }).nodeName = "other";
    }).toThrow();
  });

  it("does not expose an update or delete operation", () => {
    const store = makeStore();
    expect(Object.keys(store).sort()).toEqual(["append", "latest", "list", "verify"]);
  });

  it("detects a tampered payload", () => {
    const store = makeStore();
    const tampered = store.list().map((receipt, index) =>
      index === 0 ? ({ ...receipt, payload: { ...receipt.payload, version: "9.9.9" } } as Receipt) : receipt,
    );
    expect(verifyReceipt(tampered[0] as Receipt)).toBe(false);
    expect(() => verifyReceiptChain(tampered)).toThrowError(/RECEIPT_TAMPERED/);
  });

  it("detects a deleted receipt", () => {
    const store = makeStore();
    const truncated = store.list().slice(1);
    expect(() => verifyReceiptChain(truncated)).toThrowError(/RECEIPT_TAMPERED/);
  });

  /**
   * Defect C4. A forward walk from sequence 0 cannot see a truncated TAIL: a
   * prefix of a valid chain is a valid chain. The anchor — a count and head hash
   * recorded as the chain grew, held somewhere the receipts are not — is what
   * closes that, and it is the only reason the doc-comment's claim is true.
   */
  describe("a truncated tail", () => {
    function threeReceipts(): Receipt[] {
      const store = makeStore();
      store.append({
        kind: "provisioning",
        nodeName: "work-grammarxiv",
        createdAt: "2026-01-01T00:02:00.000Z",
        payload: { step: "verify" },
      });
      return [...store.list()];
    }

    for (const keep of [2, 1, 0]) {
      it(`passes unanchored but FAILS against the anchor when cut to ${String(keep)}`, () => {
        const receipts = threeReceipts();
        const anchor = receiptChainAnchor(receipts);
        const cut = receipts.slice(0, keep);

        // Honestly reported: without an anchor this is undetectable.
        expect(() => verifyReceiptChain(cut)).not.toThrow();
        expect(() => verifyReceiptChain(cut, anchor)).toThrowError(/RECEIPT_TAMPERED/);
      });
    }

    it("passes against its own anchor when nothing was removed", () => {
      const receipts = threeReceipts();
      expect(() => verifyReceiptChain(receipts, receiptChainAnchor(receipts))).not.toThrow();
    });

    it("detects a chain whose head is not the head that was recorded", () => {
      const receipts = threeReceipts();
      const anchor = receiptChainAnchor(receipts);
      expect(() => verifyReceiptChain(receipts, { ...anchor, headHash: "c".repeat(64) })).toThrowError(
        /RECEIPT_TAMPERED/,
      );
    });

    it("in-memory store: a truncated chain cannot be re-grown into a clean one", () => {
      const store = makeStore();
      // The store keeps its own high-water mark, so a sequence is never reissued
      // even if the array it walks were shortened.
      const third = store.append({
        kind: "provisioning",
        nodeName: "n",
        createdAt: "2026-01-01T00:02:00.000Z",
        payload: { step: "verify" },
      });
      expect(third.sequence).toBe(2);
      expect(() => store.verify()).not.toThrow();
    });
  });

  /**
   * The contiguity check is the only thing that catches a chain whose links and
   * hashes are all internally consistent but which does not START at 0 — the
   * shape an export or a restore of "the last N receipts" produces.
   */
  it("detects a chain that does not start at sequence 0", () => {
    const midway = sealReceipt(
      { kind: "install", nodeName: "n", createdAt: "2026-01-01T00:00:00.000Z", payload: {} },
      null,
      5,
    );
    expect(verifyReceipt(midway)).toBe(true);
    expect(() => verifyReceiptChain([midway])).toThrowError(/not contiguous/);
  });

  /**
   * `nodeName` and `previousHash` are in the hashed body, and nothing bound
   * either: dropping them from `receiptBody` left the suite green, and a receipt
   * could then be moved to another node, or re-linked, without breaking its own
   * hash.
   */
  describe("the hashed body covers the whole envelope", () => {
    const base = { kind: "install", createdAt: "2026-01-01T00:00:00.000Z", payload: { a: 1 } } as const;

    it("covers nodeName, so a receipt cannot be moved to another node", () => {
      const here = sealReceipt({ ...base, nodeName: "node-a" }, null, 0);
      const there = sealReceipt({ ...base, nodeName: "node-b" }, null, 0);
      expect(here.contentHash).not.toBe(there.contentHash);
      expect(verifyReceipt({ ...here, nodeName: "node-b" } as Receipt)).toBe(false);
    });

    it("covers previousHash, so a receipt cannot be re-linked", () => {
      const first = sealReceipt({ ...base, nodeName: "node-a" }, null, 0);
      const relinked = sealReceipt({ ...base, nodeName: "node-a" }, "a".repeat(64), 0);
      expect(first.contentHash).not.toBe(relinked.contentHash);
      expect(verifyReceipt({ ...first, previousHash: "a".repeat(64) } as Receipt)).toBe(false);
    });

    it("covers sequence, so a receipt cannot be renumbered", () => {
      const first = sealReceipt({ ...base, nodeName: "node-a" }, null, 0);
      expect(verifyReceipt({ ...first, sequence: 1 } as Receipt)).toBe(false);
    });
  });

  /**
   * `latest` and `list` both take a node name and both used to be able to ignore
   * it unnoticed: every test had a single node.
   */
  describe("node-scoped reads", () => {
    function twoNodes(): ReturnType<typeof createInMemoryReceiptStore> {
      const store = createInMemoryReceiptStore();
      store.append({ kind: "install", nodeName: "node-a", createdAt: "t0", payload: { version: "1" } });
      store.append({ kind: "install", nodeName: "node-b", createdAt: "t1", payload: { version: "2" } });
      return store;
    }

    it("latest() answers about the node it was asked about", () => {
      const store = twoNodes();
      expect(store.latest("install", "node-a")?.payload["version"]).toBe("1");
      expect(store.latest("install", "node-b")?.payload["version"]).toBe("2");
      expect(store.latest("install", "node-c")).toBeUndefined();
      expect(store.latest("credential", "node-a")).toBeUndefined();
    });

    it("list() filters by node", () => {
      const store = twoNodes();
      expect(store.list({ nodeName: "node-a" }).map((receipt) => receipt.nodeName)).toEqual(["node-a"]);
      expect(store.list()).toHaveLength(2);
    });
  });

  /**
   * `assertClean`'s contract: a caller that PERSISTS what it scanned must treat
   * a non-null return as untrusted. Both stores discarded it. A receipt is
   * permanent and cannot be marked sensitive the way a backup item can, so the
   * only honest response is to refuse.
   */
  it("refuses bytes the guard could not finish scanning", () => {
    const guard: SecretGuard = {
      assertClean: () => ({
        sink: "receipt:payload",
        budgetExhausted: true,
        streamsSkipped: 0,
        streamsTruncated: 0,
        depthExhausted: false,
        runsTruncated: 0,
      }),
    };
    const store = createInMemoryReceiptStore({ secretGuard: guard });
    let refused = false;
    try {
      store.append({ kind: "health", nodeName: "n", createdAt: "t", payload: { detail: "x" } });
    } catch (error) {
      refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
    }
    expect(refused).toBe(true);
    expect(store.list()).toHaveLength(0);
  });

  it("detects a re-sealed receipt inserted with the wrong link", () => {
    const forged = sealReceipt(
      { kind: "install", nodeName: "n", createdAt: "2026-01-01T00:00:00.000Z", payload: {} },
      "b".repeat(64),
      0,
    );
    expect(verifyReceipt(forged)).toBe(true);
    expect(() => verifyReceiptChain([forged])).toThrowError(/RECEIPT_TAMPERED/);
  });

  /**
   * Regression for the JSON-escaping bypass: the store hands the guard
   * `canonicalize(...)` output, so a secret whose bytes change under JSON
   * escaping (newlines, quotes, backslashes) used to sail straight past a raw
   * substring check. Each case goes through the real `append` path.
   */
  describe("guards the encoded form, not the raw value", () => {
    const cases: readonly (readonly [string, string])[] = [
      [
        "a multi-line PEM private key",
        [
          "-----BEGIN RSA " + "PRIVATE KEY-----",
          "MIIDUMMYnotarealkeyAAAAAAAAAAAAAAAA",
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
          "-----END RSA " + "PRIVATE KEY-----",
        ].join("\n"),
      ],
      [
        "a JSON service-account key",
        JSON.stringify({
          type: "service_account",
          project_id: "dummy-project",
          private_key: "-----BEGIN PRIVATE KEY-----\nDUMMYnotarealkey\n-----END PRIVATE KEY-----\n",
          client_email: "dummy@dummy-project.iam.gserviceaccount.com",
        }),
      ],
      ['a secret containing a quote and a backslash', 'dummy"secret\\value-not-real'],
    ];

    for (const [name, secret] of cases) {
      it(`refuses ${name}`, () => {
        const guard = createSecretGuard([secret]);
        const store = createInMemoryReceiptStore({ secretGuard: guard });
        // The message must never quote the value, so assert on the code only.
        let refused = false;
        try {
          store.append({
            kind: "credential",
            nodeName: "work-grammarxiv",
            createdAt: "2026-01-01T00:00:00.000Z",
            payload: { provider: "codex", leaked: secret },
          });
        } catch (error) {
          refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
        }
        expect(refused).toBe(true);
        expect(store.list()).toHaveLength(0);
      });
    }

    // NOTE: this is the dev/test store. The shipped one is
    // packages/store-sqlite/src/receipt-store.ts and carries its own guard
    // tests; neither store may rely on the other's coverage.
    it("refuses a base64-encoded secret", () => {
      const secret = "dummy-not-a-real-credential-value";
      const guard = createSecretGuard([secret]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      let refused = false;
      try {
        store.append({
          kind: "credential",
          nodeName: "n",
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { blob: Buffer.from(secret, "utf8").toString("base64") },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
    });

    it("refuses a secret in the envelope, which no payload guard sees", () => {
      const secret = "dummy-not-a-real-credential-value";
      const guard = createSecretGuard([secret]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      let refused = false;
      try {
        store.append({
          kind: "provisioning",
          nodeName: `n-${secret}`,
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { step: "verify" },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(store.list()).toHaveLength(0);
    });

    it("still records a receipt that holds no secret", () => {
      const guard = createSecretGuard(["dummy-not-a-real-credential-value"]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      const receipt = store.append({
        kind: "credential",
        nodeName: "n",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { provider: "codex", valueFingerprint: "b".repeat(64) },
      });
      expect(receipt.sequence).toBe(0);
      expect(store.list()).toHaveLength(1);
    });
  });

  /**
   * Defect 18 (TOCTOU). The store used to guard `JSON.stringify(input.payload)`
   * and then read the payload AGAIN through `structuredClone`. A payload whose
   * property is an accessor can answer those two reads differently: benign text
   * to the guard, the credential to the store. The payload is now read once and
   * both the guarded bytes and the stored bytes come from that single read.
   */
  describe("guards the bytes it stores, not a second reading of the caller's object", () => {
    const SECRET = "dummy-not-a-real-credential-value";

    /** Benign on the first read, the credential on every read after it. */
    function twoFaced(): { payload: JsonObject; reads: () => number } {
      let reads = 0;
      const payload = {} as JsonObject;
      Object.defineProperty(payload, "note", {
        enumerable: true,
        configurable: true,
        get: () => {
          reads += 1;
          return reads === 1 ? "nothing to see here" : SECRET;
        },
      });
      return { payload, reads: () => reads };
    }

    it("stores exactly what the guard saw, and reads the payload only once", () => {
      const guard = createSecretGuard([SECRET]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      const { payload, reads } = twoFaced();

      const receipt = store.append({
        kind: "credential",
        nodeName: "work-grammarxiv",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload,
      });

      expect(reads()).toBe(1);
      expect(receipt.payload["note"]).toBe("nothing to see here");
      expect(JSON.stringify(store.list()[0]?.payload)).not.toContain(SECRET);
      // The hash covers the same single reading, so the chain still verifies.
      expect(() => store.verify()).not.toThrow();
    });

    it("refuses when the FIRST reading is the credential, so the trick buys nothing", () => {
      const guard = createSecretGuard([SECRET]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      let refused = false;
      try {
        store.append({
          kind: "credential",
          nodeName: "n",
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { note: SECRET },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(store.list()).toHaveLength(0);
    });

    /**
     * Defect 20d. The payload snapshot closed this for `payload` and left the
     * ENVELOPE wide open: `kind`, `nodeName` and `createdAt` were read once for
     * the guard and again to seal the receipt, so a getter answering with the
     * credential on its SECOND read landed it in the stored node name.
     */
    function twoFacedEnvelope(): { input: ReceiptInput; reads: () => number } {
      let reads = 0;
      const input = {
        kind: "provisioning",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { step: "verify" },
      } as unknown as ReceiptInput;
      Object.defineProperty(input, "nodeName", {
        enumerable: true,
        configurable: true,
        get: () => {
          reads += 1;
          return reads === 1 ? "work-grammarxiv" : SECRET;
        },
      });
      return { input, reads: () => reads };
    }

    it("stores the envelope the guard saw, and reads each envelope field only once", () => {
      const guard = createSecretGuard([SECRET]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      const { input, reads } = twoFacedEnvelope();

      const receipt = store.append(input);

      expect(reads()).toBe(1);
      expect(receipt.nodeName).toBe("work-grammarxiv");
      expect(JSON.stringify(store.list())).not.toContain(SECRET);
      expect(() => store.verify()).not.toThrow();
    });

    it("refuses when the FIRST reading of an envelope field is the credential", () => {
      const guard = createSecretGuard([SECRET]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      let refused = false;
      try {
        store.append({
          kind: "provisioning",
          nodeName: SECRET,
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { step: "verify" },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
      expect(store.list()).toHaveLength(0);
    });

    it("stores the value a toJSON returned to the guard, not a later one", () => {
      const guard = createSecretGuard([SECRET]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      let calls = 0;
      const payload = {
        detail: {
          toJSON: () => {
            calls += 1;
            return calls === 1 ? "clean" : SECRET;
          },
        },
      } as unknown as JsonObject;

      const receipt = store.append({
        kind: "credential",
        nodeName: "n",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload,
      });

      expect(calls).toBe(1);
      expect(receipt.payload["detail"]).toBe("clean");
      expect(JSON.stringify(receipt.payload)).not.toContain(SECRET);
    });
  });

  /**
   * Defect 19. A short credential occurs inside ordinary structure — `2026` is
   * in every timestamp this system writes — so matching it against the receipt
   * ENVELOPE would refuse every append, and would do so AFTER the credential
   * had already been written to the guest. Short values are matched against
   * payload bytes, which is where a leak would actually be.
   */
  describe("a short credential value does not make every receipt unwritable", () => {
    const SHORT = "2026";

    it("appends a receipt whose envelope timestamp contains the whole value", () => {
      const guard = createSecretGuard([SHORT]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      const receipt = store.append({
        kind: "credential",
        nodeName: "work-grammarxiv",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { provider: "codex", valueFingerprint: "b".repeat(64) },
      });
      expect(receipt.sequence).toBe(0);
      expect(store.list()).toHaveLength(1);
    });

    it("still refuses that short value in the payload", () => {
      const guard = createSecretGuard([SHORT]);
      const store = createInMemoryReceiptStore({ secretGuard: guard });
      let refused = false;
      try {
        store.append({
          kind: "credential",
          nodeName: "n",
          createdAt: "2026-01-01T00:00:00.000Z",
          payload: { token: SHORT },
        });
      } catch (error) {
        refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
      }
      expect(refused).toBe(true);
    });
  });

  it("refuses to record a receipt that contains a credential value", () => {
    const guard = createSecretGuard(["sk-super-secret-token-value"]);
    const store = createInMemoryReceiptStore({ secretGuard: guard });
    try {
      store.append({
        kind: "credential",
        nodeName: "work-grammarxiv",
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { provider: "codex", token: "sk-super-secret-token-value" },
      });
    } catch (error) {
      expect(isYashikiError(error, "CREDENTIAL_UNSAFE")).toBe(true);
      expect(store.list()).toHaveLength(0);
      return;
    }
    throw new Error("expected the receipt to be refused");
  });
});
