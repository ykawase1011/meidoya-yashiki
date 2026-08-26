import { createGzip, deflateRawSync, deflateSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { isYashikiError } from "./errors.js";
import {
  createSecretGuard,
  DECODE_AMPLIFICATION,
  MAX_OVERLAP,
  MAX_WINDOW_EXTENSION,
  noopSecretGuard,
  overlapFor,
  OVERLAP_EXPANSION,
  ROUND_ZERO_AMPLIFICATION,
  ROUND_ZERO_HEADROOM,
  scanWindows,
  SCAN_WINDOW,
  type IncompleteScan,
} from "./secret-guard.js";

/**
 * Obvious dummies only. Nothing here is or resembles a live credential, and no
 * assertion ever prints a guarded value: a failing guard test must not become
 * the leak it is testing for.
 */
const SECRET = "dummy-not-a-real-credential-value";
const PEM = ["-----BEGIN RSA PRIVATE KEY-----", "DUMMYnotarealkey/with+chars", "-----END RSA PRIVATE KEY-----"].join(
  "\n",
);
/**
 * A dummy whose characters `encodeURIComponent` actually escapes. `SECRET` is
 * entirely unreserved, so percent-encoding it is the IDENTITY: the two
 * percent-encoding cases below used to "pass" against a `percentDecode` that
 * returned its argument untouched, which is no test at all.
 */
const SYMBOL_SECRET = "dummy not/a real:credential?value=1&x";

const hexOf = (value: string): string => Buffer.from(value, "utf8").toString("hex");
const percentEncode = (value: string): string =>
  [...value].map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");
const htmlEntities = (value: string): string => [...value].map((char) => `&#${char.charCodeAt(0)};`).join("");
const unicodeEscapes = (value: string): string =>
  [...value].map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");

/** `openssl base64` wraps at 76 columns by default; narrower here to force it. */
function wrap(text: string, width: number): string {
  return (text.match(new RegExp(`.{1,${width}}`, "g")) ?? []).join("\n");
}

/**
 * Never asserts on the message, only the code: the message must stay valueless.
 *
 * The observer is silenced explicitly. The DEFAULT observer writes to stderr —
 * that is defect 23's second half and it has its own test — but a helper used by
 * a hundred cases must not spray the suite's output with it.
 */
function refuses(secret: string, text: string): boolean {
  const guard = createSecretGuard([secret], { onIncompleteScan: () => undefined });
  try {
    guard.assertClean("test-sink", text);
    return false;
  } catch (error) {
    if (isYashikiError(error, "CREDENTIAL_UNSAFE")) return true;
    throw error;
  }
}

function utf16leBase64(value: string): string {
  return Buffer.from(value, "utf16le").toString("base64");
}

/** Deterministic and offline: no `Math.random` anywhere in this file. */
function pseudoRandom(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) % 2147483648;
    return state / 2147483648;
  };
}

/**
 * A deterministic xorshift32, used where `pseudoRandom` is not enough.
 *
 * `pseudoRandom`'s multiply overflows double precision and its output is
 * periodic enough that 120 KB of it gzips to a tenth of its size — fine for the
 * amplification fixtures, useless for a fixture that has to be INCOMPRESSIBLE.
 */
function noisyText(length: number, seed: number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 ";
  let state = seed >>> 0;
  let out = "";
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out += alphabet[state % alphabet.length] as string;
  }
  return out;
}

function fromAlphabet(alphabet: string, length: number, seed: number): string {
  const next = pseudoRandom(seed);
  return Array.from({ length }, () => alphabet[Math.floor(next() * alphabet.length)]).join("");
}

/**
 * An append-only receipt log of `count` rows, with a DISTINCT fingerprint per
 * row. Distinctness is the whole point: a log whose every row carries the same
 * `"a".repeat(64)` collapses to one entry in the guard's `seen` set, so a test
 * built on one measures the cost of a single row however many it appends.
 */
function receiptLog(count: number): string {
  return JSON.stringify(
    Array.from({ length: count }, (_, index) => ({
      sequence: index,
      kind: "credential",
      nodeName: "work-grammarxiv",
      createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      valueFingerprint: Buffer.from(`fingerprint-${index}`).toString("hex").padEnd(64, "0"),
      chainLink: Buffer.from(`chain-${index}`).toString("hex").padEnd(64, "5"),
    })),
  );
}

/**
 * Both halves of what one `assertClean` did: whether it refused, and everything
 * it reported it could not look at.
 *
 * The guard fails OPEN on every one of its own bounds, so "did it refuse" alone
 * can no longer distinguish a complete clean scan from an abandoned one. Tests
 * that care about the difference — and most of the ones below do — have to look
 * at both, which is exactly the position an operator is in.
 */
type Scan = { refusal: Record<string, unknown> | null; incomplete: IncompleteScan[] };

function scan(text: string, secret: string = SECRET): Scan {
  const incomplete: IncompleteScan[] = [];
  const guard = createSecretGuard([secret], { onIncompleteScan: (report) => incomplete.push(report) });
  try {
    guard.assertClean("receipt:payload", text);
    return { refusal: null, incomplete };
  } catch (error) {
    if (!isYashikiError(error, "CREDENTIAL_UNSAFE")) throw error;
    return { refusal: { ...error.details }, incomplete };
  }
}

/**
 * `encoded` positioned so that exactly `charsBeforeBoundary` of its characters
 * fall in the first scan window and the rest fall past it.
 *
 * The filler is `!`, which is in no alphabet the guard scans and is not a hex
 * separator, so the placement is the only thing the test is measuring.
 */
function acrossWindowBoundary(encoded: string, charsBeforeBoundary: number): string {
  if (encoded.length <= charsBeforeBoundary) throw new Error("the encoded form does not reach past the boundary");
  return `${"!".repeat(SCAN_WINDOW - charsBeforeBoundary)}${encoded}${"!".repeat(64)}`;
}

/** Builds a gzip stream far larger than any cap without ever holding it. */
async function streamedGzip(chunk: Buffer, times: number, head?: Buffer): Promise<Buffer> {
  const gzip = createGzip();
  const parts: Buffer[] = [];
  gzip.on("data", (part: Buffer) => parts.push(part));
  const finished = new Promise<void>((resolve) => gzip.on("end", resolve));
  if (head !== undefined) gzip.write(head);
  for (let index = 0; index < times; index += 1) gzip.write(chunk);
  gzip.end();
  await finished;
  return Buffer.concat(parts);
}

describe("secret guard", () => {
  describe("catches the value however it was encoded on the way to the sink", () => {
    const cases: [name: string, text: string, secret?: string][] = [
      ["the raw value", `token=${SECRET}`],
      ["the value inside a JSON document", JSON.stringify({ token: SECRET })],
      ["a JSON-escaped multi-line PEM", JSON.stringify({ key: PEM }), PEM],
      ["a PEM whose newlines were collapsed", PEM.replace(/\n/g, ""), PEM],
      ["a \\uXXXX-escaped value", [...SECRET].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("")],
      ["a \\xNN-escaped value", [...SECRET].map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")],
      ["an octal-escaped value", [...SECRET].map((c) => `\\${c.charCodeAt(0).toString(8).padStart(3, "0")}`).join("")],
      ["HTML decimal entities", [...SECRET].map((c) => `&#${c.charCodeAt(0)};`).join("")],
      ["HTML hex entities", [...SECRET].map((c) => `&#x${c.charCodeAt(0).toString(16)};`).join("")],
      ["UPPERCASE percent-encoding", encodeURIComponent(`${SECRET}/+ `)],
      ["lowercase percent-encoding", encodeURIComponent(`${SECRET}/+ `).toLowerCase()],
      ["lowercase hex", Buffer.from(SECRET, "utf8").toString("hex")],
      ["UPPERCASE hex", Buffer.from(SECRET, "utf8").toString("hex").toUpperCase()],
      ["base64", Buffer.from(SECRET, "utf8").toString("base64")],
      ["base64 without padding", Buffer.from(SECRET, "utf8").toString("base64").replace(/=+$/, "")],
      ["base64url", Buffer.from(SECRET, "utf8").toString("base64url")],
      ["base64 of UTF-16LE bytes", utf16leBase64(SECRET)],
      ["base64 of UTF-16BE bytes", Buffer.from(SECRET, "utf16le").swap16().toString("base64")],
      ["gzip then base64", gzipSync(Buffer.from(SECRET, "utf8")).toString("base64")],
      ["zlib deflate then base64", deflateSync(Buffer.from(SECRET, "utf8")).toString("base64")],
      ["raw deflate then base64", deflateRawSync(Buffer.from(SECRET, "utf8")).toString("base64")],
      [
        "the value at a byte offset inside a LARGER base64 blob",
        Buffer.concat([Buffer.from("abcdefghij"), Buffer.from(SECRET, "utf8"), Buffer.from("klmnopqrst")]).toString(
          "base64",
        ),
      ],
      [
        "the value inside a base64 blob at every possible byte alignment",
        // Three offsets means all three residues mod 3: one of them is the
        // alignment a naive single-form base64 comparison would have needed.
        [1, 2, 3]
          .map((pad) =>
            Buffer.concat([Buffer.alloc(pad, 0x41), Buffer.from(SECRET, "utf8")]).toString("base64"),
          )
          .join(" "),
      ],
      ["a base64 blob wrapped in a larger JSON document", JSON.stringify({ blob: `x${Buffer.from(SECRET).toString("base64")}` })],
      ["a 7-character value, shorter than any minimum", "id=abc1234", "abc1234"],
      ["a 3-character value", "id=xyz", "xyz"],

      // -- wrapped and separated encodings (defect 15) --------------------
      // `openssl base64` wraps by default and `hexdump` separates by default,
      // so a scan that only ever saw CONTIGUOUS runs was defeated by the
      // out-of-the-box behaviour of the two commonest encoding tools.
      ["base64 wrapped at a column limit, as openssl emits it", wrap(Buffer.from(SECRET).toString("base64"), 16)],
      [
        "wrapped base64 embedded in a larger document",
        `dump:\n${wrap(Buffer.from(SECRET).toString("base64"), 76)}\nend`,
      ],
      ["colon-separated hex, as a certificate dump emits it", (hexOf(SECRET).match(/../g) ?? []).join(":")],
      ["space-separated hex, as hexdump emits it", (hexOf(SECRET).match(/.{1,4}/g) ?? []).join(" ")],
      ["hex broken across lines", wrap(hexOf(SECRET), 32)],

      // -- alignment and layering ------------------------------------------
      [
        "an odd-length hex run whose real byte boundary is one character in",
        // The leading nibble means the aligned reading is `slice(1)`, not
        // `slice(0, -1)`: dropping the LAST character decodes to garbage.
        `a${hexOf(SECRET)}`,
      ],
      [
        "a value backslash-escaped BEFORE it was base64-encoded",
        Buffer.from(JSON.stringify(PEM), "utf8").toString("base64"),
        PEM,
      ],

      // -- composed BINARY layers (defect 20a) ------------------------------
      // Binary decoding used to be a single peel: one layer off, then the
      // search. Encoding twice — which `base64 | base64` does in one shell
      // pipeline — walked straight through it into `receipt:payload`.
      ["base64 of base64", Buffer.from(Buffer.from(SECRET).toString("base64")).toString("base64")],
      ["hex of base64", Buffer.from(Buffer.from(SECRET).toString("base64"), "utf8").toString("hex")],
      ["base64 of hex", Buffer.from(hexOf(SECRET), "utf8").toString("base64")],
      ["base64 of base64 of base64", [1, 2, 3].reduce((text) => Buffer.from(text).toString("base64"), SECRET)],
      [
        "base64 of gzip of base64",
        gzipSync(Buffer.from(Buffer.from(SECRET).toString("base64"))).toString("base64"),
      ],
      [
        "a doubly encoded value embedded in a larger document",
        JSON.stringify({ blob: `x${Buffer.from(Buffer.from(SECRET).toString("base64")).toString("base64")}` }),
      ],

      // -- percent-encoding, on a value that percent-encoding changes -------
      ["UPPERCASE percent-encoding of a symbol-rich value", encodeURIComponent(SYMBOL_SECRET), SYMBOL_SECRET],
      [
        "lowercase percent-encoding of a symbol-rich value",
        encodeURIComponent(SYMBOL_SECRET).toLowerCase(),
        SYMBOL_SECRET,
      ],
      [
        "percent-encoding whose percent signs are themselves HTML-escaped",
        // Two textual layers in an order the old fixed two-pass shape could
        // not express: entities first, then percent-decoding.
        encodeURIComponent(SYMBOL_SECRET).replace(/%/g, "&#37;"),
        SYMBOL_SECRET,
      ],

      // -- percent/entity stacks deeper than one textual fixpoint (defect 7) --
      // Four ordinary serialisation hops. Advancing the decode rounds through
      // the BINARY half alone capped textual composition at three, so this
      // reached `receipt:payload` while a three-layer version of it was
      // refused — the guard was strictly weaker against the plainer document.
      [
        "four composed textual layers, with no binary layer to advance the rounds",
        percentEncode(htmlEntities(percentEncode(unicodeEscapes(SECRET)))),
      ],
      [
        "five composed textual layers",
        htmlEntities(percentEncode(htmlEntities(percentEncode(unicodeEscapes(SECRET))))),
      ],

      // -- short values (defect 16) ----------------------------------------
      // Every one of these slipped past a fixed 8-character run floor: a
      // 4-byte secret is 6 base64 characters, and a 2-byte secret is 4.
      ["a 4-character value, base64-encoded", `id=${Buffer.from("2026").toString("base64")}`, "2026"],
      ["a 4-character value, hex-encoded", `id=${hexOf("2026")}`, "2026"],
      ["a 2-character value, base64-encoded", `id=${Buffer.from("hi").toString("base64")}`, "hi"],
      ["a 1-character value, hex-encoded", `id=${hexOf("q")}`, "q"],
      [
        "a 5-character value inside a larger base64 blob",
        Buffer.concat([Buffer.from("abcdefg"), Buffer.from("s3cr7"), Buffer.from("hijklm")]).toString("base64"),
        "s3cr7",
      ],
    ];

    for (const [name, text, secret = SECRET] of cases) {
      it(`refuses ${name}`, () => {
        expect(refuses(secret, text)).toBe(true);
      });
    }
  });

  /**
   * Defect 6. The run scan stripped only whitespace before matching base64,
   * but every real decoder SKIPS out-of-alphabet characters rather than
   * stopping at them. One `*` dropped into a run therefore split it into two
   * halves the guard matched separately and neither carried the value — while
   * a single `Buffer.from(run, "base64")` on the far side put it back together
   * whole, and the value reached `receipt:payload`, `limactl:stderr`,
   * `doctor:*` and `backup:archive`.
   *
   * Each case asserts BOTH halves: that a decoder really does recover the
   * value from the mangled text — otherwise the test proves nothing about a
   * leak — and that the guard refuses it.
   */
  describe("a run stays one run to a decoder, so it stays one run to the guard", () => {
    const encoded = Buffer.from(SECRET).toString("base64");
    const separators = [" ", "\n", "\t", "*", ".", ",", ":", "!", "#", "(", ")", "~", "@", "%", '"', "'", "|"];

    for (const separator of separators) {
      it(`refuses base64 interrupted by ${JSON.stringify(separator)}`, () => {
        const mangled = `${encoded.slice(0, 10)}${separator}${encoded.slice(10)}`;
        // The leak is real: this is the decode any consumer of the sink runs.
        expect(Buffer.from(mangled, "base64").toString("utf8")).toContain(SECRET);
        expect(refuses(SECRET, mangled)).toBe(true);
      });
    }

    it("refuses a run interrupted at every fourth character", () => {
      const mangled = (encoded.match(/.{1,4}/g) ?? []).join("*");
      expect(Buffer.from(mangled, "base64").toString("utf8")).toContain(SECRET);
      expect(refuses(SECRET, mangled)).toBe(true);
    });

    it("refuses a run interrupted between every character", () => {
      const mangled = [...encoded].join("~");
      expect(Buffer.from(mangled, "base64").toString("utf8")).toContain(SECRET);
      expect(refuses(SECRET, mangled)).toBe(true);
    });

    it("refuses a mangled run buried in a larger document", () => {
      const mangled = `${encoded.slice(0, 7)}!${encoded.slice(7)}`;
      expect(refuses(SECRET, JSON.stringify({ note: "guest stdout", blob: mangled, ok: true }))).toBe(true);
    });
  });

  describe("known gaps, asserted so they cannot be mistaken for coverage", () => {
    // These are the honest limits documented on `SecretGuard`. They are
    // asserted as gaps so that a future change that closes one fails loudly
    // here and the docstring gets updated with it. None of them is covered by
    // the guard; all of them are covered structurally instead — the value never
    // enters the data a sink is handed in the first place.

    it("does NOT catch a value split across two fields", () => {
      const half = Math.floor(SECRET.length / 2);
      const text = JSON.stringify({ a: SECRET.slice(0, half), b: SECRET.slice(half) });
      expect(refuses(SECRET, text)).toBe(false);
    });

    it("does NOT catch a value transformed by a keyed or custom alphabet", () => {
      const rot13 = SECRET.replace(/[a-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - 97 + 13) % 26) + 97));
      expect(refuses(SECRET, rot13)).toBe(false);
    });

    it("does NOT catch a case-folded value", () => {
      expect(refuses(SECRET, SECRET.toUpperCase())).toBe(false);
    });

    /**
     * Narrowed again (defect 20a). Binary decoding is now a bounded fixpoint
     * interleaved with the textual one, so three binary layers ARE caught (see
     * the cases above). The honest remaining limit is the bound itself: a stack
     * deeper than `MAX_DECODE_ROUNDS - 1` is not unwound.
     *
     * The bound is what keeps the guard from being its own denial of service,
     * and every extra round multiplies the work on ordinary text. This gap is
     * therefore deliberate, not an oversight — but if the bound is ever raised,
     * this test fails and says so.
     */
    it("does NOT catch a binary encoding stack deeper than the rounds it is bounded to", () => {
      const deep = [1, 2, 3, 4].reduce((text) => Buffer.from(text).toString("base64"), SECRET);
      expect(refuses(SECRET, deep)).toBe(false);
    });

    it("does NOT match a value shorter than the short-value length in a metadata region", () => {
      const guard = createSecretGuard(["2026"]);
      // Asserted so that closing this gap — if a future change finds a way to
      // distinguish a short credential from a timestamp — fails loudly here.
      expect(() => guard.assertClean("test-sink", '{"createdAt":"2026-01-01"}', "metadata")).not.toThrow();
    });

    /**
     * Narrowed by defect 6. Interleaving with anything OUTSIDE the base64
     * alphabet is now caught, because that is what a decoder skips. What
     * remains is interleaving with alphabet characters — which a decoder does
     * NOT skip either, so the two sides agree: `...Z...` is a different value,
     * not a wrapped one, and stripping it would invent matches.
     */
    it("does NOT catch a value re-wrapped with characters INSIDE the base64 alphabet", () => {
      const interleaved = [...Buffer.from(SECRET).toString("base64")].join("Z");
      // A decoder does not recover it either: this is not a leak the guard missed.
      expect(Buffer.from(interleaved, "base64").toString("utf8")).not.toContain(SECRET);
      expect(refuses(SECRET, interleaved)).toBe(false);
    });

    /**
     * The other side of the defect-6 scoping decision. Stripping to the
     * alphabet is applied to the text a sink handed over, its textual decodes
     * and decompressed streams — documents a tool wrote. Applied to bytes
     * recovered from inside a binary layer it invents a document-sized
     * pseudo-run out of arbitrary binary instead of recovering a real one, and
     * that cost is what made a decompression bomb exhaust the budget.
     */
    /**
     * The per-stream cap, asserted as the gap it is. One decompression is
     * bounded to `MAX_DECOMPRESSED_BYTES`, so a value further into the expansion
     * than that is not recovered — the prefix IS scanned, the rest of the text
     * IS scanned, and the report says a stream was truncated, but this one tail
     * is genuinely not looked at.
     *
     * Asserted rather than left implicit because the cap is what keeps 700 KB of
     * guest stdout from becoming gigabytes of host memory: if it is ever raised
     * or removed, this says so instead of the change passing unnoticed.
     */
    it("does NOT catch a value past the first megabyte of an oversized expansion", async () => {
      const head = Buffer.concat([Buffer.alloc(3 * 1024 * 1024, 0x41), Buffer.from(`\n${SECRET}\n`)]);
      const bomb = await streamedGzip(Buffer.alloc(1024 * 1024, 0x42), 6, head);
      const result = scan(bomb.toString("base64"));
      expect(result.refusal).toBeNull();
      // And it is not silent about it.
      expect(result.incomplete[0]?.streamsTruncated).toBeGreaterThan(0);
    });

    it("does NOT catch a run mangled INSIDE a binary layer", () => {
      const encoded = Buffer.from(SECRET).toString("base64");
      const mangled = `${encoded.slice(0, 10)}*${encoded.slice(10)}`;
      expect(refuses(SECRET, mangled)).toBe(true);
      expect(refuses(SECRET, Buffer.from(mangled).toString("base64"))).toBe(false);
    });
  });

  /**
   * Defect 19: dropping the length floor so short values are caught (defect 16)
   * makes a 4-character value like `2026` match every ISO timestamp this system
   * generates. Left unscoped, a receipt append refuses AFTER the credential has
   * been written to the guest, and provisioning can never succeed again — a
   * false positive strictly worse than the leak it was closing.
   */
  describe("short values are scoped to payload bytes so they cannot break provisioning", () => {
    const CALENDAR_YEAR = "2026";
    const envelope = '{"createdAt":"2026-01-01T00:00:00.000Z","kind":"credential","sequence":0}';

    it("does not match a short value against system-generated metadata", () => {
      const guard = createSecretGuard([CALENDAR_YEAR]);
      expect(() => guard.assertClean("receipt:envelope", envelope, "metadata")).not.toThrow();
    });

    it("still matches a short value in payload bytes, which is where a leak would be", () => {
      const guard = createSecretGuard([CALENDAR_YEAR]);
      expect(() => guard.assertClean("receipt:payload", `{"token":"${CALENDAR_YEAR}"}`)).toThrowError(
        /CREDENTIAL_UNSAFE/,
      );
      // And encoded, which is the half defect 16 was about.
      expect(() =>
        guard.assertClean("receipt:payload", `{"blob":"${Buffer.from(CALENDAR_YEAR).toString("base64")}"}`),
      ).toThrowError(/CREDENTIAL_UNSAFE/);
    });

    it("still matches a full-length value in metadata: only SHORT values are scoped out", () => {
      const guard = createSecretGuard([SECRET]);
      expect(() => guard.assertClean("receipt:envelope", `{"nodeName":"${SECRET}"}`, "metadata")).toThrowError(
        /CREDENTIAL_UNSAFE/,
      );
    });

    it("defaults to the strict reading when a sink does not declare a region", () => {
      const guard = createSecretGuard([CALENDAR_YEAR]);
      expect(() => guard.assertClean("test-sink", envelope)).toThrowError(/CREDENTIAL_UNSAFE/);
    });
  });

  /**
   * The bounds, and which way each of them fails.
   *
   * The history is worth keeping because both ends of it were wrong. The budget
   * began as a SILENT ceiling, so a pad in front of an encoded value bought an
   * unscanned write while the operator believed the guard had run. Making
   * exhaustion REFUSE fixed that and created the opposite defect: guest stdout
   * reaches scanned sinks, so a refusal on a self-inflicted bound was a remote,
   * permanent kill switch for `doctor`, `backup` and every receipt append.
   * The version before this one had it both ways at once — the top-level scan
   * refused, the sub-scan of a decompressed stream gave up silently — which is
   * strictly worse than either.
   *
   * Every bound now fails OPEN and every bound REPORTS. These tests hold both
   * halves of that: nothing here may refuse, and everything that could not be
   * scanned must appear in a report.
   */
  describe("bounds itself without refusing, and never quietly", () => {
    /** A refusal that names the budget, distinguished from a real match. */
    function refusalDetails(text: string, secret = SECRET): Record<string, unknown> | null {
      const guard = createSecretGuard([secret], { onIncompleteScan: () => undefined });
      try {
        guard.assertClean("receipt:payload", text);
        return null;
      } catch (error) {
        if (!isYashikiError(error, "CREDENTIAL_UNSAFE")) throw error;
        return { ...error.details };
      }
    }

    /**
     * The most amplifying text found by deliberate search: nested base64 over
     * hex-dense bytes, sprinkled with one newline and one out-of-alphabet
     * character so that all three base64 scan variants — raw,
     * whitespace-stripped, alphabet-stripped — stay distinct and each pays in
     * full. It asks for roughly 66 views per input byte against a bound of 64.
     *
     * Nothing in it is the secret. What it must produce is a REPORT and not a
     * refusal: a guard that returned quietly here would claim success on bytes
     * it never looked at, and a guard that refused here would hand a guest a
     * kill switch for every scanned sink.
     *
     * If a future change makes the report stop firing, the bound has become
     * unreachable and is no longer doing anything — which is a thing to know, so
     * this test is deliberately the canary for it.
     */
    const amplifying = ((): string => {
      const nested = [1, 2, 3].reduce((text) => Buffer.from(text).toString("base64"), fromAlphabet("0123456789abcdef", 150_000, 1));
      return [...nested]
        .map((char, index) => (index % 5001 === 5000 ? `${char}\n` : index % 4997 === 4996 ? `${char}*` : char))
        .join("");
    })();

    it("reports, and does NOT refuse, a text that wants more views than its own length allows", () => {
      expect(amplifying.length).toBeLessThan(1024 * 1024);
      const result = scan(amplifying);
      // The kill switch: 150 KB of guest output must not be able to stop a
      // backup or a receipt append.
      expect(result.refusal).toBeNull();
      expect(result.incomplete).toHaveLength(1);
      expect(result.incomplete[0]).toMatchObject({ sink: "receipt:payload", budgetExhausted: true });
    });

    /**
     * The cost defect 7 added, and the reason textual views are charged too.
     *
     * Feeding textual views back into the frontier is what lets the decoders
     * compose past three layers — but it also means a document that keeps every
     * decoder productive fans out combinatorially: up to
     * `MAX_TEXT_DECODE_ROUNDS * MAX_DECODE_ROUNDS` applications, in any
     * interleaving, each producing a whole new copy of the document.
     *
     * The padding here contains no hex or base64 run at all, so NOTHING but the
     * textual views themselves can account for the cost. Left uncharged this
     * text is scanned silently, and its cost grows with the padding while its
     * length does not — the guard's own denial of service, in the fix for the
     * previous one.
     */
    it("reports a document whose textual decodes fan out past its own length", () => {
      const padding = "!@#$^*()".repeat(10_000);
      const nested = (unit: string, tail: string): string => `${unit.repeat(14)}${tail}`;
      const text = [
        padding,
        nested("%25", "41"),
        padding,
        nested("&#38;", "#65;"),
        padding,
        nested("\\\\", "u0041"),
        padding,
      ].join("|");
      expect(/[0-9a-fA-F]{8}/.test(padding)).toBe(false);
      const result = scan(text);
      expect(result.refusal).toBeNull();
      expect(result.incomplete[0]).toMatchObject({ budgetExhausted: true });
    });

    /**
     * The other side of the same coin, and the one that keeps the pair honest:
     * a report must mean something. An ordinary receipt log — the input the
     * whole availability argument is about — has to scan COMPLETE, with nothing
     * reported at all. Shrink the budget and this goes red; remove the report
     * and the two tests above go red. Neither can mask the other.
     */
    it("reports NOTHING on an ordinary receipt log, so a report means something", () => {
      const result = scan(receiptLog(4000));
      expect(result.refusal).toBeNull();
      expect(result.incomplete).toEqual([]);
    });

    it("reports nothing on a small compressed blob either, so the floor under the budget is real", () => {
      const result = scan(gzipSync(Buffer.from(`clean payload ${"filler-".repeat(200)}`)).toString("base64"));
      expect(result.refusal).toBeNull();
      expect(result.incomplete).toEqual([]);
    });

    it("refuses the padded value the silent ceiling used to hide", () => {
      const pad = `${"A".repeat(2 * 1024 * 1024)} ${Buffer.from(SECRET).toString("base64")}`;
      const details = refusalDetails(pad);
      expect(details).not.toBeNull();
      expect(details?.["sink"]).toBe("receipt:payload");
    });

    /**
     * Defect 8. `base64(gzip(1 MiB of 'A'))` is 1,404 bytes and used to refuse
     * the ENTIRE sink, uncaught at `doctor.ts`, `runtime.ts` and
     * `receipt-store.ts` — so anything whose output reaches a scanned sink
     * (guest stdout is attacker-influenced) could stop `yashiki doctor`,
     * `backup` and every receipt append, from 1.4 KB, indefinitely.
     */
    it("does not let a small decompression bomb refuse the whole sink", () => {
      const bomb = gzipSync(Buffer.alloc(1024 * 1024, 0x41)).toString("base64");
      expect(bomb.length).toBeLessThan(4096);
      expect(refusalDetails(bomb)).toBeNull();
    });

    it("does not let many DISTINCT decompression bombs refuse the whole sink, or take long", () => {
      // Distinct so the guard's view set cannot collapse them into one: forty
      // separate 1 MiB expansions, which is what the stream bound is for.
      const bombs = Array.from({ length: 40 }, (_, index) => {
        const body = Buffer.alloc(1024 * 1024 + 4096, 0x41 + (index % 26));
        body.write(`marker-${index}`);
        return gzipSync(body).toString("base64");
      }).join(" ");
      const started = Date.now();
      expect(refusalDetails(bombs)).toBeNull();
      expect(Date.now() - started).toBeLessThan(5000);
    });

    it("keeps scanning the rest of a text that also contains a bomb", () => {
      const bomb = gzipSync(Buffer.alloc(1024 * 1024, 0x41)).toString("base64");
      const details = refusalDetails(`${bomb} ${Buffer.from(SECRET).toString("base64")}`);
      // A real match: the bomb did not blind the guard to the rest of the text.
      expect(details).toEqual({ sink: "receipt:payload" });
    });

    /**
     * The other half of the same branch, and the one that keeps it honest: an
     * oversized expansion loses its TAIL, not its head. `inflatePrefix`
     * recovers what fits under the cap and that prefix is scanned like any
     * other view, so a value at the front of a bomb is still caught.
     *
     * The bomb is built through a STREAM so the test never holds the expansion
     * itself: it cannot wedge the machine it is protecting.
     */
    it("still scans the head of an expansion too large to hold, so a bomb is not a hiding place", async () => {
      const bomb = await streamedGzip(Buffer.alloc(8 * 1024 * 1024, 0x41), 64, Buffer.from(`${SECRET}\n`));
      expect(refusalDetails(bomb.toString("base64"))).toEqual({ sink: "receipt:payload" });
    });

    it("bounds one decompression, so guest output cannot turn into gigabytes of host memory", async () => {
      const bomb = (await streamedGzip(Buffer.alloc(8 * 1024 * 1024, 0x41), 64)).toString("base64");
      const rssBefore = process.memoryUsage().rss;
      const started = Date.now();
      // 512 MiB expansion. It must neither refuse nor be materialised.
      expect(refusalDetails(bomb)).toBeNull();
      const grewMiB = (process.memoryUsage().rss - rssBefore) / (1024 * 1024);
      // Deliberately loose so it measures the bomb, not allocator noise.
      expect(grewMiB).toBeLessThan(256);
      expect(Date.now() - started).toBeLessThan(10_000);
    });

    /**
     * The number of streams one call will open is bounded, and reaching that
     * bound stops unpacking rather than refusing. This asserts the GAP as well
     * as the bound: past it, streams are not unpacked and a value inside one is
     * not found. Doing that quietly is the deliberate choice — the alternative
     * is refusing the sink, which is defect 8 again.
     */
    it("stops unpacking past a bounded number of streams, without refusing", () => {
      const stream = (marker: string): string =>
        gzipSync(Buffer.from(`${marker}\n${"filler-".repeat(140 * 1024)}`)).toString("base64");
      const decoys = Array.from({ length: 12 }, (_, index) => stream(`decoy-${index}`));

      // In the first stream, the value is found.
      expect(refusalDetails([stream(SECRET), ...decoys].join(" "))).toEqual({ sink: "receipt:payload" });
      // Past the bound it is not — and, crucially, the sink is not refused.
      expect(refusalDetails([...decoys, stream(SECRET)].join(" "))).toBeNull();
    });

    /**
     * Defect 9. A receipt log is append-only — `packages/receipts/src/store.ts`
     * has no delete path — so a fixed per-call ceiling was a size at which a
     * node's backup began to fail and could never succeed again.
     *
     * `receiptLog` gives every row a DISTINCT fingerprint. The test this
     * replaces used `"a".repeat(64)` for all 4000 of them, which collapses to a
     * single entry in the guard's `seen` set: it measured one row's cost 4000
     * times over and passed against the very ceiling it was supposed to rule
     * out. Distinctness is what makes the input real.
     */
    it("scans a receipt log past the size the old fixed ceiling refused", () => {
      const log = receiptLog(4000);
      expect(log.length).toBeGreaterThan(900_000);
      expect(refusalDetails(log)).toBeNull();
    });

    it("keeps scanning a receipt log as it grows, because there is no delete path", () => {
      const log = receiptLog(10_000);
      expect(log.length).toBeGreaterThan(2 * 1024 * 1024);
      expect(refusalDetails(log)).toBeNull();
    }, 15_000);

    it("still finds the value inside a receipt log far past the old ceiling", () => {
      const log = receiptLog(10_000).replace('"sequence":9999', `"sequence":"${SECRET}"`);
      expect(refusalDetails(log)).toEqual({ sink: "receipt:payload" });
    }, 15_000);

    /**
     * Windowing is what makes "no size limit" possible, and the overlap is what
     * keeps it from being a hole: a value lying across a window boundary — raw
     * or encoded — must still be found.
     */
    it("finds a value straddling a scan-window boundary", () => {
      const head = "x".repeat(1024 * 1024 - 10);
      expect(refusalDetails(`${head}${SECRET}${"y".repeat(4096)}`)).toEqual({ sink: "receipt:payload" });
    });

    it("finds an ENCODED value straddling a scan-window boundary", () => {
      const head = "x".repeat(1024 * 1024 - 10);
      const encoded = Buffer.from(SECRET).toString("base64");
      expect(refusalDetails(`${head}${encoded}${"y".repeat(4096)}`)).toEqual({ sink: "receipt:payload" });
    });

    /**
     * Bounding the total expansion, not just the number of streams.
     *
     * Sixty-four streams each expanding to a megabyte is half a minute of CPU
     * bought with forty kilobytes of guest output. The count bound never touched
     * that, and the input below is the cheapest way to ask for it.
     */
    it("bounds the TOTAL expansion it will scan, so many bombs cost a constant, not a multiple", () => {
      const bombs = Array.from({ length: 40 }, (_, index) => {
        const body = Buffer.alloc(1024 * 1024 + 4096, 0x41 + (index % 26));
        body.write(`marker-${index}`);
        return gzipSync(body).toString("base64");
      }).join(" ");
      const started = Date.now();
      const result = scan(bombs);
      expect(result.refusal).toBeNull();
      expect(Date.now() - started).toBeLessThan(5000);
      // And it said so, rather than quietly stopping.
      expect(result.incomplete[0]?.streamsSkipped).toBeGreaterThan(0);
    });

    /**
     * The sub-scan of a decompressed stream used to be the silent half of the
     * split: it abandoned a view and told nobody, while the top-level scan
     * refused the sink. Both directions were wrong at once. A tail the guard
     * could not see is now a reported fact.
     */
    it("reports the tail of an oversized expansion instead of losing it silently", async () => {
      const bomb = await streamedGzip(Buffer.alloc(8 * 1024 * 1024, 0x41), 8);
      const result = scan(bomb.toString("base64"));
      expect(result.refusal).toBeNull();
      expect(result.incomplete[0]?.streamsTruncated).toBeGreaterThan(0);
    });

    /**
     * The shape reported as the second half of the kill switch: a gzip blob with
     * an incompressible head and a large tail. Whatever it costs, it must not
     * cost the sink.
     */
    it("does not let an incompressible-head bomb refuse the sink", () => {
      const head = Buffer.alloc(96 * 1024);
      // A deterministic xorshift, so the head is incompressible without `Math.random`.
      let state = 0x12345678;
      for (let index = 0; index < head.length; index += 1) {
        state ^= state << 13;
        state >>>= 0;
        state ^= state >>> 17;
        state ^= state << 5;
        state >>>= 0;
        head[index] = state & 0xff;
      }
      const blob = gzipSync(Buffer.concat([head, Buffer.alloc(2 * 1024 * 1024, 0x41)])).toString("base64");
      expect(blob.length).toBeGreaterThan(100_000);
      expect(scan(blob).refusal).toBeNull();
    });

    /**
     * Defect 10. A `{2,}` quantifier over a multi-megabyte alphanumeric run
     * overflowed irregexp's backtrack stack and threw `RangeError` — an
     * unclassified crash. Whatever the guard decides here, it must decide it as
     * a `YashikiError` — never as a stray `RangeError` a caller has no
     * classification for.
     *
     * Two independent things now hold this: the run scan is a linear
     * hand-rolled walk with no backtrack stack to overflow, and windowing means
     * no scan ever sees more than `SCAN_WINDOW` characters at once. Either
     * alone is sufficient — reverting one leaves this green — so read the pair
     * as belt and braces, not as one protection tested twice.
     */
    it("does not crash on a multi-megabyte alphanumeric run", () => {
      const run = "a".repeat(6 * 1024 * 1024);
      const guard = createSecretGuard([SECRET], { onIncompleteScan: () => undefined });
      try {
        guard.assertClean("receipt:payload", run);
      } catch (error) {
        // A refusal is acceptable; a RangeError is not.
        expect(isYashikiError(error, "CREDENTIAL_UNSAFE")).toBe(true);
      }
    });

    it("still scans an ordinary document without tripping the budget", () => {
      // Bigger than any receipt, archive or report this system writes, and
      // dense in the hex a fingerprint is made of: a guard that refused here
      // would be unusable.
      const document = JSON.stringify({
        rows: Array.from({ length: 4000 }, (_, index) => ({
          index,
          fingerprint: Buffer.from(`row-${index}`).toString("hex").padEnd(64, "0"),
        })),
      });
      expect(document.length).toBeGreaterThan(300_000);
      expect(refusalDetails(document)).toBeNull();
    });
  });

  /**
   * Windowing, and the two independent things that keep a boundary from being a
   * hole. Every claim in this block was GREEN when the code implementing it was
   * deleted, which is the same as not having been tested at all.
   */
  describe("the window boundary", () => {
    /**
     * Windowing itself. Forcing `scanWindows` to yield the whole text as one
     * window left all 108 tests passing: the entire bounded-memory story rested
     * on nothing. This is the test that holds it, and it holds the property
     * directly — a bounded window size, more than one of them, and every part of
     * the text inside one of them — rather than trying to infer it from timing.
     */
    it("cuts a long text into bounded, overlapping windows that between them cover all of it", () => {
      const marker = (index: number): string => `marker-${index}-marker`;
      const stride = 100_000;
      const count = 30;
      const text = Array.from({ length: count }, (_, index) =>
        `${marker(index)}${"!".repeat(stride - marker(index).length)}`,
      ).join("");
      expect(text.length).toBe(count * stride);

      const windows = [...scanWindows(text, SECRET.length)];
      expect(windows.length).toBeGreaterThan(1);
      for (const window of windows) {
        expect(window.length).toBeLessThanOrEqual(SCAN_WINDOW + MAX_WINDOW_EXTENSION);
      }
      for (let index = 0; index < count; index += 1) {
        expect(windows.some((window) => window.includes(marker(index)))).toBe(true);
      }
    });

    /**
     * A run is never cut, and no overlap size can substitute for that.
     *
     * A compressed stream sliced in two inflates in NEITHER half — the head has
     * no trailer, the tail has no header — so it is not enough for both halves
     * to be scanned somewhere. The stream has to be whole in some window, which
     * is what snapping the boundary past the run buys. Reproduced from 2,840
     * characters of payload upwards.
     */
    it("keeps a compressed stream whole across a window boundary, which no overlap can do", () => {
      const body = noisyText(60_000, 0x5eed);
      const blob = gzipSync(Buffer.from(`${body}\n${SECRET}\n`)).toString("base64");
      // Comfortably more than twice the 7,128-character overlap, so half of it
      // sticking out past the boundary is more than any overlap here reaches.
      expect(blob.length).toBeGreaterThan(40_000);
      // Neither half of the stream carries the value on its own: this is the
      // case the overlap cannot reach.
      const half = Math.floor(blob.length / 2);
      expect(refuses(SECRET, `[ ${blob.slice(0, half)} ]`)).toBe(false);
      expect(refuses(SECRET, `[ ${blob.slice(half)} ]`)).toBe(false);

      expect(scan(acrossWindowBoundary(blob, half)).refusal).toEqual({ sink: "receipt:payload" });
    });

    /**
     * The overlap MULTIPLE, isolated.
     *
     * It used to be eight — hex-of-hex-of-hex — which counted only the binary
     * layers. `percentEncode(unicodeEscapes(v))` is eighteen times the value's
     * length on its own, so a 168-character secret written that way straddled
     * the boundary and landed wholly inside neither window.
     *
     * The placement is hard-coded rather than derived from `OVERLAP_EXPANSION`,
     * because a test that recomputes its own input from the constant it is
     * testing cannot fail when the constant changes.
     */
    it("covers an encoded form far longer than the value, at the boundary", () => {
      const long = "dummy-not-a-real-credential-".repeat(6);
      expect(long.length).toBe(168);
      const encoded = percentEncode(unicodeEscapes(long));
      expect(encoded.length).toBe(3024);
      expect(scan(acrossWindowBoundary(encoded, 3000), long).refusal).toEqual({ sink: "receipt:payload" });
    });

    /**
     * Defect 22. The multiple was `6 ** 3` — one decode round's worth of
     * textual layers — while the decoder peels `MAX_TEXT_DECODE_ROUNDS *
     * MAX_DECODE_ROUNDS` of them, because a textual view is fed back into the
     * next round. Everything between those two exponents was caught INLINE and
     * missed at a boundary, silently, which is the worst possible pair: the
     * guard demonstrably understands the encoding and still walks past it.
     *
     * Stated once, here, rather than inside the cases below: a case that derives
     * its own input from the constant it is testing cannot go red when the
     * constant changes.
     */
    it("sizes the overlap for every textual layer the decoder actually peels", () => {
      expect(OVERLAP_EXPANSION).toBe(6 ** 12);
      // The product exceeds the clamp for any value of one character or more,
      // so the clamp IS the overlap and the old floor could never bind again.
      expect(MAX_OVERLAP).toBe(SCAN_WINDOW >> 1);
      expect(overlapFor(SECRET.length)).toBe(MAX_OVERLAP);
      expect(overlapFor(4)).toBe(MAX_OVERLAP);
      expect(overlapFor(1)).toBe(MAX_OVERLAP);
    });

    it("needs the overlap for a long value's composed encoding", () => {
      const encoded = percentEncode(htmlEntities(percentEncode(unicodeEscapes(SECRET))));
      expect(encoded.length).toBeGreaterThan(5000);
      expect(scan(acrossWindowBoundary(encoded, 5000)).refusal).toEqual({ sink: "receipt:payload" });
    });

    it("needs the overlap for a SHORT value's composed encoding too", () => {
      const short = "d4v3";
      const encoded = percentEncode(htmlEntities(percentEncode(unicodeEscapes(short))));
      expect(encoded.length).toBe(1080);
      expect(scan(acrossWindowBoundary(encoded, 1000), short).refusal).toEqual({ sink: "receipt:payload" });
    });

    /**
     * The case that separates the old exponent from the new one, and the reason
     * it is stated as INLINE-VERSUS-BOUNDARY rather than as a length: whatever
     * the guard can peel where it sits, it must also peel across a boundary.
     * Five textual layers — 16,038 characters — is inside the twelve the decoder
     * composes and outside the three the overlap used to assume.
     */
    it("catches at a boundary every composed encoding it catches inline", () => {
      const encoded = [1, 2, 3, 4].reduce((text) => percentEncode(text), unicodeEscapes(SECRET));
      expect(encoded.length).toBe(16_038);
      expect(encoded.length).toBeGreaterThan(SECRET.length * 216);
      // Inline: the decoder demonstrably understands this stack.
      expect(refuses(SECRET, encoded)).toBe(true);
      // And at a boundary, which is the half that used to be missed in silence.
      const straddling = scan(acrossWindowBoundary(encoded, 16_000));
      expect(straddling.refusal).toEqual({ sink: "receipt:payload" });
    });
  });

  /**
   * Defect 6 of this round. `stringsFromBytes` spent one of the shared
   * decompression attempts on EVERY buffer of ten bytes or more, before looking
   * at whether the buffer was a compressed stream at all. Roughly twenty
   * ordinary base64 tokens — 500 bytes, no attacker involved — used the whole
   * allowance up, and every gzip stream later in the same text was silently
   * never decompressed: the guard failed open after half a kilobyte of prefix.
   */
  describe("the decompression allowance is spent on containers, not on everything", () => {
    const bomb = gzipSync(Buffer.from(`${SECRET}\n`)).toString("base64");

    it("still decompresses a stream that follows an ordinary receipt log", () => {
      // The control, so a failure below cannot be blamed on the stream itself.
      expect(refuses(SECRET, bomb)).toBe(true);
      const prefix = receiptLog(200);
      expect(prefix.length).toBeGreaterThan(30_000);
      expect(refuses(SECRET, `${prefix} ${bomb}`)).toBe(true);
    });

    it("still decompresses a stream that follows a run of innocuous base64 tokens", () => {
      const tokens = Array.from({ length: 200 }, (_, index) =>
        Buffer.from(`session-token-${index}-abcdefgh`).toString("base64"),
      ).join(" ");
      expect(refuses(SECRET, `${tokens} ${bomb}`)).toBe(true);
    });

    /**
     * Defect 11, the reported shape exactly: seventy gzip streams of five bytes
     * each — 2.6 KB of base64, cheaper to build than one receipt row — spent an
     * allowance of 64 and the stream behind them was never opened. The COUNT was
     * never what bounded the cost; `MAX_INFLATED_BYTES` is, and seventy
     * five-byte expansions charge 350 bytes against four megabytes.
     */
    it("is not spent by a pad of tiny streams in front of the real one", () => {
      const pad = Array.from({ length: 70 }, (_, index) =>
        gzipSync(Buffer.from(`pad-${index}`)).toString("base64"),
      ).join(" ");
      expect(pad.length).toBeLessThan(4096);
      expect(refuses(SECRET, `${pad} ${bomb}`)).toBe(true);
    });
  });

  /**
   * Defect 11. The file claimed, in the paragraph that justifies failing open at
   * all, that "the pad and the value are in different windows, each with its own
   * budget, and the pad cannot spend the value's". The AMPLIFICATION budget was
   * per window; the STREAM ALLOWANCES were per call, and said so forty lines
   * further down. So a pad at the head of a multi-megabyte write blinded
   * decompression for every window after it, and the archive that write produced
   * kept the value in plaintext, permanently, in a log with no delete path.
   */
  describe("the stream allowances are per window, so a pad cannot blind a later one", () => {
    /**
     * Enough tiny streams to spend the whole container allowance, packed into
     * the FIRST window only. Built as tokens rather than one blob so each is a
     * separate run with its own header — which is what makes each one an
     * attempt.
     */
    const spendingPad = Array.from({ length: 1200 }, (_, index) =>
      gzipSync(Buffer.from(`pad-${index}`)).toString("base64"),
    ).join(" ");

    it("opens a stream in a later window after a pad exhausted the first window's allowance", () => {
      const bomb = gzipSync(Buffer.from(`${SECRET}\n`)).toString("base64");
      const filler = "!".repeat(SCAN_WINDOW - spendingPad.length + 4096);
      const text = `${spendingPad}${filler} ${bomb} `;
      // The pad is inside window 0 and the stream is past it, so only a
      // per-window allowance can still open the stream.
      expect(spendingPad.length).toBeLessThan(SCAN_WINDOW);
      expect(text.indexOf(bomb)).toBeGreaterThan(SCAN_WINDOW);
      const result = scan(text);
      expect(result.refusal).toEqual({ sink: "receipt:payload" });
    });

    /**
     * And the report is emitted even though the call ended in a refusal. It used
     * to be built after the window loop, which `refuse` throws out of: a scan
     * that hit a bound in window 0 and matched in a later one told the operator
     * nothing about the part it had abandoned — the one scan where the caveats
     * matter most.
     */
    it("still reports what it abandoned when a later window refuses", () => {
      const bomb = gzipSync(Buffer.from(`${SECRET}\n`)).toString("base64");
      const filler = "!".repeat(SCAN_WINDOW - spendingPad.length + 4096);
      const result = scan(`${spendingPad}${filler} ${bomb} `);
      expect(result.refusal).not.toBeNull();
      expect(result.incomplete).toHaveLength(1);
      expect(result.incomplete[0]?.streamsSkipped).toBeGreaterThan(0);
    });
  });

  /**
   * Defect 12. `containersFor` read `bytes[0]` and `bytes[1]` and nothing else,
   * so a stream that did not begin at byte zero of a decoded buffer was
   * invisible — and invisible with an empty report, while the header of this
   * file claimed gzip/zlib/raw-deflate decoding unconditionally. A base64 run is
   * retried at four CHARACTER alignments, which shifts by six bits; it never
   * recovers a one-BYTE displacement.
   */
  describe("a compressed stream is found wherever in the bytes it starts", () => {
    const stream = gzipSync(Buffer.from(`${SECRET}\n`));

    for (const prefix of [1, 3, 4, 16, 32, 33]) {
      it(`finds a gzip stream ${prefix} bytes into the buffer`, () => {
        const bytes = Buffer.concat([Buffer.alloc(prefix, 0x42), stream]);
        expect(refuses(SECRET, bytes.toString("base64"))).toBe(true);
      });
    }

    it("finds a zlib stream at a non-zero offset", () => {
      const bytes = Buffer.concat([Buffer.alloc(3, 0x42), deflateSync(Buffer.from(`${SECRET}\n`))]);
      expect(refuses(SECRET, bytes.toString("base64"))).toBe(true);
    });

    /**
     * The other end of the same buffer. `gunzipSync` reads whatever follows a
     * complete member as a second member and throws `Z_DATA_ERROR`, and
     * `Z_SYNC_FLUSH` does not change that — so 64 bytes of trailing junk hid the
     * stream just as effectively as one leading byte, and the old code answered
     * that failure by giving up.
     */
    it("finds a gzip stream with junk behind it", () => {
      const bytes = Buffer.concat([stream, Buffer.alloc(64, 0x41)]);
      expect(refuses(SECRET, bytes.toString("base64"))).toBe(true);
    });

    it("finds a gzip stream with junk at both ends", () => {
      const bytes = Buffer.concat([Buffer.alloc(7, 0x42), stream, Buffer.alloc(64, 0x41)]);
      expect(refuses(SECRET, bytes.toString("base64"))).toBe(true);
    });

    /** The control: offset scanning must not have cost the ordinary case. */
    it("still finds one at offset zero, with nothing around it", () => {
      expect(refuses(SECRET, stream.toString("base64"))).toBe(true);
    });
  });

  /**
   * Defect 21. The header said "EVERY ONE OF THOSE BOUNDS FAILS OPEN, AND EVERY
   * ONE OF THEM IS REPORTED", which was false for three of them at once. These
   * are the two that are now reported, and the one that is documented as silent.
   */
  describe("the bounds that used to fail open in silence", () => {
    it("reports that the decode rounds ran out with a layer left to peel", () => {
      const stacked = [1, 2, 3, 4].reduce((text) => Buffer.from(text).toString("base64"), SECRET);
      const result = scan(stacked);
      // Still not caught — that is the documented depth gap — but no longer
      // caught-or-not indistinguishably.
      expect(result.refusal).toBeNull();
      expect(result.incomplete[0]).toMatchObject({ sink: "receipt:payload", depthExhausted: true });
    });

    it("says nothing about depth on a stack it did peel", () => {
      const stacked = [1, 2, 3].reduce((text) => Buffer.from(text).toString("base64"), SECRET);
      expect(scan(stacked).refusal).toEqual({ sink: "receipt:payload" });
      const clean = [1, 2, 3].reduce((text) => Buffer.from(text).toString("base64"), "nothing to see here");
      expect(scan(clean).incomplete).toEqual([]);
    });

    /**
     * `MAX_WINDOW_EXTENSION` cuts a run that is longer than a window plus the
     * extension. A compressed stream cut in two inflates in neither half, so
     * this is a genuine blind spot — and it used to be one nobody was told
     * about. The run here is deliberately one unbroken base64 run.
     */
    it("reports a run too long for any window to keep whole", () => {
      const run = "A".repeat(SCAN_WINDOW + MAX_WINDOW_EXTENSION + 4096);
      const result = scan(run);
      expect(result.refusal).toBeNull();
      expect(result.incomplete[0]).toMatchObject({ runsTruncated: 1 });
    });

    it("says nothing about runs when every one of them fits in a window", () => {
      const run = `${"A".repeat(SCAN_WINDOW - 16)} ${"B".repeat(4096)}`;
      expect(scan(run).incomplete).toEqual([]);
    });
  });

  /**
   * The property the reviewer found holding by accident, pinned so a future
   * change cannot lose it quietly.
   *
   * Nine amplification bombs, each followed by the value in one, two or three
   * layers of base64 IN THE SAME WINDOW, were all still refused. The reason is
   * structural: ROUND ZERO is the round that decodes the given text's own runs,
   * and round zero's worst-case cost fits inside `DECODE_AMPLIFICATION`, so a
   * budget that runs out runs out in a later round. Raise
   * `MAX_TEXT_DECODE_ROUNDS` to four and the textual term goes from 39 to 120,
   * the relationship is destroyed, and — without this — nothing goes red.
   */
  describe("round zero fits inside the budget, which is why a bomb cannot hide a value beside it", () => {
    it("keeps the round-zero cost inside the amplification bound", () => {
      expect([ROUND_ZERO_AMPLIFICATION, DECODE_AMPLIFICATION]).toEqual([66, 64]);
      expect(ROUND_ZERO_AMPLIFICATION).toBeLessThanOrEqual(DECODE_AMPLIFICATION * ROUND_ZERO_HEADROOM);
    });

    const base64Bomb = (bytes: number): string => {
      const nested = [1, 2, 3].reduce((text) => Buffer.from(text).toString("base64"), fromAlphabet("0123456789abcdef", bytes, 1));
      return [...nested]
        .map((char, index) => (index % 5001 === 5000 ? `${char}\n` : index % 4997 === 4996 ? `${char}*` : char))
        .join("");
    };
    const textualBomb = (reps: number): string => {
      const padding = "!@#$^*()".repeat(reps);
      return [padding, "%25".repeat(14) + "41", padding, "&#38;".repeat(14) + "#65;", padding].join("|");
    };

    const bombs: [name: string, text: string][] = [
      ["base64 40K", base64Bomb(40_000)],
      ["base64 80K", base64Bomb(80_000)],
      ["base64 150K", base64Bomb(150_000)],
      ["textual 4K", textualBomb(4_000)],
      ["textual 15K", textualBomb(15_000)],
      ["both", `${base64Bomb(80_000)}|${textualBomb(8_000)}`],
    ];

    const layered = (layers: number): string =>
      Array.from({ length: layers }).reduce<string>((text) => Buffer.from(text).toString("base64"), SECRET);

    for (const [name, bomb] of bombs) {
      it(`still refuses the value beside the ${name} bomb, however much budget it burned`, () => {
        const text = `${bomb} ${layered(1)} `;
        // One window, so the locality of the budget is not what is doing the
        // work here: the bomb and the value share a budget and the value wins.
        expect(text.length).toBeLessThan(SCAN_WINDOW);
        expect(refuses(SECRET, text)).toBe(true);
      });

      /**
       * Round zero decodes the text's own runs, so ONE layer is the property
       * above. A second layer needs round one, which a bomb genuinely can
       * starve — and the honest claim there is not "still caught" but "never
       * silently missed". Asserted, because the difference between those two is
       * the whole reason `onIncompleteScan` exists.
       */
      for (const layers of [2, 3]) {
        it(`refuses or REPORTS ${layers} base64 layers of the value beside the ${name} bomb`, () => {
          const result = scan(`${bomb} ${layered(layers)} `);
          expect(result.refusal !== null || result.incomplete.length > 0).toBe(true);
        });
      }
    }
  });

  /**
   * Defect 10 of this round. The comparison was an exact `String.includes`, so
   * every one of these reached the sink. NFC-versus-NFD is the one that matters:
   * `JSON.stringify` round-trips either form unchanged, and a shell, an HTTP
   * server and a macOS filesystem all treat the two as the same string, so it is
   * a way through that needs no encoding at all.
   */
  describe("a value is matched in the form a system would treat as the same string", () => {
    const ACCENTED = "dummy-crédential-not-real";

    it("matches an NFD-decomposed value against an NFC needle", () => {
      const decomposed = ACCENTED.normalize("NFD");
      expect(decomposed).not.toBe(ACCENTED);
      expect(refuses(ACCENTED, JSON.stringify({ token: decomposed }))).toBe(true);
    });

    it("matches an NFC value against an NFD needle, in the other direction too", () => {
      expect(refuses(ACCENTED.normalize("NFD"), JSON.stringify({ token: ACCENTED }))).toBe(true);
    });

    const invisibles: [name: string, char: string][] = [
      ["a zero-width space", "\u200b"],
      ["a zero-width joiner", "\u200d"],
      ["a zero-width non-joiner", "\u200c"],
      ["a soft hyphen", "\u00ad"],
      ["a byte-order mark", "\ufeff"],
    ];
    for (const [name, char] of invisibles) {
      it(`matches a value interrupted by ${name}`, () => {
        const split = `${SECRET.slice(0, 12)}${char}${SECRET.slice(12)}`;
        expect(split).not.toContain(SECRET);
        expect(refuses(SECRET, `token=${split}`)).toBe(true);
      });
    }

    it("matches a fullwidth rendering of the value", () => {
      const value = "dummyvalue1234";
      const fullwidth = [...value].map((char) => String.fromCharCode(char.charCodeAt(0) + 0xfee0)).join("");
      expect(fullwidth).not.toContain(value);
      expect(refuses(value, `token=${fullwidth}`)).toBe(true);
    });

    it("does not start refusing ordinary clean text", () => {
      const guard = createSecretGuard([SECRET, ACCENTED]);
      expect(() => guard.assertClean("test-sink", "doctor work-grammarxiv: ok — 3 probes")).not.toThrow();
    });
  });

  /**
   * `inflatePrefix` used to HALVE the compressed input until the expansion fit,
   * which recovers whatever the first fitting halving happens to give. For a
   * stream expanding to eight times the cap that is one sixteenth of it, so a
   * value at 900,000 bytes of expansion was missed under a cap of 1,048,576 —
   * contradicting the limit the file documents. A binary search lands on the
   * largest prefix that fits, so the documented limit is the real one.
   */
  it("recovers a prefix close to the cap, so the documented limit is the real one", async () => {
    // Built through a stream: the test never holds the 8 MiB expansion itself.
    const head = Buffer.concat([Buffer.alloc(900_000, 0x41), Buffer.from(`\n${SECRET}\n`)]);
    // Roughly 8.9 MB of expansion against a cap of 1,048,576: halving overshoots
    // to an eighth of the input and recovers about half the cap, which lands
    // short of the value. The binary search does not.
    const bomb = await streamedGzip(Buffer.alloc(1024 * 1024, 0x42), 8, head);
    expect(scan(bomb.toString("base64")).refusal).toEqual({ sink: "receipt:payload" });
  });

  /**
   * Defect 23, second half. `onIncompleteScan` was optional and defaulted to
   * NOTHING, so `createSecretGuard()` — which is what `createRuntime`'s fallback
   * and `CredentialMaterializer` both call — was a guard that could reach a
   * bound with nobody told. The shipped CLI escaped that only by construction.
   * The default is now a line on stderr, and the report carries counts and a
   * sink name and never a fragment of the text.
   */
  describe("a guard built with no options is still not silent", () => {
    it("writes the report to stderr when nobody supplied an observer", () => {
      const written: string[] = [];
      const original = process.stderr.write.bind(process.stderr);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      process.stderr.write = ((chunk: any): boolean => {
        written.push(String(chunk));
        return true;
      }) as typeof process.stderr.write;
      try {
        const guard = createSecretGuard([SECRET]);
        guard.assertClean("receipt:payload", [1, 2, 3, 4].reduce((text) => Buffer.from(text).toString("base64"), SECRET));
      } finally {
        process.stderr.write = original;
      }
      expect(written.join("")).toContain("could not fully scan receipt:payload");
      // The report is a report, not a second sink.
      expect(written.join("")).not.toContain(SECRET);
    });

    it("returns what it abandoned to the caller, so a persisting sink can act on it", () => {
      const guard = createSecretGuard([SECRET], { onIncompleteScan: () => undefined });
      const stacked = [1, 2, 3, 4].reduce((text) => Buffer.from(text).toString("base64"), SECRET);
      expect(guard.assertClean("backup:item:x", stacked)).toMatchObject({ depthExhausted: true });
      expect(guard.assertClean("backup:item:x", "nothing interesting here")).toBeNull();
    });
  });

  it("reads decompressed bytes as UTF-16LE as well as UTF-8", () => {
    // A value written out as UTF-16 and then compressed is invisible in the
    // UTF-8 reading of the same bytes, and no later stage recovers it.
    const blob = gzipSync(Buffer.from(SECRET, "utf16le")).toString("base64");
    expect(refuses(SECRET, blob)).toBe(true);
  });

  it("decodes the named HTML entities a serialiser emits", () => {
    // Numeric entities are decoded by a different branch, so this case is the
    // only thing holding the named table up.
    const escaped = SYMBOL_SECRET.replace(/&/g, "&amp;").replace(/'/g, "&apos;");
    expect(escaped).not.toContain(SYMBOL_SECRET);
    expect(refuses(SYMBOL_SECRET, escaped)).toBe(true);
  });

  describe("populating the guard", () => {
    it("guards a value shorter than any plausible minimum instead of silently ignoring it", () => {
      const guard = createSecretGuard();
      guard.remember("short12");
      expect(guard.size).toBe(1);
      expect(() => guard.assertClean("test-sink", "value=short12")).toThrowError(/CREDENTIAL_UNSAFE/);
    });

    it("refuses an empty value loudly rather than no-opping", () => {
      const guard = createSecretGuard();
      expect(() => guard.remember("")).toThrowError(/CONFIG_INVALID/);
      expect(guard.size).toBe(0);
    });

    it("reports its own blindness through `size`", () => {
      const guard = createSecretGuard();
      expect(guard.size).toBe(0);
      // An empty guard cannot catch anything; callers must check, not hope.
      expect(() => guard.assertClean("test-sink", SECRET)).not.toThrow();
      guard.remember(SECRET);
      expect(guard.size).toBe(1);
      expect(() => guard.assertClean("test-sink", SECRET)).toThrowError(/CREDENTIAL_UNSAFE/);
    });

    it("counts distinct values only", () => {
      const guard = createSecretGuard([SECRET, SECRET, PEM]);
      expect(guard.size).toBe(2);
    });
  });

  describe("refusal shape", () => {
    it("never names the value, the encoding or the offset", () => {
      const guard = createSecretGuard([SECRET]);
      try {
        guard.assertClean("doctor:render", `leak ${Buffer.from(SECRET).toString("base64")}`);
      } catch (error) {
        if (!isYashikiError(error, "CREDENTIAL_UNSAFE")) throw error;
        expect(error.message).not.toContain(SECRET);
        expect(error.message).not.toContain(Buffer.from(SECRET).toString("base64"));
        expect(error.message).toContain("doctor:render");
        expect(error.details).toEqual({ sink: "doctor:render" });
        return;
      }
      throw new Error("expected a refusal");
    });
  });

  describe("clean text still passes", () => {
    const guard = createSecretGuard([SECRET, PEM]);

    const clean = [
      "doctor work-grammarxiv: ok",
      "  [ok  ] Credential claude: present, owner meidoya, mode 0600",
      JSON.stringify({ provider: "codex", valueFingerprint: "f".repeat(64), sourceRef: "keychain:codex" }),
      JSON.stringify({ mounts: ["/workspace/x"], artifactSha256: "a".repeat(64) }),
      "limactl 1.0.0",
    ];

    for (const text of clean) {
      it(`passes ${JSON.stringify(text.slice(0, 40))}`, () => {
        expect(() => guard.assertClean("test-sink", text)).not.toThrow();
      });
    }

    it("stays fast on a large clean document", () => {
      // Distinct hashes: a document of 2000 identical rows collapses to one
      // entry in the guard's view set and measures nothing about 2000 rows.
      const big = JSON.stringify({
        rows: Array.from({ length: 2000 }, (_, i) => ({ i, hash: Buffer.from(`row-${i}`).toString("hex").padEnd(64, "0") })),
      });
      const started = Date.now();
      expect(() => guard.assertClean("test-sink", big)).not.toThrow();
      expect(Date.now() - started).toBeLessThan(5000);
    });
  });

  it("the noop guard is inert by construction", () => {
    expect(() => noopSecretGuard.assertClean("test-sink", SECRET)).not.toThrow();
  });
});
