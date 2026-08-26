import { constants, gunzipSync, inflateRawSync, inflateSync, type ZlibOptions } from "node:zlib";
import { YashikiError } from "./errors.js";

/**
 * Runtime tripwire for 11 section 7 and section 9.
 *
 * WHAT THIS IS NOT
 * ----------------
 * This guard is NOT the mechanism that keeps credentials out of sinks. The
 * primary guarantee is structural, and it is the only one that is complete:
 *
 *   - the guest write path never puts a value on a command line; it is streamed
 *     on stdin and referenced positionally (`$1 $2 $3`) inside the guest script,
 *   - a credential receipt carries a domain-salted fingerprint and never the
 *     value,
 *   - every Doctor probe observes presence and file attributes only; no probe
 *     ever reads a credential file's contents,
 *   - `YashikiError.details` is typed to scalars the caller assembled by hand,
 *     with no `cause` chain that could drag a value along.
 *
 * A value that never enters the data a sink is handed cannot be printed, and no
 * amount of scanning is needed to prove it.
 *
 * WHAT THIS IS
 * ------------
 * Defence in depth for the case where the structural rule is broken by a future
 * change: the guard is told which values are in flight in this process, and
 * every sink hands it the exact bytes it is about to write. If a remembered
 * value is recoverable from those bytes, the write is refused.
 *
 * HOW IT LOOKS
 * ------------
 * Enumerating the encodings a secret might arrive in cannot be made complete —
 * a secret embedded at an arbitrary offset inside a larger base64 blob has no
 * single aligned encoding to compare against, so needle-side enumeration is
 * structurally lost before it starts. The guard therefore works the other way
 * round: it NORMALISES THE HAYSTACK — decoding the text it was handed back
 * towards plaintext through the transports a serialiser or a shell plausibly
 * applies — and then looks for the raw value in each decoded view.
 *
 * Decoded views cover: JSON/backslash escaping (`\n`, `\"`, `\uXXXX`, `\xNN`,
 * octal), HTML numeric and basic named entities, percent-encoding in either
 * hex case, and any composition of those three; hex runs in either case;
 * base64/base64url runs at all four character alignments (so an offset inside a
 * larger blob is recovered); the same runs after separator characters are
 * stripped AND after every out-of-alphabet character is stripped, so `openssl
 * base64`'s 76-column wrapping, colon-separated hexdumps and a single `*`
 * dropped into the middle of a blob are all not a way through; the bytes of
 * those runs read as UTF-8, UTF-16LE and UTF-16BE; gzip / zlib / raw-deflate
 * decompression of those bytes AT EVERY BYTE OFFSET, not only at offset zero,
 * and with a trailing tail after the stream tolerated (see
 * `compressedCandidates` and `inflateLongestPrefix`); and the textual decodes
 * again over whatever the bytes turned out to say, so a value escaped BEFORE it
 * was encoded is still recovered. Each comparison is made both literally and
 * against a Unicode canonicalisation of the view; see `canonicalise`.
 *
 * STRIPPING TO THE ALPHABET, NOT TO WHITESPACE
 * --------------------------------------------
 * Every real base64 decoder — `Buffer.from(s, "base64")`, `atob`, `openssl
 * base64 -d`, Python's `b64decode` — SKIPS characters outside the alphabet
 * rather than stopping at them. A guard that only stripped whitespace was
 * therefore weaker than the decoders it was modelling: one `*` in the middle of
 * a run split it in two, and a single `Buffer.from` on the other side put the
 * value back together whole. The base64 scan strips `[^A-Za-z0-9+/_=-]` for the
 * same reason the hex scan strips `[\s:.,|_-]`.
 *
 * BOTH HALVES ITERATE TO A FIXPOINT
 * --------------------------------
 * Textual and binary decoding are interleaved and repeated: each round runs the
 * textual fixpoint over everything the previous round produced and then decodes
 * the hex / base64 / compressed runs it finds inside it. Both halves feed the
 * next round: a textual view is pushed onto the frontier alongside the binary
 * ones, so a stack with no binary layer in it still gets the remaining rounds
 * and textual transports compose up to `MAX_TEXT_DECODE_ROUNDS *
 * MAX_DECODE_ROUNDS` deep. Advancing the rounds through the binary half alone
 * capped textual composition at three, and
 * `percent(entity(percent(unicodeEscape(v))))` — four ordinary serialisation
 * hops — walked through. `MAX_DECODE_ROUNDS` bounds the recursion, so up to
 * `MAX_DECODE_ROUNDS - 1` BINARY layers are peeled and any composition of
 * textual and binary transports within that depth is caught —
 * `base64(base64(v))`, `hex(base64(v))` and `base64(gzip(base64(v)))` all
 * reduce to `v`.
 *
 * BOUNDED IN BOTH DIRECTIONS, AND WHICH WAY IT FAILS
 * -------------------------------------------------
 * Decoding is bounded, because a guard that decodes without limit is itself the
 * denial of service. Three separate bounds do that work, and it matters which
 * of them can be reached by someone who did not write the code:
 *
 *   - `SCAN_WINDOW` / `MAX_WINDOW_EXTENSION`. Text longer than one window is
 *     scanned in overlapping windows, each with its own budget, its own view set
 *     AND ITS OWN STREAM ALLOWANCES. Peak memory is a function of the window and
 *     cost is linear in the input, so there is no size at which an honest caller
 *     is refused: an append-only receipt log has no delete path and must stay
 *     scannable — and backup-able — forever.
 *   - `DECODE_AMPLIFICATION` / `MIN_DECODE_BUDGET`. Within one window a call may
 *     materialise this many bytes of views per input byte.
 *   - `MAX_DECOMPRESSED_BYTES` / `MAX_INFLATE_ATTEMPTS` / `MAX_INFLATED_BYTES`,
 *     and the blind-guess counterparts of the last two. One stream's expansion,
 *     the number of streams opened and the total expansion scanned, because a
 *     compression ratio is chosen by whoever wrote the stream and not by the
 *     caller whose write is at stake.
 *   - `MAX_DECODE_ROUNDS` / `MAX_TEXT_DECODE_ROUNDS`. How deep an encoding stack
 *     is peeled.
 *
 * EVERY ONE OF THOSE BOUNDS FAILS OPEN. None of them refuses. This is a
 * deliberate reversal of an earlier design in which the amplification bound
 * REFUSED, and it is deliberate for one reason: guest stdout reaches scanned
 * sinks, so anything the guard refuses on is something a guest can cause. A
 * refusal on a self-inflicted bound was therefore a remote, permanent kill
 * switch for `doctor`, `backup` and every receipt append — reachable from
 * roughly 120 KB of ordinary-looking output, and with no way back because a
 * receipt log cannot be truncated. The previous shape had it BOTH ways at once
 * (the top-level scan refused, the sub-scan of decompressed bytes gave up
 * silently), which is the worst of the two: an operator could neither rely on
 * completion nor rely on availability.
 *
 * WHICH OF THEM ARE REPORTED, EXACTLY
 * -----------------------------------
 * This used to read "and every one of them is reported", which was false in
 * three places at once, so it is now spelled out field by field. `IncompleteScan`
 * has one field per reported bound and every field is set at exactly one site:
 *
 *   - `budgetExhausted` — the amplification budget of some window (or of some
 *     sub-scan of a decompressed stream) ran out.
 *   - `streamsSkipped` — a RECOGNISED container was identified and not opened,
 *     because the window's container allowance was spent.
 *   - `streamsTruncated` — a stream expanded past `MAX_DECOMPRESSED_BYTES`, so a
 *     prefix was scanned and a tail was not.
 *   - `depthExhausted` — the decode rounds ran out with something left to peel:
 *     a textual fixpoint that had not converged, or a final-round view that is
 *     itself wholly one hex/base64 run. `base64^4(v)` sets it.
 *   - `runsTruncated` — a run of base64 characters longer than `SCAN_WINDOW +
 *     MAX_WINDOW_EXTENSION`, which `scanWindows` therefore had to cut in two.
 *
 * ONE bound is deliberately silent, and it is the only one: the BLIND
 * raw-deflate allowances (`MAX_BLIND_INFLATE_ATTEMPTS`,
 * `MAX_BLIND_INFLATED_BYTES`, and the per-buffer cap on zlib headers found at a
 * non-zero offset). A buffer with no strong header may not have been a stream at
 * all and an ordinary receipt log produces tens of thousands of them; counting
 * those would fire the report on every honest document and mean nothing. Blind
 * raw-deflate recovery is best effort, it is listed under WHAT IT DOES NOT CATCH,
 * and this sentence is the whole of the claim.
 *
 * The reason failing open is tolerable here — and it is the load-bearing reason,
 * not a shrug — is that windowing makes exhaustion LOCAL. A pad in front of a
 * value does not buy "the rest of the call unscanned": the pad and the value are
 * in different windows, each with its own amplification budget AND its own
 * stream allowances, and the pad cannot spend the value's. That locality was
 * claimed here for a year while the stream allowances were per CALL, so 2.6 KB
 * of gzip padding blinded decompression for an entire multi-megabyte write; the
 * allowances now live on the window, which is what makes the paragraph true.
 *
 * Locality is not the same as immunity: a pad in the SAME window as the value
 * still spends that window's allowances. That is why the last line of defence is
 * not this file at all — see `IncompleteScan` and `assertClean`'s return value.
 * An incomplete scan makes the scanned bytes UNTRUSTED downstream: the backup
 * path excludes (or encrypts) any item whose scan did not finish, rather than
 * archiving it as if it had passed.
 *
 * The reason it is not SILENT is `onIncompleteScan`, which has a default that
 * writes to stderr precisely so that an embedder who passes no options still
 * cannot be told a scan completed when it did not. A guard that gave up quietly
 * would be worse than no guard at all.
 *
 * SHORT VALUES
 * ------------
 * There is no length floor on a remembered value: a four-character credential
 * is still a credential. Two things follow, and both are load-bearing.
 *
 *   - The run scan's minimum length is derived from the shortest value the
 *     guard knows, not hard-coded. A four-byte secret base64-encodes to six
 *     characters, which a fixed floor of eight would never even look at.
 *     `HEURISTIC_MIN_RUN` survives only as the ceiling on that derivation: when
 *     every known value is long, short runs are not worth decoding and the
 *     floor stays where it bounds cost and false positives.
 *   - A short value is indistinguishable from ordinary structure. `2026` occurs
 *     in every ISO timestamp this system generates, so a guard that matched it
 *     against a receipt's own envelope would refuse every receipt — and, worse,
 *     would refuse AFTER the credential had already been written to the guest,
 *     leaving provisioning permanently broken. Sinks therefore declare which
 *     region they are handing over: `"payload"` (caller data — everything is
 *     matched) or `"metadata"` (structure this system generated: chain links,
 *     sequence numbers, timestamps — only values at least
 *     `SHORT_VALUE_LENGTH` long are matched there, because a match on a
 *     shorter one carries no information).
 *
 * WHAT IT DOES NOT CATCH — read this before trusting it
 * ----------------------------------------------------
 *   - encryption, or any keyed/custom transform (rot13, a private alphabet),
 *   - a value split across two fields, interleaved, reordered or truncated:
 *     the guard matches a contiguous occurrence only,
 *   - a transformed value (case-folded, re-wrapped other than by stripping
 *     separators, whitespace-normalised) other than the newline-collapsed form
 *     of a PEM,
 *   - quoted-printable (`=3D`) and base32, which no tool in this system emits;
 *     they are the next two transports worth adding if one ever does,
 *   - encoding stacks whose BINARY layers nest deeper than
 *     `MAX_DECODE_ROUNDS - 1`; the textual layers compose to
 *     `MAX_TEXT_DECODE_ROUNDS` within every one of those rounds, and across
 *     rounds to the product of the two. `base64^4(v)` is past it — but it is no
 *     longer SILENTLY past it: `depthExhausted` says the rounds ran out with
 *     something left to peel,
 *   - a raw-deflate stream (no header of any kind) once the blind allowance is
 *     spent, and a zlib stream at a non-zero offset behind more than
 *     `MAX_OFFSET_ZLIB_GUESSES` coincidental zlib headers in the same buffer.
 *     Both are the deliberate silent bound above: a two-byte zlib header is
 *     ~10 bits of evidence, which is a guess, not an identification,
 *   - a gzip or zlib stream at a non-zero offset whose TAIL is followed by junk
 *     AND whose header is the weak (zlib) one: the tolerant prefix recovery that
 *     handles a trailing tail is spent only on a gzip magic, which is 32 bits of
 *     evidence,
 *   - a base64 run broken by out-of-alphabet junk INSIDE a binary layer. The
 *     alphabet-stripped scan is applied to the text a sink handed over, to its
 *     textual decodes and to decompressed streams — documents a tool wrote —
 *     but not to bytes recovered from a hex or base64 run, where it would
 *     invent a document-sized pseudo-run out of arbitrary binary rather than
 *     recover a real one,
 *   - a value past the first `MAX_DECOMPRESSED_BYTES` of a decompression that
 *     expands beyond that cap; see `inflatePrefix`, and `streamsTruncated` in
 *     the report, which says when that happened,
 *   - anything past a bound that was hit: an exhausted amplification budget, a
 *     skipped stream, a truncated expansion, exhausted rounds, a cut run.
 *     `onIncompleteScan` — and `assertClean`'s RETURN VALUE — names each one. A
 *     caller that treats a completed call as proof of a clean scan without
 *     looking at either has misread this file,
 *   - a run longer than `SCAN_WINDOW + MAX_WINDOW_EXTENSION` that straddles a
 *     window boundary (reported as `runsTruncated`), and a SEPARATED (wrapped,
 *     colon-delimited) dump longer than `overlapFor` that straddles one; see
 *     `scanWindows`,
 *   - a value shorter than `SHORT_VALUE_LENGTH` inside a region a sink declared
 *     as `"metadata"`,
 *   - a value the guard was never told about. `size === 0` means the guard is
 *     blind, and every caller that renders credential-adjacent output is
 *     responsible for populating it first.
 *
 * A refusal is therefore strong evidence of a leak; a pass is NOT a proof of
 * safety. The structural rules above are the proof.
 */

/**
 * Which half of a sink's bytes are being handed over.
 *
 *   - `"payload"` — data that came from a caller. Everything the guard knows is
 *     matched against it. This is the default: a sink that has not thought
 *     about the distinction gets the strict reading.
 *   - `"metadata"` — structure this system generated around that data. Values
 *     shorter than `SHORT_VALUE_LENGTH` are not matched here; see SHORT VALUES.
 */
export type SinkRegion = "payload" | "metadata";

/**
 * What one `assertClean` call could not look at.
 *
 * Reported rather than refused: see BOUNDED IN BOTH DIRECTIONS. Every field is
 * a count or a flag — never a fragment of the text, which would make the report
 * itself a sink.
 */
export interface IncompleteScan {
  /** The sink that was being written, exactly as the caller named it. */
  readonly sink: string;
  /** A window's amplification budget ran out, so its deepest views were not built. */
  readonly budgetExhausted: boolean;
  /** Compressed streams left unopened because the per-window allowance ran out. */
  readonly streamsSkipped: number;
  /** Streams whose expansion overflowed the cap: a prefix was scanned, a tail was not. */
  readonly streamsTruncated: number;
  /**
   * The decode rounds ran out with something left to peel — a textual fixpoint
   * that had not converged, or a final-round view that is itself wholly one
   * hex/base64 run. This is the bound `base64^4(v)` walks through, and it used
   * to do so in complete silence.
   */
  readonly depthExhausted: boolean;
  /**
   * Runs of base64 characters longer than `SCAN_WINDOW + MAX_WINDOW_EXTENSION`,
   * which `scanWindows` could not keep whole inside one window. A compressed
   * stream cut in two inflates in neither half, so a cut run is a real blind
   * spot — and it used to be an unreported one.
   */
  readonly runsTruncated: number;
}

/** One line an operator can read, with counts and a sink name and no fragment of the text. */
export function formatIncompleteScan(report: IncompleteScan): string {
  return (
    `warning: the credential guard could not fully scan ${report.sink} ` +
    `(budget exhausted: ${report.budgetExhausted}, streams skipped: ${report.streamsSkipped}, ` +
    `streams truncated: ${report.streamsTruncated}, decode rounds exhausted: ${report.depthExhausted}, ` +
    `runs cut by a window: ${report.runsTruncated}); the write was NOT blocked`
  );
}

export interface SecretGuard {
  /**
   * `text` must be the exact bytes about to be written to the sink.
   *
   * Returns what this call could NOT look at, or `null` when the scan ran to
   * completion. A caller that persists what it scanned — the backup archive is
   * the one in this system — must treat a non-`null` return as "these bytes are
   * untrusted", because a completed call and an abandoned one are otherwise
   * indistinguishable from the outside.
   */
  assertClean(context: string, text: string, region?: SinkRegion): IncompleteScan | null;
}

export interface MutableSecretGuard extends SecretGuard {
  /**
   * Adds a value to guard. There is no minimum length: a short credential is
   * still a credential, and a silent no-op on one is worse than the
   * false-positive refusals a short value can cause.
   */
  remember(value: string): void;
  /** Number of distinct values known. `0` means the guard cannot catch anything. */
  readonly size: number;
}

export interface SecretGuardOptions {
  /**
   * Called once per `assertClean` that hit one of its own bounds.
   *
   * This is the whole of "fails open, but never silently". Leaving it unset does
   * NOT mean silence: the default writes `formatIncompleteScan` to stderr. It
   * used to mean silence, and the shipped CLI only escaped that by construction
   * — every guard in it happens to be built by `runApp` — so any embedder who
   * called `createSecretGuard()` got a guard that could reach a bound with
   * nobody told. Override it to route the report somewhere an operator reads;
   * pass `() => undefined` to opt into silence deliberately.
   */
  readonly onIncompleteScan?: (report: IncompleteScan) => void;
}

/**
 * Decoded bytes admitted per input byte, per window: what is bounded is
 * AMPLIFICATION.
 *
 * It counts the bytes of every VIEW materialised, not the runs found, because
 * views are what occupy memory: one decoded buffer becomes a UTF-8, a UTF-16LE
 * and a UTF-16BE reading of itself.
 *
 * A FIXED per-call ceiling was measured to refuse a 1.24 MB receipt log — and a
 * receipt log is append-only with no delete path, so that refusal was permanent
 * and a long-lived node could never be backed up again. Bounding the ratio
 * instead keeps the guard's cost linear in the size of what it was handed.
 *
 * Exhausting it does NOT refuse; it stops expanding that window and reports
 * through `onIncompleteScan`. See BOUNDED IN BOTH DIRECTIONS for why: this bound
 * is reachable from guest output, and a refusal on it was a remote kill switch.
 *
 * Measured, per window: an ordinary receipt log runs at ~15x, a doctor report,
 * a PEM and a plain base64 blob at ~10-32x, and the most expensive input found
 * by deliberate search — nested base64 over hex-dense bytes, sprinkled with one
 * newline and one out-of-alphabet character so all three base64 scan variants
 * stay distinct — at ~66x. The bound therefore sits about twice honest use and
 * just under the structural maximum. `secret-guard.test.ts` pins both sides: an
 * ordinary log must scan COMPLETE, and the pathological input must report.
 */
export const DECODE_AMPLIFICATION = 64;
/**
 * Floor under the derived budget, so a SMALL input can still be unpacked: a
 * 1 KB base64 blob legitimately expands to far more than 64 KB of views once
 * decompression and the UTF-16 readings are counted.
 */
export const MIN_DECODE_BUDGET = 8 * 1024 * 1024;
/**
 * Text longer than this is scanned in overlapping windows, each with its own
 * budget and its own view set. This is what keeps peak memory bounded no matter
 * how large the input is, and it is why there is no size at which an honest
 * caller is refused.
 */
export const SCAN_WINDOW = 1024 * 1024;
/**
 * How far a window may run past `SCAN_WINDOW` to finish a run the boundary
 * landed inside; see `scanWindows`. A window therefore never exceeds
 * `SCAN_WINDOW + MAX_WINDOW_EXTENSION` characters, which is the real bound on
 * peak memory.
 */
export const MAX_WINDOW_EXTENSION = SCAN_WINDOW;
/**
 * Worst-case characters one TEXTUAL layer costs per character of what it
 * encodes: `\uXXXX` is six, an HTML numeric entity of a BMP character is at
 * most seven, and percent-encoding one ASCII character is three. Six is the
 * figure the composition below is built on; a decoder whose inverse expands
 * further than this on the SAME character (percent-encoding a 4-byte UTF-8
 * character reaches twelve) is outside it, and that residual is documented as a
 * gap rather than papered over.
 */
const TEXTUAL_EXPANSION_PER_LAYER = 6;
/** How many string views one decoded buffer turns into; see `stringsFromBytes`. */
const VIEWS_PER_BUFFER = 3;
/**
 * Cap on ONE decompression, independent of what is left of the budget. Guest
 * stdout is attacker-influenced and a gzip stream expands by up to ~1000x, so
 * an uncapped `gunzipSync` turns 700 KB of output into gigabytes of host RSS.
 * The decompressed size — not the compressed size — is what is charged.
 *
 * A stream that overflows this cap is NOT a refusal. It used to be, and that
 * made 1.4 KB of base64 — `base64(gzip(1 MiB of 'A'))` — a remote kill switch
 * for `doctor`, `backup` and every receipt append. Overflowing now costs that
 * one view its tail: `inflatePrefix` recovers as much of the expansion as fits
 * under the cap, that prefix is scanned like any other view, the rest of the
 * text is scanned normally, and the report says a stream was truncated.
 */
export const MAX_DECOMPRESSED_BYTES = 1024 * 1024;
/**
 * How many probes `inflatePrefix` may spend locating the longest prefix of the
 * compressed input whose expansion still fits under the cap. It binary-searches,
 * so this covers an input of up to 2^24 bytes exactly.
 */
const MAX_PREFIX_ATTEMPTS = 24;
/**
 * Ceiling on the derived run floor. When every known value is long, runs
 * shorter than this cannot encode any of them, and decoding them would only
 * cost time and invent false positives.
 */
const HEURISTIC_MIN_RUN = 8;
/** Floor on the derived run floor: a one-byte value still needs two characters. */
const ABSOLUTE_MIN_RUN = 2;
/**
 * Below this length a value is treated as too short to be distinguished from
 * structure, and is matched in `"payload"` regions only.
 */
export const SHORT_VALUE_LENGTH = 8;
/** How many times the textual decoders may be composed with each other. */
const MAX_TEXT_DECODE_ROUNDS = 3;
/**
 * How many times the whole decoder — textual fixpoint, then binary runs — may be
 * applied to its own output. `MAX_DECODE_ROUNDS - 1` binary layers are peeled:
 * the first round scans the text as given, and each later round scans what the
 * previous round's bytes turned out to say. Four rounds cover every stack the
 * tools in this system can plausibly produce (`base64(base64(v))`,
 * `hex(base64(v))`, `base64(gzip(base64(v)))`) and cost nothing on text that
 * decodes to nothing, because the frontier empties after the first round.
 */
const MAX_DECODE_ROUNDS = 4;
/**
 * How many TEXTUAL layers the decoder can peel in total: the textual fixpoint
 * runs inside every decode round, and a textual view is fed back into the next
 * round, so the two multiply. This is the number `OVERLAP_EXPANSION` has to be
 * raised to, and getting it wrong is silent in exactly one direction — a value
 * that IS decodable inline but lands wholly inside no window.
 */
const MAX_COMPOSED_TEXT_LAYERS = MAX_TEXT_DECODE_ROUNDS * MAX_DECODE_ROUNDS;
/**
 * Overlap as a multiple of the longest known value.
 *
 * It used to be 8 — hex-of-hex-of-hex — which counted only the BINARY layers.
 * Then it was `6 ** 3`, which counted the textual layers of ONE round and forgot
 * that a textual view is fed back into the next round as well: the decoder peels
 * twelve, and `percent^4(unicodeEscape(v))` — 19,440 characters, caught inline
 * without complaint — was missed, silently, when it straddled a boundary. The
 * exponent is now the same number the decoder actually uses, so the two cannot
 * drift apart again.
 *
 * It is enormous, and deliberately so: `overlapFor` clamps it to half a window,
 * which means the overlap is now ALWAYS that clamp. That is the honest reading —
 * any composition depth past five already exceeds the clamp for a one-character
 * value — and it is why the old `MIN_OVERLAP` floor is gone rather than kept as
 * a constant that could never bind.
 */
export const OVERLAP_EXPANSION = TEXTUAL_EXPANSION_PER_LAYER ** MAX_COMPOSED_TEXT_LAYERS;
/**
 * The clamp on the overlap, and therefore — see above — the overlap itself.
 * Half a window keeps `scanWindows` advancing by at least `SCAN_WINDOW / 2` per
 * step, so cost stays linear in the input at twice the un-overlapped rate.
 */
export const MAX_OVERLAP = SCAN_WINDOW >> 1;
/**
 * Textual views one decode ROUND can charge per input character, worst case:
 * `TEXT_DECODERS.length ** 1 + ... ** MAX_TEXT_DECODE_ROUNDS`, since `spend` is
 * charged the decoded length and no textual decoder here expands its input.
 * The 3 is `TEXT_DECODERS.length`, written as a literal because the array is
 * declared below; `secret-guard.test.ts` pins the pair.
 */
const TEXTUAL_ROUND_AMPLIFICATION = Array.from(
  { length: MAX_TEXT_DECODE_ROUNDS },
  (_, index) => 3 ** (index + 1),
).reduce((total, term) => total + term, 0);
/**
 * Binary views one decode ROUND can charge per input character, worst case: the
 * three base64 scan variants, each decoded at four alignments, each alignment
 * yielding 3/4 of a byte per character, each buffer charged `VIEWS_PER_BUFFER`.
 * The hex scans are strictly cheaper (1/2 a byte per character over two scans)
 * and are inside this figure.
 */
const BINARY_ROUND_AMPLIFICATION = 3 * 4 * (3 / 4) * VIEWS_PER_BUFFER;
/**
 * THE ACCIDENTALLY-STRONG PROPERTY, WRITTEN DOWN.
 *
 * Every amplification bomb found by deliberate search — the 66x base64 bomb at
 * 40 K to 300 K bytes, the textual fan-out bomb at 4 K to 15 K repetitions, and
 * both together — followed by `base64(secret)` IN THE SAME WINDOW is still
 * refused. The reason is not luck about those particular inputs: it is that
 * ROUND ZERO is the round which decodes the given text's own runs, and round
 * zero's worst-case cost fits inside `DECODE_AMPLIFICATION`. A budget that runs
 * out therefore runs out in a LATER round, after the plain and once-decoded
 * readings of the text have already been compared.
 *
 * The claim stops exactly there, and the tests stop with it: a SECOND base64
 * layer needs round one, which a bomb genuinely can starve. What holds for those
 * is the weaker and still meaningful property — refused, or reported, never
 * silently missed.
 *
 * That relationship is structural and it is fragile: raising
 * `MAX_TEXT_DECODE_ROUNDS` to four takes the textual term from 39 to 120 and
 * destroys it with nothing going red. `secret-guard.test.ts` pins the inequality
 * below, which is the tripwire for that change.
 */
export const ROUND_ZERO_AMPLIFICATION = TEXTUAL_ROUND_AMPLIFICATION + BINARY_ROUND_AMPLIFICATION;
/**
 * How far round zero's worst case may sit above the budget and still be treated
 * as "round zero completes". It is above 1 because the worst case double-counts:
 * the textual term assumes every decoder produces a distinct full-length view of
 * every other decoder's output, which no real document does.
 */
export const ROUND_ZERO_HEADROOM = 1.1;
/**
 * Cap on decompressions of a RECOGNISED container (gzip magic, or a header that
 * checksums as zlib) per WINDOW.
 *
 * This allowance is spent only after the magic bytes have been read, and that
 * ordering is the whole of the fix for its predecessor: the old code spent one
 * attempt on EVERY buffer of ten bytes or more, before looking at what the
 * buffer was. Twenty ordinary base64 tokens — under 500 bytes of receipt log,
 * no attacker involved — used the allowance up, and every gzip stream after
 * them in the same text was silently never decompressed. Innocuous data must
 * not be able to spend the allowance that protects against the real container,
 * and after this it cannot: a buffer with no container header spends nothing.
 *
 * It was 64, which 70 gzip streams of five bytes each — 2.6 KB of base64 — spent
 * in full, blinding decompression for everything after them. The COUNT is not
 * what bounds the cost; `MAX_INFLATED_BYTES` is, and a five-byte stream charges
 * five bytes against it. The count survives only to bound the per-attempt
 * constant (a zlib call and a scan set-up) against a text made entirely of empty
 * streams, so it is raised to where innocuous density cannot reach it.
 */
export const MAX_INFLATE_ATTEMPTS = 1024;
/**
 * Zlib headers at a NON-ZERO offset examined per buffer.
 *
 * A two-byte zlib header is about ten bits of evidence, so roughly one offset in
 * a thousand of arbitrary binary satisfies it: scanning every offset for one and
 * treating each hit as a container would hand any megabyte of noise a thousand
 * decompression attempts. These hits are therefore charged to the BLIND
 * allowance, like a raw-deflate guess, and capped per buffer. A gzip magic —
 * `1f 8b 08` plus three reserved flag bits, 32 bits of evidence — is not capped
 * and is not a guess.
 */
export const MAX_OFFSET_ZLIB_GUESSES = 8;
/**
 * Total DECOMPRESSED bytes from recognised containers that one WINDOW will scan.
 *
 * The stream count alone is not the cost. Scanning one megabyte of expansion
 * costs roughly half a second — every base64 alignment of it, every
 * UTF-16 reading of those, all the way down — so sixty-four of them is half a
 * minute of CPU bought with forty kilobytes of guest output. That is not a
 * refusal and never becomes one, but it is still a denial of service, and the
 * count bound did not touch it. This is the bound that does.
 */
export const MAX_INFLATED_BYTES = 4 * 1024 * 1024;
/**
 * Cap on BLIND raw-deflate guesses per window. Raw deflate carries no magic, so
 * any buffer could be one and the guess has to be made on a structural screen
 * (`looksLikeRawDeflate`) rather than on a header. That screen lets roughly two
 * thirds of arbitrary bytes through, so this allowance IS consumable by
 * innocuous data — which is exactly why it is a separate counter. Exhausting it
 * costs raw-deflate detection for the rest of the call and nothing else; the
 * container allowance above is untouched.
 *
 * Exhausting it is NOT reported, and that is the one deliberate exception to
 * "every bound reports": a buffer with no header that was never opened may not
 * have been a stream at all, and an ordinary receipt log produces tens of
 * thousands of them. Counting those would make the report fire on every honest
 * document and mean nothing. Raw-deflate recovery is best effort; the sentence
 * above is the whole of the claim.
 */
export const MAX_BLIND_INFLATE_ATTEMPTS = 256;
/**
 * The same byte bound for blind guesses, and deliberately much smaller.
 *
 * Arbitrary bytes DO sometimes inflate as raw deflate — into arbitrary bytes,
 * which is the least valuable megabyte the guard could spend its time on. A
 * blind guess that overflows the cap is discarded outright rather than
 * prefix-recovered, for the same reason: a document that is a genuine raw
 * deflate stream and is also larger than the cap is not something any tool here
 * produces, while garbage that inflates past it is common.
 */
export const MAX_BLIND_INFLATED_BYTES = 1024 * 1024;

const BACKSLASH_ESCAPES: Record<string, string> = {
  n: "\n",
  r: "\r",
  t: "\t",
  b: "\b",
  f: "\f",
  v: "\v",
  "0": "\0",
  '"': '"',
  "'": "'",
  "/": "/",
  "\\": "\\",
};

/**
 * The named entities a serialiser emits. `&#39;` is NOT in here and must not be:
 * the entity regex below matches a named body as `[a-zA-Z]{2,6}`, which `#39`
 * can never be, and the numeric branch already decodes it. It sat here as dead
 * code that read like coverage.
 */
const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
};

/**
 * Best-effort reverse of backslash escaping over a whole document. The text is
 * not necessarily one JSON string, so this is a scan rather than a parse: it
 * only has to restore the bytes well enough for a substring test.
 */
function unescapeBackslash(text: string): string {
  if (!text.includes("\\")) return text;
  let out = "";
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index] as string;
    if (char !== "\\" || index + 1 >= text.length) {
      out += char;
      continue;
    }
    const next = text[index + 1] as string;

    if (next === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(index + 2, index + 6))) {
      out += String.fromCharCode(Number.parseInt(text.slice(index + 2, index + 6), 16));
      index += 5;
      continue;
    }
    if (next === "x" && /^[0-9a-fA-F]{2}$/.test(text.slice(index + 2, index + 4))) {
      out += String.fromCharCode(Number.parseInt(text.slice(index + 2, index + 4), 16));
      index += 3;
      continue;
    }
    // Octal (`\101`), still emitted by shells, printf and older serialisers.
    const octal = /^[0-7]{1,3}/.exec(text.slice(index + 1, index + 4))?.[0];
    if (octal !== undefined && octal.length > 1) {
      out += String.fromCharCode(Number.parseInt(octal, 8));
      index += octal.length;
      continue;
    }

    const mapped = BACKSLASH_ESCAPES[next];
    if (mapped !== undefined) {
      out += mapped;
      index += 1;
      continue;
    }
    out += char;
  }
  return out;
}

/** `&#NNN;`, `&#xNN;` and the handful of named entities a serialiser emits. */
function decodeHtmlEntities(text: string): string {
  if (!text.includes("&")) return text;
  return text.replace(/&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z]{2,6});/g, (whole, body: string) => {
    if (body.startsWith("#x") || body.startsWith("#X")) {
      const code = Number.parseInt(body.slice(2), 16);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    if (body.startsWith("#")) {
      const code = Number.parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
  });
}

/** Percent-decoding in either hex case, over whole runs so UTF-8 is rebuilt. */
function percentDecode(text: string): string {
  if (!text.includes("%")) return text;
  return text.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => Buffer.from(run.replace(/%/g, ""), "hex").toString("utf8"));
}

/**
 * The textual transports, each a single enforcement site.
 *
 * They are applied as a bounded fixpoint rather than as a hand-written pair of
 * passes. The pair this replaced had `unescapeBackslash` in both passes, so
 * deleting either one left the other covering for it and NEITHER was
 * individually falsifiable — a shape that looks like two protections and is
 * one. Here each decoder appears once: delete it and the test for its encoding
 * goes red, with nothing left to mask it.
 */
const TEXT_DECODERS: readonly ((text: string) => string)[] = [unescapeBackslash, decodeHtmlEntities, percentDecode];

/**
 * Characters that carry no glyph and no information but sit inside a value: a
 * soft hyphen, the zero-width space/non-joiner/joiner family, bidi controls, a
 * word joiner, a BOM. A shell, an HTTP header and a macOS filename all treat a
 * string with one of these in it as the same string; `String.includes` does not.
 */
const INVISIBLE_CHARS = /[\u00ad\u200b-\u200f\u2028\u2029\u2060\ufeff]/g;
/**
 * A cheap screen for "canonicalisation could change this string".
 *
 * `normalize()` over every view of a multi-megabyte document is not free, and
 * the overwhelming majority of views are pure ASCII (already NFC, no invisible
 * characters) or arbitrary binary read as UTF-8, which is a sea of U+FFFD —
 * outside every range below. Only a view that actually contains a combining
 * mark, an invisible, a variation selector or a half/fullwidth form is
 * normalised.
 *
 * The ranges are the combining marks and compatibility forms a real credential
 * or a real filename could pick up. A value in a script whose decomposition
 * lives outside them is a documented gap, not a claim.
 */
const NORMALISATION_RELEVANT =
  /[\u00ad\u0300-\u036f\u0483-\u0489\u0591-\u05c7\u0610-\u065f\u0670\u06d6-\u06dc\u0900-\u0903\u093c\u094d\u0e31\u0e34-\u0e3a\u0f71-\u0f84\u1100-\u11ff\u1ab0-\u1aff\u1dc0-\u1dff\u200b-\u200f\u2028\u2029\u2060\u20d0-\u20f0\u302a-\u302f\ufe00-\ufe2f\ufeff\uff00-\uffef]/;

/**
 * The form two strings are compared in when they are not literally equal.
 *
 * `JSON.stringify` round-trips NFC and NFD alike, a shell, an HTTP server and a
 * macOS filesystem all treat the two as the same string, and a zero-width space
 * dropped into the middle of a value survives every serialiser here — so an
 * exact `String.includes` was a way through that needed no encoding at all.
 * NFKC is used rather than NFC so that fullwidth and other compatibility forms
 * fold too; the risk it carries is a false-positive refusal on a value that has
 * a compatibility decomposition, which is the safe direction for this guard.
 */
function canonicalise(text: string): string {
  if (!NORMALISATION_RELEVANT.test(text)) return text;
  return text.normalize("NFKC").replace(INVISIBLE_CHARS, "");
}

/** Whitespace only: base64url's alphabet already contains `-` and `_`. */
const WHITESPACE_RUN = /\s+/g;
/** Whitespace plus the separators `hexdump`, `xxd -p`, and colon-hex tooling emit. */
const HEX_SEPARATOR_RUN = /[\s:.,|_-]+/g;
/**
 * Everything a base64 decoder skips. `Buffer.from(s, "base64")`, `atob`,
 * `openssl base64 -d` and Python's `b64decode` all ignore out-of-alphabet
 * characters rather than stopping at them, so a run interrupted by ANY of them
 * is still one run as far as a decoder is concerned. Stripping only whitespace
 * modelled a decoder that does not exist.
 */
const BASE64_NON_ALPHABET_RUN = /[^A-Za-z0-9+/_=-]+/g;

/**
 * Character-class membership, as predicates rather than regexes.
 *
 * A `[A-Za-z0-9]{2,}` quantifier over a ~5M-character run overflows irregexp's
 * backtrack stack and throws `RangeError`, which escapes `assertClean` as an
 * unclassified crash — losing the reporting contract the guard exists to
 * provide. A linear hand-rolled scan has no stack to overflow, cannot
 * backtrack, and is O(n) at any run length.
 */
function isHexChar(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x46) || (code >= 0x61 && code <= 0x66)
  );
}

function isBase64Char(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x2b || // +
    code === 0x2f || // /
    code === 0x5f || // _
    code === 0x2d // -
  );
}

/** Every maximal run of `member` characters at least `floor` long, in order. */
function* runsOf(text: string, member: (code: number) => boolean, floor: number): Generator<string> {
  let start = -1;
  for (let index = 0; index <= text.length; index += 1) {
    const inRun = index < text.length && member(text.charCodeAt(index));
    if (inRun) {
      if (start < 0) start = index;
      continue;
    }
    if (start >= 0) {
      if (index - start >= floor) yield text.slice(start, index);
      start = -1;
    }
  }
}

/**
 * What the whole `assertClean` call could not look at: one field per reported
 * bound, accumulated across every window and every sub-scan inside them.
 *
 * Nothing here is a control. Nothing here refuses. See BOUNDED IN BOTH
 * DIRECTIONS, and WHICH OF THEM ARE REPORTED for the field-by-field contract.
 */
type ScanReport = {
  /** An amplification budget — some window's or some sub-scan's — ran out. */
  budgetExhausted: boolean;
  /** Recognised containers a spent allowance left unopened. */
  streamsSkipped: number;
  /** Streams whose expansion overflowed the cap, so only a prefix was scanned. */
  streamsTruncated: number;
  /** The decode rounds ran out with something left to peel. */
  depthExhausted: boolean;
  /** Runs too long to keep whole inside one window, so a window cut one. */
  runsTruncated: number;
};

/**
 * The decompression allowances of ONE WINDOW, plus the call-wide report they
 * write into.
 *
 * These used to be per CALL, while the file three hundred lines above claimed
 * that "the pad and the value are in different windows, each with its own
 * budget, and the pad cannot spend the value's". They were not, and it could:
 * seventy five-byte gzip streams at the head of a document — 2.6 KB — spent the
 * container allowance and every later window in the same call inflated nothing.
 * A value gzipped into a multi-megabyte archive went to disk behind that pad.
 * Making the allowances per window is what makes the claim true; the report
 * stays per call, because that is what the caller is handed back.
 */
type WindowLimits = {
  /** Decompressions of a recognised container left in this window. */
  containerLeft: number;
  /** Decompressed bytes from recognised containers left to scan in this window. */
  containerBytesLeft: number;
  /** Blind raw-deflate guesses left in this window. */
  blindLeft: number;
  /** Decompressed bytes from blind guesses left to scan in this window. */
  blindBytesLeft: number;
  /** Shared with every other window of the same call: what could not be looked at. */
  readonly report: ScanReport;
};

/** What one scan is allowed to spend. Running out never refuses; it reports. */
type DecodeBudget = {
  readonly floor: number;
  readonly hit: (view: string) => boolean;
  readonly limits: WindowLimits;
  bytesLeft: number;
  /** Set when any scan — this one or a nested one — matched. */
  found: boolean;
  /** Set when this budget ran out. Expansion stops; nothing is refused. */
  exhausted: boolean;
};

/**
 * Spends `bytes`, or reports that it cannot.
 *
 * Returns `false` rather than throwing so that everything already materialised
 * is still compared: a budget that ran out on the fourth view must not discard
 * the first three, and exception-based abandonment did exactly that.
 */
function spend(budget: DecodeBudget, bytes: number): boolean {
  if (budget.exhausted) return false;
  budget.bytesLeft -= bytes;
  if (budget.bytesLeft >= 0) return true;
  budget.exhausted = true;
  budget.limits.report.budgetExhausted = true;
  return false;
}

/**
 * `text` plus everything reachable from it by composing the textual decoders,
 * up to `MAX_TEXT_DECODE_ROUNDS` deep. On text that uses none of them the
 * frontier empties after one round, so the common case costs three no-ops.
 *
 * A frontier that is still NON-EMPTY when the rounds run out means there was a
 * further textual layer this call did not peel, and that is reported: it is one
 * of the two ways `depthExhausted` is set. It is only reported for a view still
 * reachable by textual decoding alone (`fromText`), because binary garbage read
 * as UTF-8 produces a fresh percent-run on almost every pass and reporting that
 * would fire on every honest document.
 */
function textualViews(text: string, budget: DecodeBudget, fromText: boolean): string[] {
  const views = new Set<string>([text]);
  let frontier: string[] = [text];

  for (let round = 0; round < MAX_TEXT_DECODE_ROUNDS && frontier.length > 0; round += 1) {
    const next: string[] = [];
    for (const view of frontier) {
      for (const decode of TEXT_DECODERS) {
        const decoded = decode(view);
        if (views.has(decoded)) continue;
        // Textual views are charged for the same reason binary ones are: this
        // is a fan-out of up to `TEXT_DECODERS.length ** MAX_TEXT_DECODE_ROUNDS`
        // per input view, repeated once per decode round, and a document that
        // mixes transports so no two decoders converge can make every one of
        // those distinct. Left uncharged it is the guard's own denial of
        // service, and the one the budget would not have caught.
        if (!spend(budget, decoded.length)) return [...views];
        views.add(decoded);
        next.push(decoded);
      }
    }
    frontier = next;
  }
  if (fromText && frontier.length > 0) budget.limits.report.depthExhausted = true;
  return [...views];
}

/** zlib's signal that a decompression hit `maxOutputLength`. */
function isOutputTooLarge(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === "ERR_BUFFER_TOO_LARGE";
}

type Decompressor = (input: Buffer, options: ZlibOptions) => Buffer;

/** The smallest buffer worth handing to zlib at all: a gzip header alone is ten bytes. */
const MIN_COMPRESSED_BYTES = 10;

/**
 * One place in `bytes` where a compressed stream might start, and how strong the
 * evidence for that is.
 */
type CompressedCandidate = {
  /** Byte offset the stream would start at. */
  readonly offset: number;
  /** Tried in order, within one allowance. */
  readonly decompressors: readonly Decompressor[];
  /** A header identified it (spend the container allowance) rather than a guess. */
  readonly container: boolean;
  /**
   * A gzip magic: 32 bits of evidence. Only these are worth spending a binary
   * search on when the whole buffer fails to inflate, which is what recovers a
   * stream with a TAIL of junk behind it.
   */
  readonly strong: boolean;
};

/**
 * `1f 8b`, plus `08` for the only compression method ever defined and the three
 * reserved flag bits, which are zero in every gzip stream any tool writes. Two
 * bytes alone are 16 bits of evidence, which a megabyte of noise satisfies
 * sixteen times over; four are enough to scan every offset for.
 */
function isGzipHeaderAt(bytes: Buffer, at: number): boolean {
  return (
    bytes[at] === 0x1f &&
    bytes[at + 1] === 0x8b &&
    bytes[at + 2] === 0x08 &&
    ((bytes[at + 3] as number) & 0xe0) === 0
  );
}

/**
 * RFC 1950: low nibble is the method (8 = deflate), high nibble the window size
 * (at most 7), and the two header bytes together are a multiple of 31.
 */
function isZlibHeaderAt(bytes: Buffer, at: number): boolean {
  const first = bytes[at] as number;
  const second = bytes[at + 1] as number;
  return (first & 0x0f) === 0x08 && first >> 4 <= 7 && ((first << 8) + second) % 31 === 0;
}

/**
 * Every place in `bytes` a stream could start, read before any allowance is
 * spent.
 *
 * Reading the header first is one half of the point. Spending an attempt on
 * every buffer and only then looking at it meant twenty base64 tokens of
 * ordinary receipt data exhausted the allowance and every real gzip stream
 * behind them went unexamined.
 *
 * Reading it at EVERY OFFSET is the other half, and it was missing. This
 * inspected `bytes[0]` and `bytes[1]` alone, so one junk byte in front of a gzip
 * stream — `base64("X" + gzip(secret))` — made the stream invisible, and
 * invisible without a word in the report. A base64 run is retried at four
 * CHARACTER alignments, which shifts by six bits, so it never recovers a
 * one-BYTE displacement either. The scan is linear in the buffer and the buffers
 * are already charged to the amplification budget, so it costs a byte compare
 * per byte of view.
 */
function compressedCandidates(bytes: Buffer): readonly CompressedCandidate[] {
  if (bytes.length < MIN_COMPRESSED_BYTES) return [];
  const found: CompressedCandidate[] = [];

  if (isGzipHeaderAt(bytes, 0)) {
    found.push({ offset: 0, decompressors: [gunzipSync], container: true, strong: true });
  } else if (isZlibHeaderAt(bytes, 0)) {
    // A raw-deflate stream can coincidentally satisfy that checksum, so the raw
    // reading is kept as a fallback within the same one attempt.
    found.push({ offset: 0, decompressors: [inflateSync, inflateRawSync], container: true, strong: false });
  } else if (looksLikeRawDeflate(bytes)) {
    found.push({ offset: 0, decompressors: [inflateRawSync], container: false, strong: false });
  }

  let zlibGuesses = 0;
  const last = bytes.length - MIN_COMPRESSED_BYTES;
  for (let at = 1; at <= last; at += 1) {
    if (bytes[at] === 0x1f) {
      if (isGzipHeaderAt(bytes, at)) {
        found.push({ offset: at, decompressors: [gunzipSync], container: true, strong: true });
      }
      continue;
    }
    // A zlib header at a non-zero offset is a GUESS — see `MAX_OFFSET_ZLIB_GUESSES`
    // — so it draws on the blind allowance and is capped per buffer.
    if (zlibGuesses < MAX_OFFSET_ZLIB_GUESSES && ((bytes[at] as number) & 0x0f) === 0x08 && isZlibHeaderAt(bytes, at)) {
      zlibGuesses += 1;
      found.push({ offset: at, decompressors: [inflateSync, inflateRawSync], container: false, strong: false });
    }
  }
  return found;
}

/**
 * Whether `bytes` could be a raw deflate stream at all.
 *
 * Raw deflate carries no magic, so it can only ever be guessed at — but it can
 * be guessed at cheaply. The first bits of a deflate block are `BFINAL` and a
 * two-bit `BTYPE`, and three of the four shapes that follow are checkable
 * without inflating anything. This is not a proof; it is what keeps arbitrary
 * bytes from consuming the blind allowance quite so fast.
 */
function looksLikeRawDeflate(bytes: Buffer): boolean {
  if (bytes.length < MIN_COMPRESSED_BYTES) return false;
  const first = bytes[0] as number;
  const type = (first >> 1) & 3;
  if (type === 3) return false; // Reserved: never a valid block.
  if (type === 0) {
    // Stored block: LEN and NLEN are one's complements of each other.
    const length = (bytes[1] as number) | ((bytes[2] as number) << 8);
    const inverse = (bytes[3] as number) | ((bytes[4] as number) << 8);
    return (length ^ 0xffff) === inverse;
  }
  if (type === 2) {
    // Dynamic Huffman: HLIT and HDIST index tables with 30 valid entries each.
    return ((first >> 3) & 0x1f) <= 29 && ((bytes[1] as number) & 0x1f) <= 29;
  }
  return true; // Fixed Huffman: nothing cheap to check.
}

/**
 * The longest prefix of `bytes` that decompresses at all AND fits under
 * `maxOutputLength`, or `null` if `bytes` is not this container at all.
 *
 * It answers two different failures with the same search, and the second one was
 * a hole. A stream can fail to inflate WHOLE because it expands past the cap, or
 * because something follows it: 64 bytes of junk after a complete gzip member
 * makes `gunzipSync` throw `Z_DATA_ERROR` (it reads the tail as a second member)
 * with `Z_SYNC_FLUSH` making no difference, and the old code answered that by
 * giving up. A prefix search finds the member's own end in either case, because
 * every prefix up to it inflates and none past it does.
 *
 * There is no synchronous incremental inflate in Node, so a bounded prefix is
 * recovered by feeding a bounded PREFIX OF THE COMPRESSED INPUT.
 * `Z_SYNC_FLUSH` is what makes a truncated stream return its partial output
 * instead of erroring on the missing trailer.
 *
 * It BINARY-SEARCHES the compressed length rather than halving it. Halving
 * recovers whatever the first fitting halving happens to give, which for a
 * stream expanding to eight times the cap is one sixteenth of it: a value at
 * 900,000 bytes of expansion was missed under a cap of 1,048,576, contradicting
 * the documented limit. The search lands on the largest prefix that fits, so the
 * recovered length is close to the cap and the documented limit is the real one.
 */
function inflateLongestPrefix(decompress: Decompressor, bytes: Buffer, maxOutputLength: number): Buffer | null {
  // The caller has already established that the WHOLE input does not inflate, so
  // the answer is strictly shorter than that.
  let low = 1;
  let high = bytes.length - 1;
  let best: Buffer | null = null;

  for (let attempt = 0; attempt < MAX_PREFIX_ATTEMPTS && low <= high; attempt += 1) {
    const take = Math.floor((low + high) / 2);
    try {
      const plain = decompress(bytes.subarray(0, take), {
        maxOutputLength,
        finishFlush: constants.Z_SYNC_FLUSH,
      });
      if (best === null || plain.length > best.length) best = plain;
      low = take + 1; // It fitted: a longer prefix may fit too.
    } catch {
      // Too large, or past the end of the member and into whatever follows it.
      // Both mean the same thing to the search: try a shorter prefix.
      high = take - 1;
    }
  }
  return best;
}

/**
 * Scans what a stream decompressed to, in a budget of its OWN.
 *
 * Decompressed bytes are not charged to the parent: the expansion ratio is
 * chosen by whoever wrote the stream, not by the caller whose write is at
 * stake. What bounds the work instead is `MAX_DECOMPRESSED_BYTES` per stream —
 * counted in DECOMPRESSED bytes, because charging the compressed size is what
 * let 696 KB of guest stdout drive gigabytes of host memory — and the two
 * stream allowances per window.
 *
 * The UTF-16LE reading is not decoration: a value written out as UTF-16 and then
 * compressed is invisible in the UTF-8 reading of the same bytes, and there is
 * no later stage that would recover it.
 */
function scanInflated(plain: Buffer, parent: DecodeBudget): void {
  const sub: DecodeBudget = {
    floor: parent.floor,
    hit: parent.hit,
    limits: parent.limits,
    bytesLeft: Math.max(MIN_DECODE_BUDGET, plain.length * DECODE_AMPLIFICATION),
    found: false,
    exhausted: false,
  };
  for (const view of [plain.toString("utf8"), plain.toString("utf16le")]) {
    if (scanFrom(view, sub)) {
      parent.found = true;
      return;
    }
  }
}

/**
 * Decompresses `bytes` if it is, or could be, a compressed stream — spending the
 * matching allowance only once the header has been read.
 *
 * The container path and the blind path draw on SEPARATE counters, in both
 * attempts and bytes, and that separation is the point: whatever arbitrary data
 * spends by looking vaguely like raw deflate, it cannot spend the allowance that
 * a real gzip stream needs.
 */
function inflateInto(bytes: Buffer, budget: DecodeBudget): void {
  for (const candidate of compressedCandidates(bytes)) {
    inflateCandidate(bytes.subarray(candidate.offset), candidate, budget);
    if (budget.found) return;
  }
}

/** One candidate, one allowance. `bytes` already starts at the candidate's offset. */
function inflateCandidate(bytes: Buffer, candidate: CompressedCandidate, budget: DecodeBudget): void {
  const limits = budget.limits;
  const isContainer = candidate.container;
  const attemptsLeft = isContainer ? limits.containerLeft : limits.blindLeft;
  const bytesLeft = isContainer ? limits.containerBytesLeft : limits.blindBytesLeft;
  if (attemptsLeft <= 0 || bytesLeft <= 0) {
    // Only a CONTAINER is reported. A skipped container is a stream the guard
    // identified and chose not to open, which is a fact an operator can act on.
    // A skipped blind guess is a buffer with no header that might not have been
    // a stream at all, and every ordinary document produces tens of thousands of
    // them: counting those would drown the signal and make the report worthless.
    if (isContainer) limits.report.streamsSkipped += 1;
    return;
  }
  if (isContainer) limits.containerLeft -= 1;
  else limits.blindLeft -= 1;

  /** Charges what a stream actually expanded to, against the right counter. */
  const chargeExpansion = (length: number): void => {
    if (isContainer) limits.containerBytesLeft -= length;
    else limits.blindBytesLeft -= length;
  };

  const cap = Math.min(MAX_DECOMPRESSED_BYTES, bytesLeft);
  for (const decompress of candidate.decompressors) {
    let plain: Buffer;
    try {
      plain = decompress(bytes, { maxOutputLength: cap });
    } catch (error) {
      const overflowed = isOutputTooLarge(error);
      // A stream that overflows the cap is a stream whose TAIL this guard
      // cannot see. Refusing the sink for it — which is what this used to do —
      // turned 1.4 KB of guest output into a kill switch. Scan the prefix,
      // report the truncation, and carry on with the rest of the text.
      //
      // Recovering a prefix costs a binary search and a scan of a megabyte, so
      // it is spent only where the header is worth it: an overflowing container,
      // or a gzip magic that failed for any reason at all (which is how a stream
      // with junk behind it is recovered). A weak header that simply did not
      // inflate proves nothing and gets nothing.
      if (overflowed && isContainer) limits.report.streamsTruncated += 1;
      if (!(isContainer && (overflowed || candidate.strong))) continue;
      const prefix = inflateLongestPrefix(decompress, bytes, cap);
      if (prefix === null) continue;
      // A recovery that stopped exactly at the cap is a recovery with a tail
      // left over; one that stopped short of it found the member's own end.
      if (!overflowed && prefix.length >= cap) limits.report.streamsTruncated += 1;
      chargeExpansion(prefix.length);
      scanInflated(prefix, budget);
      if (budget.found) return;
      continue;
    }
    chargeExpansion(plain.length);
    scanInflated(plain, budget);
    if (budget.found) return;
  }
}

/** Every string a byte buffer could have been the encoding of. */
function stringsFromBytes(bytes: Buffer, budget: DecodeBudget): string[] {
  const views = [bytes.toString("utf8"), bytes.toString("utf16le")];
  if (bytes.length % 2 === 0 && bytes.length > 0) {
    views.push(Buffer.from(bytes).swap16().toString("utf16le"));
  }
  inflateInto(bytes, budget);
  return views;
}

/**
 * Decodes every hex / base64 run found in `text`, and in the separator-stripped
 * forms of `text`: a run is only contiguous until a tool wraps it. `openssl
 * base64` wraps at 76 columns by default and `hexdump` puts a space every two
 * bytes, so scanning contiguous runs alone would let either of them carry a
 * value out intact.
 *
 * Base64 is retried at all four character alignments: a secret sitting at an
 * arbitrary byte offset inside a larger blob only lines up on one of them.
 */
function binaryViews(text: string, budget: DecodeBudget, fromText: boolean): string[] {
  const views: string[] = [];
  const floor = budget.floor;
  const add = (bytes: Buffer): void => {
    if (bytes.length === 0 || budget.found || budget.exhausted) return;
    if (!spend(budget, bytes.length * VIEWS_PER_BUFFER)) return;
    views.push(...stringsFromBytes(bytes, budget));
  };
  const distinct = (...scans: string[]): string[] => [...new Set(scans)];

  for (const scan of distinct(text, text.replace(HEX_SEPARATOR_RUN, ""))) {
    for (const run of runsOf(scan, isHexChar, floor)) {
      add(Buffer.from(run.length % 2 === 0 ? run : run.slice(0, -1), "hex"));
      // An odd-length run is a run with one character too many at one end or
      // the other; only one of the two alignments is the real byte boundary.
      if (run.length % 2 === 1) add(Buffer.from(run.slice(1), "hex"));
    }
  }

  // Whitespace-stripped covers `openssl base64`'s wrapping; alphabet-stripped
  // covers everything else a decoder skips, which is every other character
  // there is. Without the second one, a single `*` dropped into a run split it
  // into two halves that neither matched — while `Buffer.from(run, "base64")`
  // on the far side still reconstituted the value whole.
  //
  // `fromText` scopes the alphabet-stripped variant to the text a sink handed
  // over and its textual decodes — a document some tool wrote, which is where
  // a stray separator comes from. Applied to bytes recovered from a binary
  // layer it does not recover a run, it INVENTS one: arbitrary binary is ~60%
  // alphabet, so stripping merges thousands of sub-floor fragments into one
  // document-sized pseudo-run, bypassing the run floor entirely and costing
  // more than every other view put together.
  const base64Scans = fromText
    ? distinct(text, text.replace(WHITESPACE_RUN, ""), text.replace(BASE64_NON_ALPHABET_RUN, ""))
    : distinct(text, text.replace(WHITESPACE_RUN, ""));
  for (const scan of base64Scans) {
    for (const run of runsOf(scan, isBase64Char, floor)) {
      for (let offset = 0; offset < 4; offset += 1) {
        const slice = run.slice(offset);
        if (slice.length < floor) break;
        add(Buffer.from(slice, "base64"));
      }
    }
  }

  return views;
}

/**
 * Whether `view` is, from end to end, a single hex or base64 run.
 *
 * This is the signal that a view still has a layer in it: `base64(secret)` is
 * wholly one base64 run, while a UTF-8 or UTF-16 reading of arbitrary bytes is
 * a sea of U+FFFD or CJK and is not. It is used only to decide whether running
 * out of decode rounds is worth reporting.
 */
function looksWhollyEncoded(view: string, floor: number): boolean {
  const trimmed = view.trim();
  if (trimmed.length < floor) return false;
  let base64 = true;
  let hex = true;
  for (let index = 0; index < trimmed.length; index += 1) {
    const code = trimmed.charCodeAt(index);
    if (base64 && !isBase64Char(code) && code !== 0x3d) base64 = false;
    if (hex && !isHexChar(code)) hex = false;
    if (!base64 && !hex) return false;
  }
  return true;
}

/**
 * Walks every plaintext `text` could be hiding, stopping at the first one `hit`
 * claims. Returns whether it stopped.
 *
 * Each round applies the textual fixpoint and then decodes the binary runs
 * inside its results; the next round starts from those bytes, so the two halves
 * interleave and a value escaped BEFORE it was encoded — or encoded twice — is
 * still reduced to plaintext. The last round only inspects what the previous one
 * produced: decoding it further would build views nothing would ever read.
 */
function scanFrom(text: string, budget: DecodeBudget): boolean {
  const seen = new Set<string>();
  // The text AS GIVEN is compared before a single byte of budget is spent, so
  // an exhausted budget can never cost the guard the plainest reading there is.
  // It is deliberately NOT put in `seen`: the loop below has to visit it again
  // to expand it, and pre-seeding the set emptied the frontier on the first
  // round for any text with no textual decode at all.
  if (budget.hit(text)) return true;
  /** `fromText` marks a view still reachable from `text` by textual decoding alone. */
  let frontier: { view: string; fromText: boolean }[] = [{ view: text, fromText: true }];

  for (let round = 0; round < MAX_DECODE_ROUNDS && frontier.length > 0; round += 1) {
    const next: { view: string; fromText: boolean }[] = [];
    for (const { view, fromText } of frontier) {
      for (const textual of textualViews(view, budget, fromText)) {
        if (seen.has(textual)) continue;
        seen.add(textual);
        if (budget.hit(textual)) return true;
        if (round + 1 === MAX_DECODE_ROUNDS) {
          // The rounds ran out on a view that is ITSELF wholly one hex/base64
          // run: there was another layer here and this call did not peel it.
          // `base64^4(v)` ends exactly here, and used to end here in silence.
          // The test is deliberately this narrow — "the whole view is one run" —
          // because a looser one ("could anything be decoded from here?") is
          // true of every UTF-8 reading of arbitrary bytes, and a report that
          // fires on every honest document says nothing.
          if (looksWhollyEncoded(textual, budget.floor)) budget.limits.report.depthExhausted = true;
          continue;
        }
        // BOTH halves advance the rounds. Feeding only `binaryViews` back into
        // the frontier meant a stack with no binary layer in it never got past
        // the third textual decode, however much budget was left over — four
        // ordinary serialisation hops were enough to walk through.
        next.push({ view: textual, fromText });
        for (const binary of binaryViews(textual, budget, fromText)) {
          if (!seen.has(binary)) next.push({ view: binary, fromText: false });
        }
        // A nested scan of a decompressed stream reports through the budget.
        if (budget.found) return true;
      }
    }
    frontier = next;
  }
  return budget.found;
}

/** Scans one window. Its exhaustion is recorded on `limits.report`, never refused. */
function scanWindowText(text: string, floor: number, limits: WindowLimits, hit: (view: string) => boolean): boolean {
  return scanFrom(text, {
    floor,
    hit,
    limits,
    bytesLeft: Math.max(MIN_DECODE_BUDGET, text.length * DECODE_AMPLIFICATION),
    found: false,
    exhausted: false,
  });
}

/**
 * How many characters two consecutive windows share.
 *
 * Sized from the TEXTUAL expansion, which is the large one: an encoded
 * occurrence of a value is at most `OVERLAP_EXPANSION` times its length, so an
 * occurrence straddling a boundary still lies wholly inside the following
 * window. Base64 alignment is not a concern: every run is decoded at all four
 * alignments already.
 *
 * `OVERLAP_EXPANSION` now covers all twelve textual layers the decoder peels
 * rather than the three one round peels, which puts the product past `MAX_OVERLAP`
 * for every value of one character or more. The clamp is therefore what the
 * overlap IS, and the old `MIN_OVERLAP` floor — which used to be the thing that
 * covered short values — can no longer bind and has been deleted rather than
 * left in place reading like coverage.
 */
export function overlapFor(longestForm: number): number {
  return Math.min(MAX_OVERLAP, Math.max(1, longestForm) * OVERLAP_EXPANSION);
}

/**
 * `text` cut into overlapping windows, exported so the windowing itself can be
 * falsified rather than merely believed.
 *
 * Each window is scanned independently, with its own budget and its own view
 * set, so cost is linear in the input and peak memory is a function of the
 * window alone. That is what makes "too big to scan" impossible: there is no
 * length at which an honest caller is refused, only more windows.
 *
 * TWO things keep a boundary from being a hole, and they cover different cases:
 *
 *   - the OVERLAP covers a value whose encoded form straddles the boundary, for
 *     any encoding whose expansion `overlapFor` bounds.
 *   - SNAPPING PAST THE RUN covers the case no overlap can. A compressed stream
 *     cut in two inflates in NEITHER half — the head has no trailer and the tail
 *     has no header — so it is not enough for the two halves to be scanned; the
 *     stream has to be whole somewhere. A boundary that lands inside a run of
 *     base64/hex characters is therefore pushed forward to the end of that run,
 *     so every contiguous run in the text lies wholly inside some window. This
 *     was reproduced from a 2,840-character stream upwards, and no overlap size
 *     fixes it.
 *
 * What is left, and is documented as a gap: a run longer than `SCAN_WINDOW +
 * MAX_WINDOW_EXTENSION`, and a SEPARATED dump (wrapped base64, colon-hex) whose
 * straddling part is longer than the overlap — those are not contiguous runs, so
 * the snap cannot see them, and only the overlap covers them.
 *
 * The first of those two is no longer SILENT. `onRunTruncated` fires when the
 * extension limit is reached with the run still going, which is the one case
 * where this function knowingly cuts a stream in half; `assertClean` turns it
 * into `runsTruncated`.
 */
export function* scanWindows(text: string, longestForm: number, onRunTruncated?: () => void): Generator<string> {
  if (text.length <= SCAN_WINDOW) {
    yield text;
    return;
  }
  const overlap = overlapFor(longestForm);
  let start = 0;
  while (start < text.length) {
    let end = Math.min(text.length, start + SCAN_WINDOW);
    // Only extend when the boundary is INSIDE a run: a run that merely starts
    // at `end` belongs wholly to the next window already, and dragging it in
    // would cost a window's worth of memory for nothing.
    if (end < text.length && isBase64Char(text.charCodeAt(end)) && isBase64Char(text.charCodeAt(end - 1))) {
      const limit = Math.min(text.length, end + MAX_WINDOW_EXTENSION);
      while (end < limit && isBase64Char(text.charCodeAt(end))) end += 1;
      if (end < text.length && isBase64Char(text.charCodeAt(end))) onRunTruncated?.();
    }
    yield text.slice(start, end);
    if (end >= text.length) return;
    start = Math.max(start + 1, end - overlap);
  }
}

/**
 * The shapes of the value itself the guard compares against. Kept to forms the
 * haystack side cannot undo: everything else is handled by decoding the text.
 */
function needles(value: string): readonly string[] {
  const collapsed = value.replace(/\r?\n/g, "");
  // Both Unicode normalisations, on the NEEDLE side, because that is the cheap
  // side. `JSON.stringify` round-trips NFC and NFD alike and a macOS filesystem
  // hands back the other one, so the two forms have to meet somewhere; doing it
  // here costs one extra string per value, while normalising every VIEW would
  // cost a `normalize()` over every megabyte the guard ever looks at.
  const forms = [value, collapsed].flatMap((form) => [form, form.normalize("NFC"), form.normalize("NFD")]);
  return [...new Set(forms)].filter((form) => form !== "");
}

/**
 * The shortest run worth decoding, given the shortest value the guard knows.
 * A value of `length` bytes occupies `ceil(length * 4 / 3)` base64 characters,
 * so anything shorter than that cannot be hiding it.
 */
function runFloorFor(shortestForm: number): number {
  return Math.max(ABSOLUTE_MIN_RUN, Math.min(HEURISTIC_MIN_RUN, Math.ceil((shortestForm * 4) / 3)));
}

/**
 * The default `onIncompleteScan`: an operator-readable line on stderr.
 *
 * A default that did nothing meant "fails open but never silently" held only for
 * callers who opted in, and the two guards this repo constructs without options
 * (`createRuntime`'s fallback and `CredentialMaterializer`'s) were both of them.
 * The shipped CLI happened to be safe because every guard in it comes from
 * `runApp`; an embedder got silence. The report carries counts and a sink name
 * and never a fragment of the text, so it is safe on any stream.
 */
function warnIncompleteScanOnStderr(report: IncompleteScan): void {
  process.stderr.write(`${formatIncompleteScan(report)}\n`);
}

export function createSecretGuard(
  initial: Iterable<string> = [],
  options: SecretGuardOptions = {},
): MutableSecretGuard {
  /** value -> the needle forms of it, precomputed so `assertClean` stays cheap. */
  const values = new Map<string, readonly string[]>();
  /** Every form, and the subset long enough to mean something in a metadata region. */
  let allForms: readonly string[] = [];
  let metadataForms: readonly string[] = [];
  /** The same two sets in the form `canonicalise` puts a view into. */
  let allCanonical: readonly string[] = [];
  let metadataCanonical: readonly string[] = [];
  let allFloor = HEURISTIC_MIN_RUN;
  let metadataFloor = HEURISTIC_MIN_RUN;
  let longestForm = 0;

  const reindex = (): void => {
    const forms = [...new Set([...values.values()].flat())];
    allForms = forms;
    metadataForms = forms.filter((form) => form.length >= SHORT_VALUE_LENGTH);
    allCanonical = [...new Set(forms.map(canonicalise))];
    allCanonical = allCanonical.filter((form) => form !== "");
    metadataCanonical = [...new Set(metadataForms.map(canonicalise))].filter((form) => form !== "");
    const shortest = (group: readonly string[]): number =>
      group.length === 0 ? HEURISTIC_MIN_RUN : Math.min(...group.map((form) => form.length));
    allFloor = runFloorFor(shortest(forms));
    metadataFloor = runFloorFor(shortest(metadataForms));
    longestForm = Math.max(0, ...forms.map((form) => form.length));
  };

  const remember = (value: string): void => {
    if (value === "") {
      // Refusing loudly: a caller that hands the guard nothing to guard has a
      // bug, and silently doing nothing is how a guard ends up empty in
      // production without anybody noticing.
      throw new YashikiError("CONFIG_INVALID", "the secret guard was handed an empty credential value");
    }
    values.set(value, needles(value));
    reindex();
  };
  for (const value of initial) remember(value);

  const refuse = (context: string): never => {
    // Deliberately no secret, no encoding name and no offset in the message:
    // the error itself is a sink.
    throw new YashikiError(
      "CREDENTIAL_UNSAFE",
      `a credential value would have been written to ${context}`,
      { sink: context },
    );
  };

  const report = options.onIncompleteScan ?? warnIncompleteScanOnStderr;

  const assertClean = (context: string, text: string, region: SinkRegion = "payload"): IncompleteScan | null => {
    const forms = region === "metadata" ? metadataForms : allForms;
    // A guard with nothing to look for did not scan anything, but it also cannot
    // have abandoned anything: `null` here means "no bound was hit", which is
    // true, and `size === 0` is the separate fact a caller checks.
    if (forms.length === 0 || text === "") return null;
    const canonicalForms = region === "metadata" ? metadataCanonical : allCanonical;
    const floor = region === "metadata" ? metadataFloor : allFloor;

    const carries = (view: string): boolean => {
      if (forms.some((form) => view.includes(form))) return true;
      const folded = canonicalise(view);
      // `canonicalise` is the identity on the overwhelming majority of views,
      // and re-testing an unchanged string against the same needles is pure
      // cost on the hot path.
      return folded !== view && canonicalForms.some((form) => folded.includes(form));
    };

    // What could not be looked at is per CALL, because that is what the caller
    // is handed back. Everything that BOUNDS the work is per window: see
    // `WindowLimits` for why the stream allowances had to move here.
    const findings: ScanReport = {
      budgetExhausted: false,
      streamsSkipped: 0,
      streamsTruncated: 0,
      depthExhausted: false,
      runsTruncated: 0,
    };
    const incomplete = (): IncompleteScan | null =>
      findings.budgetExhausted ||
      findings.depthExhausted ||
      findings.streamsSkipped > 0 ||
      findings.streamsTruncated > 0 ||
      findings.runsTruncated > 0
        ? { sink: context, ...findings }
        : null;

    try {
      // Windowed, so that peak memory is a function of the window and not of the
      // input: an append-only receipt log grows without bound and must stay
      // scannable — and backup-able — at any size it reaches.
      for (const window of scanWindows(text, longestForm, () => void (findings.runsTruncated += 1))) {
        const limits: WindowLimits = {
          containerLeft: MAX_INFLATE_ATTEMPTS,
          containerBytesLeft: MAX_INFLATED_BYTES,
          blindLeft: MAX_BLIND_INFLATE_ATTEMPTS,
          blindBytesLeft: MAX_BLIND_INFLATED_BYTES,
          report: findings,
        };
        if (scanWindowText(window, floor, limits, carries)) refuse(context);
      }
    } finally {
      // In a `finally` because `refuse` throws from INSIDE the loop: a call that
      // hit a bound in window 0 and then matched in window 3 used to report
      // nothing at all, so the one scan an operator most wants the caveats for —
      // the one that found something — was the one that suppressed them.
      const abandoned = incomplete();
      if (abandoned !== null) report(abandoned);
    }

    return incomplete();
  };

  return {
    remember,
    assertClean,
    get size() {
      return values.size;
    },
  };
}

export const noopSecretGuard: SecretGuard = {
  assertClean: () => null,
};
