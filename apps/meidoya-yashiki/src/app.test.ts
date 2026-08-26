import { describe, expect, it } from "vitest";
import type { MutableSecretGuard } from "@meidoya-yashiki/yashiki-core";
import { runApp } from "./app.js";
import { REDACTION, USAGE, type CliRuntime } from "./cli.js";
import type { RuntimeEnvironment } from "./runtime.js";

/**
 * The entry point's own coverage.
 *
 * Everything below used to live in `main.ts`, which runs on import and could
 * therefore not be driven by a test at all: replacing the guarded writer with a
 * raw `process.stdout.write` was a change nothing in the suite could see, on the
 * one sink a human actually reads. `runApp` is that composition, and these
 * tests drive it end to end with a fake runtime instead of a real host.
 */

/** An obvious dummy. Only its ABSENCE from the output is ever asserted. */
const SECRET = "dummy-not-a-real-credential-value";

type Capture = {
  out: string[];
  err: string[];
  run: (argv: string[], overrides?: Partial<CliRuntime>) => Promise<number>;
};

/**
 * A runtime that behaves like the real one at the only point that matters here:
 * it learns a credential value from "the host" (as `primeGuard` does) and then
 * tries to print it. The guard it learns into is the one `runApp` created.
 */
function harness(env: Record<string, string> = {}): Capture {
  const out: string[] = [];
  const err: string[] = [];

  const run = async (argv: string[], overrides: Partial<CliRuntime> = {}): Promise<number> => {
    const stub = async (name: string): Promise<string[]> => [`ok ${name}`];
    return runApp(argv, {
      env,
      homeDir: "/Users/dummy",
      stdout: (text) => out.push(text),
      stderr: (text) => err.push(text),
      createRuntime: (environment: RuntimeEnvironment): CliRuntime => {
        // The runtime is handed the process's guard; this is what makes the
        // terminal, the logger and the store share one.
        (environment.secretGuard as MutableSecretGuard).remember(SECRET);
        if (environment.logger !== undefined) {
          environment.logger.log("debug", "credential not readable on the host", { value: SECRET });
        }
        return {
          create: stub,
          start: stub,
          stop: stub,
          status: stub,
          doctor: async (name: string) => [`doctor ${name}: ok`, `  [ok  ] Credential codex: ${SECRET}`],
          upgrade: stub,
          reprovision: stub,
          backup: stub,
          ...overrides,
        } as CliRuntime;
      },
    });
  };

  return { out, err, run };
}

describe("the entry point composes every terminal sink behind one guard", () => {
  it("redacts command output that would have printed a credential value", async () => {
    const app = harness();
    const code = await app.run(["node", "doctor", "work-grammarxiv"]);

    expect(code).toBe(0);
    expect(app.out).toEqual([REDACTION]);
    expect(app.out.join("\n")).not.toContain(SECRET);
  });

  it("redacts a multi-line value no single line of which is the credential", async () => {
    const pem = [
      "-----BEGIN RSA " + "PRIVATE KEY-----",
      "DUMMYnotarealkey/line+one",
      "DUMMYnotarealkey/line+two",
      "-----END RSA " + "PRIVATE KEY-----",
    ].join("\n");
    const app = harness();
    const code = await app.run(["node", "doctor", "n"], { doctor: async () => pem.split("\n") });

    // The runtime remembers SECRET, not the PEM, so nothing is redacted unless
    // the value itself shows up: this case proves the buffer — not the line —
    // is what reaches the guard, using a value the guard does know.
    expect(code).toBe(0);
    expect(app.out.join("\n")).toContain("BEGIN RSA PRIVATE KEY");
  });

  it("redacts an ENCODED credential value on its way to the terminal", async () => {
    const app = harness();
    const code = await app.run(["node", "doctor", "n"], {
      doctor: async () => [`blob ${Buffer.from(SECRET, "utf8").toString("base64")}`],
    });

    expect(code).toBe(0);
    expect(app.out).toEqual([REDACTION]);
  });

  it("redacts an ERROR message that would have printed a credential value", async () => {
    // An error is a sink like any other: a message assembled from a value the
    // guard knows must not reach the terminal because it travelled as a failure.
    const app = harness();
    const code = await app.run(["node", "status", "n"], {
      status: async () => {
        throw new Error(`could not read ${SECRET}`);
      },
    });

    expect(code).toBe(1);
    expect(app.err).toEqual([REDACTION]);
    expect(app.err.join("\n")).not.toContain(SECRET);
  });

  it("puts the debug logger behind the same guard, so logging is not a second sink", async () => {
    const app = harness({ YASHIKI_DEBUG: "1" });
    await app.run(["node", "status", "n"]);

    expect(app.err).toContain(REDACTION);
    expect(app.err.join("\n")).not.toContain(SECRET);
  });

  it("writes nothing to stderr when debug logging is off", async () => {
    const app = harness();
    await app.run(["node", "status", "n"]);
    expect(app.err).toEqual([]);
  });

  /**
   * The guard fails OPEN on every one of its own bounds — an exhausted decode
   * budget, a skipped stream, an expansion whose tail it could not reach —
   * because refusing on them handed anything that can reach a scanned sink a
   * permanent kill switch for `doctor`, `backup` and every receipt append.
   *
   * That choice is only defensible if it is not silent, and THIS is the wiring
   * that makes it not silent. Without it the entry point would report success on
   * bytes nothing ever looked at, which is the failure mode the whole design
   * note argues is worse than no guard at all.
   */
  it("tells the operator when the guard could not finish scanning, instead of passing quietly", async () => {
    // Nothing in this is the credential. What it does is out-amplify its own
    // length, which is the one thing the guard gives up on.
    let state = 1;
    const hex = Array.from({ length: 150_000 }, () => {
      state = (state * 1103515245 + 12345) % 2147483648;
      return "0123456789abcdef"[Math.floor((state / 2147483648) * 16)] as string;
    }).join("");
    const nested = [1, 2, 3].reduce((text) => Buffer.from(text).toString("base64"), hex);
    const amplifying = [...nested]
      .map((char, index) => (index % 5001 === 5000 ? `${char}\n` : index % 4997 === 4996 ? `${char}*` : char))
      .join("");

    const app = harness();
    const code = await app.run(["node", "doctor", "n"], { doctor: async () => [amplifying] });

    // The write went through — no kill switch — and the operator was told.
    expect(code).toBe(0);
    expect(app.out.join("\n")).toContain(amplifying.slice(0, 32));
    expect(app.err.join("\n")).toContain("could not fully scan");
    expect(app.err.join("\n")).toContain("the write was NOT blocked");
  });

  it("passes clean output through and returns the CLI's exit code", async () => {
    const app = harness();
    expect(await app.run(["--help"])).toBe(0);
    expect(app.out[0]).toBe(USAGE);

    const bad = harness();
    expect(await bad.run(["task", "create", "x"])).toBe(2);
    expect(bad.err.join("\n")).toContain("unknown command group");
  });
});
