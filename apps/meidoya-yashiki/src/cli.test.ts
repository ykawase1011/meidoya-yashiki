import { describe, expect, it } from "vitest";
import { createConsoleLogger, createSecretGuard, YashikiError } from "@meidoya-yashiki/yashiki-core";
import { guardedWriter, REDACTION, runCli, USAGE, type CliRuntime, type CreateOverrides } from "./cli.js";

function harness(overrides: Partial<CliRuntime> = {}) {
  const calls: { command: string; name: string; overrides?: CreateOverrides }[] = [];
  const out: string[] = [];
  const err: string[] = [];

  const record =
    (command: string) =>
    async (name: string): Promise<string[]> => {
      calls.push({ command, name });
      return [`${command} ${name}`];
    };

  const runtime: CliRuntime = {
    create: async (name, createOverrides) => {
      calls.push({ command: "create", name, overrides: createOverrides });
      return [`create ${name}`];
    },
    start: record("start"),
    stop: record("stop"),
    status: record("status"),
    doctor: record("doctor"),
    upgrade: record("upgrade"),
    reprovision: record("reprovision"),
    backup: record("backup"),
    ...overrides,
  };

  return {
    calls,
    runtime,
    out,
    err,
    run: (argv: string[]) =>
      runCli(argv, { runtime, write: (text) => out.push(text), writeError: (text) => err.push(text) }),
  };
}

describe("cli", () => {
  it("exposes exactly the documented commands", () => {
    for (const command of ["create", "start", "stop", "status", "doctor", "upgrade", "reprovision", "backup"]) {
      expect(USAGE).toContain(`node ${command}`);
    }
  });

  it("parses node create with provider, cpu and memory", async () => {
    const cli = harness();
    const code = await cli.run(["node", "create", "work-grammarxiv", "--provider", "lima", "--cpu", "8", "--memory", "16GiB"]);

    expect(code).toBe(0);
    expect(cli.calls[0]).toEqual({
      command: "create",
      name: "work-grammarxiv",
      overrides: { provider: "lima", cpus: 8, memoryMiB: 16384 },
    });
    expect(cli.out).toEqual(["create work-grammarxiv"]);
  });

  it("routes every other command with just a node name", async () => {
    for (const command of ["start", "stop", "status", "doctor", "upgrade", "reprovision", "backup"]) {
      const cli = harness();
      expect(await cli.run(["node", command, "work-grammarxiv"])).toBe(0);
      expect(cli.calls[0]).toEqual({ command, name: "work-grammarxiv" });
    }
  });

  it("rejects an unknown provider and a non-integer cpu count", async () => {
    const bad = harness();
    expect(await bad.run(["node", "create", "n", "--provider", "docker"])).toBe(1);
    expect(bad.err.join("\n")).toContain("CONFIG_INVALID");

    const cpu = harness();
    expect(await cpu.run(["node", "create", "n", "--cpu", "many"])).toBe(1);
    expect(cpu.err.join("\n")).toContain("--cpu");
  });

  it("prints usage and exits 2 for unknown commands", async () => {
    const group = harness();
    expect(await group.run(["task", "create", "x"])).toBe(2);
    expect(group.err.join("\n")).toContain("unknown command group");

    const sub = harness();
    expect(await sub.run(["node", "delegate", "x"])).toBe(2);

    const missing = harness();
    expect(await missing.run(["node", "status"])).toBe(2);
    expect(missing.err.join("\n")).toContain("requires a node name");
  });

  it("prints usage for --help", async () => {
    const cli = harness();
    expect(await cli.run(["--help"])).toBe(0);
    expect(cli.out[0]).toContain("meidoya-yashiki");
  });

  it("exits 3 when recovery is required so the operator is not told it worked", async () => {
    const cli = harness({
      status: async () => {
        throw new YashikiError("RECOVERY_REQUIRED", "postcondition could not be observed");
      },
    });

    expect(await cli.run(["node", "status", "work-grammarxiv"])).toBe(3);
    expect(cli.err.join("\n")).toContain("RECOVERY_REQUIRED");
    expect(cli.out).toEqual([]);
  });

  /**
   * Previously this asserted that output which never contained the secret did
   * not contain the secret — a tautology that would have passed however badly
   * the CLI leaked. It now drives a runtime that DOES try to print a value the
   * guard knows, which is the case that matters.
   */
  it("redacts command output that would have printed a credential value", async () => {
    // An obvious dummy; only its absence is ever asserted.
    const secret = "dummy-not-a-real-credential-value";
    const guard = createSecretGuard([secret]);
    const out: string[] = [];
    const err: string[] = [];
    const cli = harness({
      doctor: async (name) => [`doctor ${name}: ok`, `  [ok  ] Credential codex: ${secret}`],
    });

    const code = await runCli(["node", "doctor", "work-grammarxiv"], {
      runtime: cli.runtime,
      write: guardedWriter(guard, "stdout", (text) => out.push(text)),
      writeError: guardedWriter(guard, "stderr", (text) => err.push(text)),
    });

    expect(code).toBe(0);
    expect(out).toEqual([REDACTION]);
    expect(out.join("\n")).not.toContain(secret);
  });

  /**
   * The defect this pins: `guardedWriter` used to be handed one line at a time,
   * and a PEM private key has no single line that contains the whole value — so
   * every one of its lines passed the guard and the key printed in full. The
   * CLI now hands the writer the entire buffer in one call.
   */
  it("refuses a multi-line credential no line of which is the value", async () => {
    const pem = [
      "-----BEGIN RSA " + "PRIVATE KEY-----",
      "DUMMYnotarealkey/line+one",
      "DUMMYnotarealkey/line+two",
      "-----END RSA " + "PRIVATE KEY-----",
    ].join("\n");
    const guard = createSecretGuard([pem]);
    const out: string[] = [];
    const cli = harness({ doctor: async () => pem.split("\n") });

    // Every individual line passes: that is exactly why the buffer must be
    // guarded instead of the line.
    for (const line of pem.split("\n")) {
      expect(() => guard.assertClean("probe", line)).not.toThrow();
    }

    const code = await runCli(["node", "doctor", "work-grammarxiv"], {
      runtime: cli.runtime,
      write: guardedWriter(guard, "stdout", (text) => out.push(text)),
      writeError: guardedWriter(guard, "stderr", (text) => out.push(text)),
    });

    expect(code).toBe(0);
    expect(out).toEqual([REDACTION]);
    expect(out.join("\n")).not.toContain("DUMMYnotarealkey");
  });

  describe("guarded terminal writer", () => {
    const secret = "dummy-not-a-real-credential-value";

    it("passes clean output through unchanged", () => {
      const written: string[] = [];
      guardedWriter(createSecretGuard([secret]), "stdout", (text) => written.push(text))("doctor node: ok");
      expect(written).toEqual(["doctor node: ok"]);
    });

    it("redacts an encoded value too, and never throws at the terminal", () => {
      const written: string[] = [];
      const write = guardedWriter(createSecretGuard([secret]), "stdout", (text) => written.push(text));
      expect(() => write(`blob ${Buffer.from(secret, "utf8").toString("base64")}`)).not.toThrow();
      expect(written).toHaveLength(1);
      expect(written[0]).toContain("redacted");
    });

    /**
     * `main.ts` used to hand `createConsoleLogger()` its default writer, which
     * goes straight to `process.stderr` with nothing in between — a second
     * terminal sink beside the guarded one. It now composes the logger from
     * this writer, and this pins that composition.
     */
    it("is what the debug logger writes through, so logging is not a second unguarded sink", () => {
      const written: string[] = [];
      const logger = createConsoleLogger(
        guardedWriter(createSecretGuard([secret]), "stderr", (text) => written.push(text)),
      );

      logger.log("debug", "credential not readable on the host", { value: secret });
      logger.log("info", "credential materialized", { node: "work-grammarxiv" });

      expect(written[0]).toBe(REDACTION);
      expect(written[1]).toContain("credential materialized");
      expect(written.join("\n")).not.toContain(secret);
    });

    it("is inert when the guard knows nothing, which is why every path must populate it", () => {
      const written: string[] = [];
      guardedWriter(createSecretGuard(), "stdout", (text) => written.push(text))(secret);
      expect(written).toEqual([secret]);
    });
  });
});
