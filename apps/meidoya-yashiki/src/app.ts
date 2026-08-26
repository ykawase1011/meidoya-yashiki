import { homedir } from "node:os";
import { createConsoleLogger, createSecretGuard, formatIncompleteScan } from "@meidoya-yashiki/yashiki-core";
import { guardedWriter, runCli, type CliRuntime } from "./cli.js";
import { createRuntime, type RuntimeEnvironment } from "./runtime.js";

/**
 * Everything the process itself supplies. Defaulted here rather than in
 * `main.ts` so that the composition below — guard, guarded writers, logger,
 * runtime — is the whole of the entry point and can be exercised without
 * spawning a CLI.
 *
 * `main.ts` is then three lines that pass `process.argv` in, and there is no
 * unguarded `process.stdout.write` anywhere for a later change to reach for.
 */
export type AppIo = {
  /** Receives a command's ENTIRE output at once; see `guardedWriter`. */
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  env?: Readonly<Record<string, string | undefined>>;
  homeDir?: string;
  /** The runtime factory. Injected only by tests; production has one. */
  createRuntime?: (environment: RuntimeEnvironment) => CliRuntime;
};

/**
 * The entry point.
 *
 * The secret guard is created HERE, not inside the runtime, because the debug
 * logger is a runtime CONSTRUCTOR argument: a guard the runtime owned could
 * never have reached it, and `createConsoleLogger()`'s default writer goes
 * straight to stderr with nothing in between. Every byte this process writes to
 * a terminal passes the same guard the receipt store and Doctor use.
 */
export async function runApp(argv: readonly string[], io: AppIo = {}): Promise<number> {
  const env = io.env ?? process.env;
  const stdout = io.stdout ?? ((text: string) => void process.stdout.write(`${text}\n`));
  const stderr = io.stderr ?? ((text: string) => void process.stderr.write(`${text}\n`));

  // The guard fails OPEN on its own bounds — an amplification budget, a stream
  // allowance, an oversized expansion — because refusing on them handed any
  // process whose output reaches a scanned sink a permanent kill switch for
  // `doctor`, `backup` and every receipt append. Failing open is only tolerable
  // because it is not silent, and THIS is where it stops being silent: the
  // report goes straight to stderr, unguarded by construction (it carries
  // counts and a sink name, never a fragment of the text it could not read).
  const secretGuard = createSecretGuard([], {
    onIncompleteScan: (report) => stderr(formatIncompleteScan(report)),
  });
  const writeOut = guardedWriter(secretGuard, "stdout", stdout);
  const writeErr = guardedWriter(secretGuard, "stderr", stderr);

  const build = io.createRuntime ?? createRuntime;
  const runtime = build({
    homeDir: io.homeDir ?? homedir(),
    xdgConfigHome: env["XDG_CONFIG_HOME"],
    xdgDataHome: env["XDG_DATA_HOME"],
    secretGuard,
    logger: env["YASHIKI_DEBUG"] === "1" ? createConsoleLogger(writeErr) : undefined,
  });

  return runCli(argv, {
    runtime,
    // The terminal is the last sink and the one a human reads: it goes behind
    // the same guard as the receipt store and Doctor.
    write: writeOut,
    writeError: writeErr,
  });
}
