import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { YashikiError } from "./errors.js";
import { noopSecretGuard, type SecretGuard } from "./secret-guard.js";

export type ProcessRequest = {
  argv: readonly string[];
  timeoutMs: number;
  stdin?: string;
  env?: Readonly<Record<string, string>>;
  /**
   * Extra host variables THIS child may inherit, by name. The base allowlist is
   * what every child gets; a caller that knows the tool it is invoking needs
   * more — `sops` looking for its age identity, say — asks for exactly those
   * names here, so nothing else in the process tree inherits them. Only names
   * in `OPTIONAL_ENV_NAMES` are honoured.
   */
  inheritEnv?: readonly string[];
  maxOutputBytes?: number;
};

export type ProcessResult = {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
};

/**
 * The single seam through which this package touches the host. Every test runs
 * against a fake, so the suite never needs limactl or a real VM.
 */
export interface ProcessPort {
  run(request: ProcessRequest): Promise<ProcessResult>;
}

const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;

/**
 * The only host environment variables a child of this process inherits.
 *
 * The host environment of a developer machine is full of credential-bearing
 * variables (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, an
 * `SSH_AUTH_SOCK` that is an agent capability rather than a value). Merging all
 * of `process.env` into `limactl shell` handed every one of them to the guest,
 * which is precisely the leak the rest of this package is built to prevent — so
 * the inheritance is an allowlist, not a subtraction. Anything a child
 * genuinely needs is added here, deliberately, with a reason.
 */
export const INHERITED_ENV_NAMES: readonly string[] = [
  "PATH", // to find limactl / security at all
  "HOME", // limactl's config and ssh keys, macOS `security`'s keychain search list
  "LIMA_HOME", // an operator-relocated Lima state directory
  "TMPDIR", // sockets and scratch files
  "LANG", // limactl's output is parsed; a missing locale changes nothing else
  "LC_ALL",
  "LC_CTYPE",
  "TERM", // limactl checks it even with --tty=false
];

/**
 * Extra variables a specific credential source may ask to inherit, keyed by the
 * `sourceRef` scheme that needs them.
 *
 * The allowlist above broke `sops:` outright: sops could not find its age or
 * GPG identity, exited non-zero, and the failure collapsed into "credential not
 * available on the host" — an error that pointed the operator at the wrong
 * thing entirely. These names put that back, deliberately and per invocation.
 *
 * EVERY NAME HERE IS A LOCATOR, NEVER A VALUE. `SOPS_AGE_KEY_FILE` is a path,
 * `GNUPGHOME` is a directory, `AWS_PROFILE` names a stanza in a file sops can
 * read for itself. The value-bearing spellings are excluded on purpose:
 *
 *   - `SOPS_AGE_KEY` carries the age identity itself,
 *   - `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` / `AWS_ACCESS_KEY_ID` carry
 *     live AWS credentials.
 *
 * A child needs to FIND its key; it does not need this process to hand the key
 * to it. An operator who keeps AWS credentials only in the environment must put
 * them in a profile — the credential is then read by sops from a file it opens
 * itself, and never passes through Yashiki's process table or a guest.
 */
export const CREDENTIAL_SOURCE_ENV_NAMES: Readonly<Record<string, readonly string[]>> = {
  // macOS Keychain: `security` needs nothing beyond HOME, which is in the base
  // allowlist. Present so that adding a scheme is a deliberate edit here.
  keychain: [],
  sops: [
    "SOPS_AGE_KEY_FILE", // path to an age identity file
    "SOPS_AGE_RECIPIENTS", // public recipients, not secret
    "XDG_CONFIG_HOME", // where sops looks for the default age keys.txt
    "GNUPGHOME", // gpg keyring DIRECTORY
    "GPG_TTY", // pinentry needs a terminal to prompt on
    "AWS_PROFILE", // names a profile in the shared credentials file
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_CONFIG_FILE", // path
    "AWS_SHARED_CREDENTIALS_FILE", // path
    "AWS_ROLE_ARN", // an identifier
    "AWS_WEB_IDENTITY_TOKEN_FILE", // path
    "AWS_SDK_LOAD_CONFIG",
  ],
};

/** Every name any credential source is permitted to opt into. */
export const OPTIONAL_ENV_NAMES: readonly string[] = [
  ...new Set(Object.values(CREDENTIAL_SOURCE_ENV_NAMES).flat()),
];

/**
 * The environment a child gets: the base allowlist, the extra names this child
 * opted into, plus whatever the caller asked for explicitly. Exported so a test
 * can assert what does NOT survive.
 */
export function childEnvironment(
  source: Readonly<Record<string, string | undefined>> = process.env,
  overrides: Readonly<Record<string, string>> = {},
  inherit: readonly string[] = [],
): Record<string, string> {
  const env: Record<string, string> = {};
  // An opt-in outside `OPTIONAL_ENV_NAMES` is ignored: a caller must not be
  // able to widen the allowlist to `AWS_SECRET_ACCESS_KEY` by naming it.
  const names = [...INHERITED_ENV_NAMES, ...inherit.filter((name) => OPTIONAL_ENV_NAMES.includes(name))];
  for (const name of names) {
    const value = source[name];
    if (value !== undefined) env[name] = value;
  }
  return { ...env, ...overrides };
}

export type NodeProcessPortOptions = {
  /**
   * Optional: refuses to spawn a child whose argv or environment carries a
   * remembered credential value. The structural rule is that a secret only ever
   * reaches a child on stdin — which is deliberately NOT guarded, because it is
   * the one channel a credential is supposed to travel down.
   */
  secretGuard?: SecretGuard;
};

/**
 * Rejects argv that could be reinterpreted by an intermediate shell or split by
 * a NUL. Guest exec always passes an argv array; there is no shell string form.
 */
export function assertSafeArgv(argv: readonly string[]): void {
  if (argv.length === 0) {
    throw new YashikiError("PROVIDER_FAILED", "argv must not be empty", {});
  }
  for (const [index, arg] of argv.entries()) {
    if (typeof arg !== "string") {
      throw new YashikiError("PROVIDER_FAILED", `argv[${index}] is not a string`, { index });
    }
    if (arg.includes("\0")) {
      throw new YashikiError("PROVIDER_FAILED", `argv[${index}] contains a NUL byte`, { index });
    }
  }
}

/**
 * Bounded subprocess: output is capped, and a timeout kills the whole process
 * GROUP so a spawned limactl cannot leave orphaned children behind
 * (13-hermes-fleet-migration.md section 1).
 */
export function createNodeProcessPort(options: NodeProcessPortOptions = {}): ProcessPort {
  const guard = options.secretGuard ?? noopSecretGuard;

  return {
    // `async` so a pre-spawn refusal is a rejected promise like every other
    // failure of this port, rather than a synchronous throw callers would have
    // to handle twice.
    async run(request) {
      assertSafeArgv(request.argv);
      const [command, ...args] = request.argv as string[];
      const limit = request.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
      const overrides = request.env ?? {};
      const inherited = childEnvironment(process.env, {}, request.inheritEnv ?? []);
      const env = { ...inherited, ...overrides };

      // argv is visible in `ps` to every process on the host, and the child's
      // environment is readable by the child and everything it spawns. Both are
      // checked BEFORE the spawn, so a refusal means nothing was started.
      guard.assertClean("process:argv", request.argv.join(" "));
      // The environment is two different things wearing one name, and guarding
      // it as a single region got one of them wrong. Values a CALLER assembled
      // are payload — a credential of any length in one of them is a leak, and
      // the metadata carve-out would have waved a short one through. The
      // inherited half is the host's own PATH, HOME and locale: system-generated
      // structure a four-character credential matches by coincidence, which is
      // exactly what the carve-out exists for.
      guard.assertClean("process:env", Object.values(overrides).join(" "));
      guard.assertClean("process:env", Object.values(inherited).join(" "), "metadata");

      return new Promise<ProcessResult>((resolve, reject) => {
        const child = spawn(command as string, args, {
          detached: true,
          stdio: ["pipe", "pipe", "pipe"],
          env,
        });

        let truncated = false;
        let timedOut = false;
        let settled = false;
        let stdinError: Error | null = null;

        /**
         * One output stream, bounded in BYTES and decoded across chunk
         * boundaries.
         *
         * The cap counted UTF-16 code units of the decoded string, so
         * `maxOutputBytes: 1000` admitted 3000 bytes of CJK and the 1 MiB
         * default admitted 3 MiB — a bound that is not the bound it names.
         * Decoding each chunk on its own with `chunk.toString("utf8")` was the
         * other half: a multi-byte character split across a pipe read became two
         * U+FFFD, which is silent corruption of the very output this port exists
         * to parse. `StringDecoder` holds the partial sequence; the counter
         * measures the bytes.
         */
        const sink = (): { text: string; push: (chunk: Buffer) => void } => {
          const decoder = new StringDecoder("utf8");
          let bytes = 0;
          const self = {
            text: "",
            push(chunk: Buffer): void {
              if (bytes >= limit) {
                truncated = true;
                return;
              }
              const room = limit - bytes;
              const slice = chunk.length > room ? chunk.subarray(0, room) : chunk;
              if (slice.length < chunk.length) truncated = true;
              bytes += slice.length;
              self.text += decoder.write(slice);
            },
          };
          return self;
        };

        const out = sink();
        const err = sink();

        const killGroup = (): void => {
          if (child.pid === undefined) return;
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            child.kill("SIGKILL");
          }
        };

        const timer = setTimeout(() => {
          timedOut = true;
          killGroup();
        }, request.timeoutMs);

        child.stdout.on("data", (chunk: Buffer) => {
          out.push(chunk);
        });
        child.stderr.on("data", (chunk: Buffer) => {
          err.push(chunk);
        });

        child.on("error", (error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(error);
        });

        child.on("close", (code, signal) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          // A child that exited non-zero explains itself; a child that exited
          // ZERO while the input it was being fed never arrived is the
          // dangerous case — the credential or the artifact was not delivered
          // and every layer above would read that as success.
          if (stdinError !== null && code === 0) {
            reject(
              new YashikiError(
                "AMBIGUOUS_RESULT",
                `writing stdin to ${command as string} produced an ambiguous result: the child closed its ` +
                  `input before it was written (${(stdinError as Error).message}) but exited 0`,
                { operation: `stdin:${command as string}` },
              ),
            );
            return;
          }
          resolve({ exitCode: code, signal, stdout: out.text, stderr: err.text, timedOut, truncated });
        });

        // An unhandled 'error' on stdin is an uncaught exception that takes the
        // WHOLE PROCESS down: `write EPIPE` and exit 1, before this promise
        // settles, past `runCli`'s exit-code path and past any `finally` that
        // would have released the node lock. Every child that exits without
        // draining its input produces it — a `limactl shell` that cannot
        // connect, exactly — and this is the channel a credential and the node
        // artifact travel down. It is recorded and decided in `close`, where
        // the child's own exit code is known.
        child.stdin.on("error", (error: Error) => {
          stdinError = error;
        });

        if (request.stdin !== undefined) {
          child.stdin.end(request.stdin);
        } else {
          child.stdin.end();
        }
      });
    },
  };
}

export type FakeProcessCall = {
  argv: readonly string[];
  stdin?: string | undefined;
};

export type FakeProcessPort = ProcessPort & {
  readonly calls: readonly FakeProcessCall[];
};

export type FakeHandler = (call: FakeProcessCall) => Partial<ProcessResult> | undefined;

/** Test double. Handlers are tried in order; the first non-undefined wins. */
export function createFakeProcessPort(handlers: readonly FakeHandler[]): FakeProcessPort {
  const calls: FakeProcessCall[] = [];

  return {
    calls,
    async run(request) {
      assertSafeArgv(request.argv);
      const call: FakeProcessCall = { argv: [...request.argv], stdin: request.stdin };
      calls.push(call);

      for (const handler of handlers) {
        const result = handler(call);
        if (result !== undefined) {
          return {
            exitCode: 0,
            signal: null,
            stdout: "",
            stderr: "",
            timedOut: false,
            truncated: false,
            ...result,
          };
        }
      }
      return { exitCode: 0, signal: null, stdout: "", stderr: "", timedOut: false, truncated: false };
    },
  };
}
