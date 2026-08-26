import { describe, expect, it } from "vitest";
import {
  createRecordingLogger,
  createSecretGuard,
  fixedClock,
  isYashikiError,
  type CredentialRequirement,
  type DesiredNodeConfig,
  type ExecInput,
  type ExecResult,
  type NodeProvider,
  type NodeRef,
} from "@meidoya-yashiki/yashiki-core";
import { canonicalize, createInMemoryReceiptStore, sha256Hex, type JsonValue } from "@meidoya-yashiki/receipts";
import { CredentialMaterializer } from "./materializer.js";
import { createExecGuestCredentialPort } from "./exec-guest-port.js";
import type { GuestCredentialPort, GuestFileStat, SecretSourcePort } from "./ports.js";

const SECRET = "sk-live-CODEX-9f3a2b7c-do-not-log";
const node: NodeRef = { name: "work-grammarxiv", provider: "lima" };

const codex: CredentialRequirement = {
  provider: "codex",
  sourceRef: "keychain:meidoya/codex-login",
  guestPath: "/home/meidoya/.codex/auth.json",
  mode: 0o600,
  owner: "meidoya",
  optional: false,
};

const config: DesiredNodeConfig = {
  name: "work-grammarxiv",
  provider: "lima",
  profile: "lima-trusted",
  platform: "linux",
  arch: "arm64",
  cpus: 8,
  memoryMiB: 16384,
  diskGiB: 100,
  mounts: [],
  credentials: [codex],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: "a".repeat(64) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: [],
};

type GuestFile = { content: string; owner: string; mode: number; symlink: boolean };

/**
 * Fake guest filesystem driven through NodeProvider.exec, as in production.
 *
 * `symlinkedDirs` maps a directory path to the physical path it really is, the
 * way `cd "$dir" && pwd -P` would report it. That is the shape of the attack
 * the write script now refuses: a link planted in the MIDDLE of the path, which
 * the final-component check never saw and the post-write `stat` followed.
 */
function fakeGuestProvider(
  seed: Record<string, GuestFile> = {},
  symlinkedDirs: Record<string, string> = {},
): {
  provider: NodeProvider;
  files: Record<string, GuestFile>;
  calls: { argv: readonly string[]; stdin?: string | undefined }[];
} {
  const files: Record<string, GuestFile> = { ...seed };
  const calls: { argv: readonly string[]; stdin?: string | undefined }[] = [];

  const dirname = (path: string): string => path.slice(0, path.lastIndexOf("/")) || "/";

  const exec = async (_node: NodeRef, input: ExecInput): Promise<ExecResult> => {
    calls.push({ argv: [...input.argv], stdin: input.stdin });
    const result = (exitCode: number, stdout = ""): ExecResult => ({
      exitCode,
      stdout,
      stderr: "",
      timedOut: false,
      truncated: false,
    });
    const ok = (stdout = ""): ExecResult => result(0, stdout);
    const fail = (): ExecResult => result(1);

    const [initialCommand, ...initialArgs] = input.argv;
    const sudoOffset = initialCommand === "sudo" && initialArgs[0] === "-u" ? 3 : 1;
    const command = initialCommand === "sudo" ? initialArgs[sudoOffset - 1] : initialCommand;
    const args = initialCommand === "sudo" ? initialArgs.slice(sudoOffset) : initialArgs;
    if (command === "sh") {
      // Production passes every guest script as `sh -c SCRIPT sh ARG...`, so
      // the fake dispatches on the script the way a shell would.
      const script = args[1] as string;
      const path = args[3] as string;

      if (script.includes('cat > "$1"')) {
        const dir = dirname(path);
        const physical = symlinkedDirs[dir] ?? dir;
        // A real `sh` only refuses when the script asks it to; the fake reads
        // the script for the same reason, so dropping the check from the script
        // shows up here as a write that lands on the attacker's directory.
        if (script.includes('[ "$physical" = "$dir" ] || exit 91') && physical !== dir) return result(91);
        if (physical !== dir) {
          files[`${physical}/${path.slice(dir.length + 1)}`] = {
            content: input.stdin ?? "",
            owner: args[5] as string,
            mode: Number.parseInt(args[4] as string, 8),
            symlink: false,
          };
          return ok();
        }
        files[path] = {
          content: input.stdin ?? "",
          owner: args[5] as string,
          mode: Number.parseInt(args[4] as string, 8),
          symlink: false,
        };
        return ok();
      }
      if (script.includes("stat")) {
        const file = files[path];
        return file === undefined ? fail() : ok(`${file.owner} ${file.mode.toString(8).padStart(3, "0")}\n`);
      }
      if (script.includes("sha256sum")) {
        const file = files[path];
        return file === undefined ? fail() : ok(`${sha256Hex(file.content)}  ${path}\n`);
      }
      return fail();
    }
    if (command === "test") {
      const path = args[1] as string;
      const file = files[path];
      if (args[0] === "-L") return file?.symlink === true ? ok() : fail();
      if (args[0] === "-e") return file === undefined ? fail() : ok();
      if (args[0] === "-r") return file === undefined ? fail() : ok();
      return fail();
    }
    if (command === "rm") {
      delete files[args[1] as string];
      return ok();
    }
    return fail();
  };

  const provider: NodeProvider = {
    create: async () => node,
    start: async () => undefined,
    stop: async () => undefined,
    inspect: async () => ({ ref: node, status: "running", cpus: null, memoryMiB: null, diskGiB: null, mounts: [] }),
    exec,
    destroy: async () => undefined,
  };

  return { provider, files, calls };
}

function fakeSource(values: Record<string, string | null> = { [codex.sourceRef]: SECRET }): SecretSourcePort {
  return { read: async (ref) => values[ref] ?? null };
}

function setup(seed: Record<string, GuestFile> = {}, symlinkedDirs: Record<string, string> = {}) {
  const guestProvider = fakeGuestProvider(seed, symlinkedDirs);
  const logger = createRecordingLogger();
  const guard = createSecretGuard();
  const receipts = createInMemoryReceiptStore({ secretGuard: guard });
  const materializer = new CredentialMaterializer({
    source: fakeSource(),
    guest: createExecGuestCredentialPort(guestProvider.provider),
    receipts,
    clock: fixedClock("2026-01-01T00:00:00.000Z"),
    logger,
    secretGuard: guard,
  });
  return { ...guestProvider, logger, receipts, materializer, guard };
}

describe("CredentialMaterializer", () => {
  it("materializes a credential and verifies owner, mode and content", async () => {
    const { materializer, files } = setup();
    const outcomes = await materializer.sync(node, config);

    expect(outcomes).toEqual([
      { provider: "codex", operation: "sync", guestPath: codex.guestPath, changed: true, skipped: false },
    ]);
    expect(files[codex.guestPath]).toEqual({ content: SECRET, owner: "meidoya", mode: 0o600, symlink: false });
  });

  it("never puts the credential value in argv", async () => {
    const { materializer, calls } = setup();
    await materializer.sync(node, config);

    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      for (const arg of call.argv) expect(arg).not.toContain(SECRET);
    }
    // The value only ever travels on stdin.
    expect(calls.some((call) => call.stdin === SECRET)).toBe(true);
  });

  it("never puts the credential value in logs or receipts", async () => {
    const { materializer, logger, receipts } = setup();
    await materializer.sync(node, config);

    for (const line of logger.lines) expect(line).not.toContain(SECRET);

    const rendered = canonicalize(receipts.list() as unknown as JsonValue);
    expect(rendered).not.toContain(SECRET);
    expect(rendered).toContain("valueFingerprint");
    expect(rendered).toContain("codex");
  });

  it("writes one receipt per provider", async () => {
    const claude: CredentialRequirement = {
      provider: "claude",
      sourceRef: "keychain:meidoya/claude-token",
      guestPath: "/home/meidoya/.claude/token",
      mode: 0o600,
      owner: "meidoya",
      optional: false,
    };
    const guestProvider = fakeGuestProvider();
    const receipts = createInMemoryReceiptStore();
    const materializer = new CredentialMaterializer({
      source: { read: async (ref) => (ref === claude.sourceRef ? "claude-secret-value" : SECRET) },
      guest: createExecGuestCredentialPort(guestProvider.provider),
      receipts,
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
    });

    await materializer.sync(node, { ...config, credentials: [codex, claude] });

    const recorded = receipts.list({ kind: "credential" });
    expect(recorded).toHaveLength(2);
    expect(recorded.map((receipt) => receipt.payload["provider"])).toEqual(["codex", "claude"]);
    expect(new Set(recorded.map((receipt) => receipt.payload["guestPath"])).size).toBe(2);
  });

  /**
   * Defect 19. A short credential must not turn `sync` into a command that
   * refuses AFTER the value has already been written to the guest: that failure
   * mode is unrecoverable — every retry writes and then refuses again — and so
   * is strictly worse than the leak that dropping the length floor closed.
   * `2026` is deliberately a value that occurs inside the receipt's own
   * timestamp.
   */
  it("materializes a four-character credential end to end instead of refusing after the guest write", async () => {
    const SHORT = "2026";
    const guestProvider = fakeGuestProvider();
    const guard = createSecretGuard();
    const receipts = createInMemoryReceiptStore({ secretGuard: guard });
    const materializer = new CredentialMaterializer({
      source: { read: async () => SHORT },
      guest: createExecGuestCredentialPort(guestProvider.provider),
      receipts,
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
      secretGuard: guard,
    });

    const outcomes = await materializer.sync(node, config);

    expect(outcomes[0]?.changed).toBe(true);
    expect(guestProvider.files[codex.guestPath]?.content).toBe(SHORT);
    expect(receipts.list({ kind: "credential" })).toHaveLength(1);
    // And the guard is NOT blind to it: it is scoped, not disabled.
    expect(() => guard.assertClean("test-probe", `token=${SHORT}`)).toThrowError(/CREDENTIAL_UNSAFE/);
  });

  it("is idempotent when the guest already holds the exact credential", async () => {
    const { materializer, files } = setup({
      [codex.guestPath]: { content: SECRET, owner: "meidoya", mode: 0o600, symlink: false },
    });
    const outcomes = await materializer.sync(node, config);

    expect(outcomes[0]?.changed).toBe(false);
    expect(files[codex.guestPath]?.content).toBe(SECRET);
  });

  it("refuses to write through a symlink at the destination", async () => {
    const { materializer } = setup({
      [codex.guestPath]: { content: "", owner: "root", mode: 0o777, symlink: true },
    });

    try {
      await materializer.sync(node, config);
    } catch (error) {
      expect(isYashikiError(error, "CREDENTIAL_UNSAFE")).toBe(true);
      return;
    }
    throw new Error("expected the symlinked destination to be rejected");
  });

  it("refuses to write through a symlinked DIRECTORY on the way to the destination", async () => {
    // Guarding only the final component left the interesting attack open: a
    // directory link planted guest-side before materialization redirects the
    // write, and the post-write `stat` follows the same link and reports the
    // attacker's file as correct. The write script compares `pwd -P` against
    // the path it was given.
    const { materializer, files } = setup({}, { "/home/meidoya/.codex": "/tmp/attacker" });

    try {
      await materializer.sync(node, config);
    } catch (error) {
      expect(isYashikiError(error, "CREDENTIAL_UNSAFE")).toBe(true);
      expect(Object.keys(files)).toEqual([]);
      return;
    }
    throw new Error("expected the symlinked credential directory to be rejected");
  });

  it("does not need root to write a credential it already owns", async () => {
    // `chown` is a privileged call, and the native provider is not root; the
    // script only chowns when the owner differs, so this configuration — which
    // config.ts accepts — can succeed at all.
    const { materializer, calls } = setup();
    await materializer.sync(node, config);

    const writeScript = calls
      .flatMap((call) => call.argv)
      .find((argument) => argument.includes('cat > "$1"'));
    expect(writeScript).toContain('[ "$(id -un)" = "$3" ] || chown');
  });

  it("reads owner, mode and digest with commands that exist on macOS as well as Linux", async () => {
    // `stat -c` and `sha256sum` are GNU coreutils. On a native darwin node
    // every credential failed at `stat: illegal option -- c` and surfaced as
    // CREDENTIAL_UNSAFE — a security refusal reporting a platform bug.
    const { materializer, calls } = setup();
    await materializer.sync(node, config);

    const scripts = calls.flatMap((call) => call.argv).filter((argument) => argument.includes("stat") || argument.includes("sha256sum"));
    expect(scripts.some((script) => script.includes('stat -c "%U %a"') && script.includes('stat -f "%Su %OLp"'))).toBe(
      true,
    );
    expect(scripts.some((script) => script.includes("sha256sum") && script.includes("shasum -a 256"))).toBe(true);
  });

  it("fails when the guest ends up with the wrong owner or mode", async () => {
    const guest: GuestCredentialPort = {
      writeSecret: async () => undefined,
      stat: async (): Promise<GuestFileStat> => ({
        exists: true,
        isSymlink: false,
        owner: "root",
        mode: 0o644,
        sha256: sha256Hex(SECRET),
      }),
      remove: async () => undefined,
    };
    const materializer = new CredentialMaterializer({
      source: fakeSource(),
      guest,
      receipts: createInMemoryReceiptStore(),
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
    });

    await expect(materializer.sync(node, config)).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
  });

  it("fails on a missing required credential and skips a missing optional one", async () => {
    const guestProvider = fakeGuestProvider();
    const materializer = new CredentialMaterializer({
      source: { read: async () => null },
      guest: createExecGuestCredentialPort(guestProvider.provider),
      receipts: createInMemoryReceiptStore(),
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
    });

    await expect(materializer.sync(node, config)).rejects.toThrowError(/NOT_FOUND/);

    const optional = await materializer.sync(node, {
      ...config,
      credentials: [{ ...codex, provider: "github", optional: true }],
    });
    expect(optional[0]?.skipped).toBe(true);
  });

  it("keeps revoke separate from sync", async () => {
    const { materializer, files, receipts } = setup();
    await materializer.sync(node, config);
    expect(files[codex.guestPath]).toBeDefined();

    const outcome = await materializer.revoke(node, codex);
    expect(outcome.operation).toBe("revoke");
    expect(files[codex.guestPath]).toBeUndefined();

    const operations = receipts.list({ kind: "credential" }).map((receipt) => receipt.payload["operation"]);
    expect(operations).toEqual(["sync", "revoke"]);
    expect(receipts.list({ kind: "credential" }).at(-1)?.payload["valueFingerprint"]).toBeNull();
  });

  /**
   * End-to-end over the real materializer: a PEM-shaped secret (the shape that
   * used to slip past the guard once JSON-escaped) must reach the guest on
   * stdin only, leave a fingerprint in the receipt, and arm the guard so any
   * later receipt carrying that value is refused.
   */
  it("keeps a multi-line PEM credential on stdin, fingerprinted, and guarded", async () => {
    const pem = [
      "-----BEGIN RSA " + "PRIVATE KEY-----",
      "MIIDUMMYnotarealkeyAAAAAAAAAAAAAAAAAAAA",
      "-----END RSA " + "PRIVATE KEY-----",
    ].join("\n");
    const guestProvider = fakeGuestProvider();
    const logger = createRecordingLogger();
    const guard = createSecretGuard();
    const receipts = createInMemoryReceiptStore({ secretGuard: guard });
    const materializer = new CredentialMaterializer({
      source: fakeSource({ [codex.sourceRef]: pem }),
      guest: createExecGuestCredentialPort(guestProvider.provider),
      receipts,
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
      logger,
      secretGuard: guard,
    });

    await materializer.sync(node, config);

    for (const call of guestProvider.calls) {
      for (const arg of call.argv) expect(arg).not.toContain("MIIDUMMY");
    }
    expect(guestProvider.calls.some((call) => call.stdin === pem)).toBe(true);

    const receipt = receipts.list({ kind: "credential" }).at(-1);
    expect(receipt?.payload["valueFingerprint"]).toMatch(/^[0-9a-f]{64}$/);
    expect(canonicalize(receipts.list() as unknown as JsonValue)).not.toContain("MIIDUMMY");
    for (const line of logger.lines) expect(line).not.toContain("MIIDUMMY");

    // The guard now knows the value; a receipt carrying it JSON-escaped is refused.
    let refused = false;
    try {
      receipts.append({
        kind: "credential",
        nodeName: node.name,
        createdAt: "2026-01-01T00:00:00.000Z",
        payload: { provider: "codex", leaked: pem },
      });
    } catch (error) {
      refused = isYashikiError(error, "CREDENTIAL_UNSAFE");
    }
    expect(refused).toBe(true);
  });

  it("fails closed when a revoked credential is still present", async () => {
    const guest: GuestCredentialPort = {
      writeSecret: async () => undefined,
      remove: async () => undefined,
      stat: async () => ({ exists: true, isSymlink: false, owner: "meidoya", mode: 0o600, sha256: sha256Hex(SECRET) }),
    };
    const materializer = new CredentialMaterializer({
      source: fakeSource(),
      guest,
      receipts: createInMemoryReceiptStore(),
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
    });

    await expect(materializer.revoke(node, codex)).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  describe("primeGuard", () => {
    /** Asserts guard knowledge without ever printing the value. */
    const knows = (guard: { assertClean(context: string, text: string): void }): boolean => {
      try {
        guard.assertClean("test-probe", `x ${SECRET} y`);
        return false;
      } catch (error) {
        if (isYashikiError(error, "CREDENTIAL_UNSAFE")) return true;
        throw error;
      }
    };

    it("teaches the guard the declared values without writing or recording anything", async () => {
      const { materializer, guard, receipts, files, calls } = setup();
      expect(knows(guard)).toBe(false);

      expect(await materializer.primeGuard(node, config)).toBe(1);

      expect(knows(guard)).toBe(true);
      // Read-only: no guest write, no receipt, no stat.
      expect(files).toEqual({});
      expect(calls).toEqual([]);
      expect(receipts.list()).toHaveLength(0);
    });

    it("never puts the value in a log line", async () => {
      const { materializer, logger } = setup();
      await materializer.primeGuard(node, config);
      expect(logger.lines.join("\n")).not.toContain(SECRET);
    });

    it("skips a credential the host cannot produce instead of failing the command", async () => {
      const guard = createSecretGuard();
      const materializer = new CredentialMaterializer({
        source: { read: async () => null },
        guest: createExecGuestCredentialPort(fakeGuestProvider().provider),
        receipts: createInMemoryReceiptStore({ secretGuard: guard }),
        clock: fixedClock("2026-01-01T00:00:00.000Z"),
        secretGuard: guard,
      });

      // Doctor exists to diagnose exactly this, so it must still run — blind.
      expect(await materializer.primeGuard(node, config)).toBe(0);
      expect(knows(guard)).toBe(false);
    });

    it("survives a host secret tool that throws", async () => {
      const guard = createSecretGuard();
      const materializer = new CredentialMaterializer({
        source: {
          read: async () => {
            throw new Error("keychain is locked");
          },
        },
        guest: createExecGuestCredentialPort(fakeGuestProvider().provider),
        receipts: createInMemoryReceiptStore({ secretGuard: guard }),
        clock: fixedClock("2026-01-01T00:00:00.000Z"),
        secretGuard: guard,
      });

      expect(await materializer.primeGuard(node, config)).toBe(0);
    });
  });
});
