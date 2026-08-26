import { describe, expect, it } from "vitest";
import { isYashikiError } from "./errors.js";
import {
  assertSafeArgv,
  childEnvironment,
  createFakeProcessPort,
  createNodeProcessPort,
  CREDENTIAL_SOURCE_ENV_NAMES,
  INHERITED_ENV_NAMES,
  OPTIONAL_ENV_NAMES,
} from "./process.js";
import { createSecretGuard } from "./secret-guard.js";

/** Obvious dummies. Nothing here is or resembles a live credential. */
const SECRET = "dummy-not-a-real-credential-value";
/** Written as an escape, never as a raw control byte in this file. */
const NUL = String.fromCharCode(0);

describe("assertSafeArgv", () => {
  it("rejects an empty argv", () => {
    expect(() => assertSafeArgv([])).toThrowError(/PROVIDER_FAILED/);
  });

  /**
   * A NUL truncates every C string. `execve` would take `["cat", "/etc/x\\0;rm"]`
   * as `/etc/x`, so an argument that passed every string-level check can still
   * name a different file than the one that was validated.
   */
  it("rejects an argument containing a NUL byte, at any position", () => {
    for (const arg of [`${NUL}leading`, `mid${NUL}dle`, `trailing${NUL}`]) {
      expect(() => assertSafeArgv(["limactl", "shell", arg])).toThrowError(/PROVIDER_FAILED/);
    }
    try {
      assertSafeArgv(["limactl", `x${NUL}y`]);
    } catch (error) {
      if (!isYashikiError(error, "PROVIDER_FAILED")) throw error;
      expect(error.message).toContain("NUL");
      expect(error.details).toEqual({ index: 1 });
      return;
    }
    throw new Error("expected a refusal");
  });

  it("accepts ordinary argv, including one carrying shell metacharacters as data", () => {
    // There is no shell: metacharacters are inert because argv is an array.
    expect(() => assertSafeArgv(["limactl", "shell", "node", "--", "sh", "-c", "echo $HOME; ls | wc"])).not.toThrow();
  });

  it("is enforced by the fake port too, so tests cannot pass argv the real port would reject", async () => {
    const port = createFakeProcessPort([]);
    await expect(port.run({ argv: ["limactl", `a${NUL}b`], timeoutMs: 1000 })).rejects.toThrowError(
      /PROVIDER_FAILED/,
    );
  });
});

describe("childEnvironment", () => {
  it("passes through only the allowlisted host variables", () => {
    const env = childEnvironment({
      PATH: "/usr/bin",
      HOME: "/Users/dummy",
      // Every one of these is a credential a developer machine really does
      // export, and every one of them used to reach `limactl shell` and the
      // guest through it.
      ANTHROPIC_API_KEY: SECRET,
      GITHUB_TOKEN: SECRET,
      AWS_SECRET_ACCESS_KEY: SECRET,
      SSH_AUTH_SOCK: "/private/tmp/agent.sock",
      NPM_TOKEN: SECRET,
    });

    expect(env["PATH"]).toBe("/usr/bin");
    expect(env["HOME"]).toBe("/Users/dummy");
    expect(Object.keys(env).sort()).toEqual(["HOME", "PATH"]);
    // Asserted by absence of the NAMES, never by printing the values.
    for (const name of ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "NPM_TOKEN"]) {
      expect(Object.keys(env)).not.toContain(name);
    }
    expect(Object.values(env).join(" ")).not.toContain(SECRET);
  });

  it("is an allowlist, not a denylist: an unknown name is dropped by default", () => {
    const env = childEnvironment({ SOME_FUTURE_VENDOR_TOKEN: SECRET });
    expect(env).toEqual({});
    expect(INHERITED_ENV_NAMES).not.toContain("SOME_FUTURE_VENDOR_TOKEN");
  });

  it("still lets a caller set what it asked for explicitly", () => {
    const env = childEnvironment({ PATH: "/usr/bin" }, { LIMA_HOME: "/tmp/lima" });
    expect(env).toEqual({ PATH: "/usr/bin", LIMA_HOME: "/tmp/lima" });
  });

  /**
   * Defect 20e. The allowlist dropped everything sops uses to FIND its key, so
   * `sops -d` failed, the failure was read as "no such credential", and the
   * operator was pointed at the wrong problem entirely. A source now opts into
   * exactly the locators its scheme needs.
   */
  describe("a credential source opts into the locators it needs", () => {
    const host = {
      PATH: "/usr/bin",
      SOPS_AGE_KEY_FILE: "/Users/dummy/.config/sops/age/keys.txt",
      GNUPGHOME: "/Users/dummy/.gnupg",
      AWS_PROFILE: "dummy-profile",
      AWS_REGION: "ap-northeast-1",
      // Values, not locators. These must not reach any child, ever.
      SOPS_AGE_KEY: SECRET,
      AWS_SECRET_ACCESS_KEY: SECRET,
      AWS_SESSION_TOKEN: SECRET,
      AWS_ACCESS_KEY_ID: SECRET,
    };

    it("forwards the locators sops needs when the sops source asks for them", () => {
      const env = childEnvironment(host, {}, CREDENTIAL_SOURCE_ENV_NAMES["sops"] ?? []);
      expect(env["SOPS_AGE_KEY_FILE"]).toBe(host.SOPS_AGE_KEY_FILE);
      expect(env["GNUPGHOME"]).toBe(host.GNUPGHOME);
      expect(env["AWS_PROFILE"]).toBe("dummy-profile");
      expect(env["AWS_REGION"]).toBe("ap-northeast-1");
    });

    it("forwards no key VALUE, only the places a key can be found", () => {
      const env = childEnvironment(host, {}, CREDENTIAL_SOURCE_ENV_NAMES["sops"] ?? []);
      for (const name of ["SOPS_AGE_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID"]) {
        expect(Object.keys(env)).not.toContain(name);
        expect(CREDENTIAL_SOURCE_ENV_NAMES["sops"]).not.toContain(name);
      }
      // Asserted by absence of the names above and of the value here.
      expect(Object.values(env).join(" ")).not.toContain(SECRET);
    });

    it("gives the keychain source nothing beyond the base allowlist", () => {
      const env = childEnvironment(host, {}, CREDENTIAL_SOURCE_ENV_NAMES["keychain"] ?? []);
      expect(Object.keys(env)).toEqual(["PATH"]);
    });

    it("ignores an opt-in that is not on the optional list, so it cannot widen itself", () => {
      const env = childEnvironment(host, {}, ["AWS_SECRET_ACCESS_KEY", "SOPS_AGE_KEY"]);
      expect(Object.keys(env)).toEqual(["PATH"]);
      expect(OPTIONAL_ENV_NAMES).not.toContain("AWS_SECRET_ACCESS_KEY");
      expect(OPTIONAL_ENV_NAMES).not.toContain("SOPS_AGE_KEY");
    });

    it("does not leak one source's locators into another source's child", () => {
      const env = childEnvironment(host, {}, CREDENTIAL_SOURCE_ENV_NAMES["keychain"] ?? []);
      expect(Object.keys(env)).not.toContain("SOPS_AGE_KEY_FILE");
    });
  });
});

describe("the real process port refuses to spawn a leak", () => {
  it("refuses argv carrying a remembered credential value, before spawning anything", async () => {
    const port = createNodeProcessPort({ secretGuard: createSecretGuard([SECRET]) });
    // `/usr/bin/true` is never reached: the refusal happens before `spawn`.
    await expect(port.run({ argv: ["/usr/bin/true", `--token=${SECRET}`], timeoutMs: 1000 })).rejects.toThrowError(
      /CREDENTIAL_UNSAFE/,
    );
  });

  it("refuses argv carrying an encoded credential value too", async () => {
    const port = createNodeProcessPort({ secretGuard: createSecretGuard([SECRET]) });
    const encoded = Buffer.from(SECRET, "utf8").toString("base64");
    await expect(port.run({ argv: ["/usr/bin/true", encoded], timeoutMs: 1000 })).rejects.toThrowError(
      /CREDENTIAL_UNSAFE/,
    );
  });

  it("refuses an explicitly passed environment variable carrying the value", async () => {
    const port = createNodeProcessPort({ secretGuard: createSecretGuard([SECRET]) });
    await expect(
      port.run({ argv: ["/usr/bin/true"], timeoutMs: 1000, env: { LIMA_HOME: `/tmp/${SECRET}` } }),
    ).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
  });

  /**
   * Defect 20f. `process:env` was guarded wholesale as `"metadata"`, but half of
   * it is data a caller assembled. The metadata carve-out exists to stop a
   * four-character credential matching a timestamp the system generated — it
   * has no business covering a value a caller put there.
   */
  describe("the two halves of the environment are guarded as what they are", () => {
    /** Shorter than SHORT_VALUE_LENGTH: only a payload region matches it. */
    const SHORT = "d0y";

    it("guards caller-supplied environment values as PAYLOAD, so a short credential is caught", async () => {
      const port = createNodeProcessPort({ secretGuard: createSecretGuard([SHORT]) });
      await expect(
        port.run({ argv: ["/usr/bin/true"], timeoutMs: 1000, env: { LIMA_HOME: `/tmp/${SHORT}` } }),
      ).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
    });

    it("guards the INHERITED half as metadata, so a short value does not refuse every spawn", async () => {
      const previous = process.env["LIMA_HOME"];
      process.env["LIMA_HOME"] = `/tmp/lima-${SHORT}`;
      try {
        const port = createNodeProcessPort({ secretGuard: createSecretGuard([SHORT]) });
        const result = await port.run({ argv: ["/usr/bin/true"], timeoutMs: 10_000 });
        expect(result.exitCode).toBe(0);
      } finally {
        if (previous === undefined) delete process.env["LIMA_HOME"];
        else process.env["LIMA_HOME"] = previous;
      }
    });

    it("still refuses a full-length credential in the inherited half", async () => {
      const previous = process.env["LIMA_HOME"];
      process.env["LIMA_HOME"] = `/tmp/${SECRET}`;
      try {
        const port = createNodeProcessPort({ secretGuard: createSecretGuard([SECRET]) });
        await expect(port.run({ argv: ["/usr/bin/true"], timeoutMs: 1000 })).rejects.toThrowError(
          /CREDENTIAL_UNSAFE/,
        );
      } finally {
        if (previous === undefined) delete process.env["LIMA_HOME"];
        else process.env["LIMA_HOME"] = previous;
      }
    });
  });

  it("gives a child the locators it opted into, and nothing else from the host", async () => {
    const previous = { key: process.env["SOPS_AGE_KEY_FILE"], value: process.env["SOPS_AGE_KEY"] };
    process.env["SOPS_AGE_KEY_FILE"] = "/Users/dummy/.config/sops/age/keys.txt";
    process.env["SOPS_AGE_KEY"] = SECRET;
    try {
      const port = createNodeProcessPort({ secretGuard: createSecretGuard([SECRET]) });
      const result = await port.run({
        argv: ["/usr/bin/env"],
        timeoutMs: 10_000,
        inheritEnv: CREDENTIAL_SOURCE_ENV_NAMES["sops"] ?? [],
      });

      expect(result.exitCode).toBe(0);
      const names = result.stdout.split("\n").map((line) => line.split("=")[0] ?? "");
      expect(names).toContain("SOPS_AGE_KEY_FILE");
      expect(names).not.toContain("SOPS_AGE_KEY");
      expect(result.stdout).not.toContain(SECRET);
    } finally {
      if (previous.key === undefined) delete process.env["SOPS_AGE_KEY_FILE"];
      else process.env["SOPS_AGE_KEY_FILE"] = previous.key;
      if (previous.value === undefined) delete process.env["SOPS_AGE_KEY"];
      else process.env["SOPS_AGE_KEY"] = previous.value;
    }
  });

  it("runs a clean command, and the child gets the allowlisted environment only", async () => {
    const port = createNodeProcessPort({ secretGuard: createSecretGuard([SECRET]) });
    const result = await port.run({ argv: ["/usr/bin/env"], timeoutMs: 10_000 });

    expect(result.exitCode).toBe(0);
    for (const line of result.stdout.split("\n")) {
      const name = line.split("=")[0] ?? "";
      if (name === "") continue;
      expect(INHERITED_ENV_NAMES).toContain(name);
    }
  });
});

/**
 * The bounds this port advertises, measured. Every child here is a short-lived
 * `sh` or a `node -e` one-liner reading from a pipe; none touches the network
 * or a VM, and all of them exit on their own.
 */
describe("the real process port's bounds are the bounds it names", () => {
  const port = createNodeProcessPort();
  /** 3 bytes, 1 UTF-16 code unit — the two units the cap could be counting. */
  const WIDE = "\u3042";

  it("counts maxOutputBytes in BYTES, not UTF-16 code units", async () => {
    // A cap that measured `string.length` let a 1000-"byte" limit through 3000
    // actual bytes, and the 1 MiB default through 3 MiB.
    const result = await port.run({
      argv: [process.execPath, "-e", `process.stdout.write(Buffer.from(${JSON.stringify(WIDE)}.repeat(4000), "utf8"))`],
      timeoutMs: 30_000,
      maxOutputBytes: 300,
    });

    expect(result.truncated).toBe(true);
    expect(Buffer.byteLength(result.stdout, "utf8")).toBeLessThanOrEqual(300);
  });

  it("decodes multi-byte characters that straddle a pipe boundary", async () => {
    // Node reads a pipe in 64 KiB chunks and 65536 is not a multiple of 3, so
    // one 600 KB write is guaranteed to split characters across reads.
    // `chunk.toString("utf8")` per chunk turned each split into two U+FFFD —
    // 122 of them here — which is silent corruption of the output this port
    // exists to parse.
    const result = await port.run({
      argv: [
        process.execPath,
        "-e",
        `process.stdout.write(Buffer.from(${JSON.stringify(WIDE)}.repeat(200000), "utf8"))`,
      ],
      timeoutMs: 60_000,
      maxOutputBytes: 8 * 1024 * 1024,
    });

    expect(result.truncated).toBe(false);
    expect(result.stdout).toHaveLength(200_000);
    expect(result.stdout).not.toContain("\uFFFD");
  });

  it("refuses to call an undelivered stdin a success", async () => {
    // A child that exits ZERO while the value it was being fed never arrived
    // is the dangerous case: nothing above would ever know that the credential
    // or the artifact was not written.
    const value = "y".repeat(8 * 1024 * 1024);
    let error: unknown = null;
    try {
      await port.run({ argv: ["sh", "-c", "exit 0"], timeoutMs: 30_000, stdin: value });
    } catch (caught) {
      error = caught;
    }
    // Whether the pipe breaks depends on the kernel buffer, so this asserts the
    // DISPOSITION: either the write landed, or it is reported as ambiguous.
    if (error !== null) expect(isYashikiError(error, "AMBIGUOUS_RESULT")).toBe(true);
  });
});

/**
 * `child.stdin.end(value)` with no `error` listener is an UNCAUGHT EXCEPTION —
 * `write EPIPE`, exit 1 — for any child that exits without draining its input.
 * It fires before the port's promise settles, so it bypasses `runCli`'s
 * exit-code path and any `finally` that would have released the node lock. This
 * is the channel `writeSecret` and the node artifact travel down, and a
 * `limactl shell` that cannot connect is exactly this shape.
 *
 * Vitest installs its own `uncaughtException` handler, which is why the suite
 * stayed green under the unguarded version while a real `node` running the same
 * code exited 1 with `Error: write EPIPE`. This listens for the same event
 * itself, so the crash is visible here rather than absorbed.
 */
describe("an unread stdin does not take the process down", () => {
  it("reports the child's own exit code instead of dying on EPIPE", async () => {
    const uncaught: Error[] = [];
    const record = (error: Error): void => {
      uncaught.push(error);
    };
    process.on("uncaughtException", record);
    try {
      const result = await createNodeProcessPort().run({
        // 1 MiB is comfortably past any pipe buffer, so the child exits with
        // the write still in flight.
        argv: ["sh", "-c", "exit 3"],
        timeoutMs: 30_000,
        stdin: "x".repeat(1024 * 1024),
      });
      // Give the failed write a turn to surface, as it would in production.
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(result.exitCode).toBe(3);
    } finally {
      process.off("uncaughtException", record);
    }

    expect(uncaught.map((error) => error.message)).toEqual([]);
  });
});
