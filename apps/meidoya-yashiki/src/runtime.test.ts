import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import {
  createSecretGuard,
  findNode,
  fixedClock,
  isYashikiError,
  parseYashikiConfig,
  type ProcessPort,
  type ProcessRequest,
  type ProcessResult,
} from "@meidoya-yashiki/yashiki-core";
import { runBackup, type BackupManifest } from "@meidoya-yashiki/backup";
import { createInMemoryReceiptStore, type JsonObject } from "@meidoya-yashiki/receipts";
import {
  collectBackupItems,
  createBackupArchiveSink,
  createRuntime,
  type RuntimeEnvironment,
} from "./runtime.js";

/**
 * Wires the real CLI runtime — the same `createRuntime` `main.ts` calls — against
 * a fake host process. This is where the secret guard is created and where each
 * command decides whether to populate it, so it is the only place the doctor /
 * status / backup guard population can actually be proved.
 */

/** An obvious dummy. It is never printed, only compared against. */
const SECRET = "dummy-not-a-real-credential-value";
const SOURCE_REF = "keychain:meidoya/claude-dummy";
const GUEST_PATH = "/home/meidoya/.claude/token";
const NODE = "work-grammarxiv";

const ARTIFACT_BYTES = Buffer.from("#!/bin/sh\nexit 0\n");
const ARTIFACT_SHA256 = createHash("sha256").update(ARTIFACT_BYTES).digest("hex");
const MANIFEST = JSON.stringify({
  product: "meidoya-node",
  version: "0.1.0",
  protocolVersion: 1,
  artifacts: [{ platform: "linux", arch: "arm64", sha256: ARTIFACT_SHA256 }],
});
const MANIFEST_SHA256 = createHash("sha256").update(MANIFEST).digest("hex");

function configYaml(): string {
  return `schema_version: 1
node_bundle:
  version: "0.1.0"
  protocol_version: 1
  manifest_sha256: "${MANIFEST_SHA256}"
nodes:
  ${NODE}:
    provider: lima
    profile: lima-trusted
    platform: linux
    arch: arm64
    cpus: 8
    memory: 16GiB
    disk: 100GiB
    max_concurrency: 4
    capabilities:
      - repo.read
    control_plane:
      endpoint: unix:///tmp/meidoya-dummy.sock
      temporal_address: 127.0.0.1:7233
      task_queue: meidoya/node/work-grammarxiv
    mounts: []
    credentials:
      - provider: claude
        source_ref: ${SOURCE_REF}
        guest_path: ${GUEST_PATH}
        mode: "0600"
        owner: meidoya
`;
}

type HostOptions = {
  /** What the fake Keychain returns for the declared credential. */
  keychainValue?: string | null;
  /** The guest's poller.json — a sink a Doctor line is rendered straight from. */
  pollerQueue?: string;
};

function ok(stdout = ""): ProcessResult {
  return { exitCode: 0, signal: null, stdout, stderr: "", timedOut: false, truncated: false };
}

function fail(exitCode = 1, stderr = ""): ProcessResult {
  return { exitCode, signal: null, stdout: "", stderr, timedOut: false, truncated: false };
}

function fakeHost(options: HostOptions = {}): ProcessPort & { readonly requests: readonly ProcessRequest[] } {
  const requests: ProcessRequest[] = [];
  const keychainValue = options.keychainValue === undefined ? SECRET : options.keychainValue;
  const pollerQueue = options.pollerQueue ?? "meidoya/node/dummy";

  const guest = (argv: readonly string[]): ProcessResult => {
    let guestArgv = argv[0] === "sudo" ? argv.slice(1) : argv;
    if (guestArgv[0] === "-u") guestArgv = guestArgv.slice(2);
    const line = guestArgv.join(" ");
    if (line === "cat /var/lib/meidoya-node/receipt.json") {
      return ok(
        JSON.stringify({
          product: "meidoya-node",
          version: "0.1.0",
          protocolVersion: 1,
          artifactSha256: ARTIFACT_SHA256,
          installedAt: "2026-01-01T00:00:00.000Z",
        }),
      );
    }
    if (line === "cat /var/lib/meidoya-node/poller.json") {
      return ok(JSON.stringify({ polling: true, queue: pollerQueue }));
    }
    if (line === "cat /var/lib/meidoya-node/registration.json") {
      return ok(JSON.stringify({ registered: true, protocolVersion: 1, lastHeartbeatAt: Date.parse("2026-01-01T00:00:00.000Z") }));
    }
    if (line === "test -f /etc/systemd/system/meidoya-node.service") return ok();
    if (line === "systemctl is-active meidoya-node") return ok("active\n");
    if (line.includes("/usr/local/bin/meidoya-node --runtime-probe")) return ok();
    if (guestArgv[0] === "sh") {
      // Guest scripts are `sh -c SCRIPT sh ARG...`; the stat and digest probes
      // try the GNU spelling and fall back to the BSD one, so a native darwin
      // node can materialize a credential at all.
      const script = guestArgv[2] ?? "";
      if (script.includes("stat")) return ok("meidoya 600\n");
      if (script.includes("sha256sum")) return ok(`${"d".repeat(64)}  ${guestArgv[4] ?? ""}\n`);
      return ok(); // `command -v <runtime>`
    }
    if (guestArgv[0] === "test" && guestArgv[1] === "-L") return fail();
    if (guestArgv[0] === "test" && guestArgv[1] === "-e") return ok();
    if (guestArgv[0] === "test" && guestArgv[1] === "-r") return ok();
    return fail(127, `unexpected guest command: ${line}`);
  };

  return {
    requests,
    async run(request) {
      requests.push(request);
      const [command, ...rest] = request.argv;

      if (command === "security") {
        return keychainValue === null ? fail() : ok(`${keychainValue}\n`);
      }
      if (command === "limactl") {
        if (rest[0] === "--version") return ok("limactl version 1.0.0\n");
        if (rest[0] === "list") {
          return ok(
            JSON.stringify({
              name: NODE,
              status: "Running",
              cpus: 8,
              memory: 16384 * 1024 * 1024,
              disk: 100 * 1024 * 1024 * 1024,
            }),
          );
        }
        if (rest[0] === "shell") {
          const separator = rest.indexOf("--");
          return guest(rest.slice(separator + 1));
        }
      }
      return fail(127, `unexpected host command: ${request.argv.join(" ")}`);
    },
  };
}

const created: string[] = [];

async function environment(host: ProcessPort): Promise<RuntimeEnvironment> {
  const root = await mkdtemp(path.join(tmpdir(), "yashiki-runtime-"));
  created.push(root);

  const configDir = path.join(root, "config", "meidoya-yashiki");
  await mkdir(configDir, { recursive: true });
  await writeFile(path.join(configDir, "config.yaml"), configYaml());

  const artifactDir = path.join(root, "data", "meidoya-yashiki", "artifacts", "0.1.0");
  await mkdir(artifactDir, { recursive: true });
  await writeFile(path.join(artifactDir, "manifest.json"), MANIFEST);
  await writeFile(path.join(artifactDir, "meidoya-node-linux-arm64"), ARTIFACT_BYTES);

  return {
    homeDir: root,
    xdgConfigHome: path.join(root, "config"),
    xdgDataHome: path.join(root, "data"),
    clock: fixedClock("2026-01-01T00:00:00.000Z"),
    processPort: host,
  };
}

afterEach(() => {
  created.length = 0;
});

/** Asserts the guard knows SECRET without ever printing it. */
function guardKnowsTheSecret(guard: { assertClean(context: string, text: string): void }): boolean {
  try {
    guard.assertClean("test-probe", `[dummy] ${SECRET}`);
    return false;
  } catch (error) {
    if (isYashikiError(error, "CREDENTIAL_UNSAFE")) return true;
    throw error;
  }
}

describe("cli runtime secret guard", () => {
  it("doctor populates the guard from the host before rendering anything", async () => {
    const runtime = createRuntime(await environment(fakeHost()));

    expect(guardKnowsTheSecret(runtime.secretGuard)).toBe(false);
    const lines = await runtime.doctor(NODE);

    expect(lines[0]).toBe("doctor work-grammarxiv: ok");
    // Populated by the doctor path itself: nothing here ever called `sync`.
    expect(guardKnowsTheSecret(runtime.secretGuard)).toBe(true);
  });

  it("doctor refuses to render a line that echoes the host credential", async () => {
    // The guest's poller.json is rendered verbatim into a Doctor line. A guest
    // that echoes the credential back must not reach the terminal.
    const runtime = createRuntime(await environment(fakeHost({ pollerQueue: SECRET })));

    await expect(runtime.doctor(NODE)).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
  });

  it("status populates the guard", async () => {
    const runtime = createRuntime(await environment(fakeHost()));
    await runtime.status(NODE);
    expect(guardKnowsTheSecret(runtime.secretGuard)).toBe(true);
  });

  it("backup populates the guard", async () => {
    const runtime = createRuntime(await environment(fakeHost()));
    const lines = await runtime.backup(NODE);

    expect(lines[0]).toContain("backed up work-grammarxiv");
    expect(guardKnowsTheSecret(runtime.secretGuard)).toBe(true);
  });

  /**
   * The archive is a file on disk a human will later open, and it embeds the
   * desired config verbatim — so it is a sink in its own right, guarded on the
   * exact bytes rather than on the objects they came from. The previous test of
   * this claim asserted only that a CLEAN backup succeeded, which would have
   * passed with the guard call deleted; this one drives a value the guard knows
   * into the archive bytes.
   *
   * The host credential here is path-shaped, so it also appears in the node's
   * declared `guest_path`. Contrived on purpose: it is the shortest way to put
   * a remembered value into the archive without any other sink seeing it first.
   */
  it("refuses to write an archive whose bytes contain a credential value", async () => {
    const runtime = createRuntime(await environment(fakeHost({ keychainValue: GUEST_PATH })));

    await expect(runtime.backup(NODE)).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
  });

  it("uses an injected guard, which is how main.ts puts its logger behind the same one", async () => {
    const guard = createSecretGuard();
    const runtime = createRuntime({ ...(await environment(fakeHost())), secretGuard: guard });

    expect(runtime.secretGuard).toBe(guard);
    await runtime.status(NODE);
    // The value the runtime learned from the host is known to the caller's
    // guard, so a logger or writer main.ts built from it is covered too.
    expect(guardKnowsTheSecret(guard)).toBe(true);
  });

  it("still runs when the host secret cannot be read, and says nothing about it", async () => {
    // Doctor's job includes diagnosing a locked Keychain, so an unreadable
    // credential must not abort it — the guard is simply blind to that value,
    // which is why Doctor's real protection is structural.
    const runtime = createRuntime(await environment(fakeHost({ keychainValue: null })));
    const lines = await runtime.doctor(NODE);

    expect(lines.join("\n")).toContain("Credential claude: present");
    expect(guardKnowsTheSecret(runtime.secretGuard)).toBe(false);
  });

  /**
   * The default host port — the one every real invocation uses, since nothing
   * injects `processPort` outside tests — is constructed here and nowhere else.
   * Dropping the guard from that construction was a change no test could see:
   * argv is world-readable in `ps` and the child's environment is readable by
   * everything it spawns, and neither would have been checked again.
   *
   * The refusal happens BEFORE `spawn`, so this stays offline: no limactl, no
   * VM, no child process at all.
   */
  it("wires the real host port behind the shared guard, argv and environment alike", async () => {
    const guard = createSecretGuard([SECRET]);
    const environmentWithoutPort = { ...(await environment(fakeHost())) };
    delete environmentWithoutPort.processPort;
    const runtime = createRuntime({ ...environmentWithoutPort, secretGuard: guard });

    await expect(
      runtime.processPort.run({ argv: ["/usr/bin/true", `--token=${SECRET}`], timeoutMs: 1000 }),
    ).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
    await expect(
      runtime.processPort.run({ argv: ["/usr/bin/true"], timeoutMs: 1000, env: { LIMA_HOME: `/tmp/${SECRET}` } }),
    ).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
  });

  /**
   * Defect 11 and defect 23, end to end and on disk.
   *
   * The archive is a real file, mode 0600, written by the real `runBackup`
   * through the real sink, and the receipt log that records it has no delete
   * path — so a value that lands there lands there forever. Every item used to
   * be collected with `sensitive: false` hard-coded, which made `planBackup`'s
   * encryption gate unreachable in production, and the guard fails open on its
   * own bounds: 2.6 KB of gzip padding in front of the log was enough to blind
   * decompression for the whole write, and the value came back out of the file
   * with one `Buffer.from(run, "base64")` and a `gunzipSync`.
   *
   * The guard still cannot see this value — a pad in the SAME window still
   * spends that window's allowance, and that is the honest limit of a bound that
   * fails open. What changed is what an incomplete scan MEANS: the item is
   * untrusted, so it is excluded rather than archived.
   */
  describe("an incomplete scan makes the bytes untrusted, so they never reach the archive", () => {
    /** Enough tiny gzip streams to spend one window's container allowance. */
    const padStreams = Array.from({ length: 1200 }, (_, index) =>
      gzipSync(Buffer.from(`pad-${index}`)).toString("base64"),
    ).join(" ");

    async function backupWith(payload: JsonObject): Promise<{ manifest: BackupManifest; archive: string }> {
      const root = await mkdtemp(path.join(tmpdir(), "yashiki-archive-"));
      created.push(root);
      const clock = fixedClock("2026-01-01T00:00:00.000Z");
      // Silent by choice, so the test's own output stays clean; the default
      // observer is exercised in `secret-guard.test.ts`.
      const guard = createSecretGuard([SECRET], { onIncompleteScan: () => undefined });
      // No guard on the store: this models a receipt that was appended before
      // this process knew the value, or behind an append-time scan that itself
      // could not finish. Either way the archive is the last line, not the first.
      const receipts = createInMemoryReceiptStore();
      receipts.append({ kind: "credential", nodeName: NODE, createdAt: "2026-01-01T00:00:00.000Z", payload });

      const config = findNode(parseYashikiConfig(configYaml(), { homeDir: root }), NODE);
      const manifest = await runBackup(config, {
        source: { collect: async () => collectBackupItems(config, receipts, guard) },
        sink: createBackupArchiveSink({ backupDir: root, clock, secretGuard: guard }),
        receipts,
        clock,
      });
      return { manifest, archive: await readFile(manifest.archiveRef, "utf8") };
    }

    /**
     * Every way out of the archive a reader has: the bytes themselves, and every
     * base64 run in them decoded and — if it is a stream — inflated. Never
     * prints what it found; only whether it found it.
     */
    function recoversTheValue(archive: string): boolean {
      if (archive.includes(SECRET)) return true;
      for (const run of archive.match(/[A-Za-z0-9+/=]{16,}/g) ?? []) {
        const bytes = Buffer.from(run, "base64");
        if (bytes.includes(SECRET)) return true;
        try {
          if (gunzipSync(bytes).includes(SECRET)) return true;
        } catch {
          // Not a stream; the raw reading above already covered it.
        }
      }
      return false;
    }

    it("excludes a receipt the guard could not finish scanning, instead of archiving it", async () => {
      const hidden = gzipSync(Buffer.from(SECRET)).toString("base64");
      const { manifest, archive } = await backupWith({ note: `${padStreams} ${hidden}` });

      expect(manifest.excluded.map((entry) => entry.id)).toContain("credential-receipts");
      expect(manifest.entries.map((entry) => entry.id)).not.toContain("credential-receipts");
      // The whole point: not on disk, by any decoding a reader could apply.
      expect(recoversTheValue(archive)).toBe(false);
    });

    it("says why, so an operator knows the entry is missing and not empty", async () => {
      const { manifest } = await backupWith({ note: `${padStreams} ${gzipSync(Buffer.from(SECRET)).toString("base64")}` });
      expect(manifest.excluded[0]?.reason).toContain("could not fully scan");
    });

    /**
     * The control, and the thing that keeps the rule above from being "exclude
     * everything": an ordinary receipt log scans to completion and is archived
     * in full. Without this, hard-coding `sensitive: true` would pass.
     */
    it("archives an ordinary receipt log in full, because that scan completes", async () => {
      const { manifest, archive } = await backupWith({ valueFingerprint: "a".repeat(64), mode: "0600" });
      expect(manifest.excluded).toEqual([]);
      expect(manifest.entries.map((entry) => entry.id)).toContain("credential-receipts");
      expect(archive).toContain("valueFingerprint");
    });

    /** And a value the guard CAN see is still a refusal, not an exclusion. */
    it("still refuses outright when it can actually see the value", async () => {
      await expect(backupWith({ note: `token=${SECRET}` })).rejects.toThrowError(/CREDENTIAL_UNSAFE/);
    });
  });

  it("never puts the credential value on a host command line", async () => {
    const host = fakeHost();
    const runtime = createRuntime(await environment(host));
    await runtime.doctor(NODE);

    for (const request of host.requests) {
      expect(request.argv.join(" ")).not.toContain(SECRET);
    }
  });
});
