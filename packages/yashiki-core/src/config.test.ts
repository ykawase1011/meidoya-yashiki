import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { findNode, parseYashikiConfig, validateDesiredNodeConfig } from "./config.js";
import { isYashikiError } from "./errors.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

const env = { homeDir: "/Users/tester" };

const CONFIG = `
schema_version: 1

node_bundle:
  version: 0.1.0
  protocol_version: 1
  manifest_sha256: "${"a".repeat(64)}"

nodes:
  work-grammarxiv:
    provider: lima
    profile: lima-trusted
    platform: linux
    arch: arm64
    cpus: 8
    memory: 16GiB
    disk: 100GiB
    max_concurrency: 4
    capabilities: [repo.read, repo.write, shell]
    control_plane:
      endpoint: unix://~/.local/share/meidoya/meidoya.sock
      temporal_address: 127.0.0.1:7233
      task_queue: meidoya/node/work-grammarxiv
    mounts:
      - source: ~/Workspace/Repositories/GrammarXiv
        target: /workspace/GrammarXiv
        writable: true
    credentials:
      - provider: codex
        source_ref: keychain:meidoya/codex-login
        guest_path: /home/meidoya/.codex/auth.json
        mode: "0600"
        owner: meidoya
      - provider: node-registration
        source_ref: keychain:meidoya/node-token
        guest_path: /home/meidoya/.config/meidoya-node/registration.token
        mode: "0400"
        owner: meidoya
`;

describe("parseYashikiConfig", () => {
  it("parses a complete node configuration", () => {
    const config = parseYashikiConfig(CONFIG, env);
    expect(config.paths.databaseFile).toBe("/Users/tester/.local/share/meidoya-yashiki/yashiki.sqlite");
    expect(config.paths.configFile).toBe("/Users/tester/.config/meidoya-yashiki/config.yaml");

    const node = findNode(config, "work-grammarxiv");
    expect(node.cpus).toBe(8);
    expect(node.memoryMiB).toBe(16 * 1024);
    expect(node.diskGiB).toBe(100);
    expect(node.controlPlane.temporalAddress).toBe("127.0.0.1:7233");
    expect(node.mounts[0]?.source).toBe("/Users/tester/Workspace/Repositories/GrammarXiv");
    expect(node.credentials.map((c) => c.provider)).toEqual(["codex", "node-registration"]);
    expect(node.credentials[1]?.mode).toBe(0o400);
    expect(node.bundle.protocolVersion).toBe(1);
  });

  it("rejects a task queue assigned to a different node", () => {
    const text = CONFIG.replace(
      "task_queue: meidoya/node/work-grammarxiv",
      "task_queue: meidoya/node/another-node",
    );
    expect(() => parseYashikiConfig(text, env)).toThrowError(/meidoya\/node\/work-grammarxiv/);
  });

  it("rejects a config that mounts the host home", () => {
    const text = CONFIG.replace(
      "source: ~/Workspace/Repositories/GrammarXiv",
      'source: "~"',
    );
    expect(() => parseYashikiConfig(text, env)).toThrowError(/MOUNT_POLICY_VIOLATION/);
  });

  it("rejects duplicate credential providers", () => {
    const text = CONFIG.replace("provider: node-registration", "provider: codex");
    try {
      parseYashikiConfig(text, env);
    } catch (error) {
      expect(isYashikiError(error, "CONFIG_INVALID")).toBe(true);
      return;
    }
    throw new Error("expected duplicate credential providers to be rejected");
  });

  describe("credential file modes", () => {
    const withMode = (yaml: string): (() => unknown) => () => parseYashikiConfig(CONFIG.replace('mode: "0400"', yaml), env);

    it("refuses an unquoted mode instead of reading it as decimal", () => {
      // YAML 1.2 has no leading-zero octal, so `mode: 0400` is the NUMBER 400.
      // It used to pass the 0..0o777 bound and get re-rendered as octal, so a
      // credential asked to be owner-read-only landed as 0620 —
      // group-writable. 0500 landed as 0764. The common modes (600, 644 as
      // decimal) exceeded the bound and errored, so only the more restrictive
      // intents failed, and they failed silently and looser.
      for (const yaml of ["mode: 0400", "mode: 0500", "mode: 0100", "mode: 384"]) {
        expect(withMode(yaml)).toThrowError(/CONFIG_INVALID/);
      }
      expect(withMode("mode: 0400")).toThrowError(/QUOTED octal string/);
    });

    it("accepts the quoted spelling and keeps its value", () => {
      const config = parseYashikiConfig(CONFIG.replace('mode: "0400"', 'mode: "0400"'), env);
      expect(findNode(config, "work-grammarxiv").credentials[1]?.mode).toBe(0o400);
    });

    it("refuses a mode that grants anything to group or other", () => {
      for (const yaml of ['mode: "0640"', 'mode: "0644"', 'mode: "0604"', 'mode: "0620"', 'mode: "0777"']) {
        expect(withMode(yaml)).toThrowError(/CONFIG_INVALID/);
      }
      for (const yaml of ['mode: "0400"', 'mode: "0600"', 'mode: "0700"', 'mode: "0000"']) {
        expect(withMode(yaml)).not.toThrow();
      }
    });
  });

  describe("the one-file-per-provider invariant", () => {
    const twoPaths = (second: string): (() => unknown) =>
      () =>
        parseYashikiConfig(
          CONFIG.replace("guest_path: /home/meidoya/.config/meidoya-node/registration.token", `guest_path: ${second}`),
          env,
        );

    it("sees through a re-spelled path to the same guest file", () => {
      // Deduping raw strings made these four distinct declarations of one file:
      // two providers wrote it, last writer won, both receipts claimed success,
      // and the surviving file carried the other provider's mode and owner.
      for (const spelling of [
        "/home/meidoya/.codex/auth.json",
        "/home/meidoya/.codex//auth.json",
        "/home/meidoya/./.codex/auth.json",
        "/home/meidoya/.codex/x/../auth.json",
      ]) {
        expect(twoPaths(spelling)).toThrowError(/CONFIG_INVALID/);
      }
    });

    it("refuses a guest path that traverses out of the directory it names", () => {
      // The mount policy has rejected '..' from the beginning; credentials had
      // no such check, so `/home/m/../../etc/cron.d/pwn` with `owner: root`
      // parsed without complaint.
      expect(twoPaths("/home/meidoya/../../etc/cron.d/pwn")).toThrowError(/CONFIG_INVALID/);
      expect(twoPaths("relative/path")).toThrowError(/CONFIG_INVALID/);
    });
  });

  describe("the node profile", () => {
    const withNode = (replacements: [string, string][]): (() => unknown) => {
      let text = CONFIG;
      for (const [from, to] of replacements) text = text.replace(from, to);
      return () => parseYashikiConfig(text, env);
    };

    it("refuses a non-lima node that claims lima-trusted", () => {
      // The rule was enforced one way only, so a `native` node — a process on
      // the operator's own machine — could declare `lima-trusted` and have
      // `renderNodeConfig` emit `filesystem.mode: guest-full` for it.
      expect(
        withNode([
          ["provider: lima", "provider: native"],
          ["mounts:", "unused_mounts:"],
        ]),
      ).toThrowError(/CONFIG_INVALID/);
    });

    it("defaults a non-lima node by its platform rather than always to macOS", () => {
      const text = CONFIG.replace("provider: lima", "provider: native")
        .replace(/^ {4}profile: lima-trusted\n/m, "")
        .replace(/^ {4}mounts:\n(?: {6,}.*\n)+/m, "");
      const node = findNode(parseYashikiConfig(text, env), "work-grammarxiv");
      expect(node.platform).toBe("linux");
      expect(node.profile).toBe("linux-restricted");

      const darwin = findNode(parseYashikiConfig(text.replace("platform: linux", "platform: darwin"), env), "work-grammarxiv");
      expect(darwin.profile).toBe("mac-restricted");
    });

    it("refuses a restricted profile that does not match the platform", () => {
      const text = CONFIG.replace("provider: lima", "provider: native")
        .replace("profile: lima-trusted", "profile: mac-restricted")
        .replace(/^ {4}mounts:\n(?: {6,}.*\n)+/m, "");
      expect(() => parseYashikiConfig(text, env)).toThrowError(/CONFIG_INVALID/);
    });
  });

  it("rejects a non-hex manifest checksum", () => {
    const text = CONFIG.replace("a".repeat(64), "not-a-checksum");
    expect(() => parseYashikiConfig(text, env)).toThrowError(/CONFIG_INVALID/);
  });

  it("rejects a lima node that is not lima-trusted", () => {
    const text = CONFIG.replace("profile: lima-trusted", "profile: linux-restricted");
    expect(() => parseYashikiConfig(text, env)).toThrowError(/CONFIG_INVALID/);
  });

  it("parses the checked-in config.example.yaml", () => {
    const text = readFileSync(join(repoRoot, "config.example.yaml"), "utf8");
    const config = parseYashikiConfig(text, env);
    const node = findNode(config, "work-grammarxiv");

    expect(node.credentials.map((credential) => credential.provider)).toEqual([
      "codex",
      "claude",
      "node-registration",
      "github",
    ]);
    expect(node.credentials.at(-1)?.optional).toBe(true);
  });

  it("revalidates a materialized desired config", () => {
    const node = findNode(parseYashikiConfig(CONFIG, env), "work-grammarxiv");
    expect(validateDesiredNodeConfig(node, env.homeDir).name).toBe("work-grammarxiv");
    expect(() =>
      validateDesiredNodeConfig({ ...node, name: "Bad Name" }, env.homeDir),
    ).toThrowError(/CONFIG_INVALID/);
    expect(() =>
      validateDesiredNodeConfig(
        { ...node, mounts: [{ source: "/Users/tester", target: "/host", writable: true }] },
        env.homeDir,
      ),
    ).toThrowError(/MOUNT_POLICY_VIOLATION/);
  });
});
