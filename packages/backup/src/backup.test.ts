import { describe, expect, it } from "vitest";
import { fixedClock, type DesiredNodeConfig } from "@meidoya-yashiki/yashiki-core";
import { canonicalize, createInMemoryReceiptStore, type JsonValue } from "@meidoya-yashiki/receipts";
import { planBackup, runBackup, type BackupItem, type BackupSinkPort, type BackupSourcePort } from "./backup.js";

const SECRET = "sk-live-CODEX-secret-value";

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
  credentials: [],
  bundle: { version: "0.1.0", protocolVersion: 1, manifestSha256: "a".repeat(64) },
  controlPlane: { endpoint: "unix:///tmp/meidoya.sock", temporalAddress: "127.0.0.1:7233", taskQueue: "meidoya/node/work-grammarxiv" },
  modelEnvironment: {},
  maxConcurrency: 4,
  capabilities: [],
};

const items: BackupItem[] = [
  { id: "config", kind: "desired-config", content: JSON.stringify(config), sensitive: false },
  { id: "install", kind: "install-receipt", content: '{"version":"0.1.0"}', sensitive: false },
  { id: "codex-auth", kind: "credential-document", content: SECRET, sensitive: true },
];

function sink(): BackupSinkPort & { written: string[] } {
  const written: string[] = [];
  return {
    written,
    write: async (_node, entries) => {
      for (const entry of entries) written.push(entry.content);
      return { archiveRef: "cas://archive-1" };
    },
  };
}

const source: BackupSourcePort = { collect: async () => items };

describe("backup", () => {
  it("backs up a sensitive item that happens to be empty", async () => {
    // `"anything".includes("")` is true, so a zero-length sensitive item — an
    // empty receipt list, a credential file not written yet — aborted the WHOLE
    // backup with CREDENTIAL_UNSAFE: a security refusal naming an encryption
    // port that had done nothing wrong. There is no plaintext in "".
    const encryption = { encrypt: async (plaintext: string) => `enc(${plaintext})` };
    const plan = await planBackup(
      [{ id: "empty", kind: "credential-document", content: "", sensitive: true }],
      encryption,
    );

    expect(plan.entries.map((entry) => entry.id)).toEqual(["empty"]);
    expect(plan.entries[0]?.encrypted).toBe(true);
    expect(plan.excluded).toEqual([]);
  });

  it("still refuses an encryption port that returns the plaintext", async () => {
    await expect(planBackup(items, { encrypt: async (plaintext) => `prefix:${plaintext}` })).rejects.toThrowError(
      /CREDENTIAL_UNSAFE/,
    );
  });

  it("excludes plaintext credential sinks when no encryption is configured", async () => {
    const plan = await planBackup(items);

    expect(plan.entries.map((entry) => entry.id)).toEqual(["config", "install"]);
    expect(plan.excluded).toEqual([
      {
        id: "codex-auth",
        kind: "credential-document",
        reason: "plaintext credential sink excluded: no encryption port configured",
      },
    ]);
  });

  it("includes credential documents only in encrypted form", async () => {
    const plan = await planBackup(items, { encrypt: async (text) => `enc(${Buffer.from(text).toString("base64")})` });
    const credential = plan.entries.find((entry) => entry.id === "codex-auth");

    expect(credential?.encrypted).toBe(true);
    expect(credential?.content).not.toContain(SECRET);
    expect(plan.excluded).toEqual([]);
  });

  it("rejects an encryption port that returns the plaintext", async () => {
    await expect(planBackup(items, { encrypt: async (text) => `wrapped:${text}` })).rejects.toThrowError(
      /CREDENTIAL_UNSAFE/,
    );
  });

  it("never writes a plaintext credential to the sink and never records one in the receipt", async () => {
    const target = sink();
    const receipts = createInMemoryReceiptStore();
    const manifest = await runBackup(config, {
      source,
      sink: target,
      receipts,
      clock: fixedClock("2026-01-01T00:00:00.000Z"),
    });

    for (const written of target.written) expect(written).not.toContain(SECRET);
    expect(manifest.excluded).toHaveLength(1);
    expect(manifest.entries.every((entry) => entry.sha256.length === 64)).toBe(true);

    const rendered = canonicalize(receipts.list() as unknown as JsonValue);
    expect(rendered).not.toContain(SECRET);
    expect(rendered).toContain("cas://archive-1");
  });
});
