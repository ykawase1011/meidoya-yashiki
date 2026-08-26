import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { NODE_PROTOCOL_VERSION } from "./version.js";

/**
 * This drift check is deliberately test-only code, not a src/ export: the
 * mirror in packages/node-protocol-client/src/ must stay type-only (see
 * `tools/repository-boundary.test.ts`'s "keeps the only cross-repository
 * contract in node-protocol-client" check, which forbids runtime functions
 * there). A self-referential assertion like `expect(NODE_PROTOCOL_VERSION)
 * .toBe(1)` (see version.test.ts) can never catch drift because it only
 * restates the constant back at itself. This does something a static
 * assertion cannot: read the real `@meidoya/node-protocol` source as text
 * (never an import, path mapping, or `file:` dependency, so it does not
 * create a real dependency on the meidoya repository) and compare it against
 * the vendored value.
 */
const VERSION_PATTERN = /NODE_PROTOCOL_VERSION\s*=\s*(\d+)/;

type DriftResult = { checked: boolean; sourceVersion: number | null; matches: boolean };

function checkAgainst(nodeProtocolSrcDir: string): DriftResult {
  let text: string;
  try {
    text = readFileSync(join(nodeProtocolSrcDir, "version.ts"), "utf8");
  } catch {
    return { checked: false, sourceVersion: null, matches: false };
  }

  const match = VERSION_PATTERN.exec(text);
  const sourceVersion = match?.[1] === undefined ? null : Number.parseInt(match[1], 10);
  return { checked: true, sourceVersion, matches: sourceVersion === NODE_PROTOCOL_VERSION };
}

const here = dirname(fileURLToPath(import.meta.url));

/**
 * meidoya-yashiki's own repository root, then the sibling repository
 * (meidoya) that may or may not be checked out next to it.
 */
function siblingNodeProtocolSrc(): string {
  const repoRoot = resolve(here, "../../..");
  return join(resolve(repoRoot, "..", "meidoya"), "packages", "node-protocol", "src");
}

describe("vendored node protocol version drift", () => {
  it("detects a deliberate drift against a simulated source", () => {
    const dir = mkdtempSync(join(tmpdir(), "node-protocol-drift-"));
    try {
      writeFileSync(join(dir, "version.ts"), "export const NODE_PROTOCOL_VERSION = 999 as const;\n", "utf8");

      const result = checkAgainst(dir);

      expect(result.checked).toBe(true);
      expect(result.sourceVersion).toBe(999);
      expect(result.matches).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports no drift when the simulated source matches the vendored mirror", () => {
    const dir = mkdtempSync(join(tmpdir(), "node-protocol-drift-"));
    try {
      writeFileSync(
        join(dir, "version.ts"),
        `export const NODE_PROTOCOL_VERSION = ${NODE_PROTOCOL_VERSION} as const;\n`,
        "utf8",
      );

      const result = checkAgainst(dir);

      expect(result.checked).toBe(true);
      expect(result.matches).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("skips cleanly (checked: false) when no source directory is available", () => {
    const result = checkAgainst(join(tmpdir(), "does-not-exist-node-protocol-src"));
    expect(result.checked).toBe(false);
    expect(result.sourceVersion).toBeNull();
  });

  it("matches the real @meidoya/node-protocol source when meidoya is checked out alongside meidoya-yashiki", () => {
    const srcDir = siblingNodeProtocolSrc();
    if (!existsSync(join(srcDir, "version.ts"))) {
      // CI for meidoya-yashiki alone does not have the meidoya repository
      // checked out; skip cleanly rather than fail on an absent sibling.
      return;
    }

    const result = checkAgainst(srcDir);
    expect(result.checked).toBe(true);
    expect(result.matches).toBe(true);
  });
});
