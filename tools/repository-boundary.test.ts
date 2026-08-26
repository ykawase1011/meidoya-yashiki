import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, resolve } from "node:path";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SOURCE_ROOTS = ["packages", "apps", "tools"];
/**
 * Every extension this repository can execute. `.ts/.sql/.js` left `.mts`,
 * `.cts`, `.mjs`, `.cjs` and the `x` variants unscanned, which is a boundary
 * check that a file can step outside of by being named differently.
 */
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".sql", ".js", ".jsx", ".mjs", ".cjs"];

function walk(dir: string, into: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, into);
    else if (SOURCE_EXTENSIONS.some((extension) => full.endsWith(extension))) into.push(full);
  }
  return into;
}

const sourceFiles = SOURCE_ROOTS.flatMap((root) => walk(join(repoRoot, root)));

/**
 * Identifiers that belong to the meidoya Control Plane. Yashiki is allowed to
 * name a Temporal task queue (it is part of the node registration contract), so
 * those spellings are stripped before the scan.
 */
const ALLOWED_SPELLINGS = [
  /taskQueue/g,
  /task_queue/g,
  /TaskQueue/g,
  /task queue/gi,
  /taskQueuePoller/g,
  /workspace metadata/gi,
  /workspaceBindings/g,
  /allowedWorkspaces/g,
  /workspace-metadata/g,
  /workspace\/GrammarXiv/g,
  /\/workspace/g,
  /Workspace\/Repositories/g,
];

const FORBIDDEN_CONCEPTS: { pattern: RegExp; why: string }[] = [
  { pattern: /\bcreateTask\b/, why: "Yashiki must never create Tasks" },
  { pattern: /\bTaskLifecycle\b/, why: "Task lifecycle belongs to meidoya" },
  { pattern: /\btaskEngine\b/i, why: "Task engine belongs to meidoya" },
  { pattern: /\bhumanGate\b/i, why: "Human Gates belong to meidoya" },
  { pattern: /\bhuman_gate\b/i, why: "Human Gates belong to meidoya" },
  { pattern: /\bslack\b/i, why: "Yashiki must never post to chat" },
  { pattern: /\bdiscord\b/i, why: "Yashiki must never post to chat" },
  { pattern: /\bconversation\b/i, why: "Workspace conversations belong to meidoya" },
  { pattern: /\bchatTransport\b/i, why: "Chat transport belongs to meidoya" },
  { pattern: /\bmodelRouter\b/i, why: "Model routing belongs to meidoya" },
  { pattern: /\bmodelProfile\b/i, why: "Model selection belongs to meidoya" },
  { pattern: /\bworkerProfile\b/i, why: "Worker selection belongs to meidoya" },
  { pattern: /\bagentPrompt\b/i, why: "Agent prompt generation belongs to meidoya" },
  { pattern: /\bpromptTemplate\b/i, why: "Agent prompt generation belongs to meidoya" },
  { pattern: /\bdelegationGrant\b/i, why: "Workspace delegation belongs to meidoya" },
  { pattern: /\bnotificationOutbox\b/i, why: "The Notification Outbox belongs to meidoya" },
];

/**
 * `from "…"` is one of several ways to name a module, and it was the only one
 * checked: `await import("@meidoya/task-engine")` and
 * `require("@meidoya/task-engine")` sailed past a boundary test that stayed
 * 5/5 green. The specifier is what matters, not the syntax that reaches it, so
 * every form that can carry one is matched.
 */
const SPECIFIER = String.raw`(?:from|import|require)\s*\(?\s*`;

const FORBIDDEN_IMPORTS: { pattern: RegExp; why: string }[] = [
  {
    pattern: new RegExp(`${SPECIFIER}["']@meidoya/(?!node-protocol-client)`),
    why: "unpublished meidoya packages must not be imported",
  },
  {
    pattern: new RegExp(`${SPECIFIER}["'][^"']*/meidoya/(packages|apps)/`),
    why: "cross-repository source path reads are forbidden",
  },
  { pattern: /["']file:.*\/meidoya\//, why: "path dependencies on the meidoya repository are forbidden" },
];

/** The one place a forbidden-import verdict is reached, so a test can drive it. */
export function forbiddenImportsIn(text: string): string[] {
  return FORBIDDEN_IMPORTS.filter(({ pattern }) => pattern.test(text)).map(({ why }) => why);
}

/** Every package manifest whose dependencies belong to this repository. */
function manifestPaths(): string[] {
  return [
    join(repoRoot, "package.json"),
    ...readdirSync(join(repoRoot, "packages")).map((name) => join(repoRoot, "packages", name, "package.json")),
    // `apps/*` was scanned for forbidden imports but NOT for dependencies, so a
    // third-party runtime dependency in the one package that ships the CLI —
    // the place it matters most — was invisible to the check that exists to
    // find exactly that.
    ...readdirSync(join(repoRoot, "apps")).map((name) => join(repoRoot, "apps", name, "package.json")),
  ];
}

/**
 * Anything in the vendored mirror that would exist at RUNTIME rather than only
 * in the type system. Exported shape so the check can be driven directly.
 */
export function runtimeValueViolations(text: string): string[] {
  const rules: { pattern: RegExp; why: string }[] = [
    { pattern: /^\s*import\b(?!\s+type\b)/m, why: "value import" },
    { pattern: /\brequire\s*\(/, why: "require() call" },
    { pattern: /\bfunction\b|\bclass\b/, why: "function or class declaration" },
    { pattern: /=>/, why: "arrow function" },
    { pattern: /\bnew\s+[A-Z]/, why: "constructor call" },
  ];
  return rules.filter(({ pattern }) => pattern.test(text)).map(({ why }) => why);
}

function scrub(text: string): string {
  let scrubbed = text;
  for (const allowed of ALLOWED_SPELLINGS) scrubbed = scrubbed.replace(allowed, "");
  return scrubbed;
}

describe("repository boundary (03-repository-boundaries.md sections 2-4)", () => {
  it("finds source files to scan", () => {
    expect(sourceFiles.length).toBeGreaterThan(20);
  });

  it("does not implement any Control Plane concept", () => {
    const violations: string[] = [];
    for (const file of sourceFiles) {
      if (file.endsWith("repository-boundary.test.ts")) continue;
      const text = scrub(readFileSync(file, "utf8"));
      for (const { pattern, why } of FORBIDDEN_CONCEPTS) {
        if (pattern.test(text)) violations.push(`${relative(repoRoot, file)}: ${pattern.source} (${why})`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("does not read or depend on the meidoya source repository", () => {
    const violations: string[] = [];
    for (const file of [...sourceFiles, ...manifestPaths()]) {
      if (file.endsWith("repository-boundary.test.ts")) continue;
      const text = readFileSync(file, "utf8");
      for (const why of forbiddenImportsIn(text)) violations.push(`${relative(repoRoot, file)}: ${why}`);
    }
    expect(violations).toEqual([]);
  });

  it("catches a forbidden module however it is named", () => {
    // Each of these was a real evasion of the `from "…"`-only pattern.
    for (const source of [
      'const engine = await import("@meidoya/task-engine");',
      'const engine = require("@meidoya/task-engine");',
      'import("@meidoya/control-plane").then((m) => m);',
      'await import("../../meidoya/packages/task-engine/src/index.js");',
    ]) {
      expect(forbiddenImportsIn(source)).not.toEqual([]);
    }
    // The one permitted cross-repository specifier stays permitted.
    expect(forbiddenImportsIn('import type { NodeInstallReceipt } from "@meidoya-yashiki/node-protocol-client";')).toEqual(
      [],
    );
    expect(forbiddenImportsIn('const c = await import("@meidoya/node-protocol-client");')).toEqual([]);
  });

  it("scans the app manifests for dependencies, not only the packages", () => {
    expect(manifestPaths().some((file) => file.includes(`${"apps"}/meidoya-yashiki/package.json`))).toBe(true);
  });

  it("keeps the only cross-repository contract in node-protocol-client", () => {
    const contract = readFileSync(join(repoRoot, "packages", "node-protocol-client", "src", "index.ts"), "utf8");
    expect(contract).toContain("VENDORED TYPE-ONLY MIRROR");

    // The vendored mirror must stay type-only: no runtime value beyond the pin.
    const files = walk(join(repoRoot, "packages", "node-protocol-client", "src")).filter(
      (file) => !file.endsWith(".test.ts"),
    );
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const violation of runtimeValueViolations(text)) {
        expect(`${relative(repoRoot, file)}: ${violation}`).toBe("");
      }
    }
  });

  it("catches a runtime value in the vendored mirror however it is spelled", () => {
    // `/^import\s+(?!type)/m` needed whitespace after `import`, and
    // `/function|class/` did not know about arrow functions — so a minified
    // `import{readFileSync}from"node:fs"` plus `const f = () => …` was a
    // runtime file passing a type-only check.
    expect(runtimeValueViolations('import{readFileSync}from"node:fs"')).not.toEqual([]);
    expect(runtimeValueViolations('import { readFileSync } from "node:fs";')).not.toEqual([]);
    expect(runtimeValueViolations("export const read = () => 1;")).not.toEqual([]);
    expect(runtimeValueViolations("const x = require('node:fs');")).not.toEqual([]);
    expect(runtimeValueViolations("export function read() { return 1; }")).not.toEqual([]);
    // What the mirror legitimately contains stays legitimate.
    expect(runtimeValueViolations('import type { A } from "./a.js";\nexport const NODE_PROTOCOL_VERSION = 1;')).toEqual(
      [],
    );
    expect(runtimeValueViolations('export * from "./version.js";\nexport type X = { a: string };')).toEqual([]);
  });

  it("declares no runtime dependency outside this repository", () => {
    const allowedExternal = new Set(["yaml", "better-sqlite3"]);
    for (const file of manifestPaths()) {
      if (file === join(repoRoot, "package.json")) continue; // the workspace root has devDependencies only
      const manifest = JSON.parse(readFileSync(file, "utf8")) as { dependencies?: Record<string, string> };
      for (const [dependency, range] of Object.entries(manifest.dependencies ?? {})) {
        const internal = dependency.startsWith("@meidoya-yashiki/");
        expect(`${relative(repoRoot, file)}: ${dependency}`).toBe(
          internal || allowedExternal.has(dependency) ? `${relative(repoRoot, file)}: ${dependency}` : "",
        );
        if (internal) expect(range).toBe("workspace:*");
      }
    }
  });
});
