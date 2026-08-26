import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type AliasOptions } from "vitest/config";

const root = dirname(fileURLToPath(import.meta.url));

/**
 * Map every workspace package to its TypeScript source entrypoint.
 *
 * Without this, `main`/`exports` point at `./dist/index.js` and the suite
 * validates the LAST BUILD instead of the current sources: editing
 * `packages/X/src` has no effect on any test outside package X until
 * `pnpm -r build` runs. Measured before this existed: making
 * `BundleInstaller.installVerified` throw turned node-bundle's own tests red
 * while all 13 node-provisioner tests stayed green — every cross-package
 * assertion in this repo was green against code that no longer existed.
 *
 * The list is derived from the filesystem so a newly added workspace package is
 * covered automatically; a hardcoded list would silently reintroduce the bug.
 *
 * EXPORTS. Every package here declares an `exports` map, so refusing outright
 * (as the sibling meidoya repo does, where none do) would only mean refusing to
 * run. What is actually unsafe is guessing an entrypoint for a package that
 * publishes MORE than one: a subpath like `./foo` would keep resolving to
 * `dist/` while `.` resolved to `src/`, and the two halves of one package would
 * disagree about module identity. So the shape is checked instead of ignored:
 * a package may declare exactly the `"."` entry and nothing else. Anything
 * richer throws at config load — loudly, at the one moment somebody is in a
 * position to decide what the extra entrypoint should resolve to — rather than
 * falling back to `dist` in silence.
 *
 * Production `main`/`exports` stay on `dist`; this alias affects vitest
 * resolution exclusively. The `find` patterns are anchored RegExps, so bare
 * specifiers are redirected while an explicit subpath import
 * (`@meidoya-yashiki/store-sqlite/dist/...`) keeps resolving as written.
 */
type Manifest = {
  name?: string;
  exports?: unknown;
  bin?: unknown;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

function readManifests(): { dir: string; manifest: Manifest }[] {
  const found: { dir: string; manifest: Manifest }[] = [];
  for (const group of ["packages", "apps"]) {
    const groupDir = join(root, group);
    if (!existsSync(groupDir)) continue;
    for (const entry of readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = join(groupDir, entry.name);
      const manifestPath = join(dir, "package.json");
      if (!existsSync(manifestPath)) continue;
      found.push({ dir, manifest: JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest });
    }
  }
  return found;
}

function workspaceSourceAliases(): AliasOptions {
  const aliases: { find: RegExp; replacement: string }[] = [];
  const manifests = readManifests();
  // Every name any workspace package can import by bare specifier.
  const imported = new Set<string>();
  for (const { manifest } of manifests) {
    for (const deps of [manifest.dependencies, manifest.devDependencies]) {
      for (const dep of Object.keys(deps ?? {})) imported.add(dep);
    }
  }

  {
    for (const { dir: pkgDir, manifest } of manifests) {
      const name = manifest.name;
      if (name === undefined) continue;

      const exportKeys =
        manifest.exports === undefined || manifest.exports === null || typeof manifest.exports !== "object"
          ? []
          : Object.keys(manifest.exports as Record<string, unknown>);
      const extraEntrypoints = exportKeys.filter((key) => key !== ".");
      if (extraEntrypoints.length > 0) {
        throw new Error(
          `vitest.config.ts: ${name} declares the extra export entrypoint(s) ` +
            `${extraEntrypoints.join(", ")}; add an explicit source alias for each one instead of ` +
            `letting it resolve to dist/.`,
        );
      }

      const entryPoint = join(pkgDir, "src", "index.ts");
      if (!existsSync(entryPoint)) {
        // An executable with no library entrypoint (the CLI app) has nothing to
        // alias — but only as long as nothing imports it by bare specifier. If
        // anything ever does, that import would resolve to `dist/` in silence,
        // which is the whole defect, so it is an error rather than a shrug.
        if (manifest.bin !== undefined && exportKeys.length === 0 && !imported.has(name)) continue;
        throw new Error(
          `vitest.config.ts: ${name} has no src/index.ts; tests would silently fall back to dist/.`,
        );
      }
      aliases.push({
        find: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`),
        replacement: entryPoint,
      });
    }
  }
  return aliases;
}

export default defineConfig({
  resolve: {
    alias: workspaceSourceAliases(),
  },
  test: {
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts", "tools/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
