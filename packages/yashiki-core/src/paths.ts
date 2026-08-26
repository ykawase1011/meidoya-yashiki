import path from "node:path";
import { YashikiError } from "./errors.js";
import { expandHome } from "./mount-policy.js";
import type { YashikiPaths } from "./types.js";

export type PathEnvironment = {
  homeDir: string;
  xdgConfigHome?: string | undefined;
  xdgDataHome?: string | undefined;
};

/**
 * One XDG base directory, resolved to an absolute path or refused.
 *
 * `??` treats only `undefined` and `null` as unset, so `XDG_CONFIG_HOME=""`
 * — which the XDG spec itself says must be handled as unset, and which a
 * `env -u`-shaped shell line produces by accident — survived as the empty
 * string and made every path below it RELATIVE. Yashiki then loaded
 * `./meidoya-yashiki/config.yaml`: a `cd` into an untrusted checkout
 * substituted that repository's mounts, control-plane endpoint and credential
 * source refs. The same line forked the state directory under the working
 * directory, and since the node lock is keyed on `paths.databaseFile`, two runs
 * from two directories were not mutually exclusive — the one invariant the lock
 * exists to provide.
 *
 * So: blank is unset, and anything that survives must be absolute. A relative
 * XDG value is a configuration error with a name, never a directory silently
 * rooted wherever the process happens to be standing.
 */
function resolveBaseDir(value: string | undefined, variable: string, fallback: string, home: string): string {
  const raw = value?.trim() ?? "";
  const expanded = raw === "" ? fallback : expandHome(raw, home);
  if (!path.isAbsolute(expanded)) {
    throw new YashikiError(
      "CONFIG_INVALID",
      raw === ""
        ? `the home directory '${home}' is not absolute, so Yashiki cannot place its ${variable} directory`
        : `${variable} is '${raw}', which is a relative path; it must be absolute or unset ` +
          `(a relative value roots Yashiki's config and state in the current working directory)`,
      { variable, value: raw === "" ? home : raw },
    );
  }
  return path.normalize(expanded);
}

/** 11-yashiki-design.md section 3. */
export function resolveYashikiPaths(env: PathEnvironment): YashikiPaths {
  const home = env.homeDir;
  const configHome = resolveBaseDir(env.xdgConfigHome, "XDG_CONFIG_HOME", path.join(home, ".config"), home);
  const dataHome = resolveBaseDir(env.xdgDataHome, "XDG_DATA_HOME", path.join(home, ".local", "share"), home);
  const dataDir = path.join(dataHome, "meidoya-yashiki");

  return {
    configFile: path.join(configHome, "meidoya-yashiki", "config.yaml"),
    dataDir,
    databaseFile: path.join(dataDir, "yashiki.sqlite"),
    artifactsDir: path.join(dataDir, "artifacts"),
    locksDir: path.join(dataDir, "locks"),
  };
}
