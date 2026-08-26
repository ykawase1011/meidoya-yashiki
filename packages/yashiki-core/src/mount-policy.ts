import { realpathSync } from "node:fs";
import path from "node:path";
import { YashikiError } from "./errors.js";
import type { MountSpec, ProviderKind } from "./types.js";

export type MountPolicyContext = {
  /** Host home directory. Injected so the policy is testable off any machine. */
  homeDir: string;
  /**
   * Resolves a host path through symlinks. Injected so the suite can describe a
   * symlink farm without creating one, and so a path that does not exist yet is
   * a test's business rather than the filesystem's.
   */
  resolveHostPath?: (input: string) => string;
};

/**
 * Host paths that must never be handed to a guest even when explicitly listed
 * (10-execution-nodes-and-security.md section 3).
 */
const FORBIDDEN_HOME_RELATIVE = [
  ".ssh",
  ".gnupg",
  ".aws",
  ".kube",
  ".docker",
  "Library",
  ".config/gh",
  ".local/share/keyrings",
];

export function expandHome(input: string, homeDir: string): string {
  if (input === "~") return homeDir;
  if (input.startsWith("~/")) return path.posix.join(homeDir, input.slice(2));
  return input;
}

function normalizeHostPath(input: string, homeDir: string): string {
  const expanded = expandHome(input.trim(), homeDir);
  const normalized = path.posix.normalize(expanded);
  return normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

/**
 * Host path comparison, case-folded.
 *
 * The default macOS filesystem (APFS, and HFS+ before it) is case-INSENSITIVE.
 * A case-sensitive string comparison therefore said `~/.SSH`, `~/library` and
 * `~/.GnuPG` were not the forbidden directories, while the kernel happily
 * opened exactly those directories. The fold is applied to HOST paths only:
 * the guest side is Linux, where `/workspace/A` and `/workspace/a` really are
 * two directories.
 */
function foldHost(input: string): string {
  return input.toLowerCase();
}

function isAtOrUnder(child: string, ancestor: string): boolean {
  if (child === ancestor) return true;
  const base = ancestor === "/" ? "/" : `${ancestor}/`;
  return child.startsWith(base);
}

/** True when either path contains the other — the containment is symmetric. */
function overlaps(a: string, b: string): boolean {
  return isAtOrUnder(a, b) || isAtOrUnder(b, a);
}

function hostOverlaps(a: string, b: string): boolean {
  return overlaps(foldHost(a), foldHost(b));
}

/**
 * Resolves the longest existing prefix of a host path through symlinks and
 * re-attaches the remainder.
 *
 * Lima resolves the host side of a mount itself, so a policy that reads only
 * the spelling in config.yaml checks a path nobody dereferences:
 * `~/projects/link -> ~/.ssh` passed every rule and mounted the ssh directory.
 * Resolving the longest EXISTING prefix (rather than requiring the whole path
 * to exist) means a symlinked parent is caught even when the leaf has not been
 * created yet.
 */
function defaultResolveHostPath(input: string): string {
  let head = input;
  const tail: string[] = [];
  for (;;) {
    try {
      return path.posix.join(realpathSync(head), ...tail);
    } catch {
      const parent = path.posix.dirname(head);
      if (parent === head) return input;
      tail.unshift(path.posix.basename(head));
      head = parent;
    }
  }
}

function reject(reason: string, mount: MountSpec): never {
  throw new YashikiError("MOUNT_POLICY_VIOLATION", reason, {
    source: mount.source,
    target: mount.target,
  });
}

/**
 * Validates and normalizes mounts. Mounting the whole host home (or any
 * ancestor of it) is forbidden: guest-full does not mean host-full
 * (11-yashiki-design.md section 8).
 */
export function validateMounts(
  mounts: readonly MountSpec[],
  context: MountPolicyContext,
  provider: ProviderKind = "lima",
): MountSpec[] {
  const homeDir = normalizeHostPath(context.homeDir, context.homeDir);

  if (provider === "native" && mounts.length > 0) {
    throw new YashikiError(
      "MOUNT_POLICY_VIOLATION",
      "the native provider shares the host filesystem and must not declare mounts",
      { provider },
    );
  }

  const resolveHostPath = context.resolveHostPath ?? defaultResolveHostPath;
  const seenTargets: string[] = [];
  const seenSources: string[] = [];
  const validated: MountSpec[] = [];

  for (const mount of mounts) {
    if (mount.source.trim() === "" || mount.target.trim() === "") {
      reject("mount source and target must both be non-empty", mount);
    }

    const declared = normalizeHostPath(mount.source, homeDir);
    const target = path.posix.normalize(mount.target.trim());

    if (!declared.startsWith("/")) {
      reject("mount source must be an absolute host path (or ~-relative)", mount);
    }
    if (!target.startsWith("/")) {
      reject("mount target must be an absolute guest path", mount);
    }
    if (declared.split("/").includes("..") || target.split("/").includes("..")) {
      reject("mount paths must not contain '..' segments", mount);
    }
    // Both paths are interpolated into a Lima instance definition, so a quote,
    // a backslash or a control byte in one of them is a way to write config
    // Yashiki did not author.
    for (const candidate of [declared, target]) {
      if (/["'\\`$\u0000-\u001f\u007f]/.test(candidate)) {
        reject("mount paths must not contain quotes, backslashes or control characters", mount);
      }
    }

    // Everything below is asked of the path Lima will actually mount, not only
    // of the one config.yaml spells.
    const source = normalizeHostPath(resolveHostPath(declared), homeDir);
    if (source !== declared && (!source.startsWith("/") || source.split("/").includes(".."))) {
      reject(`mount source '${declared}' resolves to '${source}', which is not an absolute host path`, mount);
    }

    for (const candidate of new Set([declared, source])) {
      if (candidate === "/") {
        reject("mounting the host root filesystem is forbidden", mount);
      }
      if (hostOverlaps(candidate, homeDir) && candidate.length <= homeDir.length) {
        // The home directory itself and every ancestor of it: mounting either
        // hands over the whole home.
        reject(
          candidate === homeDir
            ? "mounting the entire host home directory is forbidden"
            : `mounting '${candidate}' would expose the entire host home directory and is forbidden`,
          mount,
        );
      }
      for (const relative of FORBIDDEN_HOME_RELATIVE) {
        const forbidden = path.posix.join(homeDir, relative);
        // Symmetric on purpose. A descendant-only test accepted `~/.config`
        // (which contains the forbidden `~/.config/gh`) and `~/.local/share`
        // (which contains the keyrings): mounting the PARENT of a forbidden
        // directory exposes it just as completely as mounting it directly.
        if (hostOverlaps(candidate, forbidden)) {
          reject(
            isAtOrUnder(foldHost(candidate), foldHost(forbidden))
              ? `mounting '${forbidden}' is forbidden`
              : `mounting '${candidate}' is forbidden: it contains '${forbidden}'`,
            mount,
          );
        }
      }
      for (const existing of seenSources) {
        // Target overlap was checked from the start and source overlap was not,
        // which is backwards: two host paths that contain each other are one
        // subtree handed to the guest twice, with two different writabilities.
        if (hostOverlaps(candidate, existing)) {
          reject(`mount source '${candidate}' overlaps the already declared source '${existing}'`, mount);
        }
      }
    }

    for (const existing of seenTargets) {
      if (overlaps(target, existing)) {
        reject(`mount target '${target}' overlaps the already declared target '${existing}'`, mount);
      }
    }

    seenTargets.push(target);
    seenSources.push(source);
    validated.push({ source, target, writable: mount.writable });
  }

  return validated;
}
