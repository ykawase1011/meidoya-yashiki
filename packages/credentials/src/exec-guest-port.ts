import { failClosed, YashikiError, type NodeProvider, type NodeRef } from "@meidoya-yashiki/yashiki-core";
import type { GuestCredentialPort, GuestFileStat } from "./ports.js";

const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/**
 * Guest-side shell fragments that work on BOTH a Linux guest and a macOS host.
 *
 * `stat -c` and `sha256sum` are GNU coreutils. The `native` provider runs these
 * commands on the host, and `config.ts` accepts `provider: native` alongside
 * `credentials` — so on a darwin host every credential failed at `stat:
 * illegal option -- c` and surfaced as `CREDENTIAL_UNSAFE`, which reads as a
 * security refusal rather than the platform bug it is. Each form is tried and
 * the BSD spelling is the fallback.
 */
const STAT_SCRIPT = 'stat -c "%U %a" "$1" 2>/dev/null || stat -f "%Su %OLp" "$1"';
const SHA256_SCRIPT = 'sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"';

/**
 * Refuses a destination whose DIRECTORY path traverses a symlink.
 *
 * Guarding only the final component leaves the interesting attack untouched: a
 * directory symlink planted guest-side before materialization redirects the
 * write, and the post-write `stat` follows the very same link, so it reports
 * the attacker's file as correct. `cd "$dir" && pwd -P` is the physical path;
 * if it differs from the spelled one, something in the middle is a link.
 */
const WRITE_SCRIPT = [
  "set -e",
  "umask 077",
  'dir=$(dirname "$1")',
  '[ "$(id -un)" = "$3" ] && mkdir -p "$dir" || sudo -u "$3" mkdir -p "$dir"',
  'physical=$(cd "$dir" && pwd -P)',
  '[ "$physical" = "$dir" ] || exit 91',
  '[ "$(id -un)" = "$3" ] || chown "$3" "$dir"',
  'chmod 0700 "$dir"',
  'rm -f "$1"',
  'cat > "$1"',
  'chmod "$2" "$1"',
  // chown requires root, and the native provider is not root. Changing nothing
  // needs no privilege, so the call is skipped when the owner already matches.
  '[ "$(id -un)" = "$3" ] || chown "$3" "$1"',
].join("; ");

/**
 * Guest credential IO over NodeProvider.exec.
 *
 * The value is streamed on stdin and the destination path is passed as a shell
 * POSITIONAL parameter, so neither ever appears expanded in argv (11 section 7).
 */
export function createExecGuestCredentialPort(provider: NodeProvider): GuestCredentialPort {
  const run = async (node: NodeRef, argv: readonly string[], stdin?: string) => {
    const result = await provider.exec(node, stdin === undefined ? { argv } : { argv, stdin });
    return result;
  };
  const privileged = (node: NodeRef, argv: readonly string[]): readonly string[] =>
    node.provider === "lima" ? ["sudo", ...argv] : argv;

  return {
    async writeSecret(node, guestPath, value, attributes) {
      const mode = `0${attributes.mode.toString(8).padStart(3, "0")}`;
      const write = await run(
        node,
        privileged(node, ["sh", "-c", WRITE_SCRIPT, "sh", guestPath, mode, attributes.owner]),
        value,
      );

      if (write.exitCode === 91) {
        throw new YashikiError("CREDENTIAL_UNSAFE", "the credential directory traverses a symlink", {
          node: node.name,
          guestPath,
        });
      }
      if (write.exitCode !== 0) {
        throw new YashikiError("CREDENTIAL_UNSAFE", "guest refused the credential write", {
          node: node.name,
          guestPath,
          exitCode: write.exitCode,
        });
      }
    },

    async stat(node, guestPath): Promise<GuestFileStat> {
      const symlink = await run(node, privileged(node, ["test", "-L", guestPath]));
      const exists = await run(node, privileged(node, ["test", "-e", guestPath]));
      if (exists.exitCode !== 0) {
        return { exists: false, isSymlink: symlink.exitCode === 0, owner: "", mode: 0, sha256: EMPTY_SHA256 };
      }

      const stat = await run(node, privileged(node, ["sh", "-c", STAT_SCRIPT, "sh", guestPath]));
      if (stat.exitCode !== 0) {
        failClosed(`guest stat ${guestPath}`, "the credential file attributes could not be read");
      }
      const [owner, modeText] = stat.stdout.trim().split(/\s+/);
      if (owner === undefined || modeText === undefined || !/^[0-7]{3,4}$/.test(modeText)) {
        failClosed(`guest stat ${guestPath}`, "unexpected stat output");
      }

      if (node.provider === "lima") {
        const readable = await run(node, ["sudo", "-u", owner, "test", "-r", guestPath]);
        if (readable.exitCode !== 0) {
          return { exists: false, isSymlink: false, owner: "", mode: 0, sha256: EMPTY_SHA256 };
        }
      }

      const digest = await run(node, privileged(node, ["sh", "-c", SHA256_SCRIPT, "sh", guestPath]));
      const sha256 = digest.stdout.trim().split(/\s+/)[0];
      if (digest.exitCode !== 0 || sha256 === undefined || !/^[0-9a-f]{64}$/.test(sha256)) {
        failClosed(`guest sha256sum ${guestPath}`, "the credential file digest could not be read");
      }

      return {
        exists: true,
        isSymlink: symlink.exitCode === 0,
        owner,
        mode: Number.parseInt(modeText, 8),
        sha256,
      };
    },

    async remove(node, guestPath) {
      const result = await run(node, privileged(node, ["rm", "-f", guestPath]));
      if (result.exitCode !== 0) {
        throw new YashikiError("VERIFICATION_FAILED", "guest refused to remove the credential file", {
          node: node.name,
          guestPath,
        });
      }
    },
  };
}
