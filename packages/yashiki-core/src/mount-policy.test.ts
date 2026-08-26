import { describe, expect, it } from "vitest";
import { validateMounts } from "./mount-policy.js";
import { isYashikiError } from "./errors.js";

const context = { homeDir: "/Users/tester" };

function expectRejected(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(isYashikiError(error, "MOUNT_POLICY_VIOLATION")).toBe(true);
    return;
  }
  throw new Error("expected the mount to be rejected");
}

describe("mount policy", () => {
  it("accepts an explicit project mount and normalizes ~", () => {
    const mounts = validateMounts(
      [{ source: "~/Workspace/Repositories/GrammarXiv", target: "/workspace/GrammarXiv", writable: true }],
      context,
    );
    expect(mounts).toEqual([
      { source: "/Users/tester/Workspace/Repositories/GrammarXiv", target: "/workspace/GrammarXiv", writable: true },
    ]);
  });

  it("rejects mounting the entire host home", () => {
    expectRejected(() => validateMounts([{ source: "~", target: "/host", writable: false }], context));
    expectRejected(() => validateMounts([{ source: "~/", target: "/host", writable: false }], context));
    expectRejected(() =>
      validateMounts([{ source: "/Users/tester", target: "/host", writable: false }], context),
    );
  });

  it("rejects ancestors of the host home and the root filesystem", () => {
    expectRejected(() => validateMounts([{ source: "/", target: "/host", writable: false }], context));
    expectRejected(() => validateMounts([{ source: "/Users", target: "/host", writable: false }], context));
  });

  it("rejects traversal that escapes into the home root", () => {
    expectRejected(() =>
      validateMounts([{ source: "~/Workspace/../", target: "/host", writable: false }], context),
    );
  });

  it("rejects known-sensitive host directories", () => {
    for (const source of ["~/.ssh", "~/.ssh/id_ed25519", "~/Library/Keychains", "~/.gnupg", "~/.aws"]) {
      expectRejected(() => validateMounts([{ source, target: "/secrets", writable: false }], context));
    }
  });

  it("rejects relative sources and targets", () => {
    expectRejected(() =>
      validateMounts([{ source: "Workspace/x", target: "/workspace/x", writable: false }], context),
    );
    expectRejected(() =>
      validateMounts([{ source: "~/Workspace/x", target: "workspace/x", writable: false }], context),
    );
  });

  it("rejects overlapping guest targets", () => {
    expectRejected(() =>
      validateMounts(
        [
          { source: "~/Workspace/a", target: "/workspace", writable: false },
          { source: "~/Workspace/b", target: "/workspace/b", writable: false },
        ],
        context,
      ),
    );
  });

  it("rejects a PARENT of a forbidden directory, not only a descendant", () => {
    // The containment test ran one way only. `~/.config` contains
    // `~/.config/gh`; `~/.local/share` contains the keyrings. Mounting the
    // parent exposes the forbidden directory just as completely as mounting it,
    // and the two-way test already existed one screen up, for `homeDir`.
    for (const source of ["~/.config", "~/.local/share", "~/.local", "~/.config/", "/Users/tester/.config"]) {
      expectRejected(() => validateMounts([{ source, target: "/secrets", writable: false }], context));
    }
  });

  it("rejects a sensitive directory spelled in another case", () => {
    // APFS is case-insensitive, so every one of these opens exactly the
    // directory the policy says it will never hand to a guest.
    for (const source of ["~/.SSH", "~/.Ssh", "~/library", "~/LIBRARY", "~/.AWS", "~/.GnuPG", "~/.Config/gh"]) {
      expectRejected(() => validateMounts([{ source, target: "/secrets", writable: false }], context));
    }
  });

  it("rejects a symlink that resolves into a forbidden directory", () => {
    // Lima resolves the host side itself, so a policy that reads only the
    // spelling in config.yaml checks a path nobody dereferences.
    const linked = {
      ...context,
      resolveHostPath: (input: string) =>
        input === "/Users/tester/projects/link" ? "/Users/tester/.ssh" : input,
    };
    expectRejected(() =>
      validateMounts([{ source: "~/projects/link", target: "/workspace/x", writable: false }], linked),
    );
  });

  it("returns the resolved source, so the guest gets the path that was validated", () => {
    const linked = {
      ...context,
      resolveHostPath: (input: string) =>
        input === "/Users/tester/projects/link" ? "/Users/tester/Workspace/real" : input,
    };
    expect(validateMounts([{ source: "~/projects/link", target: "/workspace/x", writable: true }], linked)).toEqual([
      { source: "/Users/tester/Workspace/real", target: "/workspace/x", writable: true },
    ]);
  });

  it("rejects overlapping host sources, the way it always rejected overlapping targets", () => {
    expectRejected(() =>
      validateMounts(
        [
          { source: "~/Workspace", target: "/workspace/all", writable: false },
          { source: "~/Workspace/a", target: "/workspace/a", writable: true },
        ],
        context,
      ),
    );
  });

  it("rejects paths carrying quotes, backslashes or control characters", () => {
    // Both halves are interpolated into the Lima instance definition.
    for (const source of ['~/Work"space', "~/Work\\space", "~/Work`space", "~/Work$space"]) {
      expectRejected(() => validateMounts([{ source, target: "/workspace/x", writable: false }], context));
    }
    expectRejected(() =>
      validateMounts([{ source: "~/Workspace/a", target: '/workspace/"x"', writable: false }], context),
    );
  });

  it("rejects mounts on the native provider", () => {
    expectRejected(() =>
      validateMounts([{ source: "~/Workspace/a", target: "/workspace/a", writable: false }], context, "native"),
    );
    expect(validateMounts([], context, "native")).toEqual([]);
  });
});
