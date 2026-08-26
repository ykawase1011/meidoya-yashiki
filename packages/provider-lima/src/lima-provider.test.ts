import { describe, expect, it } from "vitest";
import {
  createFakeProcessPort,
  createSecretGuard,
  isYashikiError,
  type FakeHandler,
  type FakeProcessPort,
} from "@meidoya-yashiki/yashiki-core";
import { LimaProvider, mountsExpression } from "./lima-provider.js";

type GuestMount = { location: string; mountPoint: string; writable: boolean };
type FakeInstance = {
  name: string;
  status: string;
  cpus: number;
  memory: number;
  disk: number;
  /** What the guest ACTUALLY has mounted, derived from what `create` passed. */
  guestMounts?: GuestMount[];
};

const GIB = 1024 * 1024 * 1024;

/**
 * In-process limactl simulator: the suite never touches a real Lima.
 *
 * The mount half is the point. `create` and `verifyMounts` used to be tested
 * against two unrelated fakes — `createInput.mounts` was `[]` in every case,
 * and the mount read-back answered `mountpoint -q` without reference to
 * anything `create` had been given — so the two could disagree completely and
 * all 384 tests stayed green while `--mount=${source}:...` mounted every path
 * at its HOST location inside the guest. Here the instance remembers what it
 * was created with, and the guest answers `mountpoint`/`test -w` from that.
 */
function fakeLima(initial: FakeInstance[] = []): { port: FakeProcessPort; instances: FakeInstance[] } {
  const instances = [...initial];

  const flag = (argv: readonly string[], name: string): string | undefined =>
    argv.find((arg) => arg.startsWith(`${name}=`))?.slice(name.length + 1);

  /** The mounts an instance definition declares, as Lima would read them. */
  const declaredMounts = (argv: readonly string[]): GuestMount[] => {
    const expression = argv.find((arg) => arg.startsWith("--set=.mounts"));
    if (expression === undefined) return [];
    const json = expression.slice(expression.indexOf("=", "--set".length) + 1).replace(/^\.mounts\s*=\s*/, "");
    return JSON.parse(json) as GuestMount[];
  };

  const handler: FakeHandler = ({ argv }) => {
    const command = argv[1];

    if (command === "list") {
      return {
        // `limactl list --json` reports the instance, not the guest's mount
        // table, so the fake keeps that field to itself.
        stdout: instances
          .map((instance) => JSON.stringify({ ...instance, guestMounts: undefined }))
          .join("\n"),
      };
    }
    if (command === "create") {
      instances.push({
        name: flag(argv, "--name") ?? "",
        status: "Stopped",
        cpus: Number(flag(argv, "--cpus") ?? 0),
        memory: Number(flag(argv, "--memory") ?? 0) * GIB,
        disk: Number(flag(argv, "--disk") ?? 0) * GIB,
        guestMounts: declaredMounts(argv),
      });
      return { exitCode: 0 };
    }
    if (command === "edit") {
      const target = argv[argv.length - 1];
      const instance = instances.find((entry) => entry.name === target);
      if (instance !== undefined) {
        instance.cpus = Number(flag(argv, "--cpus") ?? instance.cpus);
        instance.memory = Number(flag(argv, "--memory") ?? 0) * GIB;
        instance.disk = Number(flag(argv, "--disk") ?? 0) * GIB;
      }
      return { exitCode: 0 };
    }
    if (command === "start" || command === "stop") {
      const target = argv[argv.length - 1];
      const instance = instances.find((entry) => entry.name === target);
      if (instance !== undefined) instance.status = command === "start" ? "Running" : "Stopped";
      return { exitCode: 0 };
    }
    if (command === "delete") {
      const target = argv[argv.length - 1];
      const index = instances.findIndex((entry) => entry.name === target);
      if (index >= 0) instances.splice(index, 1);
      return { exitCode: 0 };
    }
    if (command === "shell") {
      const separator = argv.indexOf("--");
      const guestArgv = argv.slice(separator + 1);
      const instance = instances.find((entry) => entry.name === argv[separator - 1]);
      const mounted = instance?.guestMounts ?? [];

      // The guest sees a mount point where the instance definition put one, and
      // nowhere else.
      if (guestArgv[0] === "mountpoint") {
        return { exitCode: mounted.some((mount) => mount.mountPoint === guestArgv[2]) ? 0 : 1 };
      }
      if (guestArgv[0] === "test" && guestArgv[1] === "-w") {
        const mount = mounted.find((entry) => entry.mountPoint === guestArgv[2]);
        return { exitCode: mount?.writable === true ? 0 : 1 };
      }
      return { exitCode: 0, stdout: "" };
    }
    return { exitCode: 1, stderr: `unexpected limactl invocation: ${argv.join(" ")}` };
  };

  return { port: createFakeProcessPort([handler]), instances };
}

const ref = { name: "work-grammarxiv", provider: "lima" as const };
const createInput = { name: "work-grammarxiv", cpus: 8, memoryMiB: 16 * 1024, diskGiB: 100, mounts: [] };

describe("LimaProvider", () => {
  it("creates an instance and verifies the resource config by read-back", async () => {
    const lima = fakeLima();
    const provider = new LimaProvider({ process: lima.port });

    const created = await provider.create(createInput);
    expect(created).toEqual(ref);
    expect(lima.instances[0]).toMatchObject({ name: "work-grammarxiv", cpus: 8, memory: 16 * GIB });

    const inspection = await provider.inspect(ref);
    expect(inspection.status).toBe("stopped");
    expect(inspection.cpus).toBe(8);
    expect(inspection.memoryMiB).toBe(16 * 1024);
    expect(inspection.diskGiB).toBe(100);
  });

  it("is idempotent: a second create reconciles instead of recreating", async () => {
    const lima = fakeLima();
    const provider = new LimaProvider({ process: lima.port });
    await provider.create(createInput);
    await provider.create({ ...createInput, cpus: 12 });

    expect(lima.instances).toHaveLength(1);
    expect(lima.instances[0]?.cpus).toBe(12);
  });

  it("verifies start and stop transitions", async () => {
    const lima = fakeLima();
    const provider = new LimaProvider({ process: lima.port });
    await provider.create(createInput);

    await provider.start(ref);
    expect((await provider.inspect(ref)).status).toBe("running");
    await provider.stop(ref);
    expect((await provider.inspect(ref)).status).toBe("stopped");

    await provider.destroy(ref);
    expect((await provider.inspect(ref)).status).toBe("absent");
  });

  it("fails closed when limactl leaves the instance in a non-target state", async () => {
    const port = createFakeProcessPort([
      ({ argv }) =>
        argv[1] === "list"
          ? { stdout: JSON.stringify({ name: "work-grammarxiv", status: "Stopped", cpus: 8, memory: 16 * GIB }) }
          : undefined,
      () => ({ exitCode: 0 }),
    ]);
    const provider = new LimaProvider({ process: port });

    await expect(provider.start(ref)).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  it("fails closed when the instance status is not understood", async () => {
    const port = createFakeProcessPort([
      ({ argv }) =>
        argv[1] === "list"
          ? { stdout: JSON.stringify({ name: "work-grammarxiv", status: "Broken", cpus: 8, memory: 16 * GIB }) }
          : undefined,
      () => ({ exitCode: 0 }),
    ]);
    const provider = new LimaProvider({ process: port });

    await expect(provider.start(ref)).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("fails closed when limactl list output is not parseable", async () => {
    const port = createFakeProcessPort([() => ({ exitCode: 0, stdout: "not json" })]);
    const provider = new LimaProvider({ process: port });

    await expect(provider.inspect(ref)).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("fails closed when limactl list itself fails", async () => {
    const port = createFakeProcessPort([() => ({ exitCode: 127, stderr: "limactl: not found" })]);
    const provider = new LimaProvider({ process: port });

    await expect(provider.inspect(ref)).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("fails closed when the instance name is reported twice", async () => {
    const lima = fakeLima([
      { name: "work-grammarxiv", status: "Stopped", cpus: 8, memory: 16 * GIB, disk: 100 * GIB },
      { name: "work-grammarxiv", status: "Running", cpus: 8, memory: 16 * GIB, disk: 100 * GIB },
    ]);
    const provider = new LimaProvider({ process: lima.port });

    await expect(provider.inspect(ref)).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("rejects a resource config that limactl accepted but did not apply", async () => {
    // limactl edit exits 0 but the instance keeps its old shape.
    const provider = new LimaProvider({
      process: createFakeProcessPort([
        ({ argv }) =>
          argv[1] === "list"
            ? {
                stdout: JSON.stringify({
                  name: "work-grammarxiv",
                  status: "Stopped",
                  cpus: 2,
                  memory: 2 * GIB,
                  disk: 20 * GIB,
                }),
              }
            : { exitCode: 0 },
      ]),
    });

    await expect(provider.applyResourceConfig(ref, createInput)).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  it("rejects a disk that limactl accepted and did not grow", async () => {
    // The doc comment claims "every applied value is read back" and `disk` was
    // in the change detection but not in the read-back, so a disk that stayed
    // small was reported as a verified apply.
    const provider = new LimaProvider({
      process: createFakeProcessPort([
        ({ argv }) =>
          argv[1] === "list"
            ? {
                stdout: JSON.stringify({
                  name: "work-grammarxiv",
                  status: "Stopped",
                  cpus: 8,
                  memory: 16 * GIB,
                  disk: 20 * GIB,
                }),
              }
            : { exitCode: 0 },
      ]),
    });

    await expect(provider.applyResourceConfig(ref, createInput)).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  it("passes guest commands as argv, never as a shell string", async () => {
    const lima = fakeLima([{ name: "work-grammarxiv", status: "Running", cpus: 8, memory: 16 * GIB, disk: 100 * GIB }]);
    const provider = new LimaProvider({ process: lima.port });

    await provider.exec(ref, { argv: ["ls", "/workspace; rm -rf /"] });

    const call = lima.port.calls.at(-1);
    expect(call?.argv).toEqual(["limactl", "shell", "work-grammarxiv", "--", "ls", "/workspace; rm -rf /"]);
    expect(call?.argv).not.toContain("sh");
  });

  it("fails closed when a guest command times out", async () => {
    const port = createFakeProcessPort([
      ({ argv }) =>
        argv[1] === "list"
          ? { stdout: JSON.stringify({ name: "work-grammarxiv", status: "Running", cpus: 8, memory: 16 * GIB }) }
          : { exitCode: null, timedOut: true },
    ]);
    const provider = new LimaProvider({ process: port });

    await expect(provider.exec(ref, { argv: ["sleep", "999"] })).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });

  it("rejects argv containing a NUL byte", async () => {
    const lima = fakeLima([{ name: "work-grammarxiv", status: "Running", cpus: 8, memory: 16 * GIB, disk: 100 * GIB }]);
    const provider = new LimaProvider({ process: lima.port });

    await expect(provider.exec(ref, { argv: ["ls", "a\0b"] })).rejects.toThrowError(/PROVIDER_FAILED/);
  });

  describe("mounts reach the guest at the target that was validated", () => {
    const mounts = [
      { source: "/Users/tester/Workspace/x", target: "/workspace/x", writable: true },
      { source: "/Users/tester/Workspace/y", target: "/workspace/y", writable: false },
    ];

    /**
     * The binding test. `create` is given mounts, the guest is asked about them
     * by `verifyMounts`, and the two are the same instance — so a `create` that
     * does not carry the guest mount point makes THIS test red rather than
     * making no test red at all.
     *
     * With `--mount=${source}:${writable}` the guest mounted each path at its
     * HOST location, `mountpoint -q /workspace/x` failed, and no node with a
     * mount could provision. Nothing caught it because `createInput.mounts` was
     * `[]` in every lima test.
     */
    it("creates the instance so that the guest verification of the same mounts passes", async () => {
      const lima = fakeLima();
      const provider = new LimaProvider({ process: lima.port });

      await provider.create({ ...createInput, mounts });
      await provider.start(ref);

      await expect(provider.verifyMounts(ref, mounts)).resolves.toBeUndefined();
      expect(lima.instances[0]?.guestMounts).toEqual([
        { location: "/Users/tester/Workspace/x", mountPoint: "/workspace/x", writable: true },
        { location: "/Users/tester/Workspace/y", mountPoint: "/workspace/y", writable: false },
      ]);
    });

    it("passes the guest mount point on the instance definition, which is the only place Lima reads it", () => {
      // `limactl --mount` takes `<host_path>[:w]` and nothing else (limactl
      // 2.1.1), so a target can only be expressed in the YAML.
      const expression = mountsExpression(mounts);
      expect(expression.startsWith("--set=.mounts")).toBe(true);
      expect(expression).toContain('"mountPoint":"/workspace/x"');
      // And an instance with no declared mounts gets no mounts — not the
      // default template's read-only mount of the whole host home.
      expect(mountsExpression([])).toBe("--set=.mounts = []");
    });

    it("rejects a mount the guest does not actually have", async () => {
      const lima = fakeLima();
      const provider = new LimaProvider({ process: lima.port });
      await provider.create({ ...createInput, mounts: [] });
      await provider.start(ref);

      try {
        await provider.verifyMounts(ref, mounts);
        throw new Error("expected the missing mount to be rejected");
      } catch (error) {
        expect(isYashikiError(error, "VERIFICATION_FAILED")).toBe(true);
      }
    });

    it("rejects a mount whose writability does not match the declaration", async () => {
      const lima = fakeLima();
      const provider = new LimaProvider({ process: lima.port });
      await provider.create({ ...createInput, mounts });
      await provider.start(ref);

      try {
        await provider.verifyMounts(ref, [{ ...(mounts[1] as (typeof mounts)[number]), writable: true }]);
        throw new Error("expected the writability mismatch to be rejected");
      } catch (error) {
        expect(isYashikiError(error, "VERIFICATION_FAILED")).toBe(true);
      }
    });
  });

  describe("limactl stderr in error messages", () => {
    // An obvious dummy. limactl's stderr is untrusted text that ends up on the
    // operator's terminal, so it may only be quoted if the guard clears it.
    const secret = "dummy-not-a-real-credential-value";

    it("quotes stderr when it carries no credential value", async () => {
      const port = createFakeProcessPort([() => ({ exitCode: 1, stderr: "instance is broken" })]);
      const provider = new LimaProvider({ process: port, secretGuard: createSecretGuard([secret]) });

      await expect(provider.start(ref)).rejects.toThrowError(/instance is broken/);
    });

    it("withholds stderr that echoes a credential value, and still fails", async () => {
      const port = createFakeProcessPort([() => ({ exitCode: 1, stderr: `cat: ${secret}: No such file` })]);
      const provider = new LimaProvider({ process: port, secretGuard: createSecretGuard([secret]) });

      let message = "";
      try {
        await provider.start(ref);
      } catch (error) {
        expect(isYashikiError(error)).toBe(true);
        message = (error as Error).message;
      }
      expect(message).not.toContain(secret);
      expect(message).toContain("stderr withheld");
    });

    it("withholds an encoded credential value in stderr too", async () => {
      const encoded = Buffer.from(secret, "utf8").toString("base64");
      const port = createFakeProcessPort([() => ({ exitCode: 127, stderr: `blob ${encoded}` })]);
      const provider = new LimaProvider({ process: port, secretGuard: createSecretGuard([secret]) });

      let message = "";
      try {
        await provider.inspect(ref);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).not.toContain(encoded);
      expect(message).toContain("stderr withheld");
    });
  });
});
