import { describe, expect, it } from "vitest";
import { createFakeProcessPort } from "@meidoya-yashiki/yashiki-core";
import { createFakeHostServicePort, NativeProvider } from "./native-provider.js";

function setup() {
  const service = createFakeHostServicePort();
  const port = createFakeProcessPort([() => ({ exitCode: 0, stdout: "ok" })]);
  return { service, port, provider: new NativeProvider({ process: port, service }) };
}

describe("NativeProvider", () => {
  it("creates a ref without touching the host", async () => {
    const { provider } = setup();
    expect(await provider.create({ name: "mac-main", cpus: 8, memoryMiB: 16384, diskGiB: 100, mounts: [] })).toEqual({
      name: "mac-main",
      provider: "native",
    });
  });

  it("rejects mounts: a native node has no host boundary to narrow", async () => {
    const { provider } = setup();
    await expect(
      provider.create({
        name: "mac-main",
        cpus: 8,
        memoryMiB: 16384,
        diskGiB: 100,
        mounts: [{ source: "/Users/tester/Workspace", target: "/workspace", writable: true }],
      }),
    ).rejects.toThrowError(/MOUNT_POLICY_VIOLATION/);
  });

  it("verifies service transitions by read-back", async () => {
    const { provider, service } = setup();
    const ref = { name: "mac-main", provider: "native" as const };

    await expect(provider.start(ref)).rejects.toThrowError(/NOT_FOUND/);

    service.installed.add("mac-main");
    expect((await provider.inspect(ref)).status).toBe("stopped");
    await provider.start(ref);
    expect((await provider.inspect(ref)).status).toBe("running");
    await provider.stop(ref);
    expect((await provider.inspect(ref)).status).toBe("stopped");
    await provider.destroy(ref);
    expect((await provider.inspect(ref)).status).toBe("absent");
  });

  it("fails closed when the service reports it is still running after stop", async () => {
    const service = createFakeHostServicePort();
    service.installed.add("mac-main");
    service.running.add("mac-main");
    const provider = new NativeProvider({
      process: createFakeProcessPort([]),
      service: { ...service, stop: async () => undefined },
    });

    await expect(provider.stop({ name: "mac-main", provider: "native" })).rejects.toThrowError(/VERIFICATION_FAILED/);
  });

  it("fails closed when a local command times out", async () => {
    const provider = new NativeProvider({
      process: createFakeProcessPort([() => ({ exitCode: null, timedOut: true })]),
      service: createFakeHostServicePort(),
    });

    await expect(
      provider.exec({ name: "mac-main", provider: "native" }, { argv: ["sleep", "999"] }),
    ).rejects.toThrowError(/AMBIGUOUS_RESULT/);
  });
});
