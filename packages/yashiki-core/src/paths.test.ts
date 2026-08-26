import { describe, expect, it } from "vitest";
import { isYashikiError } from "./errors.js";
import { resolveYashikiPaths } from "./paths.js";

const HOME = "/Users/tester";

describe("resolveYashikiPaths", () => {
  it("places config and state under the XDG defaults", () => {
    const paths = resolveYashikiPaths({ homeDir: HOME });
    expect(paths.configFile).toBe("/Users/tester/.config/meidoya-yashiki/config.yaml");
    expect(paths.databaseFile).toBe("/Users/tester/.local/share/meidoya-yashiki/yashiki.sqlite");
  });

  it("honours an absolute XDG override", () => {
    const paths = resolveYashikiPaths({ homeDir: HOME, xdgConfigHome: "/etc/xdg", xdgDataHome: "~/state" });
    expect(paths.configFile).toBe("/etc/xdg/meidoya-yashiki/config.yaml");
    expect(paths.dataDir).toBe("/Users/tester/state/meidoya-yashiki");
  });

  describe("an XDG variable that is set to nothing", () => {
    /**
     * `??` treats only null and undefined as unset, so an exported-but-empty
     * `XDG_CONFIG_HOME` — which the XDG spec says to handle as unset — made
     * every path RELATIVE. Yashiki then read `./meidoya-yashiki/config.yaml`:
     * a `cd` into an untrusted checkout substituted that repository's mounts,
     * control-plane endpoint and credential source refs, and Yashiki went on to
     * spawn the real limactl with them.
     */
    it("is unset, not the current working directory", () => {
      for (const blank of ["", " ", "\t"]) {
        const paths = resolveYashikiPaths({ homeDir: HOME, xdgConfigHome: blank, xdgDataHome: blank });
        expect(paths.configFile).toBe("/Users/tester/.config/meidoya-yashiki/config.yaml");
        expect(paths.databaseFile).toBe("/Users/tester/.local/share/meidoya-yashiki/yashiki.sqlite");
      }
    });

    it("never yields a path that is relative to wherever the process is standing", () => {
      for (const key of ["xdgConfigHome", "xdgDataHome"] as const) {
        for (const value of [".", "state", "./state", "../elsewhere"]) {
          expect(() => resolveYashikiPaths({ homeDir: HOME, [key]: value })).toThrowError(/CONFIG_INVALID/);
        }
      }
    });

    it("names the variable it is refusing", () => {
      try {
        resolveYashikiPaths({ homeDir: HOME, xdgDataHome: "state" });
      } catch (error) {
        expect(isYashikiError(error, "CONFIG_INVALID")).toBe(true);
        expect((error as Error).message).toContain("XDG_DATA_HOME");
        return;
      }
      throw new Error("expected a relative XDG_DATA_HOME to be refused");
    });

    /**
     * The lock is keyed on `paths.databaseFile`, so a data directory that moves
     * with the working directory means two concurrent runs against the SAME
     * node take two different locks and neither blocks — the one invariant the
     * lock exists to provide.
     */
    it("keeps the database path — and so the node lock — independent of the working directory", () => {
      const fromAnywhere = resolveYashikiPaths({ homeDir: HOME, xdgDataHome: "" }).databaseFile;
      const fromElsewhere = resolveYashikiPaths({ homeDir: HOME, xdgDataHome: undefined }).databaseFile;
      expect(fromAnywhere).toBe(fromElsewhere);
      expect(fromAnywhere.startsWith("/")).toBe(true);
    });
  });
});
