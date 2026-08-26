import { parseArgs } from "node:util";
import {
  isYashikiError,
  parseSizeToGiB,
  parseSizeToMiB,
  YashikiError,
  type ProviderKind,
  type SecretGuard,
} from "@meidoya-yashiki/yashiki-core";

export const USAGE = `meidoya-yashiki - Meidoya Infrastructure Plane

Usage:
  meidoya-yashiki node create <name> --provider lima --cpu N --memory 16GiB [--disk 100GiB]
  meidoya-yashiki node start <name>
  meidoya-yashiki node stop <name>
  meidoya-yashiki node status <name>
  meidoya-yashiki node doctor <name>
  meidoya-yashiki node upgrade <name>
  meidoya-yashiki node reprovision <name>
  meidoya-yashiki node backup <name>

Yashiki manages execution nodes only. It never creates Tasks, chooses Workers or
Models, posts to chat, or releases a Human Gate.`;

export type CreateOverrides = {
  provider?: ProviderKind;
  cpus?: number;
  memoryMiB?: number;
  diskGiB?: number;
};

/** Every command returns human-readable lines. No secret value is ever a line. */
export interface CliRuntime {
  create(name: string, overrides: CreateOverrides): Promise<readonly string[]>;
  start(name: string): Promise<readonly string[]>;
  stop(name: string): Promise<readonly string[]>;
  status(name: string): Promise<readonly string[]>;
  doctor(name: string): Promise<readonly string[]>;
  upgrade(name: string): Promise<readonly string[]>;
  reprovision(name: string): Promise<readonly string[]>;
  backup(name: string): Promise<readonly string[]>;
}

export const REDACTION = "[redacted: this output would have printed a credential value]";

/**
 * Wraps a terminal writer in the process's secret guard. The terminal is the
 * last sink and the one a human reads, so it gets the same guard as the receipt
 * store and Doctor. A hit becomes a redaction rather than a thrown error:
 * refusing to write at all would lose the output and tell the operator nothing
 * about what happened.
 *
 * IT GUARDS THE WHOLE BUFFER, NOT A LINE. A line-at-a-time guard is not a guard
 * at all for the credential shape that matters most: a PEM private key spans
 * four or more lines, and NO line of it contains the remembered value, so every
 * single line passes and the key prints in full. The caller therefore hands
 * this function everything it is about to write in one call, and a hit anywhere
 * in that buffer suppresses the buffer — losing legitimate output is the
 * correct trade against printing a key.
 */
export function guardedWriter(guard: SecretGuard, sink: string, write: (text: string) => void): (text: string) => void {
  return (text) => {
    try {
      guard.assertClean(sink, text);
    } catch {
      write(REDACTION);
      return;
    }
    write(text);
  };
}

export type CliDeps = {
  runtime: CliRuntime;
  /** Receives a command's entire output at once; see `guardedWriter`. */
  write: (text: string) => void;
  writeError: (text: string) => void;
};

const SUBCOMMANDS = ["create", "start", "stop", "status", "doctor", "upgrade", "reprovision", "backup"] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

function parseCreateOverrides(rest: readonly string[]): CreateOverrides {
  const { values } = parseArgs({
    args: [...rest],
    options: {
      provider: { type: "string" },
      cpu: { type: "string" },
      cpus: { type: "string" },
      memory: { type: "string" },
      disk: { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });

  const overrides: CreateOverrides = {};
  if (values.provider !== undefined) {
    if (values.provider !== "lima" && values.provider !== "native") {
      throw new YashikiError("CONFIG_INVALID", "--provider must be 'lima' or 'native'", { provider: values.provider });
    }
    overrides.provider = values.provider;
  }
  const cpuText = values.cpu ?? values.cpus;
  if (cpuText !== undefined) {
    const cpus = Number(cpuText);
    if (!Number.isInteger(cpus) || cpus < 1) {
      throw new YashikiError("CONFIG_INVALID", "--cpu must be a positive integer", { cpu: cpuText });
    }
    overrides.cpus = cpus;
  }
  if (values.memory !== undefined) overrides.memoryMiB = parseSizeToMiB(values.memory, "--memory");
  if (values.disk !== undefined) overrides.diskGiB = parseSizeToGiB(values.disk, "--disk");
  return overrides;
}

function dispatch(
  command: Subcommand,
  name: string,
  rest: readonly string[],
  runtime: CliRuntime,
): Promise<readonly string[]> {
  switch (command) {
    case "create":
      return runtime.create(name, parseCreateOverrides(rest));
    case "start":
      return runtime.start(name);
    case "stop":
      return runtime.stop(name);
    case "status":
      return runtime.status(name);
    case "doctor":
      return runtime.doctor(name);
    case "upgrade":
      return runtime.upgrade(name);
    case "reprovision":
      return runtime.reprovision(name);
    case "backup":
      return runtime.backup(name);
  }
}

export async function runCli(argv: readonly string[], deps: CliDeps): Promise<number> {
  const [group, subcommand, name, ...rest] = argv;

  if (group === undefined || group === "--help" || group === "-h" || group === "help") {
    deps.write(USAGE);
    return 0;
  }
  if (group !== "node") {
    deps.writeError(`unknown command group '${group}'`);
    deps.writeError(USAGE);
    return 2;
  }
  if (subcommand === undefined || !(SUBCOMMANDS as readonly string[]).includes(subcommand)) {
    deps.writeError(`unknown node subcommand '${subcommand ?? ""}'`);
    deps.writeError(USAGE);
    return 2;
  }
  if (name === undefined || name.startsWith("-")) {
    deps.writeError(`node ${subcommand} requires a node name`);
    return 2;
  }

  try {
    const command = subcommand as Subcommand;
    const lines = await dispatch(command, name, rest, deps.runtime);
    // One write, not one per line: the guard behind `deps.write` can only see a
    // multi-line credential if it is handed the whole buffer at once.
    if (lines.length > 0) deps.write(lines.join("\n"));
    return 0;
  } catch (error) {
    if (isYashikiError(error)) {
      deps.writeError(error.message);
      return error.code === "RECOVERY_REQUIRED" ? 3 : 1;
    }
    deps.writeError(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
