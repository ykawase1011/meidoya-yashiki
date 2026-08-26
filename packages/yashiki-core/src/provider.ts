import type { MountSpec, ProviderKind } from "./types.js";

export type NodeRef = {
  name: string;
  provider: ProviderKind;
};

export type CreateNodeInput = {
  name: string;
  cpus: number;
  memoryMiB: number;
  diskGiB: number;
  mounts: readonly MountSpec[];
};

export type NodeLifecycleStatus = "absent" | "stopped" | "running" | "unknown";

export type NodeInspection = {
  ref: NodeRef;
  status: NodeLifecycleStatus;
  cpus: number | null;
  memoryMiB: number | null;
  diskGiB: number | null;
  mounts: readonly MountSpec[];
};

export type ExecInput = {
  argv: readonly string[];
  stdin?: string;
  timeoutMs?: number;
  cwd?: string;
};

export type ExecResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
};

/** 11-yashiki-design.md section 4. MVP implements LimaProvider only. */
export interface NodeProvider {
  create(input: CreateNodeInput): Promise<NodeRef>;
  start(node: NodeRef): Promise<void>;
  stop(node: NodeRef): Promise<void>;
  inspect(node: NodeRef): Promise<NodeInspection>;
  exec(node: NodeRef, input: ExecInput): Promise<ExecResult>;
  destroy(node: NodeRef): Promise<void>;
}
