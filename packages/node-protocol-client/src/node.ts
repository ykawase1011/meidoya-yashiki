export type NodePlatform = "darwin" | "linux";

export type NodeArchitecture = "arm64" | "x64";

export type NodeProfile = "mac-restricted" | "linux-restricted" | "lima-trusted";

export type NodeStatus = "online" | "draining" | "offline";

export type ExecutionNode = {
  id: string;
  protocolVersion: number;
  platform: NodePlatform;
  architecture: NodeArchitecture;
  profile: NodeProfile;
  capabilities: string[];
  allowedWorkspaces: string[];
  maxConcurrency: number;
  status: NodeStatus;
};

export type NodeRegistration = {
  nodeId: string;
  nodeVersion: string;
  protocolVersion: number;
  platform: NodePlatform;
  arch: NodeArchitecture;
  profile: NodeProfile;
  capabilities: string[];
  workspaceBindings: string[];
  maxConcurrency: number;
};

export type NodeHeartbeat = {
  nodeId: string;
  status: NodeStatus;
  activeRunCount: number;
  timestamp: number;
};
