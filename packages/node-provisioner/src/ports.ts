import type { DesiredNodeConfig, NodeRef } from "@meidoya-yashiki/yashiki-core";

export interface SystemDependencyPort {
  /** Installs missing packages and returns the set still missing afterwards. */
  ensure(node: NodeRef, packages: readonly string[]): Promise<{ missing: readonly string[] }>;
}

export type ServiceState = "absent" | "installed" | "running";

export interface NodeServicePort {
  /** Installs the launchd/systemd unit for the node. */
  install(node: NodeRef, config: DesiredNodeConfig): Promise<void>;
  start(node: NodeRef): Promise<void>;
  /** Returns null when the state cannot be determined; the caller fails closed. */
  state(node: NodeRef): Promise<ServiceState | null>;
}

export type RegistrationStatus = {
  registered: boolean;
  protocolVersion: number | null;
  /** Age of the most recent heartbeat; null when it cannot be determined. */
  heartbeatAgeMs: number | null;
};

export interface RegistrationVerifierPort {
  /**
   * Observes the Control Plane's view of the node. Yashiki only READS this: it
   * never creates work for the node (03-repository-boundaries.md section 2.2).
   */
  check(node: NodeRef, config: DesiredNodeConfig): Promise<RegistrationStatus>;
}
