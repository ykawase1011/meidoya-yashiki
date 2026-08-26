import type { CredentialProviderId, NodeRef } from "@meidoya-yashiki/yashiki-core";

/**
 * Host secret source (Keychain / SOPS). Injected: the test suite never touches a
 * real Keychain, and no other package is allowed to read secret material.
 */
export interface SecretSourcePort {
  /** Returns the secret value, or null when the reference does not exist. */
  read(sourceRef: string): Promise<string | null>;
}

export type GuestFileStat = {
  exists: boolean;
  isSymlink: boolean;
  owner: string;
  /** POSIX mode bits, e.g. 0o600. */
  mode: number;
  sha256: string;
};

/**
 * Guest-side credential file operations. Implementations MUST NOT place the
 * value on a command line; it is streamed over stdin (11 section 7).
 */
export interface GuestCredentialPort {
  writeSecret(
    node: NodeRef,
    guestPath: string,
    value: string,
    attributes: { mode: number; owner: string },
  ): Promise<void>;
  stat(node: NodeRef, guestPath: string): Promise<GuestFileStat>;
  remove(node: NodeRef, guestPath: string): Promise<void>;
}

export type CredentialOperation = "sync" | "revoke";

export type CredentialOutcome = {
  provider: CredentialProviderId;
  operation: CredentialOperation;
  guestPath: string;
  changed: boolean;
  skipped: boolean;
};
