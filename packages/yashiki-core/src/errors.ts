export const YASHIKI_ERROR_CODES = [
  "CONFIG_INVALID",
  "MOUNT_POLICY_VIOLATION",
  "NODE_LOCKED",
  "PROVIDER_FAILED",
  "AMBIGUOUS_RESULT",
  "VERIFICATION_FAILED",
  "CHECKSUM_MISMATCH",
  "ARTIFACT_MISMATCH",
  "PROTOCOL_MISMATCH",
  "CREDENTIAL_UNSAFE",
  "RECEIPT_TAMPERED",
  "RECOVERY_REQUIRED",
  "NOT_FOUND",
] as const;

export type YashikiErrorCode = (typeof YASHIKI_ERROR_CODES)[number];

export class YashikiError extends Error {
  readonly code: YashikiErrorCode;
  readonly details: Readonly<Record<string, string | number | boolean>>;

  constructor(
    code: YashikiErrorCode,
    message: string,
    details: Readonly<Record<string, string | number | boolean>> = {},
  ) {
    super(`${code}: ${message}`);
    this.name = "YashikiError";
    this.code = code;
    this.details = details;
  }
}

export function isYashikiError(error: unknown, code?: YashikiErrorCode): error is YashikiError {
  if (!(error instanceof YashikiError)) return false;
  return code === undefined || error.code === code;
}

/**
 * Fail-closed helper: an operation whose outcome could not be observed is an
 * error, never an optimistic success (13-hermes-fleet-migration.md section 3).
 */
export function failClosed(what: string, reason: string): never {
  throw new YashikiError("AMBIGUOUS_RESULT", `${what} produced an ambiguous result: ${reason}`, {
    operation: what,
  });
}
