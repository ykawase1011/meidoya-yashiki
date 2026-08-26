import { YashikiError } from "./errors.js";

const UNIT_TO_MIB: Record<string, number> = {
  mib: 1,
  m: 1,
  mb: 1,
  gib: 1024,
  g: 1024,
  gb: 1024,
  tib: 1024 * 1024,
  t: 1024 * 1024,
  tb: 1024 * 1024,
};

/** Parses "16GiB" / "16384MiB" / 16384 into whole MiB. */
export function parseSizeToMiB(input: string | number, field: string): number {
  if (typeof input === "number") {
    if (!Number.isFinite(input) || input <= 0 || !Number.isInteger(input)) {
      throw new YashikiError("CONFIG_INVALID", `${field} must be a positive integer of MiB`, { field });
    }
    return input;
  }

  const match = /^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]+)?\s*$/.exec(input);
  const amount = match?.[1];
  if (amount === undefined) {
    throw new YashikiError("CONFIG_INVALID", `${field} is not a valid size: '${input}'`, { field });
  }
  const unit = (match?.[2] ?? "MiB").toLowerCase();
  const multiplier = UNIT_TO_MIB[unit];
  if (multiplier === undefined) {
    throw new YashikiError("CONFIG_INVALID", `${field} has an unknown size unit: '${unit}'`, { field });
  }

  const mib = Number(amount) * multiplier;
  if (!Number.isInteger(mib) || mib <= 0) {
    throw new YashikiError("CONFIG_INVALID", `${field} must resolve to a positive whole MiB`, { field });
  }
  return mib;
}

export function parseSizeToGiB(input: string | number, field: string): number {
  const mib = parseSizeToMiB(input, field);
  if (mib % 1024 !== 0) {
    throw new YashikiError("CONFIG_INVALID", `${field} must be a whole number of GiB`, { field });
  }
  return mib / 1024;
}

export function formatMiB(mib: number): string {
  return mib % 1024 === 0 ? `${mib / 1024}GiB` : `${mib}MiB`;
}
