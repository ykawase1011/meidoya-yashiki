import { createHash } from "node:crypto";

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/**
 * Deterministic JSON: object keys sorted, no incidental whitespace.
 *
 * REFUSES WHAT IT CANNOT REPRESENT. This is a hash input and a secret-guard
 * input, so a value it renders WRONG is worse than one it rejects. `JSON`
 * silently maps `NaN` and `Infinity` to `null`, and it renders a `Map`, a `Set`,
 * a `BigInt` wrapper, a function or any other exotic object as `{}` — so every
 * one of those hashes identically, and a guard handed `{}` has been shown
 * nothing. `JsonValue` says none of them can occur; that is a compile-time
 * claim, and this is exported API a JS caller or an `as never` reaches directly.
 */
export function canonicalize(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(
        `canonicalize: ${String(value)} has no JSON representation; JSON would silently write null, ` +
          `so NaN, Infinity and -Infinity would all hash the same.`,
      );
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  if (typeof value !== "object") {
    throw new TypeError(`canonicalize: a value of type ${typeof value} is not JSON`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(
      `canonicalize: ${(value as object).constructor.name} is not a plain object; JSON would render it ` +
        `as {} and every instance of it would hash the same.`,
    );
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => {
      const child = value[key];
      if (child === undefined) {
        throw new TypeError(
          `canonicalize: property ${JSON.stringify(key)} is undefined; JSON would drop the key entirely.`,
        );
      }
      return `${JSON.stringify(key)}:${canonicalize(child)}`;
    })
    .join(",")}}`;
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function contentHash(value: JsonValue): string {
  return sha256Hex(canonicalize(value));
}

export function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

/** Walks every string in a payload; used to keep secret material out of sinks. */
export function collectStrings(value: JsonValue, into: string[] = []): string[] {
  if (typeof value === "string") into.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, into);
  else if (typeof value === "object" && value !== null)
    for (const item of Object.values(value)) collectStrings(item, into);
  return into;
}
