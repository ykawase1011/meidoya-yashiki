/**
 * VENDORED TYPE-ONLY MIRROR of `@meidoya/node-protocol` at NODE_PROTOCOL_VERSION = 1.
 *
 * This file is the ONLY cross-repository contract surface in meidoya-yashiki
 * (03-repository-boundaries.md section 4). It is a hand-maintained copy because
 * `@meidoya/node-protocol` is not published to a registry yet. It MUST be
 * replaced by the published package once available; do not extend it with
 * Yashiki-local concepts, and never add a git/path/submodule dependency on the
 * meidoya source repository.
 *
 * Types only: no runtime validation lives here, so a drift between this mirror
 * and the published contract can only be caught by the protocol-version pin
 * test and by integration against a real meidoya-node.
 */

export * from "./version.js";
export * from "./node.js";
export * from "./manifest.js";
