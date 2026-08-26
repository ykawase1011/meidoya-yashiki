/**
 * Mirrors `@meidoya/node-protocol` NODE_PROTOCOL_VERSION.
 * Yashiki pins a Node Protocol version, not a meidoya release version
 * (03-repository-boundaries.md section 6).
 */
export const NODE_PROTOCOL_VERSION = 1 as const;

export type NodeProtocolVersion = typeof NODE_PROTOCOL_VERSION;
