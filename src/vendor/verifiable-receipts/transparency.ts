// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from verifiable-receipts,
// packages/verifiable-receipts/src/transparency.ts at commit
// f41348eac297c81e1c2a0dca91b7bd49dd2a5d9a. Licence:
// third_party/verifiable-receipts/LICENSE.
//
// Changed from the original: only the verification half is kept
// (leafHash, innerHash, verifyInclusionProof, canonicalizeSth and the
// SignedTreeHead type); tree building, proof generation and consistency
// proofs are left out. leafHash takes a string only. isHashHex, which the
// original imports from src/hash.ts, is defined here. verifyInclusionProof
// returns false when an audit-path entry is missing, which the original
// left to the length check alone.

/**
 * RFC 6962 / RFC 9162 Merkle tree primitives for checking that a receipt
 * is in a transparency log. Hash domains follow RFC 6962 §2.1:
 *   leaf  = SHA-256(0x00 || leaf_bytes)
 *   inner = SHA-256(0x01 || left || right)
 */
import { createHash } from "node:crypto";

const LEAF_PREFIX = Buffer.from([0x00]);
const INNER_PREFIX = Buffer.from([0x01]);

/** Leaf hash per RFC 6962 §2.1, over the UTF-8 bytes of `data`. */
export function leafHash(data: string): string {
  return createHash("sha256").update(LEAF_PREFIX).update(Buffer.from(data, "utf8")).digest("hex");
}

/** Inner-node hash per RFC 6962 §2.1. */
export function innerHash(leftHex: string, rightHex: string): string {
  return createHash("sha256")
    .update(INNER_PREFIX)
    .update(Buffer.from(leftHex, "hex"))
    .update(Buffer.from(rightHex, "hex"))
    .digest("hex");
}

/** A hash on the wire: 32 bytes, written as exactly 64 lowercase hex digits. */
const HASH_HEX = /^[0-9a-f]{64}$/;

function isHashHex(x: unknown): x is string {
  return typeof x === "string" && HASH_HEX.test(x);
}

/** A leaf index or tree size: a whole number that a double holds exactly. */
function isCount(n: unknown): n is number {
  return Number.isSafeInteger(n) && (n as number) >= 0;
}

/** Number of bits required to represent `n` (with `bitsLen(0) === 0`). */
function bitsLen(n: number): number {
  let len = 0;
  let x = n;
  while (x > 0) {
    x = Math.floor(x / 2);
    len++;
  }
  return len;
}

/** Number of set bits in `n`. */
function onesCount(n: number): number {
  let x = n;
  let c = 0;
  while (x > 0) {
    c += x & 1;
    x = Math.floor(x / 2);
  }
  return c;
}

/**
 * Verify an inclusion proof. Returns true iff folding `leafHashHex` with
 * `proof` along the bit-pattern of `idx` reproduces `rootHashHex`.
 * Algorithm: the standard CT (RFC 6962) verifier decomposition into an
 * "inner" segment that walks the bits of `idx` and a "border" segment of
 * left-siblings up the right edge.
 *
 * Returns false, never throws, for malformed input: `idx` and `treeSize`
 * must be safe integers with 0 <= idx < treeSize, and every hash must be
 * 64 lowercase hex digits (32 bytes).
 */
export function verifyInclusionProof(
  leafHashHex: string,
  idx: number,
  treeSize: number,
  proof: readonly string[],
  rootHashHex: string,
): boolean {
  if (!isCount(idx) || !isCount(treeSize)) return false;
  if (idx >= treeSize) return false;
  if (!isHashHex(leafHashHex) || !isHashHex(rootHashHex)) return false;
  if (!Array.isArray(proof) || !proof.every(isHashHex)) return false;
  if (treeSize === 1) {
    return proof.length === 0 && leafHashHex === rootHashHex;
  }
  // BigInt: `^` on numbers truncates to 32 bits, which breaks trees of
  // 2^31 leaves or more.
  const inner = bitsLen(Number(BigInt(idx) ^ BigInt(treeSize - 1)));
  const border = onesCount(Math.floor(idx / Math.pow(2, inner)));
  if (proof.length !== inner + border) return false;

  let hash = leafHashHex;
  for (let i = 0; i < inner; i++) {
    const sib = proof[i];
    if (sib === undefined) return false;
    if (Math.floor(idx / Math.pow(2, i)) % 2 === 0) {
      hash = innerHash(hash, sib);
    } else {
      hash = innerHash(sib, hash);
    }
  }
  for (let i = 0; i < border; i++) {
    const sib = proof[inner + i];
    if (sib === undefined) return false;
    hash = innerHash(sib, hash);
  }
  return hash === rootHashHex;
}

/** Signed Tree Head: the log's commitment to its state at one point. */
export interface SignedTreeHead {
  v: 1;
  logId: string;
  treeSize: number;
  rootHash: string; // hex
  timestamp: string; // ISO 8601
  signature?: string; // v2= wire format
}

/**
 * Canonical byte projection of an STH, used as the signing input: keys
 * sorted, no whitespace, `signature` omitted.
 */
export function canonicalizeSth(sth: Omit<SignedTreeHead, "signature">): string {
  return JSON.stringify({
    logId: sth.logId,
    rootHash: sth.rootHash,
    timestamp: sth.timestamp,
    treeSize: sth.treeSize,
    v: sth.v,
  });
}
