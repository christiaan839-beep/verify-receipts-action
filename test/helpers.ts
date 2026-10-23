// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

/**
 * Test helpers. Keys are made at run time and never written to the
 * repository. The signer and the Merkle tree builder here are written
 * independently of the vendored verifier, from SPEC.md and RFC 6962, so
 * the tests do not check the verifier against itself.
 */
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parsePublicKeys, type PinnedKey } from "../src/keys.ts";

export const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "conformance");

export function readFixture(name: string): string {
  return readFileSync(join(FIXTURES, name), "utf8");
}

export interface TestKey {
  privateKey: KeyObject;
  pem: string;
  pinned: PinnedKey;
}

export function makeKey(): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const [pinned] = parsePublicKeys(pem, "test key");
  if (pinned === undefined) throw new Error("test key did not parse");
  return { privateKey, pem, pinned };
}

export function conformanceKey(): PinnedKey {
  const [k] = parsePublicKeys(readFixture("public-key.pem"), "conformance key");
  if (k === undefined) throw new Error("conformance key did not parse");
  return k;
}

function sortKeysDeep(v: unknown): unknown {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  const out: Record<string, unknown> = {};
  const obj = v as Record<string, unknown>;
  for (const k of Object.keys(obj).sort()) out[k] = sortKeysDeep(obj[k]);
  return out;
}

export interface SignedReceipt {
  canonical: string;
  contentHash: string;
  signature: string;
  [field: string]: unknown;
}

/** Signs `body` per SPEC.md §2 and §3 and returns the receipt with the body fields beside the envelope. */
export function signReceipt(body: Record<string, unknown>, privateKey: KeyObject): SignedReceipt {
  const canonical = JSON.stringify(sortKeysDeep(body));
  const bytes = Buffer.from(canonical, "utf8");
  return {
    ...body,
    canonical,
    contentHash: "sha256:" + createHash("sha256").update(bytes).digest("hex"),
    signature: "v2=" + sign(null, bytes, privateKey).toString("base64"),
  };
}

export function sampleBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    receiptId: "rcpt_sample_001",
    agentSlug: "sample-agent",
    issuedAt: "2026-10-01T09:00:00Z",
    overall: "pass",
    rules: [{ ruleId: "sample-rule", verdict: "pass" }],
    ...overrides,
  };
}

// RFC 6962 §2.1 Merkle tree hash and audit path, written from the RFC.

export function rfcLeafHash(data: string): string {
  return createHash("sha256").update(Buffer.from([0])).update(data, "utf8").digest("hex");
}

function node(left: string, right: string): string {
  return createHash("sha256")
    .update(Buffer.from([1]))
    .update(Buffer.from(left, "hex"))
    .update(Buffer.from(right, "hex"))
    .digest("hex");
}

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function mth(leaves: readonly string[]): string {
  if (leaves.length === 0) return createHash("sha256").digest("hex");
  if (leaves.length === 1) return leaves[0] ?? "";
  const k = split(leaves.length);
  return node(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

export function auditPath(m: number, leaves: readonly string[]): string[] {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  if (m < k) return [...auditPath(m, leaves.slice(0, k)), mth(leaves.slice(k))];
  return [...auditPath(m - k, leaves.slice(k)), mth(leaves.slice(0, k))];
}

export interface TreeHead {
  v: number;
  logId: string;
  treeSize: number;
  rootHash: string;
  timestamp: string;
  signature?: string;
}

/** Signs a tree head over its canonical projection (transparency-log.md §3.3). */
export function signTreeHead(head: Omit<TreeHead, "signature">, privateKey: KeyObject): TreeHead {
  const canonical = JSON.stringify({
    logId: head.logId,
    rootHash: head.rootHash,
    timestamp: head.timestamp,
    treeSize: head.treeSize,
    v: head.v,
  });
  return { ...head, signature: "v2=" + sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64") };
}

/** A log holding `receipts` (and `extraLeaves` after them), its signed tree head and one proof per receipt. */
export function buildLog(
  receipts: readonly SignedReceipt[],
  logKey: KeyObject,
  extraLeaves: readonly string[] = [],
  logId = "test-log",
): { treeHead: TreeHead; proofs: Record<string, unknown>[]; leaves: string[] } {
  const leaves = [...receipts.map((r) => rfcLeafHash(r.canonical)), ...extraLeaves];
  const treeHead = signTreeHead(
    { v: 1, logId, treeSize: leaves.length, rootHash: mth(leaves), timestamp: "2026-10-02T00:00:00Z" },
    logKey,
  );
  const proofs = receipts.map((_, i) => ({
    leafHashHex: leaves[i],
    leafIndex: i,
    treeSize: leaves.length,
    auditPath: auditPath(i, leaves),
  }));
  return { treeHead, proofs, leaves };
}
