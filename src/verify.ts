// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

/**
 * The checks the action makes, as pure functions over file contents
 * already read into memory. Nothing here reads files, the environment or
 * the network.
 */
import type { PinnedKey } from "./keys.ts";
import {
  SIGNATURE_MISMATCH_REASON,
  verifyV2Receipt,
  type VerifyResult,
} from "./vendor/verifiable-receipts/receipt.ts";
import {
  canonicalizeSth,
  leafHash,
  verifyInclusionProof,
} from "./vendor/verifiable-receipts/transparency.ts";

/** A file the action read: its path as reported, and its text. */
export interface SourceFile {
  file: string;
  content: string;
}

interface LogOptions {
  treeHead: SourceFile;
  keys: readonly PinnedKey[];
  proofs: readonly SourceFile[];
}

export interface VerifyOptions {
  keys: readonly PinnedKey[];
  log?: LogOptions;
  now: Date;
  /** When set, a receipt's signed `issuedAt` must be at most this many days before `now`. */
  maxAgeDays?: number;
}

export interface ReceiptResult {
  file: string;
  /** Position in the file when the file holds an array of receipts; null for a single receipt. */
  index: number | null;
  ok: boolean;
  reason?: string;
  /** Fingerprint of the pinned key the signature verified under. */
  key?: string;
  /** The receipt's leaf index in the log, when inclusion was confirmed. */
  leafIndex?: number;
}

/** A problem with a file that is not a receipt: a tree head or a proof file. */
export interface FileError {
  file: string;
  reason: string;
}

interface TreeHeadInfo {
  file: string;
  logId: string;
  treeSize: number;
  rootHash: string;
  key: string;
}

export interface Report {
  results: ReceiptResult[];
  fileErrors: FileError[];
  treeHead?: TreeHeadInfo;
}

const HEX64 = /^[0-9a-f]{64}$/;
const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const DAY_MS = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function parseJson(content: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(content) as unknown };
  } catch {
    return { ok: false };
  }
}

function parseTime(v: unknown): number | null {
  if (typeof v !== "string" || !ISO_8601.test(v)) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

/**
 * Verifies `signed` (an object with `canonical` and `signature`) under each
 * key and returns the first success. When every key fails, the reason is
 * one where the signature did verify but a later check failed, if there
 * is one, so that a tampered envelope is not reported as a wrong key.
 */
function verifyUnderKeys(
  signed: unknown,
  keys: readonly PinnedKey[],
): VerifyResult & { key?: string } {
  if (isObject(signed) && typeof signed.signature === "string") {
    const prefix = /^(v\d+)=/.exec(signed.signature)?.[1];
    if (prefix !== undefined && prefix !== "v2") {
      return {
        ok: false,
        reason: `unsupported signature algorithm "${prefix}=" (this action verifies v2= Ed25519 signatures only)`,
      };
    }
  }
  let first: VerifyResult | undefined;
  let afterSignature: VerifyResult | undefined;
  for (const k of keys) {
    const r = verifyV2Receipt(signed, k.key);
    if (r.ok) return { ok: true, key: k.fingerprint };
    first ??= r;
    if (r.reason !== SIGNATURE_MISMATCH_REASON) afterSignature ??= r;
  }
  const chosen = afterSignature ?? first ?? { ok: false, reason: "no public key to verify with" };
  if (chosen.reason === SIGNATURE_MISMATCH_REASON && keys.length > 1) {
    return { ok: false, reason: `signature does not verify under any of the ${keys.length} pinned public keys` };
  }
  return chosen;
}

function checkTimes(
  signed: Record<string, unknown>,
  now: Date,
  maxAgeDays: number | undefined,
): string | null {
  const nowMs = now.getTime();
  if (Object.hasOwn(signed, "expiresAt")) {
    const expires = parseTime(signed.expiresAt);
    if (expires === null) return "signed expiresAt is not an ISO 8601 date-time";
    if (nowMs > expires) return `receipt expired at ${String(signed.expiresAt)}`;
  }
  if (maxAgeDays !== undefined) {
    if (!Object.hasOwn(signed, "issuedAt")) return "max-age-days is set and the receipt has no signed issuedAt";
    const issued = parseTime(signed.issuedAt);
    if (issued === null) return "signed issuedAt is not an ISO 8601 date-time";
    if (issued > nowMs + CLOCK_SKEW_MS) return `receipt issuedAt ${String(signed.issuedAt)} is in the future`;
    if (nowMs - issued > maxAgeDays * DAY_MS) {
      return `receipt issued at ${String(signed.issuedAt)} is older than ${maxAgeDays} days`;
    }
  }
  return null;
}

interface Proof {
  file: string;
  leafHashHex: string;
  leafIndex: number;
  treeSize: number;
  auditPath: string[];
}

function isCount(v: unknown, min: number): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= min;
}

function parseProofEntry(v: unknown, file: string): Proof | string {
  if (!isObject(v)) return "an inclusion proof must be an object";
  const { leafHashHex, leafIndex, treeSize, auditPath } = v;
  if (typeof leafHashHex !== "string" || !HEX64.test(leafHashHex)) {
    return "leafHashHex must be 64 lowercase hex characters";
  }
  if (!isCount(leafIndex, 0)) return "leafIndex must be a non-negative integer";
  if (!isCount(treeSize, 1)) return "treeSize must be a positive integer";
  if (!Array.isArray(auditPath) || !auditPath.every((h) => typeof h === "string" && HEX64.test(h))) {
    return "auditPath must be an array of 64-character lowercase hex hashes";
  }
  return { file, leafHashHex, leafIndex, treeSize, auditPath: auditPath as string[] };
}

/** Reads proof files into a map from leaf hash to the proofs offered for it. */
function readProofs(files: readonly SourceFile[], errors: FileError[]): Map<string, Proof[]> {
  const byLeaf = new Map<string, Proof[]>();
  for (const f of files) {
    const parsed = parseJson(f.content);
    if (!parsed.ok) {
      errors.push({ file: f.file, reason: "inclusion proof file is not valid JSON" });
      continue;
    }
    const entries = Array.isArray(parsed.value) ? parsed.value : [parsed.value];
    entries.forEach((entry, i) => {
      const proof = parseProofEntry(entry, f.file);
      if (typeof proof === "string") {
        const where = Array.isArray(parsed.value) ? ` (entry ${i})` : "";
        errors.push({ file: f.file, reason: `${proof}${where}` });
        return;
      }
      const list = byLeaf.get(proof.leafHashHex) ?? [];
      list.push(proof);
      byLeaf.set(proof.leafHashHex, list);
    });
  }
  return byLeaf;
}

interface TrustedTreeHead {
  treeSize: number;
  rootHash: string;
  info: TreeHeadInfo;
}

function readTreeHead(log: LogOptions): TrustedTreeHead | string {
  const parsed = parseJson(log.treeHead.content);
  if (!parsed.ok) return "tree head is not valid JSON";
  const sth = parsed.value;
  if (!isObject(sth)) return "tree head must be a JSON object";
  if (sth.v !== 1) return "tree head v must be 1";
  if (typeof sth.logId !== "string" || sth.logId === "") return "tree head logId must be a non-empty string";
  if (!isCount(sth.treeSize, 1)) return "tree head treeSize must be a positive integer";
  if (typeof sth.rootHash !== "string" || !HEX64.test(sth.rootHash)) {
    return "tree head rootHash must be 64 lowercase hex characters";
  }
  if (typeof sth.timestamp !== "string") return "tree head timestamp must be a string";
  if (typeof sth.signature !== "string" || sth.signature === "") return "tree head has no signature";
  const canonical = canonicalizeSth({
    v: 1,
    logId: sth.logId,
    treeSize: sth.treeSize,
    rootHash: sth.rootHash,
    timestamp: sth.timestamp,
  });
  const r = verifyUnderKeys({ canonical, signature: sth.signature }, log.keys);
  if (!r.ok || r.key === undefined) return `tree head ${r.reason ?? "does not verify"}`;
  return {
    treeSize: sth.treeSize,
    rootHash: sth.rootHash,
    info: {
      file: log.treeHead.file,
      logId: sth.logId,
      treeSize: sth.treeSize,
      rootHash: sth.rootHash,
      key: r.key,
    },
  };
}

function checkInclusion(
  canonical: string,
  head: TrustedTreeHead,
  proofs: Map<string, Proof[]>,
): { ok: true; leafIndex: number } | { ok: false; reason: string } {
  const leaf = leafHash(canonical);
  const offered = proofs.get(leaf);
  if (offered === undefined || offered.length === 0) {
    return { ok: false, reason: `no inclusion proof for leaf ${leaf.slice(0, 16)}… in the inclusion-proofs files` };
  }
  let reason = "";
  for (const p of offered) {
    if (p.treeSize !== head.treeSize) {
      reason ||= `inclusion proof in ${p.file} is for tree size ${p.treeSize}; the tree head has size ${head.treeSize}`;
      continue;
    }
    if (verifyInclusionProof(leaf, p.leafIndex, p.treeSize, p.auditPath, head.rootHash)) {
      return { ok: true, leafIndex: p.leafIndex };
    }
    reason = `inclusion proof in ${p.file} does not lead to the tree head's root`;
  }
  return { ok: false, reason };
}

function verifyOne(
  receipt: unknown,
  options: VerifyOptions,
  head: TrustedTreeHead | string | undefined,
  proofs: Map<string, Proof[]>,
): Omit<ReceiptResult, "file" | "index"> {
  const sig = verifyUnderKeys(receipt, options.keys);
  if (!sig.ok || sig.key === undefined || !isObject(receipt) || typeof receipt.canonical !== "string") {
    return { ok: false, reason: sig.reason ?? "receipt does not verify" };
  }
  const key = sig.key;
  const canonical = receipt.canonical;
  // The vendored verifier has already checked that canonical parses to an object.
  const signed = JSON.parse(canonical) as Record<string, unknown>;
  const timeProblem = checkTimes(signed, options.now, options.maxAgeDays);
  if (timeProblem !== null) return { ok: false, reason: timeProblem, key };
  if (head === undefined) return { ok: true, key };
  if (typeof head === "string") {
    return { ok: false, reason: `inclusion not confirmed: ${head}`, key };
  }
  const inc = checkInclusion(canonical, head, proofs);
  if (!inc.ok) return { ok: false, reason: inc.reason, key };
  return { ok: true, key, leafIndex: inc.leafIndex };
}

/** Verifies every receipt in `files` and returns one result per receipt. */
export function verifyReceipts(files: readonly SourceFile[], options: VerifyOptions): Report {
  const fileErrors: FileError[] = [];
  let head: TrustedTreeHead | string | undefined;
  let proofs = new Map<string, Proof[]>();
  if (options.log !== undefined) {
    head = readTreeHead(options.log);
    if (typeof head === "string") fileErrors.push({ file: options.log.treeHead.file, reason: head });
    proofs = readProofs(options.log.proofs, fileErrors);
  }

  const results: ReceiptResult[] = [];
  for (const f of files) {
    const parsed = parseJson(f.content);
    if (!parsed.ok) {
      results.push({ file: f.file, index: null, ok: false, reason: "file is not valid JSON" });
      continue;
    }
    const value = parsed.value;
    if (Array.isArray(value)) {
      if (value.length === 0) {
        results.push({ file: f.file, index: null, ok: false, reason: "file holds an empty array; expected receipts" });
        continue;
      }
      value.forEach((receipt: unknown, i) => {
        results.push({ file: f.file, index: i, ...verifyOne(receipt, options, head, proofs) });
      });
    } else if (isObject(value)) {
      results.push({ file: f.file, index: null, ...verifyOne(value, options, head, proofs) });
    } else {
      results.push({
        file: f.file,
        index: null,
        ok: false,
        reason: "file must hold a receipt object or an array of receipt objects",
      });
    }
  }
  const report: Report = { results, fileErrors };
  if (head !== undefined && typeof head !== "string") report.treeHead = head.info;
  return report;
}
