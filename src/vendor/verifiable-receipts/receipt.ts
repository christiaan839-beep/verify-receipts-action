// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from verifiable-receipts,
// packages/verifiable-receipts/conformance/verify-v2.mjs at commit
// 03b38ee2d28080a2a4aa0810dbb1dfcd447379fd. Licence:
// third_party/verifiable-receipts/LICENSE.
//
// Changed from the original: converted to TypeScript with explicit types,
// and the signature-mismatch reason exported as SIGNATURE_MISMATCH_REASON.
// No change to the checks, their order or their failure reasons.

/**
 * The v2 (Ed25519) receipt verifier of the verifiable-receipts conformance
 * corpus. It makes these checks, in this order:
 *
 *   1. `canonical` and `signature` are non-empty strings.
 *   2. `signature` is "v2=<base64>" with standard base64.
 *   3. `contentHash`, when present and not null, is a string; when
 *      non-empty, it equals the hex SHA-256 of `canonical`'s UTF-8
 *      bytes ("sha256:" prefix optional).
 *   4. The Ed25519 signature verifies over `canonical`'s UTF-8 bytes,
 *      exactly as given.
 *   5. `canonical` parses as a JSON object.
 *   6. Every other top-level field of the receipt equals the same field
 *      of that object (deep JSON-value equality); a field that
 *      disagrees, or that the canonical lacks, is rejected.
 */
import { createHash, verify as nodeVerify, type KeyObject } from "node:crypto";

const ENVELOPE_ONLY = new Set(["canonical", "contentHash", "signature"]);

const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const SIGNATURE_MISMATCH_REASON = "signature does not verify under the supplied public key";

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Deep JSON-value equality; object key order does not matter. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((x: unknown, i: number) => jsonEqual(x, b[i]))
    );
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return false;
    const ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    return ka.every((k) => Object.hasOwn(b, k) && jsonEqual(a[k], b[k]));
  }
  return a === b; // null, booleans, numbers, strings
}

export function verifyV2Receipt(receipt: unknown, publicKey: KeyObject): VerifyResult {
  if (!isObject(receipt)) return { ok: false, reason: "receipt must be an object" };
  const { canonical, signature, contentHash } = receipt;
  if (typeof canonical !== "string" || canonical === "") {
    return { ok: false, reason: "missing canonical projection" };
  }
  if (typeof signature !== "string" || signature === "") {
    return { ok: false, reason: "missing signature" };
  }
  if (!signature.startsWith("v2=")) {
    return { ok: false, reason: "signature is not v2 (expected 'v2=<base64>')" };
  }
  if (!STANDARD_BASE64.test(signature.slice(3))) {
    return { ok: false, reason: "signature base64 invalid" };
  }
  const sigBytes = Buffer.from(signature.slice(3), "base64");
  // One valid spelling: non-zero padding bits decode to the same bytes.
  if (sigBytes.toString("base64") !== signature.slice(3)) {
    return { ok: false, reason: "signature base64 invalid: not canonical" };
  }
  const canonicalBytes = Buffer.from(canonical, "utf8");

  if (contentHash != null && typeof contentHash !== "string") {
    return { ok: false, reason: "contentHash must be a string" };
  }
  if (contentHash) {
    const actual = createHash("sha256").update(canonicalBytes).digest("hex");
    if (actual !== contentHash.replace(/^sha256:/, "")) {
      return { ok: false, reason: "contentHash mismatch with canonical bytes" };
    }
  }

  let verified: boolean;
  try {
    verified = nodeVerify(null, canonicalBytes, publicKey, sigBytes);
  } catch {
    verified = false;
  }
  if (!verified) {
    return { ok: false, reason: SIGNATURE_MISMATCH_REASON };
  }

  // Only now parse the canonical: these bytes are authenticated.
  let signed: unknown;
  try {
    signed = JSON.parse(canonical);
  } catch {
    return { ok: false, reason: "canonical is not valid JSON" };
  }
  if (!isObject(signed)) {
    return { ok: false, reason: "canonical is not a JSON object" };
  }
  for (const key of Object.keys(receipt).sort()) {
    if (ENVELOPE_ONLY.has(key)) continue;
    if (!Object.hasOwn(signed, key)) {
      return {
        ok: false,
        reason: `envelope field "${key}" is not in the signed canonical`,
      };
    }
    if (!jsonEqual(receipt[key], signed[key])) {
      return {
        ok: false,
        reason: `envelope field "${key}" disagrees with the signed canonical`,
      };
    }
  }
  return { ok: true };
}
