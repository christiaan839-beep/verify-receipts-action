// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Property tests (fast-check) for the receipt check and the vendored
// inclusion-proof verifier: they never throw, they accept only the exact
// signed bytes and the one valid spelling of each hash and signature.
// FC_NUM_RUNS raises the number of cases per property (default 200).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import fc from "fast-check";

import { innerHash, leafHash, verifyInclusionProof } from "../src/vendor/verifiable-receipts/transparency.ts";
import { verifyReceipts } from "../src/verify.ts";
import { makeKey, sampleBody, signReceipt } from "./helpers.ts";

const NUM_RUNS = Number(process.env.FC_NUM_RUNS ?? "200");
fc.configureGlobal({ numRuns: Number.isSafeInteger(NUM_RUNS) && NUM_RUNS > 0 ? NUM_RUNS : 200 });

const NOW = new Date("2026-10-23T00:00:00Z");
const issuer = makeKey();

/** True iff the file yields at least one receipt and every receipt in it verifies. */
function check(content: string): { ok: boolean } {
  const report = verifyReceipts([{ file: "r.json", content }], { keys: [issuer.pinned], now: NOW });
  return { ok: report.results.length > 0 && report.results.every((r) => r.ok) };
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

describe("receipts", () => {
  it("never throws, whatever the file holds", () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.json(), fc.jsonValue().map((v) => JSON.stringify(v))), (content) => {
        const r = check(content);
        assert.equal(typeof r.ok, "boolean");
      }),
    );
  });

  it("accepts a receipt signed by the pinned key, and rejects it when one character changes", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 40 }),
        fc.constantFrom("canonical", "signature"),
        fc.nat(),
        fc.integer({ min: 1, max: 0xffff }),
        (receiptId, field, pos, delta) => {
          const signed = signReceipt(sampleBody({ receiptId }), issuer.privateKey);
          assert.equal(check(JSON.stringify(signed)).ok, true);
          const text = signed[field];
          const i = (field === "signature" ? 3 : 0) + (pos % (text.length - (field === "signature" ? 3 : 0)));
          const changed = text.slice(0, i) + String.fromCharCode((text.charCodeAt(i) + delta) % 0x10000) + text.slice(i + 1);
          fc.pre(changed !== text);
          let receipt = { ...signed, [field]: changed };
          if (field === "canonical") {
            receipt = { ...receipt, contentHash: "sha256:" + createHash("sha256").update(changed, "utf8").digest("hex") };
          }
          assert.equal(check(JSON.stringify(receipt)).ok, false);
        },
      ),
    );
  });

  it("rejects every other spelling of a valid signature", () => {
    fc.assert(
      fc.property(fc.nat(), fc.constantFrom("\n", "\r", " ", "\t", "=", "A"), fc.integer({ min: 1, max: 15 }), (pos, insert, bits) => {
        const signed = signReceipt(sampleBody(), issuer.privateKey);
        const b64 = signed.signature.slice(3);
        const last = B64.indexOf(b64.charAt(b64.length - 3));
        const spellings = [
          `v2=${b64.slice(0, pos % b64.length)}${insert}${b64.slice(pos % b64.length)}`,
          `v2=${b64.slice(0, -3)}${B64.charAt(last ^ bits)}==`,
          `v2=${b64.replace(/=+$/, "")}`,
          `v2=${b64.replaceAll("+", "-").replaceAll("/", "_")}`,
          `V2=${b64}`,
        ];
        for (const s of spellings) {
          if (s === signed.signature) continue;
          assert.equal(check(JSON.stringify({ ...signed, signature: s })).ok, false, s);
        }
      }),
    );
  });
});

const hex32 = fc.uint8Array({ minLength: 32, maxLength: 32 }).map((b) => Buffer.from(b).toString("hex"));
const count = fc.oneof(
  fc.integer({ min: -2, max: 70 }),
  fc.integer(),
  fc.double(),
  fc.constantFrom(2 ** 31, 2 ** 32 + 2, 2 ** 53, Number.MAX_SAFE_INTEGER),
);

function auditPath(m: number, leaves: string[]): string[] {
  if (leaves.length <= 1) return [];
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return m < k
    ? [...auditPath(m, leaves.slice(0, k)), root(leaves.slice(k))]
    : [...auditPath(m - k, leaves.slice(k)), root(leaves.slice(0, k))];
}

function root(leaves: string[]): string {
  const [only] = leaves;
  if (leaves.length === 1 && only !== undefined) return only;
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return innerHash(root(leaves.slice(0, k)), root(leaves.slice(k)));
}

describe("inclusion proofs", () => {
  it("never throw, and accept only lowercase 64-digit hashes and safe-integer indexes", () => {
    fc.assert(
      fc.property(
        fc.oneof(hex32, fc.string()),
        count,
        count,
        fc.array(fc.oneof(hex32, fc.string()), { maxLength: 40 }),
        fc.oneof(hex32, fc.string()),
        (leaf, idx, size, path, rootHash) => {
          const ok = verifyInclusionProof(leaf, idx, size, path, rootHash);
          assert.equal(typeof ok, "boolean");
          if (ok) {
            assert.ok(Number.isSafeInteger(idx) && Number.isSafeInteger(size));
            for (const h of [leaf, rootHash, ...path]) assert.match(h, /^[0-9a-f]{64}$/);
          }
        },
      ),
    );
  });

  it("verify a real proof, and reject a wrong root, a changed entry or another spelling", () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 40 }), fc.nat(), fc.string(), hex32, fc.nat(), (n, pick, salt, wrong, entry) => {
        const leaves = Array.from({ length: n }, (_, i) => leafHash(`${salt}:${i}`));
        const idx = pick % n;
        const path = auditPath(idx, leaves);
        const r = root(leaves);
        const leaf = leaves[idx];
        if (leaf === undefined) throw new Error("index out of range");
        assert.equal(verifyInclusionProof(leaf, idx, n, path, r), true);
        if (wrong !== r) assert.equal(verifyInclusionProof(leaf, idx, n, path, wrong), false);
        assert.equal(verifyInclusionProof(leaf.toUpperCase(), idx, n, path, r), leaf === leaf.toUpperCase());
        if (path.length > 0) {
          const i = entry % path.length;
          const changed = path.map((h, j) => (j === i ? (h.startsWith("0") ? "1" : "0") + h.slice(1) : h));
          assert.equal(verifyInclusionProof(leaf, idx, n, changed, r), false);
        }
      }),
    );
  });
});
