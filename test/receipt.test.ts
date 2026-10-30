// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the vendored verifier's own defences, which the action's
// text-first depth counting would otherwise keep every input away from.
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, it } from "node:test";

import {
  ed25519KeyProblem,
  jsonEqual,
  SIGNATURE_MISMATCH_REASON,
  verifyEd25519Strict,
} from "../src/vendor/verifiable-receipts/receipt.ts";
import { arrays, readFixture } from "./helpers.ts";

/** `n` objects, each holding the next under "k": objects(1) is {}. */
function objects(n: number): Record<string, unknown> {
  let v: Record<string, unknown> = {};
  for (let i = 1; i < n; i++) v = { k: v };
  return v;
}

describe("jsonEqual depth bound", () => {
  it("equates arrays nested 64 deep", () => {
    assert.equal(jsonEqual(arrays(64), arrays(64)), true);
  });

  it("equates nothing in arrays nested 65 deep", () => {
    assert.equal(jsonEqual(arrays(65), arrays(65)), false);
  });

  it("equates objects nested 64 deep", () => {
    assert.equal(jsonEqual(objects(64), objects(64)), true);
  });

  it("equates nothing in objects nested 65 deep", () => {
    assert.equal(jsonEqual(objects(65), objects(65)), false);
  });

  it("counts from the depth it is given", () => {
    assert.equal(jsonEqual(arrays(2), arrays(2), 63), true);
    assert.equal(jsonEqual(arrays(2), arrays(2), 64), false);
  });
});

/** A strict Ed25519 vector given as a receipt, as raw key, message and signature bytes. */
function rawVector(fixture: string): { key: Buffer; message: Buffer; signature: Buffer } {
  const { publicKeyPem, receipt } = JSON.parse(readFixture(fixture)) as {
    publicKeyPem: string;
    receipt: { canonical: string; signature: string };
  };
  const { x } = createPublicKey(publicKeyPem).export({ format: "jwk" });
  assert.ok(typeof x === "string");
  return {
    key: Buffer.from(x, "base64url"),
    message: Buffer.from(receipt.canonical, "utf8"),
    signature: Buffer.from(receipt.signature.slice("v2=".length), "base64"),
  };
}

describe("verifyEd25519Strict (VAOS 2.0 §7.3)", () => {
  const honest = rawVector("ed25519-honest.json");

  it("verifies an honest signature", () => {
    assert.deepEqual(verifyEd25519Strict(honest.key, honest.message, honest.signature), { ok: true });
  });

  it("refuses an argument that is not bytes, without throwing", () => {
    const refused = { ok: false, reason: SIGNATURE_MISMATCH_REASON };
    assert.deepEqual(verifyEd25519Strict("key", honest.message, honest.signature), refused);
    assert.deepEqual(verifyEd25519Strict(honest.key, "message", honest.signature), refused);
    assert.deepEqual(verifyEd25519Strict(honest.key, honest.message, null), refused);
  });

  it("refuses a key that is not 32 bytes", () => {
    const result = verifyEd25519Strict(honest.key.subarray(0, 31), honest.message, honest.signature);
    assert.deepEqual(result, { ok: false, reason: "public key is not 32 bytes" });
  });

  it("refuses a signature that is not 64 bytes, or that does not verify", () => {
    for (const [message, signature] of [
      [honest.message, honest.signature.subarray(0, 63)],
      [Buffer.from("another message"), honest.signature],
    ]) {
      const result = verifyEd25519Strict(honest.key, message, signature);
      assert.deepEqual(result, { ok: false, reason: SIGNATURE_MISMATCH_REASON });
    }
  });

  for (const [fixture, reason] of [
    ["ed25519-key-mixed-order-4.json", "public key is not in the prime-order subgroup"],
    ["ed25519-key-identity-sign-bit.json", "public key is a small-order point"],
    ["ed25519-r-identity.json", "signature R is a small-order point"],
    ["ed25519-r-noncanonical.json", "signature R is not a canonical encoding"],
    ["ed25519-r-off-curve.json", "signature R is not a point on the curve"],
    ["ed25519-s-plus-l.json", SIGNATURE_MISMATCH_REASON],
  ] as const) {
    it(`refuses ${fixture} with "${reason}"`, () => {
      const v = rawVector(fixture);
      assert.deepEqual(verifyEd25519Strict(v.key, v.message, v.signature), { ok: false, reason });
    });
  }

  it("gives each key the same answer after more keys than its cache holds", () => {
    const weak = rawVector("ed25519-key-mixed-order-8.json").key;
    const before = verifyEd25519Strict(weak, honest.message, honest.signature);
    for (let i = 0; i < 300; i++) verifyEd25519Strict(randomBytes(32), honest.message, honest.signature);
    assert.deepEqual(verifyEd25519Strict(weak, honest.message, honest.signature), before);
    assert.deepEqual(verifyEd25519Strict(honest.key, honest.message, honest.signature), { ok: true });
  });
});

describe("ed25519KeyProblem", () => {
  it("leaves a key that is not Ed25519 to the signature check", () => {
    const { publicKey } = generateKeyPairSync("x25519");
    assert.equal(ed25519KeyProblem(publicKey), null);
  });
});
