// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Runs the verifiable-receipts conformance corpus (copied into
// test/fixtures/conformance, see its README) through the action's checks.
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { readdirSync } from "node:fs";
import { describe, it } from "node:test";

import { KeyError, parsePublicKeys, type PinnedKey } from "../src/keys.ts";
import { verifyEd25519Strict, verifyV2Receipt } from "../src/vendor/verifiable-receipts/receipt.ts";
import { verifyInclusionProof } from "../src/vendor/verifiable-receipts/transparency.ts";
import { verifyReceipts } from "../src/verify.ts";
import { conformanceKey, FIXTURES, readFixture } from "./helpers.ts";

interface Expected {
  ok: boolean;
  reasonContains?: string;
}

const NOW = new Date("2026-10-23T00:00:00Z");
const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json")).sort();

describe("conformance corpus", () => {
  it("holds the 50 fixtures of the source corpus", () => {
    assert.equal(files.length, 50);
  });

  // The v2 receipt fixtures, and the strict Ed25519 vectors of VAOS 2.0
  // §7.3 that come as receipts (ed25519-*.json with a receipt): each
  // through the action's own path, verifyReceipts, under its key.
  const receiptFixtures = files.filter(
    (f) => f.startsWith("v2-") || (f.startsWith("ed25519-") && !("ed25519" in (JSON.parse(readFixture(f)) as object))),
  );

  it("holds 34 receipt fixtures, 17 of them strict Ed25519 vectors", () => {
    assert.equal(receiptFixtures.length, 34);
    assert.equal(receiptFixtures.filter((f) => f.startsWith("ed25519-")).length, 17);
  });

  for (const name of receiptFixtures) {
    it(`receipt ${name}`, () => {
      // A fixture gives the receipt as an object (receipt) or as the text of
      // a receipt file (receiptText), which the action reads as it reads a
      // file. publicKeyPem, when present, is the key to verify with.
      const fixture = JSON.parse(readFixture(name)) as {
        receipt?: unknown;
        receiptText?: string;
        publicKeyPem?: string;
        expected: Expected;
      };
      const content = fixture.receiptText ?? JSON.stringify(fixture.receipt);
      let key: PinnedKey = conformanceKey();
      if (fixture.publicKeyPem !== undefined) {
        const pem = fixture.publicKeyPem;
        try {
          const [parsed] = parsePublicKeys(pem, "publicKeyPem");
          assert.ok(parsed, "publicKeyPem holds no key");
          key = parsed;
        } catch (err) {
          // The action refuses a weak key when it reads its inputs. The
          // verifier is given it directly as well, and refuses it again.
          assert.ok(err instanceof KeyError, String(err));
          assert.equal(fixture.expected.ok, false, err.message);
          if (fixture.expected.reasonContains !== undefined) {
            assert.match(err.message, new RegExp(fixture.expected.reasonContains, "i"));
          }
          key = { key: createPublicKey(pem), fingerprint: "publicKeyPem" };
        }
      }
      const report = verifyReceipts([{ file: name, content }], { keys: [key], now: NOW });
      const [result] = report.results;
      assert.ok(result);
      assert.equal(result.ok, fixture.expected.ok, result.reason);
      if (fixture.expected.reasonContains !== undefined) {
        assert.match(result.reason ?? "", new RegExp(fixture.expected.reasonContains, "i"));
      }

      // The vendored verifier on its own, given the receipt as an object, as
      // the upstream harness runs it. The action counts depth on the text
      // first, so only this path reaches the verifier's own depth checks.
      if (fixture.receipt !== undefined) {
        const direct = verifyV2Receipt(fixture.receipt, key.key);
        assert.equal(direct.ok, fixture.expected.ok, direct.reason);
        if (fixture.expected.reasonContains !== undefined) {
          assert.match(direct.reason ?? "", new RegExp(fixture.expected.reasonContains, "i"));
        }
      }
    });
  }

  // The strict Ed25519 vectors that come as raw bytes (the RFC 8032
  // tests): their messages are not receipts, so they cannot go through
  // verifyReceipts. The key goes through the action's key reader as PEM,
  // and the signature through the vendored verifyEd25519Strict, the same
  // key, R and S checks verifyV2Receipt makes.
  for (const name of files.filter((f) => f.startsWith("ed25519-") && !receiptFixtures.includes(f))) {
    it(`raw Ed25519 vector ${name}`, () => {
      const f = JSON.parse(readFixture(name)) as {
        ed25519: { publicKey: string; message: string; signature: string };
        expected: Expected;
      };
      const raw = Buffer.from(f.ed25519.publicKey, "hex");
      const pem = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" })
        .export({ type: "spki", format: "pem" })
        .toString();
      assert.equal(parsePublicKeys(pem, name).length, 1);
      const result = verifyEd25519Strict(raw, Buffer.from(f.ed25519.message, "hex"), Buffer.from(f.ed25519.signature, "hex"));
      assert.equal(result.ok, f.expected.ok, result.reason);
    });
  }

  for (const name of files.filter((f) => f.startsWith("inclusion-"))) {
    it(`inclusion proof ${name}`, () => {
      const f = JSON.parse(readFixture(name)) as {
        leafHashHex: string;
        leafIndex: number;
        treeSize: number;
        auditPath: string[];
        rootHashHex: string;
        expected: Expected;
      };
      assert.equal(
        verifyInclusionProof(f.leafHashHex, f.leafIndex, f.treeSize, f.auditPath, f.rootHashHex),
        f.expected.ok,
      );
    });
  }

  it("rejects v2-invalid-empty-contenthash.json, whose signature is valid", () => {
    const { receipt } = JSON.parse(readFixture("v2-invalid-empty-contenthash.json")) as {
      receipt: { canonical: string; contentHash: string; signature: string };
    };
    assert.equal(receipt.contentHash, "");
    const key = createPublicKey(readFixture("public-key.pem"));
    const sig = Buffer.from(receipt.signature.slice("v2=".length), "base64");
    assert.equal(verify(null, Buffer.from(receipt.canonical, "utf8"), key, sig), true);

    const report = verifyReceipts([{ file: "empty.json", content: JSON.stringify(receipt) }], {
      keys: [conformanceKey()],
      now: NOW,
    });
    const [result] = report.results;
    assert.ok(result);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? "", /contentHash mismatch/);
  });
});
