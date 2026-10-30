// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash, createPublicKey } from "node:crypto";
import { describe, it } from "node:test";

import { verifyReceipts, type ReceiptResult, type VerifyOptions } from "../src/verify.ts";
import type { PinnedKey } from "../src/keys.ts";
import {
  arrays,
  buildLog,
  makeKey,
  readFixture,
  rfcLeafHash,
  sampleBody,
  signReceipt,
  signTreeHead,
  type SignedReceipt,
} from "./helpers.ts";

const NOW = new Date("2026-10-23T12:00:00Z");
const issuer = makeKey();
const other = makeKey();
const logKey = makeKey();

function one(content: unknown, options: Partial<VerifyOptions> = {}): ReceiptResult {
  const text = typeof content === "string" ? content : JSON.stringify(content);
  const report = verifyReceipts([{ file: "r.json", content: text }], { keys: [issuer.pinned], now: NOW, ...options });
  assert.equal(report.results.length, 1);
  const [r] = report.results;
  assert.ok(r);
  return r;
}

function rehash(r: SignedReceipt): SignedReceipt {
  const hex = createHash("sha256").update(r.canonical, "utf8").digest("hex");
  return { ...r, contentHash: "sha256:" + hex };
}

describe("valid receipts", () => {
  it("verifies a receipt signed by a pinned key and names the key", () => {
    const r = one(signReceipt(sampleBody(), issuer.privateKey));
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.key, issuer.pinned.fingerprint);
  });

  it("verifies a receipt with only the envelope fields", () => {
    const { canonical, contentHash, signature } = signReceipt(sampleBody(), issuer.privateKey);
    assert.equal(one({ canonical, contentHash, signature }).ok, true);
  });

  it("verifies every receipt in a file holding an array", () => {
    const a = signReceipt(sampleBody({ receiptId: "a" }), issuer.privateKey);
    const b = signReceipt(sampleBody({ receiptId: "b" }), issuer.privateKey);
    const report = verifyReceipts([{ file: "many.json", content: JSON.stringify([a, b]) }], {
      keys: [issuer.pinned],
      now: NOW,
    });
    assert.deepEqual(
      report.results.map((r) => [r.index, r.ok]),
      [
        [0, true],
        [1, true],
      ],
    );
  });

  it("verifies a receipt whose contentHash is null or absent", () => {
    const { canonical, signature } = signReceipt(sampleBody(), issuer.privateKey);
    assert.equal(one({ canonical, contentHash: null, signature }).ok, true);
    assert.equal(one({ canonical, signature }).ok, true);
  });

  it("accepts a receipt signed by any one of several pinned keys", () => {
    const r = one(signReceipt(sampleBody(), issuer.privateKey), { keys: [other.pinned, issuer.pinned] });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.key, issuer.pinned.fingerprint);
  });
});

describe("tampered receipts", () => {
  it("rejects a canonical edited after signing, even with a recomputed contentHash", () => {
    const signed = signReceipt(sampleBody(), issuer.privateKey);
    const forged = rehash({ ...signed, canonical: signed.canonical.replace('"pass"', '"fail"'), overall: "fail" });
    const r = one(forged);
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /signature does not verify/);
  });

  it("rejects an empty contentHash on a correctly signed receipt", () => {
    const signed = signReceipt(sampleBody(), issuer.privateKey);
    const r = one({ ...signed, contentHash: "" });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /contentHash mismatch/);
  });

  it("rejects a canonical edited without updating contentHash", () => {
    const signed = signReceipt(sampleBody(), issuer.privateKey);
    const r = one({ ...signed, canonical: signed.canonical.replace("sample-agent", "other-agent") });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /contentHash mismatch/);
  });

  it("rejects an envelope field that disagrees with the signed canonical", () => {
    const r = one({ ...signReceipt(sampleBody(), issuer.privateKey), overall: "fail" });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /envelope field "overall" disagrees/);
  });

  it("rejects a repeated number of magnitude 2^53 or more, even one that matches", () => {
    // JSON.parse reads 2^53 + 1 as 2^53; the Python and Go verifiers would
    // not, so every verifier rejects such a number instead of comparing it.
    assert.equal(one(signReceipt(sampleBody({ n: 2 ** 53 - 1 }), issuer.privateKey)).ok, true);
    for (const n of [2 ** 53, -(2 ** 53), 1e300]) {
      const r = one(signReceipt(sampleBody({ n }), issuer.privateKey));
      assert.equal(r.ok, false, String(n));
      assert.match(r.reason ?? "", /envelope field "n" disagrees/);
    }
  });

  it("rejects an envelope field the signer never signed", () => {
    const r = one({ ...signReceipt(sampleBody(), issuer.privateKey), approvedBy: "someone" });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /"approvedBy" is not in the signed canonical/);
  });

  it("rejects a flipped signature bit", () => {
    const signed = signReceipt(sampleBody(), issuer.privateKey);
    const sig = Buffer.from(signed.signature.slice(3), "base64");
    sig[0] = (sig[0] ?? 0) ^ 1;
    assert.equal(one({ ...signed, signature: "v2=" + sig.toString("base64") }).ok, false);
  });
});

describe("wrong key", () => {
  it("rejects a receipt signed by a key that is not pinned", () => {
    const r = one(signReceipt(sampleBody(), other.privateKey));
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /signature does not verify under the supplied public key/);
  });

  it("names the number of keys tried when several are pinned", () => {
    const stranger = makeKey();
    const r = one(signReceipt(sampleBody(), stranger.privateKey), { keys: [issuer.pinned, other.pinned] });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /any of the 2 pinned public keys/);
  });

  it("reports the envelope problem, not a key problem, when one key verifies the signature", () => {
    const tampered = { ...signReceipt(sampleBody(), issuer.privateKey), overall: "fail" };
    const r = one(tampered, { keys: [other.pinned, issuer.pinned] });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /envelope field "overall" disagrees/);
  });
});

/** A key the action refuses when it reads its inputs, pinned here directly, as a caller of verifyReceipts could. */
function refusedKey(fixture: string): PinnedKey {
  const { publicKeyPem } = JSON.parse(readFixture(fixture)) as { publicKeyPem: string };
  return { key: createPublicKey(publicKeyPem), fingerprint: `refused:${fixture}` };
}

/** A conformance receipt with its own ordinary key. */
function fixtureReceipt(fixture: string): { receipt: unknown; key: PinnedKey } {
  const { receipt, publicKeyPem } = JSON.parse(readFixture(fixture)) as { receipt: unknown; publicKeyPem: string };
  return { receipt, key: { key: createPublicKey(publicKeyPem), fingerprint: `key:${fixture}` } };
}

describe("signature-level failures under several keys (VAOS 2.0 §7.3)", () => {
  const mixedOrder = refusedKey("ed25519-key-mixed-order-4.json");
  const offCurve = refusedKey("ed25519-key-off-curve.json");

  it("reports the envelope problem, not a refused key, when another key verifies the signature", () => {
    const tampered = { ...signReceipt(sampleBody(), issuer.privateKey), overall: "fail" };
    const r = one(tampered, { keys: [mixedOrder, issuer.pinned] });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /envelope field "overall" disagrees/);
  });

  it("counts a refused key as one that does not verify the signature", () => {
    const stranger = makeKey();
    const r = one(signReceipt(sampleBody(), stranger.privateKey), { keys: [offCurve, other.pinned] });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "signature does not verify under any of the 2 pinned public keys");
  });

  it("names the key's problem when it is the only key", () => {
    const r = one(signReceipt(sampleBody(), other.privateKey), { keys: [mixedOrder] });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "public key is not in the prime-order subgroup");
  });

  it("names the problem with R, which is the same under every key", () => {
    const { receipt, key } = fixtureReceipt("ed25519-r-identity.json");
    const r = one(receipt, { keys: [other.pinned, key, issuer.pinned] });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "signature R is a small-order point");
  });

  it("does not report a problem with R as a check after the signature", () => {
    const { receipt, key } = fixtureReceipt("ed25519-r-mixed-order.json");
    const r = one(receipt, { keys: [mixedOrder, key] });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "signature R is not in the prime-order subgroup");
  });

  it("verifies under the good key when a refused key is pinned beside it", () => {
    const r = one(signReceipt(sampleBody(), issuer.privateKey), { keys: [offCurve, issuer.pinned] });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.key, issuer.pinned.fingerprint);
  });
});

describe("expiry and age", () => {
  it("rejects a receipt whose signed expiresAt has passed", () => {
    const r = one(signReceipt(sampleBody({ expiresAt: "2026-10-22T00:00:00Z" }), issuer.privateKey));
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /expired at 2026-10-22T00:00:00Z/);
  });

  it("accepts a receipt whose signed expiresAt is still ahead", () => {
    assert.equal(one(signReceipt(sampleBody({ expiresAt: "2026-12-01T00:00:00Z" }), issuer.privateKey)).ok, true);
  });

  it("rejects an expiresAt that is not an ISO 8601 date-time", () => {
    const r = one(signReceipt(sampleBody({ expiresAt: "next week" }), issuer.privateKey));
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /expiresAt is not an ISO 8601/);
  });

  it("rejects a receipt older than max-age-days", () => {
    const r = one(signReceipt(sampleBody({ issuedAt: "2026-09-01T00:00:00Z" }), issuer.privateKey), {
      maxAgeDays: 30,
    });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /older than 30 days/);
  });

  it("accepts a receipt within max-age-days", () => {
    const r = one(signReceipt(sampleBody({ issuedAt: "2026-10-20T00:00:00Z" }), issuer.privateKey), {
      maxAgeDays: 30,
    });
    assert.equal(r.ok, true, r.reason);
  });

  it("rejects a receipt issued in the future when max-age-days is set", () => {
    const r = one(signReceipt(sampleBody({ issuedAt: "2027-01-01T00:00:00Z" }), issuer.privateKey), {
      maxAgeDays: 30,
    });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /in the future/);
  });

  it("rejects a receipt without issuedAt when max-age-days is set", () => {
    const body = sampleBody();
    delete body.issuedAt;
    const r = one(signReceipt(body, issuer.privateKey), { maxAgeDays: 30 });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /no signed issuedAt/);
  });

  it("does not trust an unsigned expiresAt beside the envelope", () => {
    // An expiresAt added outside the canonical is an unsigned envelope field.
    const r = one({ ...signReceipt(sampleBody(), issuer.privateKey), expiresAt: "2030-01-01T00:00:00Z" });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /not in the signed canonical/);
  });
});

describe("unknown algorithms", () => {
  for (const prefix of ["v1", "v3", "v9"]) {
    it(`rejects a ${prefix}= signature as unsupported`, () => {
      const signed = signReceipt(sampleBody(), issuer.privateKey);
      const r = one({ ...signed, signature: `${prefix}=${signed.signature.slice(3)}` });
      assert.equal(r.ok, false);
      assert.match(r.reason ?? "", new RegExp(`unsupported signature algorithm "${prefix}="`));
    });
  }

  it("rejects a signature with no version prefix", () => {
    const signed = signReceipt(sampleBody(), issuer.privateKey);
    const r = one({ ...signed, signature: signed.signature.slice(3) });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /signature is not v2/);
  });
});

describe("malformed input", () => {
  const cases: [string, string, RegExp][] = [
    ["not JSON", "{ receipt", /not valid JSON/],
    ["a JSON number", "42", /receipt object or an array/],
    ["a JSON string", '"v2=abc"', /receipt object or an array/],
    ["null", "null", /receipt object or an array/],
    ["an empty array", "[]", /empty array/],
    ["an empty object", "{}", /missing canonical projection/],
    ["no signature", JSON.stringify({ canonical: "{}" }), /missing signature/],
    ["bad base64", JSON.stringify({ canonical: "{}", signature: "v2=***" }), /base64 invalid/],
    ["a numeric contentHash", JSON.stringify({ canonical: "{}", signature: "v2=AAAA", contentHash: 7 }), /contentHash must be a string/],
  ];
  for (const [label, content, reason] of cases) {
    it(`rejects ${label}`, () => {
      const r = one(content);
      assert.equal(r.ok, false);
      assert.match(r.reason ?? "", reason);
    });
  }

  it("rejects a non-object entry in an array and still checks the others", () => {
    const good = signReceipt(sampleBody(), issuer.privateKey);
    const report = verifyReceipts([{ file: "mixed.json", content: JSON.stringify([good, 5]) }], {
      keys: [issuer.pinned],
      now: NOW,
    });
    assert.deepEqual(
      report.results.map((r) => [r.index, r.ok, r.reason]),
      [
        [0, true, undefined],
        [1, false, "receipt must be an object"],
      ],
    );
  });

  it("rejects a signed canonical that is a JSON array", () => {
    const signed = signReceipt(sampleBody(), issuer.privateKey);
    const forged = rehash({ ...signed, canonical: "[1]" });
    // The signature no longer covers the bytes, so this fails at the signature.
    assert.equal(one({ canonical: forged.canonical, contentHash: forged.contentHash, signature: forged.signature }).ok, false);
  });
});

describe("inclusion in the transparency log", () => {
  const a = signReceipt(sampleBody({ receiptId: "a" }), issuer.privateKey);
  const b = signReceipt(sampleBody({ receiptId: "b" }), issuer.privateKey);
  const c = signReceipt(sampleBody({ receiptId: "c" }), issuer.privateKey);
  const extra = [rfcLeafHash("x"), rfcLeafHash("y"), rfcLeafHash("z"), rfcLeafHash("w")];
  const log = buildLog([a, b, c], logKey.privateKey, extra); // seven leaves: an unbalanced tree

  function withLog(
    receipts: unknown[],
    treeHead: unknown = log.treeHead,
    proofs: unknown = log.proofs,
    keys = [logKey.pinned],
  ) {
    return verifyReceipts(
      receipts.map((r, i) => ({ file: `r${i}.json`, content: JSON.stringify(r) })),
      {
        keys: [issuer.pinned],
        now: NOW,
        log: {
          treeHead: { file: "sth.json", content: JSON.stringify(treeHead) },
          keys,
          proofs: [{ file: "proofs.json", content: JSON.stringify(proofs) }],
        },
      },
    );
  }

  it("confirms each receipt's inclusion and reports its leaf index", () => {
    const report = withLog([a, b, c]);
    assert.deepEqual(report.fileErrors, []);
    assert.deepEqual(
      report.results.map((r) => [r.ok, r.leafIndex]),
      [
        [true, 0],
        [true, 1],
        [true, 2],
      ],
    );
    assert.equal(report.treeHead?.treeSize, 7);
    assert.equal(report.treeHead.key, logKey.pinned.fingerprint);
  });

  it("fails a validly signed receipt that has no inclusion proof", () => {
    const d = signReceipt(sampleBody({ receiptId: "d" }), issuer.privateKey);
    const [r] = withLog([d]).results;
    assert.equal(r?.ok, false);
    assert.match(r.reason ?? "", /no inclusion proof for leaf/);
    assert.equal(r.key, issuer.pinned.fingerprint);
  });

  it("fails when the audit path is altered", () => {
    const proofs = log.proofs.map((p) => ({ ...p, auditPath: [...(p.auditPath as string[])].reverse() }));
    const [r] = withLog([a], log.treeHead, proofs).results;
    assert.equal(r?.ok, false);
    assert.match(r.reason ?? "", /does not lead to the tree head's root/);
  });

  it("fails when the proof claims another leaf index", () => {
    const proofs = [{ ...log.proofs[0], leafIndex: 1 }];
    assert.equal(withLog([a], log.treeHead, proofs).results[0]?.ok, false);
  });

  it("fails when the proof is for another tree size", () => {
    const proofs = [{ ...log.proofs[0], treeSize: 8 }];
    const [r] = withLog([a], log.treeHead, proofs).results;
    assert.equal(r?.ok, false);
    assert.match(r.reason ?? "", /tree size 8; the tree head has size 7/);
  });

  it("fails every receipt when the tree head's root was changed after signing", () => {
    const head = { ...log.treeHead, rootHash: "0".repeat(64) };
    const report = withLog([a, b], head);
    assert.ok(report.results.every((r) => !r.ok && (r.reason ?? "").includes("inclusion not confirmed: tree head signature")));
    assert.deepEqual(report.fileErrors.map((e) => e.file), ["sth.json"]);
  });

  it("fails when the tree head is signed by a key that is not pinned for the log", () => {
    const report = withLog([a], log.treeHead, log.proofs, [other.pinned]);
    assert.equal(report.results[0]?.ok, false);
    assert.match(report.fileErrors[0]?.reason ?? "", /signature does not verify/);
  });

  it("does not accept the receipt issuer's key for the tree head unless pinned for the log", () => {
    const head = signTreeHead({ ...log.treeHead }, issuer.privateKey);
    assert.equal(withLog([a], head).results[0]?.ok, false);
  });

  it("rejects a tree head with an unknown signature algorithm", () => {
    const head = { ...log.treeHead, signature: "v3=" + (log.treeHead.signature ?? "").slice(3) };
    const report = withLog([a], head);
    assert.match(report.fileErrors[0]?.reason ?? "", /unsupported signature algorithm "v3="/);
  });

  const badHeads: [string, unknown, RegExp][] = [
    ["is not an object", [1], /must be a JSON object/],
    ["has v 2", { ...log.treeHead, v: 2 }, /v must be 1/],
    ["has no logId", { ...log.treeHead, logId: "" }, /logId/],
    ["has a fractional treeSize", { ...log.treeHead, treeSize: 1.5 }, /treeSize/],
    ["has an upper-case root", { ...log.treeHead, rootHash: log.treeHead.rootHash.toUpperCase() }, /rootHash/],
    ["has no signature", { ...log.treeHead, signature: undefined }, /no signature/],
  ];
  for (const [label, head, reason] of badHeads) {
    it(`rejects a tree head that ${label}`, () => {
      const report = withLog([a], head);
      assert.equal(report.results[0]?.ok, false);
      assert.match(report.fileErrors[0]?.reason ?? "", reason);
    });
  }

  it("rejects a tree head file that is not JSON", () => {
    const report = verifyReceipts([{ file: "r.json", content: JSON.stringify(a) }], {
      keys: [issuer.pinned],
      now: NOW,
      log: { treeHead: { file: "sth.json", content: "nope" }, keys: [logKey.pinned], proofs: [] },
    });
    assert.match(report.fileErrors[0]?.reason ?? "", /not valid JSON/);
    assert.equal(report.results[0]?.ok, false);
  });

  it("refuses a tree head file nested 65 deep, counted on its text", () => {
    const deep = JSON.stringify(arrays(64));
    for (const content of [
      JSON.stringify({ ...log.treeHead, x: arrays(64) }),
      `${JSON.stringify(log.treeHead).slice(0, -1)},"logId":${deep},"logId":${JSON.stringify(log.treeHead.logId)}}`,
    ]) {
      const report = verifyReceipts([{ file: "r.json", content: JSON.stringify(a) }], {
        keys: [issuer.pinned],
        now: NOW,
        log: { treeHead: { file: "sth.json", content }, keys: [logKey.pinned], proofs: [] },
      });
      assert.deepEqual(report.fileErrors, [{ file: "sth.json", reason: "tree head nesting deeper than 64" }]);
      assert.equal(report.treeHead, undefined);
      assert.equal(report.results[0]?.ok, false);
    }
  });

  it("refuses an inclusion proof file nested 65 deep, counted on its text", () => {
    const deep = JSON.stringify(arrays(64));
    const proof = log.proofs[0] ?? {};
    for (const content of [
      JSON.stringify({ ...proof, x: arrays(64) }),
      `${JSON.stringify(proof).slice(0, -1)},"auditPath":${deep},"auditPath":${JSON.stringify(proof.auditPath)}}`,
    ]) {
      const report = verifyReceipts([{ file: "r.json", content: JSON.stringify(a) }], {
        keys: [issuer.pinned],
        now: NOW,
        log: {
          treeHead: { file: "sth.json", content: JSON.stringify(log.treeHead) },
          keys: [logKey.pinned],
          proofs: [{ file: "p.json", content }],
        },
      });
      assert.deepEqual(report.fileErrors, [{ file: "p.json", reason: "inclusion proof file nesting deeper than 64" }]);
      const [r] = report.results;
      assert.ok(r);
      assert.equal(r.ok, false);
      assert.match(r.reason ?? "", /no inclusion proof/);
    }
  });

  it("counts a proof file holding an array from inside the array", () => {
    const at = { ...log.proofs[0], x: arrays(63) };
    const over = { ...log.proofs[0], x: arrays(64) };
    const run = (proofs: unknown[]) =>
      verifyReceipts([{ file: "r.json", content: JSON.stringify(a) }], {
        keys: [issuer.pinned],
        now: NOW,
        log: {
          treeHead: { file: "sth.json", content: JSON.stringify(log.treeHead) },
          keys: [logKey.pinned],
          proofs: [{ file: "p.json", content: ` \n${JSON.stringify(proofs)}` }],
        },
      });
    const fine = run([at]);
    assert.deepEqual(fine.fileErrors, []);
    assert.equal(fine.results[0]?.ok, true, fine.results[0]?.reason);
    assert.deepEqual(run([at, over]).fileErrors, [
      { file: "p.json", reason: "inclusion proof file nesting deeper than 64" },
    ]);
  });

  it("accepts tree head and proof files nested 64 deep", () => {
    const report = verifyReceipts([{ file: "r.json", content: JSON.stringify(a) }], {
      keys: [issuer.pinned],
      now: NOW,
      log: {
        treeHead: { file: "sth.json", content: JSON.stringify({ ...log.treeHead, x: arrays(63) }) },
        keys: [logKey.pinned],
        proofs: [{ file: "p.json", content: JSON.stringify({ ...log.proofs[0], x: arrays(63) }) }],
      },
    });
    assert.deepEqual(report.fileErrors, []);
    assert.equal(report.results[0]?.ok, true, report.results[0]?.reason);
  });

  it("reports malformed proof entries and ignores them", () => {
    const proofs = [{ leafHashHex: "xyz", leafIndex: 0, treeSize: 7, auditPath: [] }, log.proofs[1]];
    const report = withLog([a, b], log.treeHead, proofs);
    assert.match(report.fileErrors[0]?.reason ?? "", /leafHashHex must be 64 lowercase hex characters \(entry 0\)/);
    assert.deepEqual(
      report.results.map((r) => r.ok),
      [false, true],
    );
  });

  const badProofs: [string, Record<string, unknown>, RegExp][] = [
    ["a negative leafIndex", { leafIndex: -1 }, /leafIndex/],
    ["a zero treeSize", { treeSize: 0 }, /treeSize/],
    ["a non-hex audit path entry", { auditPath: ["zz"] }, /auditPath/],
  ];
  for (const [label, change, reason] of badProofs) {
    it(`rejects a proof with ${label}`, () => {
      const report = withLog([a], log.treeHead, { ...log.proofs[0], ...change });
      assert.match(report.fileErrors[0]?.reason ?? "", reason);
      assert.equal(report.results[0]?.ok, false);
    });
  }

  it("does not check inclusion for a receipt whose signature fails", () => {
    const [r] = withLog([{ ...a, overall: "fail" }]).results;
    assert.equal(r?.ok, false);
    assert.match(r.reason ?? "", /envelope field/);
  });
});

describe("nesting depth", () => {
  it("reports a receipt file that is not JSON as \"receipt is not valid JSON\"", () => {
    assert.equal(one("{ receipt").reason, "receipt is not valid JSON");
    assert.equal(one("[1,").reason, "receipt is not valid JSON");
  });

  it("verifies a receipt that nests exactly 64 deep", () => {
    const r = one(signReceipt(sampleBody({ deep: arrays(63) }), issuer.privateKey));
    assert.equal(r.ok, true, r.reason);
  });

  it("refuses a signed receipt that nests 65 deep", () => {
    const r = one(signReceipt(sampleBody({ deep: arrays(64) }), issuer.privateKey));
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /receipt nesting deeper than 64/);
  });

  it("refuses a signed canonical that nests 65 deep, counted on its text", () => {
    const { canonical, contentHash, signature } = signReceipt(sampleBody({ deep: arrays(64) }), issuer.privateKey);
    const r = one({ canonical, contentHash, signature });
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /canonical nesting deeper than 64/);
  });

  it("refuses a receipt file whose duplicate key hides nesting 65 deep", () => {
    const text = JSON.stringify(signReceipt(sampleBody(), issuer.privateKey));
    const deep = JSON.stringify(arrays(64));
    const content = `${text.slice(0, -1)},"overall":${deep},"overall":"pass"}`;
    assert.equal((JSON.parse(content) as { overall: unknown }).overall, "pass");
    const r = one(content);
    assert.equal(r.ok, false);
    assert.match(r.reason ?? "", /receipt nesting deeper than 64/);
  });

  it("counts an array file's entries from their own level", () => {
    const at = signReceipt(sampleBody({ deep: arrays(63) }), issuer.privateKey);
    const fine = verifyReceipts([{ file: "a.json", content: JSON.stringify([at, at]) }], { keys: [issuer.pinned], now: NOW });
    assert.deepEqual(fine.results.map((r) => r.ok), [true, true]);

    const over = signReceipt(sampleBody({ deep: arrays(64) }), issuer.privateKey);
    const report = verifyReceipts([{ file: "a.json", content: JSON.stringify([at, over]) }], { keys: [issuer.pinned], now: NOW });
    assert.equal(report.results.some((r) => r.ok), false);
    assert.match(report.results[0]?.reason ?? "", /receipt nesting deeper than 64/);
  });

  it("refuses an array file whose duplicate key hides nesting 65 deep", () => {
    const text = JSON.stringify(signReceipt(sampleBody(), issuer.privateKey));
    const content = `[${text.slice(0, -1)},"overall":${JSON.stringify(arrays(64))},"overall":"pass"}]`;
    const report = verifyReceipts([{ file: "a.json", content }], { keys: [issuer.pinned], now: NOW });
    assert.equal(report.results.some((r) => r.ok), false);
    assert.match(report.results[0]?.reason ?? "", /receipt nesting deeper than 64/);
  });
});
