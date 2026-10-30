// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from verifiable-receipts,
// packages/verifiable-receipts/tests/edwards25519.test.ts at commit
// 4d9943a99376527f742dcfdf93652ed040a51b43. Licence:
// third_party/verifiable-receipts/LICENSE.
//
// Changed from the original: node:test and node:assert instead of vitest;
// the import path; point() throws the problem without `?? ""`, which
// decode's type makes unnecessary. The cases are the original's.

/**
 * The pure edwards25519 arithmetic behind the strict Ed25519 checks of
 * VAOS 2.0 section 7.3: its constants against RFC 8032, decoding and
 * encoding, and the order of points.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import {
  BASE,
  BASE_Y,
  D,
  L,
  NOT_CANONICAL,
  NOT_IN_SUBGROUP,
  NOT_ON_CURVE,
  P,
  SMALL_ORDER,
  SQRT_M1,
  decode,
  encode,
  hasSmallOrder,
  inPrimeOrderSubgroup,
  isIdentity,
  isOnCurve,
  pointAdd,
  pointProblem,
  pointsEqual,
  scalarMult,
  type Point,
} from "../src/vendor/verifiable-receipts/edwards25519.ts";

const BASE_HEX = "5866666666666666666666666666666666666666666666666666666666666666";
const T8_HEX = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
// The encodings of the points of small order (sign bit clear), with their order.
const TORSION: [string, number][] = [
  ["0100000000000000000000000000000000000000000000000000000000000000", 1],
  ["ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 2],
  ["0000000000000000000000000000000000000000000000000000000000000000", 4],
  ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 8],
  [T8_HEX, 8],
];

const mod = (a: bigint) => ((a % P) + P) % P;
const inv = (a: bigint) => {
  let r = 1n;
  let b = mod(a);
  for (let e = P - 2n; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
};
const fromY = (y: bigint, sign = 0n) =>
  Buffer.from((y | (sign << 255n)).toString(16).padStart(64, "0"), "hex").reverse();
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const point = (h: string): Point => {
  const [p, problem] = decode(Buffer.from(h, "hex"));
  if (p === null) throw new Error(problem);
  return p;
};
function order(p: Point): number {
  for (const n of [1, 2, 4, 8]) if (isIdentity(scalarMult(BigInt(n), p))) return n;
  throw new Error("not of small order");
}
/** A deterministic scalar stream for the round trips. */
function* scalars(seed: string, count: number) {
  for (let i = 0; i < count; i++) {
    const h = createHash("sha512").update(`${seed} ${i}`).digest("hex");
    yield (BigInt("0x" + h) % (L - 1n)) + 1n;
  }
}

describe("edwards25519 constants", () => {
  it("match RFC 8032", () => {
    assert.equal(P, 2n ** 255n - 19n);
    assert.equal(L, 2n ** 252n + 27742317777372353535851937790883648493n);
    assert.equal(L, 7237005577332262213973186563042994240857116359379907606001950938285454250989n);
    assert.equal(D, mod(-121665n * inv(121666n)));
    assert.equal(D, 37095705934669439343138083508754565189542113879843219016388785533085940283555n);
    assert.equal((SQRT_M1 * SQRT_M1) % P, P - 1n);
    assert.equal(BASE_Y, (4n * inv(5n)) % P);
    assert.equal(hex(encode(BASE)), BASE_HEX);
  });

  it("give a base point of order L", () => {
    assert.equal(isOnCurve(BASE), true);
    assert.equal(isIdentity(BASE), false);
    assert.equal(isIdentity(scalarMult(L, BASE)), true);
    assert.equal(isIdentity(scalarMult(L - 1n, BASE)), false);
    assert.equal(hex(encode(scalarMult(L + 1n, BASE))), BASE_HEX);
  });

  it("derive RFC 8032 TEST 1's public key", () => {
    const secret = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
    const h = createHash("sha512").update(secret).digest();
    let a = BigInt("0x" + Buffer.from(h.subarray(0, 32)).reverse().toString("hex"));
    a &= (1n << 254n) - 8n;
    a |= 1n << 254n;
    assert.equal(
      hex(encode(scalarMult(a, BASE))),
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
  });
});

describe("edwards25519 points", () => {
  for (const [h, n] of TORSION) {
    it(`gives ${h.slice(0, 8)}… order ${n}`, () => {
      const t = point(h);
      assert.equal(order(t), n);
      assert.equal(isIdentity(scalarMult(8n, t)), true);
      assert.equal(hasSmallOrder(t), true);
      assert.equal(inPrimeOrderSubgroup(t), n === 1);
      assert.equal(pointProblem(Buffer.from(h, "hex")), SMALL_ORDER);
    });
  }

  it("round-trips encode and decode for multiples of B", () => {
    for (const k of scalars("round trip", 48)) {
      const p = scalarMult(k, BASE);
      const data = encode(p);
      const back = point(hex(data));
      assert.equal(hex(encode(back)), hex(data));
      assert.equal(pointsEqual(back, p), true);
      assert.equal(inPrimeOrderSubgroup(back), true);
      assert.equal(hasSmallOrder(back), false);
      assert.equal(pointProblem(data), null);
    }
  });

  it("puts a mixed-order point outside the subgroup, and [8] clears it", () => {
    const mixed = pointAdd(scalarMult(12345n, BASE), point(T8_HEX));
    assert.equal(hasSmallOrder(mixed), false);
    assert.equal(inPrimeOrderSubgroup(mixed), false);
    assert.equal(inPrimeOrderSubgroup(scalarMult(8n, mixed)), true);
    assert.equal(pointProblem(encode(mixed)), NOT_IN_SUBGROUP);
  });

  it("refuses non-canonical encodings", () => {
    for (const data of [fromY(P), fromY(P + 1n), fromY(2n ** 255n - 1n), fromY(1n, 1n), fromY(P - 1n, 1n)]) {
      assert.deepEqual(decode(data), [null, NOT_CANONICAL]);
    }
    assert.equal(decode(fromY(1n))[1], null);
    assert.equal(decode(fromY(P - 1n))[1], null);
    for (const n of [0, 31, 33, 64]) assert.deepEqual(decode(new Uint8Array(n)), [null, NOT_CANONICAL]);
  });

  it("refuses points off the curve, about half of all y", () => {
    assert.deepEqual(decode(fromY(2n)), [null, NOT_ON_CURVE]);
    assert.equal(pointProblem(fromY(2n)), NOT_ON_CURVE);
    let off = 0;
    for (const y of scalars("off curve", 200)) {
      const [p, problem] = decode(fromY(y % P));
      if (problem === NOT_ON_CURVE) off++;
      else assert.equal(p !== null && isOnCurve(p), true);
    }
    assert.ok(off > 60);
    assert.ok(off < 140);
  });
});
