// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";

import { dedupeKeys, KeyError, parsePublicKeys } from "../src/keys.ts";
import { makeKey, rawKeyPem } from "./helpers.ts";

describe("parsePublicKeys", () => {
  it("reads every Ed25519 PUBLIC KEY block in the text", () => {
    const a = makeKey();
    const b = makeKey();
    const keys = parsePublicKeys(`# issuer keys\n${a.pem}\nsome note\n${b.pem}`, "test");
    assert.deepEqual(
      keys.map((k) => k.fingerprint),
      [a.pinned.fingerprint, b.pinned.fingerprint],
    );
    assert.match(a.pinned.fingerprint, /^sha256:[0-9a-f]{16}$/);
  });

  it("returns no keys for empty text", () => {
    assert.deepEqual(parsePublicKeys("  \n", "test"), []);
  });

  it("rejects text with no PEM block", () => {
    assert.throws(() => parsePublicKeys("not a key", "input public-keys"), {
      name: "Error",
      message: /input public-keys: no PEM "PUBLIC KEY" block/,
    });
  });

  it("rejects a private key, so that one is never pasted into a workflow by mistake", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    assert.throws(() => parsePublicKeys(pem, "test"), (err: unknown) => {
      return err instanceof KeyError && err.message.includes("private key");
    });
  });

  it("rejects a key that is not Ed25519", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    assert.throws(() => parsePublicKeys(pem, "test"), /ec key, expected ed25519/);
  });

  it("rejects a corrupted PUBLIC KEY block", () => {
    const pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
    assert.throws(() => parsePublicKeys(pem, "test"), /not a readable public key/);
  });

  it("rejects a block of another type", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert.throws(() => parsePublicKeys(pem, "test"), /"CERTIFICATE", expected "PUBLIC KEY"/);
  });
});

describe("weak Ed25519 keys", () => {
  // The libsodium small-order blocklist, sign bit cleared (verify-v2.mjs).
  const smallOrder = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ];
  for (const hex of smallOrder) {
    for (const signBit of [false, true]) {
      const raw = Buffer.from(hex, "hex");
      if (signBit) raw[31] = (raw[31] ?? 0) | 0x80;
      it(`refuses the small-order key ${raw.toString("hex").slice(0, 8)}…${raw.toString("hex").slice(-2)}`, () => {
        assert.throws(() => parsePublicKeys(rawKeyPem(raw.toString("hex")), "input public-keys"), (err: unknown) => {
          return (
            err instanceof KeyError &&
            err.message.startsWith("input public-keys: block 1 is refused: public key is a small-order point")
          );
        });
      });
    }
  }

  it("refuses a non-canonical encoding, y = p + 3", () => {
    const pem = rawKeyPem("f0" + "ff".repeat(30) + "7f");
    assert.throws(() => parsePublicKeys(pem, "test"), /block 1 is refused: public key is not a canonical encoding/);
  });

  it("names the weak block among good ones", () => {
    const good = makeKey();
    const weak = rawKeyPem("01" + "00".repeat(31));
    assert.throws(() => parsePublicKeys(`${good.pem}${weak}`, "keys.pem"), /keys\.pem: block 2 is refused/);
  });
});

describe("dedupeKeys", () => {
  it("keeps the first copy of a key given twice", () => {
    const a = makeKey();
    const b = makeKey();
    assert.deepEqual(
      dedupeKeys([a.pinned, b.pinned, a.pinned]).map((k) => k.fingerprint),
      [a.pinned.fingerprint, b.pinned.fingerprint],
    );
  });
});
