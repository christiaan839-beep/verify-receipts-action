// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Runs the action end to end in a temporary workspace, with every way of
// opening a network connection replaced by one that records the attempt
// and throws. Each test checks that none was attempted.
import assert from "node:assert/strict";
import dgram from "node:dgram";
import dns from "node:dns";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import tls from "node:tls";

import { run } from "../src/main.ts";
import {
  arrays,
  buildLog,
  conformanceKey,
  IDENTITY_KEY_HEX,
  IDENTITY_SIGNATURE,
  makeKey,
  rawKeyPem,
  readFixture,
  sampleBody,
  signReceipt,
} from "./helpers.ts";

const NOW = new Date("2026-10-23T12:00:00Z");

const networkAttempts: string[] = [];
function block(target: object, name: string, label: string): void {
  Object.defineProperty(target, name, {
    configurable: true,
    writable: true,
    value: () => {
      networkAttempts.push(label);
      throw new Error(`network access attempted: ${label}`);
    },
  });
}
block(net.Socket.prototype, "connect", "net.Socket.connect");
block(net, "connect", "net.connect");
block(net, "createConnection", "net.createConnection");
block(tls, "connect", "tls.connect");
block(http, "request", "http.request");
block(http, "get", "http.get");
block(https, "request", "https.request");
block(https, "get", "https.get");
block(dns, "lookup", "dns.lookup");
block(dns, "resolve", "dns.resolve");
block(dgram, "createSocket", "dgram.createSocket");
block(globalThis, "fetch", "fetch");

interface Captured {
  outputs: Record<string, string>;
  summary: string;
  stdout: string;
  exitCode: number | undefined;
}

let dir = "";
const savedEnv = { ...process.env };
const savedCwd = process.cwd();

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "verify-receipts-"));
  for (const k of Object.keys(process.env)) {
    if (k.startsWith("INPUT_") || k.startsWith("GITHUB_")) Reflect.deleteProperty(process.env, k);
  }
  process.env.GITHUB_WORKSPACE = dir;
  process.env.GITHUB_OUTPUT = join(dir, ".output");
  process.env.GITHUB_STEP_SUMMARY = join(dir, ".summary");
  writeFileSync(process.env.GITHUB_OUTPUT, "");
  writeFileSync(process.env.GITHUB_STEP_SUMMARY, "");
  process.chdir(dir);
});

afterEach(() => {
  process.chdir(savedCwd);
  rmSync(dir, { recursive: true, force: true });
  process.env = { ...savedEnv };
  process.exitCode = undefined;
  assert.deepEqual(networkAttempts, [], "the action attempted network access");
});

function write(rel: string, content: string | object): void {
  const path = join(dir, rel);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content, null, 2));
}

function parseOutputs(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /^([^<\n]+)<<(\S+)\n([\s\S]*?)\n\2$/gm;
  for (const m of text.matchAll(re)) out[m[1] ?? ""] = m[3] ?? "";
  return out;
}

async function act(inputs: Record<string, string>): Promise<Captured> {
  for (const [name, value] of Object.entries(inputs)) {
    process.env[`INPUT_${name.toUpperCase()}`] = value;
  }
  let stdout = "";
  const original = process.stdout.write.bind(process.stdout);
  // @actions/core writes workflow commands as strings. The test runner
  // reports results through this process's stdout as binary chunks, which
  // pass through untouched.
  process.stdout.write = (chunk: string | Uint8Array, ...rest: never[]): boolean => {
    if (typeof chunk !== "string") return original(chunk, ...rest);
    stdout += chunk;
    return true;
  };
  try {
    await run({ now: NOW });
  } finally {
    process.stdout.write = original;
  }
  const exitCode = typeof process.exitCode === "number" ? process.exitCode : undefined;
  process.exitCode = undefined;
  return {
    outputs: parseOutputs(readFileSync(join(dir, ".output"), "utf8")),
    summary: readFileSync(join(dir, ".summary"), "utf8"),
    stdout,
    exitCode,
  };
}

describe("run", () => {
  it("passes when every receipt verifies, and writes the outputs and the summary", async () => {
    const issuer = makeKey();
    write("receipts/a.json", signReceipt(sampleBody({ receiptId: "a" }), issuer.privateKey));
    write("receipts/b.json", signReceipt(sampleBody({ receiptId: "b" }), issuer.privateKey));
    write("keys/issuer.pem", issuer.pem);
    const r = await act({ receipts: "receipts/*.json", "public-keys-file": "keys/issuer.pem" });
    assert.equal(r.exitCode, undefined, r.stdout);
    assert.equal(r.outputs.total, "2");
    assert.equal(r.outputs.verified, "2");
    assert.equal(r.outputs.failed, "0");
    assert.equal(r.outputs.failures, "[]");
    assert.match(r.summary, /2 of 2 receipts verified offline/);
    assert.match(r.summary, /<code>receipts\/a\.json<\/code>/);
    assert.doesNotMatch(r.stdout, /::error/);
  });

  it("fails on a tampered receipt, annotates the file and lists the reason", async () => {
    const issuer = makeKey();
    write("receipts/good.json", signReceipt(sampleBody(), issuer.privateKey));
    write("receipts/bad.json", { ...signReceipt(sampleBody(), issuer.privateKey), overall: "fail" });
    const r = await act({ receipts: "receipts/**/*.json", "public-keys": issuer.pem });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.verified, "1");
    assert.equal(r.outputs.failed, "1");
    const failures = JSON.parse(r.outputs.failures ?? "[]") as { file: string; reason: string }[];
    assert.equal(failures[0]?.file, "receipts/bad.json");
    assert.match(failures[0].reason, /envelope field "overall" disagrees/);
    assert.match(r.stdout, /::error title=Receipt verification failed,file=receipts\/bad\.json::envelope field/);
    assert.match(r.summary, /<strong>failed<\/strong>/);
  });

  it("verifies the conformance corpus receipts under the corpus key", async () => {
    for (const name of ["v2-valid-001.json", "v2-valid-envelope-agrees.json", "v2-invalid-wrong-key.json"]) {
      const fixture = JSON.parse(readFixture(name)) as { receipt: unknown };
      write(`corpus/${name}`, fixture.receipt as object);
    }
    write("corpus.pem", readFixture("public-key.pem"));
    const r = await act({ receipts: "corpus/*.json", "public-keys-file": "corpus.pem" });
    assert.equal(r.outputs.total, "3");
    assert.equal(r.outputs.verified, "2");
    assert.equal(r.exitCode, 1);
    assert.match(r.stdout, /file=corpus\/v2-invalid-wrong-key\.json::/);
    assert.ok(r.summary.includes(`key ${conformanceKey().fingerprint}`), r.summary);
  });

  it("warns instead of failing when fail-on-invalid is false", async () => {
    const issuer = makeKey();
    const other = makeKey();
    write("r.json", signReceipt(sampleBody(), other.privateKey));
    const r = await act({ receipts: "r.json", "public-keys": issuer.pem, "fail-on-invalid": "false" });
    assert.equal(r.exitCode, undefined);
    assert.equal(r.outputs.failed, "1");
    assert.match(r.stdout, /::warning title=Receipt verification failed,file=r\.json/);
  });

  it("fails when no receipt file matches, unless fail-on-empty is false", async () => {
    const issuer = makeKey();
    const strict = await act({ receipts: "nothing/*.json", "public-keys": issuer.pem });
    assert.equal(strict.exitCode, 1);
    assert.match(strict.stdout, /no receipt files matched/);
    process.env["INPUT_FAIL-ON-EMPTY"] = "false";
    const lax = await act({ receipts: "nothing/*.json", "public-keys": issuer.pem });
    assert.equal(lax.exitCode, undefined);
    assert.equal(lax.outputs.total, "0");
  });

  it("confirms inclusion in the log against a pinned tree head", async () => {
    const issuer = makeKey();
    const logKey = makeKey();
    const a = signReceipt(sampleBody({ receiptId: "a" }), issuer.privateKey);
    const b = signReceipt(sampleBody({ receiptId: "b" }), issuer.privateKey);
    const log = buildLog([a, b], logKey.privateKey);
    write("receipts/a.json", a);
    write("receipts/b.json", b);
    write("log/sth.json", log.treeHead);
    write("log/proofs/a.json", log.proofs[0] ?? {});
    write("log/proofs/b.json", log.proofs[1] ?? {});
    const r = await act({
      receipts: "receipts/*.json",
      "public-keys": issuer.pem,
      "tree-head": "log/sth.json",
      "log-public-keys": logKey.pem,
      "inclusion-proofs": "log/proofs/*.json",
    });
    assert.equal(r.exitCode, undefined, r.stdout);
    assert.equal(r.outputs.verified, "2");
    assert.match(r.summary, /Tree head <code>log\/sth\.json<\/code>: log <code>test-log<\/code>, size 2/);
  });

  it("fails a receipt missing from the proofs and annotates it", async () => {
    const issuer = makeKey();
    const logKey = makeKey();
    const a = signReceipt(sampleBody({ receiptId: "a" }), issuer.privateKey);
    const late = signReceipt(sampleBody({ receiptId: "late" }), issuer.privateKey);
    const log = buildLog([a], logKey.privateKey);
    write("receipts/a.json", a);
    write("receipts/late.json", late);
    write("sth.json", log.treeHead);
    write("proofs.json", log.proofs);
    const r = await act({
      receipts: "receipts/*.json",
      "public-keys": issuer.pem,
      "tree-head": "sth.json",
      "log-public-keys": logKey.pem,
      "inclusion-proofs": "proofs.json",
    });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.verified, "1");
    assert.match(r.stdout, /::error title=Receipt verification failed,file=receipts\/late\.json::no inclusion proof/);
  });

  it("escapes receipt-controlled text in the job summary", async () => {
    const issuer = makeKey();
    write("r.json", { ...signReceipt(sampleBody(), issuer.privateKey), "<img src=x>": 1 });
    const r = await act({ receipts: "r.json", "public-keys": issuer.pem });
    assert.equal(r.exitCode, 1);
    assert.doesNotMatch(r.summary, /<img/);
    assert.match(r.summary, /&lt;img src=x&gt;/);
  });

  it("reports an unreadable or oversized receipt file as a failure", async () => {
    const issuer = makeKey();
    write("big.json", " ".repeat(5 * 1024 * 1024 + 1));
    const r = await act({ receipts: "big.json", "public-keys": issuer.pem });
    assert.equal(r.exitCode, 1);
    assert.match(r.outputs.failures ?? "", /larger than/);
  });

  it("reports an oversized proof file with its own reason and annotation title", async () => {
    const issuer = makeKey();
    const logKey = makeKey();
    const a = signReceipt(sampleBody({ receiptId: "a" }), issuer.privateKey);
    const log = buildLog([a], logKey.privateKey);
    write("receipts/a.json", a);
    write("sth.json", log.treeHead);
    write("proofs/big.json", " ".repeat(5 * 1024 * 1024 + 1));
    const r = await act({
      receipts: "receipts/*.json",
      "public-keys": issuer.pem,
      "tree-head": "sth.json",
      "log-public-keys": logKey.pem,
      "inclusion-proofs": "proofs/*.json",
    });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.failed, "2");
    assert.match(r.stdout, /::error title=Tree head or inclusion proof file unusable,file=proofs\/big\.json::file is larger than/);
  });

  const configErrors: [string, Record<string, string>, RegExp][] = [
    ["no receipts input", { "public-keys": "" }, /input receipts is required/],
    ["no keys", { receipts: "*.json" }, /at least one Ed25519 key/],
    ["a private key", { receipts: "*.json", "public-keys": ["-----BEGIN", "PRIVATE KEY-----\nAA\n-----END", "PRIVATE KEY-----"].join(" ") }, /private key/],
    ["a missing keys file", { receipts: "*.json", "public-keys-file": "missing.pem" }, /public-keys-file: missing\.pem: file could not be read/],
    ["a bad boolean", { receipts: "*.json", "fail-on-invalid": "yes" }, /must be "true" or "false"/],
    ["a bad max-age-days", { receipts: "*.json", "max-age-days": "-3" }, /max-age-days must be a positive whole number/],
  ];
  for (const [label, inputs, message] of configErrors) {
    it(`fails with a clear message on ${label}`, async () => {
      const r = await act(inputs);
      assert.equal(r.exitCode, 1);
      assert.match(r.stdout, message);
    });
  }

  it("fails when tree-head is given without log keys, or log inputs without tree-head", async () => {
    const issuer = makeKey();
    write("sth.json", "{}");
    const noKeys = await act({ receipts: "*.json", "public-keys": issuer.pem, "tree-head": "sth.json" });
    assert.match(noKeys.stdout, /tree-head needs at least one key/);
    Reflect.deleteProperty(process.env, "INPUT_TREE-HEAD");
    const noHead = await act({ receipts: "*.json", "public-keys": issuer.pem, "inclusion-proofs": "p/*.json" });
    assert.match(noHead.stdout, /need tree-head/);
  });

  it("refuses a receipt file whose duplicate key hides nesting deeper than 64", async () => {
    const issuer = makeKey();
    const text = JSON.stringify(signReceipt(sampleBody(), issuer.privateKey));
    write("r.json", `${text.slice(0, -1)},"overall":${JSON.stringify(arrays(64))},"overall":"pass"}`);
    const r = await act({ receipts: "r.json", "public-keys": issuer.pem });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.verified, "0");
    assert.match(r.outputs.failures ?? "", /receipt nesting deeper than 64/);
  });

  // Under the identity point this signature verifies every message.
  const forged = { ...sampleBody(), canonical: JSON.stringify(sampleBody()), signature: IDENTITY_SIGNATURE };
  const weakPem = rawKeyPem(IDENTITY_KEY_HEX);

  it("refuses a small-order key in public-keys", async () => {
    write("r.json", forged);
    const r = await act({ receipts: "r.json", "public-keys": weakPem });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.verified, undefined);
    assert.match(r.stdout, /input public-keys: block 1 is refused: public key is a small-order point/);
  });

  it("refuses a small-order key in public-keys-file", async () => {
    write("r.json", forged);
    write("weak.pem", weakPem);
    const r = await act({ receipts: "r.json", "public-keys-file": "weak.pem" });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.verified, undefined);
    assert.match(r.stdout, /public-keys-file weak\.pem: block 1 is refused: public key is a small-order point/);
  });

  it("refuses a small-order key in log-public-keys", async () => {
    const issuer = makeKey();
    const receipt = signReceipt(sampleBody(), issuer.privateKey);
    write("r.json", receipt);
    write("sth.json", { v: 1, logId: "l", treeSize: 1, rootHash: "0".repeat(64), timestamp: "t", signature: IDENTITY_SIGNATURE });
    const r = await act({ receipts: "r.json", "public-keys": issuer.pem, "tree-head": "sth.json", "log-public-keys": weakPem });
    assert.equal(r.exitCode, 1);
    assert.equal(r.outputs.verified, undefined);
    assert.match(r.stdout, /input log-public-keys: block 1 is refused: public key is a small-order point/);
  });
});
