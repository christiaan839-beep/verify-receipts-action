// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Writes selftest/, the files the self-test workflow verifies with the
// action. The receipts are the verifiable-receipts conformance receipts
// (test/fixtures/conformance), checked under the corpus public key. The
// log is made here: a throwaway Ed25519 key signs a tree head over the
// valid receipts' leaf and two padding leaves, and only its public half is
// written. The private half is never stored, so the tree head cannot be
// re-signed; run this script again to make a new log.
//
// Run: node scripts/make-selftest.mjs   (Node 22.18 or later)
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildLog, rfcLeafHash } from "../test/helpers.ts";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const fixtures = join(root, "test", "fixtures", "conformance");
const out = join(root, "selftest");
rmSync(out, { recursive: true, force: true });

function write(rel, content) {
  const path = join(out, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content, null, 2) + "\n");
}

function receipt(name) {
  return JSON.parse(readFileSync(join(fixtures, name), "utf8")).receipt;
}

// A fixture that gives its receipt as text (receiptText) is written as
// that text, byte for byte, so the action reads it as the fixture means.
function receiptFile(name) {
  const fixture = JSON.parse(readFileSync(join(fixtures, name), "utf8"));
  return fixture.receiptText ?? fixture.receipt;
}

const valid = ["v2-valid-001.json", "v2-valid-envelope-agrees.json"];
const invalid = [
  "v2-invalid-tampered.json",
  "v2-invalid-wrong-key.json",
  "v2-invalid-envelope-disagrees.json",
  "v2-invalid-wrong-version.json",
  "v2-invalid-empty-contenthash.json",
  "v2-invalid-deep-nesting.json",
  "v2-invalid-duplicate-deep-key.json",
];
for (const name of valid) write(`receipts/valid/${name}`, receipt(name));
for (const name of invalid) write(`receipts/invalid/${name}`, receiptFile(name));
write("keys/issuer.pem", readFileSync(join(fixtures, "public-key.pem"), "utf8"));

// Both valid receipts carry the same canonical, so they share one leaf.
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const padding = [rfcLeafHash("selftest padding 1"), rfcLeafHash("selftest padding 2")];
const log = buildLog([receipt(valid[0])], privateKey, padding, "verify-receipts-action-selftest");
write("log/tree-head.json", log.treeHead);
write("log/proofs/valid.json", log.proofs[0]);
write("keys/log.pem", publicKey.export({ type: "spki", format: "pem" }).toString());

write(
  "README.md",
  [
    "# Self-test files",
    "",
    "The self-test workflow (`.github/workflows/self-test.yml`) runs the action on these files.",
    "`scripts/make-selftest.mjs` writes them; do not edit them by hand.",
    "",
    "- `receipts/` holds receipts from the verifiable-receipts conformance corpus",
    "  (`packages/verifiable-receipts/conformance/fixtures` at the commit named in",
    "  `test/fixtures/conformance/README.md`, Apache-2.0, licence in",
    "  `third_party/verifiable-receipts/LICENSE`). `valid/` must verify; `invalid/` must not.",
    "- `keys/issuer.pem` is the corpus public key. Its private half was discarded when the corpus was made.",
    "- `log/` is a three-leaf log made by the script: a tree head, signed by the key in `keys/log.pem`,",
    "  and the inclusion proof of the valid receipts' leaf. The log's private key was never written to disk.",
    "",
  ].join("\n"),
);
