// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Runs the verifiable-receipts conformance corpus (copied into
// test/fixtures/conformance, see its README) through the action's checks.
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { describe, it } from "node:test";

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
  it("holds the 14 fixtures of the source corpus", () => {
    assert.equal(files.length, 14);
  });

  for (const name of files.filter((f) => f.startsWith("v2-"))) {
    it(`receipt ${name}`, () => {
      const fixture = JSON.parse(readFixture(name)) as { receipt: unknown; expected: Expected };
      const report = verifyReceipts([{ file: name, content: JSON.stringify(fixture.receipt) }], {
        keys: [conformanceKey()],
        now: NOW,
      });
      const [result] = report.results;
      assert.ok(result);
      assert.equal(result.ok, fixture.expected.ok, result.reason);
      if (fixture.expected.reasonContains !== undefined) {
        assert.match(result.reason ?? "", new RegExp(fixture.expected.reasonContains, "i"));
      }
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
});
