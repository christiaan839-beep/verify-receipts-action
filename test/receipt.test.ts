// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the vendored verifier's own defences, which the action's
// text-first depth counting would otherwise keep every input away from.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { jsonEqual } from "../src/vendor/verifiable-receipts/receipt.ts";
import { arrays } from "./helpers.ts";

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
