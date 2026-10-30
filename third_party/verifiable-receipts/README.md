# verifiable-receipts

Source: https://github.com/christiaan839-beep/verifiable-receipts, commit
f41348eac297c81e1c2a0dca91b7bd49dd2a5d9a.

Licence: Apache License 2.0, in `LICENSE` beside this file (copied from
`packages/verifiable-receipts/LICENSE`).

Used here:

- `src/vendor/verifiable-receipts/receipt.ts`, from `packages/verifiable-receipts/conformance/verify-v2.mjs`.
- `src/vendor/verifiable-receipts/edwards25519.ts`, from `packages/verifiable-receipts/src/edwards25519.ts`.
- `src/vendor/verifiable-receipts/transparency.ts`, from `packages/verifiable-receipts/src/transparency.ts`.
- `test/fixtures/conformance/`, from `packages/verifiable-receipts/conformance/fixtures/` and `public-key.pem`.
- `test/edwards25519.test.ts`, from `packages/verifiable-receipts/tests/edwards25519.test.ts`, converted to `node:test`.
- `selftest/receipts/` and `selftest/keys/issuer.pem`, written from those fixtures by `scripts/make-selftest.mjs`.

Each vendored source file states in its header what was changed.
