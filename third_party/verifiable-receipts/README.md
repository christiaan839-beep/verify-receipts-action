# verifiable-receipts

Source: https://github.com/christiaan839-beep/verifiable-receipts, commit
03b38ee2d28080a2a4aa0810dbb1dfcd447379fd.

Licence: Apache License 2.0, in `LICENSE` beside this file (copied from
`packages/verifiable-receipts/LICENSE`).

Used here:

- `src/vendor/verifiable-receipts/receipt.ts`, from `packages/verifiable-receipts/conformance/verify-v2.mjs`.
- `src/vendor/verifiable-receipts/transparency.ts`, from `packages/verifiable-receipts/src/transparency.ts`.
- `test/fixtures/conformance/`, from `packages/verifiable-receipts/conformance/fixtures/` and `public-key.pem`.
- `selftest/receipts/` and `selftest/keys/issuer.pem`, written from those fixtures by `scripts/make-selftest.mjs`.

Each vendored source file states in its header what was changed.
