# Self-test files

The self-test workflow (`.github/workflows/self-test.yml`) runs the action on these files.
`scripts/make-selftest.mjs` writes them; do not edit them by hand.

- `receipts/` holds receipts from the verifiable-receipts conformance corpus
  (`packages/verifiable-receipts/conformance/fixtures` at commit
  55d30b72b277a025e7a20e0952aa5813241ba38f, Apache-2.0, licence in
  `third_party/verifiable-receipts/LICENSE`). `valid/` must verify; `invalid/` must not.
- `keys/issuer.pem` is the corpus public key. Its private half was discarded when the corpus was made.
- `log/` is a three-leaf log made by the script: a tree head, signed by the key in `keys/log.pem`,
  and the inclusion proof of the valid receipts' leaf. The log's private key was never written to disk.
