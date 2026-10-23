# Conformance fixtures

Copied unchanged from verifiable-receipts
(https://github.com/christiaan839-beep/verifiable-receipts), commit
03b38ee2d28080a2a4aa0810dbb1dfcd447379fd:
`packages/verifiable-receipts/conformance/fixtures/*.json` and
`packages/verifiable-receipts/conformance/public-key.pem`.

Licence: Apache License 2.0, Copyright 2026 Christiaan de Wet / Sovereign Matrix;
see `third_party/verifiable-receipts/LICENSE`.

The v2 fixtures are signed by the key in `public-key.pem`. Its private half was
discarded when the corpus was made. `test/conformance.test.ts` runs every fixture, and CI checks that the copies
match that commit byte for byte (`.github/workflows/ci.yml`, job `vendor`).
