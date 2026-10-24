# verify-receipts-action

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/christiaan839-beep/verify-receipts-action/badge)](https://scorecard.dev/viewer/?uri=github.com/christiaan839-beep/verify-receipts-action)

A GitHub Action that fails a build when a verifiable receipt is forged or tampered with. It checks each receipt's Ed25519
signature against public keys pinned in the workflow, and, when given a signed tree head and inclusion proofs, checks that
each receipt is in the transparency log. Every check runs inside the job, on files in the checkout. The action makes no
network request.

The receipt format is the v2 wire format of [verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
(`SPEC.md` and `docs/specs/vaos-2.0.md` there). The log format is that project's transparency log
(`docs/specs/transparency-log.md`, after RFC 6962 and RFC 9162).

## Usage

```yaml
permissions:
  contents: read

jobs:
  receipts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Verify receipts
        id: receipts
        uses: christiaan839-beep/verify-receipts-action@FULL_COMMIT_SHA # the release's commit
        with:
          receipts: |
            receipts/**/*.json
          public-keys-file: .github/receipt-keys/issuer.pem
          # Optional: confirm each receipt is in the transparency log.
          tree-head: receipts/log/tree-head.json
          log-public-keys-file: .github/receipt-keys/log.pem
          inclusion-proofs: receipts/log/proofs/*.json
          max-age-days: "365"
```

Pin the action to a full commit SHA, as with any third-party action. Keep the pinned keys in the repository, where a
change to them shows in review.

`.github/workflows/self-test.yml` runs the action on the files in `selftest/` and is a second, working example.

## Inputs

| Input                  | Required | Default | Meaning                                                                                                    |
| ---------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `receipts`             | yes      |         | Glob patterns, one per line, for the receipt files.                                                        |
| `public-keys`          | no       | `""`    | Pinned Ed25519 public keys as PEM `PUBLIC KEY` blocks. A receipt verifies under any one of them.           |
| `public-keys-file`     | no       | `""`    | Paths, one per line, of files holding PEM `PUBLIC KEY` blocks. Combined with `public-keys`.                |
| `tree-head`            | no       | `""`    | Path of the log's signed tree head. When set, every receipt also needs an inclusion proof.                |
| `log-public-keys`      | no       | `""`    | Pinned Ed25519 public keys (PEM) of the log. Required with `tree-head`.                                    |
| `log-public-keys-file` | no       | `""`    | Paths, one per line, of files holding the log's PEM public keys.                                           |
| `inclusion-proofs`     | no       | `""`    | Glob patterns, one per line, for inclusion proof files.                                                    |
| `max-age-days`         | no       | `""`    | Whole days. A receipt's signed `issuedAt` must be at most this old and at most five minutes in the future. |
| `fail-on-invalid`      | no       | `true`  | `true` fails the step on any failure, including an unusable tree head or proof file. `false` warns.        |
| `fail-on-empty`        | no       | `true`  | `true` fails the step when the `receipts` patterns match no file.                                          |

In the inputs that take one entry per line (`receipts`, `public-keys-file`, `log-public-keys-file`, `inclusion-proofs`),
blank lines and lines starting with `#` are ignored. Paths and patterns are relative to the workspace.

At least one receipt key is required, from `public-keys`, `public-keys-file` or both. `log-public-keys`,
`log-public-keys-file` and `inclusion-proofs` without `tree-head` are a configuration error, as is `tree-head` without a
log key. A private key in any key input is a configuration error, as is a weak Ed25519 key: a point of small order or a
non-canonical encoding (VAOS 2.0 §7.3), under which a signature proves nothing.

## Outputs

| Output     | Meaning                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| `total`    | Number of receipts checked.                                                                                     |
| `verified` | Number of receipts that passed every check.                                                                     |
| `failed`   | Number of failures: failed receipts plus unusable tree head or proof files.                                     |
| `failures` | JSON array of `{"file", "entry", "reason"}`, one per failure. `entry` is the index in an array file, or `null`. |

The action also writes a job summary with one row per receipt (file, result, the fingerprint of the key that verified
it, its leaf index, or the reason it failed), and an error annotation on each failing file: "Receipt verification failed"
on a receipt file, "Tree head or inclusion proof file unusable" on a log file. With `fail-on-invalid: false` the
annotations are warnings. A key's fingerprint is `sha256:` and the first 16 hex characters of the SHA-256 of its
SPKI DER encoding.

## File formats

**Receipt file.** A JSON object holding one receipt, or a JSON array of receipts. A receipt has `canonical` (the signed
string), `signature` (`v2=` and the standard base64 of the 64-byte Ed25519 signature) and optionally `contentHash`
(`sha256:` and the hex SHA-256 of `canonical`). Any other top-level field must equal the same field of the parsed
`canonical`.

**Inclusion proof file.** A JSON object, or an array of them, each with `leafHashHex`, `leafIndex`, `treeSize` and
`auditPath` (as in the verifiable-receipts conformance fixtures). Hashes are 64 lowercase hex characters. A receipt's
leaf hash is `SHA-256(0x00 || canonical)`; the action matches proofs to receipts by it, so file names do not matter.

**Tree head file.** A JSON object with `v` (1), `logId`, `treeSize`, `rootHash`, `timestamp` and `signature`. The
signature is a `v2=` signature over `{"logId","rootHash","timestamp","treeSize","v"}` serialised in that key order with
no whitespace.

## What the action checks

For each receipt, in this order:

1. The file is JSON and holds a receipt object or a non-empty array of them, and no receipt nests more than 64 arrays and
   objects deep (VAOS 2.0 §7.2). Depth is counted on the file's text before it is parsed, so a duplicate key that
   `JSON.parse` discards still counts; in an array, each receipt is counted from its own level.
2. `signature` starts with `v2=`. Any other version prefix (`v1=`, `v3=` and so on) fails as an unsupported algorithm.
3. The checks of the verifiable-receipts v2 verifier: `canonical` and `signature` are present, the base64 is standard,
   `contentHash`, unless absent or null, matches (an empty string does not), the Ed25519 signature verifies over the
   UTF-8 bytes of `canonical` under one of the pinned keys, `canonical` nests at most 64 deep (counted on its text) and
   is a JSON object, and every other top-level field agrees with it. A number of magnitude 2^53 or more in such a field
   agrees with nothing.
4. If the signed `canonical` has `expiresAt`, it is an ISO 8601 date-time that has not passed.
5. If `max-age-days` is set, the signed `issuedAt` is an ISO 8601 date-time no older than that and at most five minutes
   in the future.
6. If `tree-head` is set: the tree head is well formed and its signature verifies under a pinned log key, a proof exists
   for the receipt's leaf hash, the proof's `treeSize` equals the tree head's, and the proof's audit path leads from the
   leaf to the tree head's `rootHash`. The tree head file and each proof file nest at most 64 deep, counted on their
   text before they are parsed (transparency-log.md §3.6); a file over the limit is refused and named.

Time checks read only fields inside the signed `canonical`. A field beside it is unsigned and fails step 3.

## Security model

- **Trust comes from the pinned keys.** The action trusts a receipt because its signature verifies under a key written
  in the workflow or the repository. It never fetches a key, so a compromised or impersonated key server cannot supply
  one. Whoever can change the pinned keys can change what verifies: protect those files with code review and branch
  rules.
- **No network.** Verification uses `node:crypto` on files already in the checkout. The source may not import a network
  module or use `fetch` (an ESLint rule), the end-to-end tests fail if the action opens a socket, resolves a name or calls
  `fetch`, and CI runs the bundle in a network namespace with no interfaces up. The bundle contains the HTTP client of
  `@actions/core`, which that library uses only for OIDC tokens; the action does not call it.
- **The log is checked against one pinned tree head.** An inclusion proof shows that a receipt is in the tree the tree
  head commits to. It does not show that the log is append-only or that every party sees the same tree; that needs
  consistency proofs and witnesses, which this action does not check.
- **Receipt content is untrusted.** Text from receipts is HTML-escaped in the job summary and escaped as workflow command
  data in annotations. Files larger than 5 MiB are not read. Symbolic links are not followed when globbing.
- **Fail closed.** A malformed key, receipt, proof or tree head is a failure, never a skip.

## Limits

- Only `v2=` (Ed25519) signatures are verified. `v3=` (Ed25519 with ML-DSA-65) and `v1=` (HMAC-SHA256) receipts fail as
  unsupported algorithms.
- Signed bundles (`MANIFEST.signed.json`) are not verified.
- One tree head per run. Every inclusion proof must be for that tree head's size; consistency proofs between tree sizes
  are not supported.
- Keys carry no validity period: a pinned key verifies receipts until it is removed from the inputs.
- A top-level field beside `canonical` cannot hold a number of magnitude 2^53 or more: `JSON.parse` rounds such a
  number, so the verifier rejects the field instead of comparing rounded values. Inside `canonical` any number is
  allowed, because the signature covers its bytes.
- The runtime is `node20`, as declared in `action.yml`. The unit tests need Node 22.18 or later, which runs TypeScript
  directly.

## Where the verification code comes from

The `@sovereign-matrix/verifiable-receipts` package is not published on npm, so the action vendors the verification code
it needs in `src/vendor/verifiable-receipts/`:

- `receipt.ts` is `packages/verifiable-receipts/conformance/verify-v2.mjs`, converted to TypeScript with its checks,
  their order and their failure reasons unchanged.
- `transparency.ts` is the verification half of `packages/verifiable-receipts/src/transparency.ts`: `leafHash`,
  `innerHash`, `verifyInclusionProof` and `canonicalizeSth`.

Both come from commit `24f5c4780dba7c4f76b159b7f7844e17d0226cd6` of verifiable-receipts, under the Apache License 2.0.
Each file's header says what changed. The licence is in `third_party/verifiable-receipts/LICENSE`. The conformance
fixtures in `test/fixtures/conformance/` are copied from the same commit; `test/fixtures/conformance/README.md` says so.
The `vendor` job in `.github/workflows/ci.yml` checks the copies against that commit, named there as `VR_REF`.

## Development

```bash
npm ci
npm run typecheck   # tsc, strict
npm run lint        # eslint, typescript-eslint strict type-checked rules
npm test            # node:test; keys are generated at test time
npm run build       # esbuild bundle to dist/index.js and dist/licenses.txt
```

`dist/` is committed, because a JavaScript action runs from the repository as checked out. CI rebuilds it and fails if
the result differs from what is committed. `node scripts/make-selftest.mjs` rewrites `selftest/` with a new throwaway log
key; the private half is never written to disk.

## Licence

Apache License 2.0, the licence of verifiable-receipts. See `LICENSE` and `NOTICE`. `dist/licenses.txt` lists the
licences of the bundled dependencies.
