# Changelog

Notable changes to verify-receipts-action. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The vendored verifier is synced to verifiable-receipts f41348e, which adds the
  strict Ed25519 profile of VAOS 2.0 §7.3. Before the signature check, a pinned
  key is refused if it is a non-canonical encoding, off the curve, of small
  order or outside the prime-order subgroup, and a signature is refused if its
  R has any of those faults (R = identity included) or its S is not below L.
  Each refusal has its own reason (`public key is …`, `signature R is …`). The
  arithmetic is pure BigInt, in `src/vendor/verifiable-receipts/edwards25519.ts`.
- Node.js 24.22.1, the `node24` runtime, refuses an R equal to the identity that
  Node.js 22 accepts. The action now refuses it before Node.js sees it, so the
  verdict no longer depends on the runtime and agrees with the Python and Go
  verifiers.
- The conformance tests run the 20 shared `ed25519-*.json` vectors: the 17 given
  as receipts through the action's verify path, the 3 RFC 8032 vectors through
  the action's key reader and the vendored strict check.
- The vendored copies are re-pinned to verifiable-receipts 4d9943a. That commit
  changes `ed25519PublicKeyProblem` and `ed25519SignatureProblem` in the
  library's `src/ed25519-key.ts` to return a reason for anything that is not a
  `Uint8Array` instead of throwing; the action does not vendor that file, and
  none of the files it vendors changed, so the copies and the fixtures are as
  they were. `receipt.ts` keeps `publicKey.asymmetricKeyType` where upstream has
  `publicKey?.asymmetricKeyType`, since its parameter is a `KeyObject`; its
  header now says so.

### Fixed

- With several pinned keys, a refused key or a problem with R is now reported as
  a signature failure. Before, any reason other than "signature does not verify"
  was taken for a check after the signature, so a refused key could hide a
  tampered envelope that another key's signature check reached, and a mix of a
  refused key and a wrong key was not reported as "does not verify under any of
  the N pinned public keys".

## [0.1.0] — 2026-10-30

The first release: a GitHub Action that fails a build when a verifiable receipt
is forged or tampered with, checked offline against public keys pinned in the
workflow.

### Added

- Verifies each receipt file (one receipt or an array) with the checks of the
  verifiable-receipts v2 verifier, vendored from verifiable-receipts 24f5c47:
  the 64-level nesting limit counted on the text, standard base64, the
  `contentHash`, the Ed25519 signature under a pinned key, and agreement of every
  top-level field with the signed `canonical`.
- Rejects a receipt whose signed `expiresAt` has passed, and, with
  `max-age-days`, one whose signed `issuedAt` is too old.
- With `tree-head` and `inclusion-proofs`, checks the tree head's signature
  under a pinned log key and each receipt's RFC 9162 inclusion proof against it.
- Fails closed, makes no network request, escapes receipt text in the job
  summary and annotations, and reports counts and each failure as outputs, with
  one job-summary row per receipt.
- Runs on the `node24` runtime; GitHub removed Node 20 from Actions runners on
  23 September 2026.
- Release files (`dist/index.js`, `action.yml`) carry signed build provenance;
  the release notes give the line to pin the action by its commit.

### Fixed

- Each receipt, key, tree-head and proof file is opened once, and its type check,
  size check and read all go through that one handle, so the file read is the
  file checked. A file whose size changes between the check and the read is
  refused ("file changed while being read").
