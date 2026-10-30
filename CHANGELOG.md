# Changelog

Notable changes to verify-receipts-action. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Each receipt, key, tree-head and proof file is opened once, and its type check,
  size check and read all go through that one handle, so the file read is the
  file checked. A file whose size changes between the check and the read is
  refused ("file changed while being read").

## [0.1.0] — 2026-10-29

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
