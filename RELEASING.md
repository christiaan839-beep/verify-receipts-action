# Releasing

A release is a `vX.Y.Z` tag that matches `version` in `package.json` and
points at a commit on `main`. `dist/` must already be built and committed;
CI fails a pull request whose `dist/` does not match the sources.

Pushing the tag starts `.github/workflows/release.yml`. It runs the CI and
self-test workflows, records a signed build-provenance attestation for
`dist/index.js` and `action.yml`, and waits for a maintainer to approve the
`release` environment. After approval it creates the GitHub release with
those two files, a `SHA256SUMS` file and the attestation bundle
(`attestation.sigstore.json`). The release notes give the line to pin the
action by its full commit SHA.

Releases are immutable: once published, a release's tag and files cannot
change. There is no moving `v1` tag; pin a full SHA and let Dependabot
propose updates.

## A release

1. Bump `version` in `package.json` (and `package-lock.json`), rebuild
   `dist/` with `npm run build`, and merge the pull request.
2. Tag the merge commit, signed, and push the tag:

   ```
   git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. Approve the `release` deployment in the Actions run.

## Checking a release

```
gh attestation verify index.js --repo christiaan839-beep/verify-receipts-action
```

## GitHub Marketplace

Listing the action is a manual step on the release page ("Publish this
Action to the GitHub Marketplace"), done once by a maintainer.
