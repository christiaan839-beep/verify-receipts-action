# Contributing

Thank you for helping. This action checks verifiable receipts offline,
against pinned keys, inside a workflow job.

## Reporting

- **A security flaw**: report it privately, as `SECURITY.md` says. Don't
  open a public issue.
- **A bug**: open an issue with the version or commit, the workflow
  inputs, and the receipts, keys, tree head or proofs that show it (test
  keys only).
- **A proposal**: open an issue first for anything that changes the
  inputs, outputs or what the action accepts.

## Changing code

1. Fork, branch from `main`, and open a pull request. CI must pass and
   every review conversation must be resolved before it merges; `main`
   takes merge commits only.
2. `dist/` is the bundle the action runs. Rebuild it with `npm run build`
   and commit it with the source change; CI fails when it does not match.
3. `src/vendor/verifiable-receipts/` and `test/fixtures/conformance/` come
   from one verifiable-receipts commit (`VR_REF` in
   `.github/workflows/ci.yml`). Change the verifier there first, then
   bring the change here with the fixtures and update `VR_REF`.
4. Add tests with the change.

## The checks CI runs

```bash
npm ci
npm run typecheck
npm run lint
npm test
npm run build && git diff --exit-code dist/
```

The `self-test` workflow runs the action on `selftest/`. CodeQL, zizmor
and OpenSSF Scorecard report to code scanning.

## Style

- Plain, declarative prose in docs and comments; each fact once.
- Commit messages: a subject line under 72 characters, a blank line, then
  what changed and why.

By contributing you agree that your contribution is licensed under the
Apache License 2.0 (`LICENSE`).
