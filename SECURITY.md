# Security

## Reporting a vulnerability

Report a suspected flaw privately, through a GitHub security advisory:
<https://github.com/christiaan839-beep/verify-receipts-action/security/advisories/new>
(the repository's **Security** tab, then **Report a vulnerability**).
Don't open a public issue for it.

If you cannot use GitHub, email `sovereign.systems007@gmail.com` with
`[security]` at the start of the subject.

Please include the version or commit, the workflow inputs, what you expected
and what happened, and the receipts, keys, tree head or proofs that show it,
using test keys only, never a key in real use.

You should get a first reply within seven days. A fix is developed in the
private advisory, and the advisory is published with the release that
fixes it, crediting you unless you ask otherwise.

## Scope

In scope: anything that makes the action pass a receipt that is forged,
tampered with, signed by a key that is not pinned, or missing from the log
when inclusion is checked; a way for a receipt or input to run code, read
files outside the workspace or reach the network; and a crash or hang on
attacker-supplied files.

Out of scope: a pinned key that is itself compromised, a workflow that pins
the action by tag or branch instead of a full commit SHA, and
vulnerabilities in dependencies that do not affect the bundled code (report
those upstream).

## Supported versions

Fixes go into `main` and the latest release; older versions are not
patched. Releases are immutable and carry a signed provenance attestation
for `dist/index.js` (see `RELEASING.md`).
