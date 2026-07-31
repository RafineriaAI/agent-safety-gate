# Delivering this repository

The repository is prepared locally with full history and is ready to push to
`https://github.com/RafineriaAI/agent-safety-gate`, which is empty.

## Push it

```bash
cd agent-safety-gate
git remote add origin https://github.com/RafineriaAI/agent-safety-gate.git
git push -u origin main
```

If you would rather move it as a file, the same history travels in a bundle:

```bash
git bundle create agent-safety-gate.bundle --all
# on the other side
git clone agent-safety-gate.bundle agent-safety-gate
```

## Before the first push

Two things in the repository are deliberately unfinished, both flagged in
[OWNER_DECISIONS.md](OWNER_DECISIONS.md):

1. **The licence.** `LICENSE` is a placeholder. Publishing a repository with an
   undecided licence is itself a signal, and a restrictive answer is a barrier to
   entry for exactly the evaluation the quickstart is built around.
   `tests/test_project_constraints.py` fails as soon as the placeholder is
   replaced, so that `pyproject.toml` and both READMEs get updated in the same
   change.
2. **The committed demo key.** `examples/demo_signing_key.INSECURE.json` is a
   real Ed25519 private key, committed on purpose so the sample records are
   reproducible byte for byte. It is labelled in the filename, in the file and in
   every record it signs. GitHub secret scanning does not recognise this format,
   so nothing will flag it; that is a reason to keep the label loud, not to
   remove the key.

## What CI will do on the first push

`.github/workflows/ci.yml` runs `tools/verify_all.sh` on Python 3.11 and 3.12:
lint, format, strict types, the full test suite including the headless browser
verifier and the end-to-end MCP run, the vendored-kernel digest check against an
upstream clone, the claims audit, the benchmark and the README quickstart
executed verbatim in a clean virtual environment.

It also installs `aos-kernel` from GitHub, because the interop test runs against
the real kernel rather than the vendored copy. If that repository is ever made
private, that step fails loudly instead of the test skipping quietly.

## About the history

The commits are ordered by build stage, and each carries the reasoning for what
it changed. CI has been run against the final tree - a fresh clone into a fresh
virtual environment passes all nine steps of `tools/verify_all.sh` - but the
intermediate commits were not individually gated, so `git bisect` across them is
not guaranteed to find a green build at every step.

## Suggested repository settings

* Default branch `main`, protected, with the CI check required.
* Issues enabled: unfinished work lives there, and the code contains no `TODO`
  comments by design (a test enforces it).
* No release yet. A version tag should wait for the licence decision, since
  `pyproject.toml` carries the licence metadata.

## What is not in this repository

Production key management, LangChain integration, approval expiry, and anything
beyond the MCP `tools` capability. Each of those is a phase-2 decision, not an
omission - see the last section of the README.
