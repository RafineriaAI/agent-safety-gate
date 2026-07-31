# Decisions left to the owner

Three things in this repository are not engineering calls. They are flagged here
rather than resolved.

## 1. The licence

`LICENSE` is a placeholder. Nothing else in the repository can be finished until
this is settled, because the licence decides who can run the tool at all, and
`pyproject.toml`, both READMEs and `LICENSE` must be updated together.

**The trade-off worth naming first:** a restrictive licence is itself a barrier
to entry. This product's whole argument is that an evaluator can go from `pip
install` to a verified record in five minutes and then point the gate at their
own MCP server. A licence that stops them from running it inside their own
pipeline removes most of that value, no matter how good the quickstart is.

| Option | What it gets you | What it costs |
| --- | --- | --- |
| **Apache-2.0** | Widest adoption. Explicit patent grant, which enterprise legal teams look for. Other people's tooling can read and write gate records, which is the only way this record format becomes something an auditor recognises. | A competitor may ship a closed commercial fork. The name and the trademark are your remaining leverage. |
| **BSL 1.1** (converting to Apache-2.0 after 3-4 years) | Free for internal use, including in a customer's own pipeline, so the quickstart still works. Blocks a competitor from selling it as a hosted service during the licensed period. | Unfamiliar to many legal teams; some enterprises refuse non-OSI licences outright, which turns a five-minute evaluation into a three-week review. |
| **Proprietary demonstrator** (matching `aos-kernel`) | Consistent with the kernel's existing notice. Keeps every future option open. | An evaluator cannot legally run it in a real pipeline, which is exactly the step the product is designed to make easy. The repository becomes a brochure. |

A recommendation, to be overridden freely: **BSL 1.1 with an Apache-2.0 change
date** matches the actual worry (someone reselling the gate as a service)
without blocking the evaluation path the product depends on. If the goal is that
the record format spreads, Apache-2.0 is the stronger choice.

Whichever is picked, the vendored kernel file keeps the upstream terms in
[NOTICE](../NOTICE); the new licence covers this repository's own code.

## 2. Signing keys

`examples/demo_signing_key.INSECURE.json` is a real Ed25519 private key,
committed on purpose so that `examples/sample_records.jsonl` is reproducible
byte for byte on any machine. It is labelled
`DEMO KEY - DO NOT USE IN PRODUCTION`, and that label travels into every record
it signs.

`agent-safety-gate demo` does **not** use it: on first run it generates a
separate key in `~/.agent-safety-gate/demo_key.json`, so a user's own records are
signed by a key only they hold.

Production key management - where the operator's private key lives, who can
reach it, how it is rotated, how a verifier learns which public key to trust -
is out of scope for this MVP and is a decision with an infrastructure cost
attached. The gate supports pinning a public key today
(`agent-safety-gate verify --public-key`, and the pin field in `verify.html`),
which is the minimum needed to turn "signed by some key" into "signed by ours".

## 3. Publishing

The package name `agent-safety-gate` is not reserved on PyPI. Until it is
published, the quickstart installs from a checkout, and the README says so.
Publishing requires the licence decision first.

The repository is prepared for `git push` with full history. See
[DELIVERY.md](DELIVERY.md).
