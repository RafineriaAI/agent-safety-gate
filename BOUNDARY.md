# Where the kernel ends and this adapter begins

Two different things decide something in this repository, and only one of them
is the AOS kernel. Conflating them would make the kernel look like it knows
things it does not know.

## The kernel decides. It decides one thing.

The kernel is `src/agent_safety_gate/_vendor/aos_kernel/aos_public_core.py`, a
byte-identical copy of `core/aos_public_core.py` from
[RafineriaAI/aos-kernel](https://github.com/RafineriaAI/aos-kernel) v0.1.1. It
is not modified here. See [NOTICE](NOTICE) and
[`_vendor/aos_kernel/VENDOR.md`](src/agent_safety_gate/_vendor/aos_kernel/VENDOR.md).

It takes five bounded numbers and returns a verdict:

| Field | Meaning |
| --- | --- |
| `score` | how much risk the policy assigns to this call, 0..10000 |
| `uncertainty` | how much the gate does not know about this call, 0..10000 |
| `limit` | above this, BLOCK |
| `warn_margin` | the band below `limit` where the verdict is WARN |
| `metadata_complete` | false forces BLOCK |

```text
PASS   when score + uncertainty <= limit - warn_margin
WARN   when score + uncertainty <= limit
BLOCK  otherwise, or whenever metadata_complete is false
```

That is the whole of the kernel's contribution: an interval comparison and a
replayable evidence packet. It has no opinion about `rm -rf`, about MCP, about
prompt injection, or about what a "tool" is.

## Everything else is adapter policy

Every statement below is a decision made in this repository, in
`policy.py`, `signals.py` and `gate.py`, and it is all visible and editable in
one YAML file:

* **Which tools exist and what class of action each performs.** Declared by the
  operator. Never inferred from a tool's name, description or arguments.
* **What each action class costs.** `read_only: 1000`, `irreversible: 4000`, and
  so on. These are weights in a file, not properties of the world.
* **What counts as out of scope.** Literal prefix and domain matching against an
  allowlist the operator writes.
* **What an approval is.** A file named after the call's action digest, in a
  directory the operator controls.
* **What self-attestation is.** The reserved `agent_safety_gate` key on a call.
* **The thresholds.** `limit: 7000`, `warn_margin: 2000`.
* **The human-readable reason and the remediation text.** The kernel returns a
  short reason of its own; the sentence a person reads is written here, from the
  signals, and the kernel's own reason is kept in `kernel_evidence`.

If a number in this repository looks like a safety property, it is a policy
value. Change the YAML and the verdict changes, without touching the kernel.

## The demonstration defaults are demonstration defaults

The weights shipped in `examples/demo_policy.yaml` and
`benchmarks/benchmark_policy.yaml` were chosen to make the demo and the
benchmark legible. They are not tuned, not validated against production traffic,
and not a recommendation.

The same defaults can be right for one deployment and wrong for the next. A
threshold that is correct for a coding agent inside one repository is wrong for
an agent that can send email on your behalf. `unknown_tool: warn` keeps a first
run from being a wall of blocks; `unknown_tool: block` is the safer setting once
your policy is complete, and it is one line.

There are deliberately **no production defaults** in this repository. Calibrate
on your own traffic: replay a real session with
`benchmarks/workflow_replay.py --trace your_trace.jsonl` and look at what the
policy does to calls you already know the answer for.

## What the record claims, field by field

| Claim | Where it comes from | What it is worth |
| --- | --- | --- |
| the verdict | the kernel, from the five numbers above | deterministic given those numbers |
| the numbers | the adapter, from the policy | only as good as the policy |
| the signals | measured, or explicitly reported as not measured | never invented |
| `record_sha256` and the chain | SHA-256 over canonical JSON | tamper-evident: shows a file was altered |
| `signature` | Ed25519 over the record | unforgeable without the private key; authenticates the issuer, not their identity |
| `input_sha256`, `decision_hash` | SHA-256 over the recorded decision input and material | anyone can recompute them offline |

The word "unforgeable" appears in this repository only about the signature. A
hash chain shows that something changed; it does not stop anyone from writing a
new consistent chain of their own.

## Determinism, precisely

Identical input produces identical decision bytes and identical digests, on any
machine.

* No clock and no randomness enter a decision. The timestamp lives in the record
  envelope, outside `input_sha256` and `decision_hash`.
* No floating-point number is ever hashed. `records.canonical_json_bytes`
  refuses floats, and tool arguments are stored as one canonical JSON *string*
  that both Python and JavaScript hash as UTF-8 bytes rather than
  re-serialising. Nothing is rounded, so no rounding rule can differ between
  implementations.
* Paths are normalised with `posixpath`, not `os.path`, so the same call decides
  the same way on Windows and on Linux.
* The policy digest is part of the decision input, so recalibrating a threshold
  is visible in the digest rather than silently changing what "PASS" meant.

`tests/test_records.py` checks this in process and across processes;
`tests/test_verifier_browser.py` checks that the browser agrees byte for byte on
200 generated values.

## Why the kernel is vendored rather than depended on

`agent-safety-gate` must install with one `pip install` and then run with no
network. `aos-kernel` is a source-available proprietary demonstrator that is not
on PyPI, and PyPI does not accept packages with direct-URL dependencies. A git
dependency would either break `pip install agent-safety-gate` or add a clone
step to the five-minute quickstart. The quickstart wins.

The copy is kept honest three ways: the digest is pinned in
`vendor_manifest.json` and checked by `tools/check_vendor.py`; the file is
compared byte for byte against an upstream checkout when one is available; and
record-format compatibility is tested against the *real* kernel CLI in
`tests/test_kernel_interop.py`, not against the copy.
