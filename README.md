# agent-safety-gate

*Polish version: [README.pl.md](README.pl.md)*

## Monday morning

Your agent did something on Friday. Someone is asking you why it was allowed.

You have the agent's transcript in one place, the tool server's logs in another,
and CI logs in a third. Two hours later you have a story that sounds plausible.
You cannot prove it, you cannot replay it, and you are not certain it is what
happened.

Here is what that looks like when the calls went through a gate first:

```text
PASS   fetch_url    The agent reads the setup page it was asked to follow.
                    Every control signal was measured and came from a source other than the gated agent.
WARN   write_file   The page told it to leave a note outside the area it was given.
                    Forwarded with a warning because path='docs/NOTES.md' is outside the declared scope (paths src/, tests/).
BLOCK  run_shell    The page told it to wipe the workspace and force-push. The agent vouches for itself.
                    Blocked because the gated agent attached its own safety claim to this call (self-attestation, never
                    counted in favour of the call); the scope of this call could not be measured; no independent approval
                    exists for this `irreversible` call.
```

Three signed records, chained. Drop the file into a single HTML page and every
digest is recomputed in front of you, offline. That page is the product.

**agent-safety-gate** sits in front of an agent's tool calls and answers one
question before each one runs: *are the control signals around this call
complete, and did any of them come from somewhere other than the agent itself?*
It returns PASS, WARN or BLOCK, and leaves a signed, replayable record either
way.

## What this is NOT

* It does **not** improve the agent, review its code, or judge whether an action
  was a good idea.
* It contains **no language model**. There is no LLM judge inside the gate, no
  classifier, no heuristic that looks at `rm -rf` and decides it is scary. Grep
  the dependencies; `tests/test_project_constraints.py` asserts it.
* It does **not** detect dangerous actions. The operator declares what each tool
  does. The gate applies that declaration and reports what it could not measure.
* It does **not** guarantee compliance with anything. See
  [Recording obligations](#recording-obligations) for what it is designed to
  support.

The one safety claim it makes: **paths that cannot be audited are cut off or
marked.** That is all.

## Quickstart

From a clone of this repository. Once the package is published to PyPI, the
first line becomes `pip install agent-safety-gate`; see
[docs/OWNER_DECISIONS.md](docs/OWNER_DECISIONS.md).

<!-- quickstart:begin -->
```bash
pip install .
agent-safety-gate demo
```
<!-- quickstart:end -->

`demo` writes three records, copies the verifier next to them, and tells you to
open it. No account, no registration, no network, no configuration. A signing key
is generated on first run and labelled `DEMO KEY - DO NOT USE IN PRODUCTION`.

Then open `verify.html` and drop `records.jsonl` onto it. You are looking at a
blocked irreversible action with a green signature check, computed in your
browser.

**Measured time from `pip install` to that green check: 10.3 s**
(8-11 s across runs on one laptop, headless browser doing the dragging).

```bash
bash tools/quickstart_check.sh   # runs the two commands above verbatim and times it
```

## Pain, feature, proof

| The pain | What the gate does | Prove it |
| --- | --- | --- |
| "It did something and nobody can reconstruct why it was allowed." | Every call leaves one record with the signals, the numbers, the verdict and the reason. `explain` reads it back in English months later. | `agent-safety-gate explain examples/sample_records.jsonl --line 3` |
| "I can't delegate, because I don't trust it." Approving everything is approval fatigue; approving nothing means not delegating. | Irreversible and external-effect calls are blocked unless an independent approval exists, bound to that exact call. Everything reversible and in scope passes silently. | `python benchmarks/workflow_replay.py` |
| "An auditor asks what control we have over agents, and we have nothing to show." | A signed, chained record file, and a single HTML page that verifies it offline on the auditor's own machine, with no install and no trust in us. | `agent-safety-gate demo` then drop the file into `verify.html` |
| "The agent read a poisoned page and acted on it." | The gate never counts the agent's own claim about a call in favour of that call. A call carrying a self-assessment is blocked. | `agent-safety-gate explain examples/sample_records.jsonl --line 3` |
| "Wiring a new tool server up to anything takes a day." | One YAML file, one changed address in the client config. No code change on either side. | `python tools/measure_wiring.py --policy examples/public_server_policy.yaml --tool get_current_time --arguments '{"timezone": "Europe/Warsaw"}'` |

## Wrap your own MCP server

The gate is an MCP proxy. Your client connects to it instead of to the tool
server; the tool server does not know it is there.

```bash
pip install "agent-safety-gate[mcp]"
```

Write one policy file:

```yaml
policy_id: my_agent
policy_version: "1.0.0"

upstream:
  label: my-tools
  command: [python, -m, my_mcp_server]

tools:
  read_file:
    action_class: read_only
    scope:
      argument: path
      allow_path_prefixes: [src/, tests/]
  write_file:
    action_class: reversible_write
    scope:
      argument: path
      allow_path_prefixes: [src/]
  run_shell:
    action_class: irreversible      # requires an independent approval
```

Ask the gate what the server exposes and what you have not declared yet:

```bash
agent-safety-gate wrap --policy my_policy.yaml --check
```

It starts the upstream server, lists its tools, and prints a policy block for
the ones you have not covered - with the action class filled in wherever the
server publishes MCP annotations about itself, labelled as a proposal, plus the
scope argument it found in the schema. Where the server says nothing,
`action_class:` is left empty: the gate does not guess what a tool does, and a
guessed class would be worse than no entry.

Then point your MCP client at the gate instead of the server:

```json
{
  "mcpServers": {
    "my-tools": {
      "command": "agent-safety-gate",
      "args": ["wrap", "--policy", "/abs/path/my_policy.yaml"]
    }
  }
}
```

PASS is forwarded unchanged, WARN is forwarded with the warning attached to the
response, BLOCK never reaches the tool. This fits a tool surface that is narrow
and named; put it in front of one do-anything shell tool and you get approval
fatigue, which is measured rather than asserted in
[Usability on a real session](#usability-on-a-real-session). A worked example against a third-party
server is in [`examples/public_server_policy.yaml`](examples/public_server_policy.yaml).

## Read a decision

```bash
agent-safety-gate explain examples/sample_records.jsonl --line 3
```

```text
Record 3 of 3   BLOCK   run_shell
  arguments: {"command":"rm -rf /home/dev/project && git push --force origin main"}

What was measured
  action_class           irreversible   independent   policy:demo_coding_agent@...
  agent_self_assessment  self_attested  SELF-ATTESTED gated agent (call metadata)
  approval_present       absent         independent   approvals_dir:...
  policy_coverage        covered        independent   policy:demo_coding_agent@...
  scope_match            not measured   independent   policy:demo_coding_agent@...

What to do
  3. `run_shell` is declared `irreversible` and requires an independent approval, which is missing
     -> If a human really wants this exact call to run, write an approval file bound to its
        action digest. The approval covers these arguments only: change one character and the
        digest no longer matches.
        mkdir -p .agent-safety-gate/approvals && printf '{"approved_by":"me"}' > .agent-safety-gate/approvals/266cba07....json
```

Every decision says what was missing and what to do about it, not just a code.

## Verify a chain offline

On the command line:

```bash
agent-safety-gate verify examples/sample_records.jsonl
agent-safety-gate verify examples/sample_records.jsonl --public-key b7aaWkspKWjoOeaWZ5zE4g3D4gp5EkGIUhA4gT0zzBk=
```

Or in a browser, with nothing installed: open
[`verifier/verify.html`](verifier/verify.html) and drop any record file onto it -
including one from your own run, which is the point. The page recomputes every
digest, follows the chain and checks every Ed25519 signature with WebCrypto. It
declares a content security policy that forbids network access, so "nothing is
uploaded" is something the browser enforces rather than something we promise.

Two different properties, and the difference matters:

* the **hash chain** is *tamper-evident*: it shows that a file was altered, and
  which record;
* the **Ed25519 signature** is *issuer authentication*: it is unforgeable
  without the private key.

A valid signature says the holder of that key signed the record. It does not say
who the holder is. Pin the key you expect - that is what `--public-key` and the
pin field on the page are for.

## Works with what you already run

Three doors, one gate, one record chain - all configuration, no code changes:

* **MCP proxy** (`wrap`) - Claude Desktop, Cursor, Windsurf, Claude Code and
  anything else with an `mcpServers` config points at the gate instead of the
  server.
* **Claude Code hook** (`hook`) - one entry in `.claude/settings.json` gates the
  *native* tools (Bash, Edit, Write) that no MCP proxy can see. PASS stops
  prompting, WARN asks with the reason, BLOCK denies with the remediation; a
  missing policy never bricks the agent.
* **Any framework** (`eval`) - a subprocess primitive: JSON in, verdict and
  signed record out, exit codes 0/3/2.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "agent-safety-gate hook" } ] }
    ]
  }
}
```

Then calibrate on your own recorded traffic before you enforce anything:

```bash
agent-safety-gate calibrate .agent-safety-gate/records.jsonl --policy candidate.yaml
```

Snippets for every host, the verdict-to-permission mapping and the policy
discovery rules are in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## How it decides

For every call the gate collects four signals, plus one observation about the
agent itself. Each carries where it came from and whether that source is
independent of the gated agent.

| Signal | Values | Where it comes from |
| --- | --- | --- |
| `action_class` | `read_only` / `reversible_write` / `irreversible` / `external_effect` | the policy entry for that tool, never a heuristic |
| `scope_match` | in scope / out of scope | literal prefix or domain matching against the allowlist |
| `approval_present` | present / absent / not required | a file named after the call's action digest, in a directory the operator controls |
| `policy_coverage` | covered / absent | whether the policy knows this tool at all |
| `agent_self_assessment` | absent / self-attested | the reserved `agent_safety_gate` key on the call |

Two rules never bend:

1. **A signal produced by the gated agent never counts in favour of PASS.** A
   call that carries the agent's own safety claim is recorded with
   `independent: false` and blocked. Self-assessment can only tighten a decision.
2. **A missing signal feeds uncertainty.** The gate never invents a value or a
   severity for something it did not measure. An undeclared tool produces
   uncertainty, not a guessed action class.

The signals become two bounded numbers - a score and an uncertainty - which the
AOS kernel turns into PASS, WARN or BLOCK. Which numbers, and which thresholds,
is policy; the comparison is the kernel. That line is drawn field by field in
[BOUNDARY.md](BOUNDARY.md).

### These thresholds are demonstration defaults

The weights in `examples/demo_policy.yaml` exist to make the demo legible. They
are not tuned and not a recommendation. The same defaults are right for one task
and wrong for the next: a threshold that suits a coding agent inside one
repository is wrong for an agent that can send mail on your behalf.

There are no "production" defaults here on purpose. Calibrate on your own
traffic - replay a session you already know the answers for:

```bash
python benchmarks/workflow_replay.py --trace your_session.jsonl --policy your_policy.yaml
```

## Numbers, and how to reproduce them

Every number below comes from a command in this repository. Run it yourself; all
of them were measured on one ordinary laptop and none of them will be identical
on yours.

### Workflow replay

`python benchmarks/workflow_replay.py`

| | |
| --- | --- |
| trace | 71 calls: 61 ordinary, 10 risky |
| catch rate | 100% (10/10 risky calls not passed; 7 blocked outright, 3 warned) |
| false alarm rate | 0% (0/61 ordinary calls not passed) |
| decision | p50 78 us, p95 179 us |
| decision + signed record | p50 255 us, p95 418 us |

A catch rate on a trace written by the same people who wrote the gate shows that
the policy covers the cases we thought of, and nothing more.
[benchmarks/README.md](benchmarks/README.md) says what else these numbers do not
tell you, and how to replace them with numbers from your own session.

### Usability on a real session

```bash
python benchmarks/session_replay.py ~/.claude/projects/<project>/<session-id>.jsonl
```

Run that on a session of your own. The numbers below come from the 269 tool
calls of the coding-agent session that built this repository, replayed against a
careful first-cut policy for that tool surface. Nothing in it was labelled benign
or risky, and the policy was not adjusted after seeing the result.

The trace itself is not shipped: it is session data, and it is not ours to
publish. So treat these four numbers as a worked example rather than as a
benchmark you can re-run - the command above gives you the version that counts,
which is the one measured on your own traffic.

| | |
| --- | --- |
| silent (PASS) | 118 (43.9%) |
| flagged (WARN) | 18 (6.7%) |
| interrupted (BLOCK) | 133 (49.4%) |
| distinct approvals those would need | 133 |

**Half of a real session would have stopped, and all of it was one tool.** Every
interruption is a `Bash` call. The gate assigns an action class per tool; a shell
can do anything, so the only honest class for it is the worst thing it can do,
and the gate will not read the command text to decide otherwise. A do-anything
tool is therefore approved every time or blocked every time.

So: in front of an agent whose tools are narrow and named - an MCP server
exposing `run_tests`, `git_commit`, `deploy` - the classes fit and the
interruptions land where an operator wanted to be asked. In front of a raw
shell, this is approval fatigue with extra steps. That is a real limit of the
MVP, found by measuring instead of arguing, and
[benchmarks/README.md](benchmarks/README.md) works through it.

The 18 warnings turned out to be a bug in the policy rather than a risk: the
allowlist named directories and forgot the files at the repository root, so
editing `README.md` counted as out of scope. One run against real work found it.
That is the everyday use of this: point it at work you have already done and see
what your policy would have said.

### Calibrated against data none of us made

`python benchmarks/independent_replay.py`

Every number above comes from traffic produced on one machine by the people who
wrote the gate. This one does not: it replays published OpenHands trajectories
from [a dataset on the Hugging Face Hub](https://huggingface.co/datasets/nebius/SWE-rebench-openhands-trajectories) -
another agent, another model, 38 other people's repositories, 2 525 tool calls.

| What it showed | Number |
| --- | --- |
| an independent agent's calls that go through one do-anything shell | 51.1% (this repository's own session: 49.4%) |
| calls to the editor tool that are actually reads (`command: view`) | 63.8% |
| calls recorded with a different action class once the policy can say so | 687 (27.2%) |

Two of those numbers changed the tool.

**A class per argument value.** An editor tool that both reads and writes cannot
be described by one class per tool, so the policy can now declare a class per
value of a selector argument. It is still a declaration - the gate looks the
value up in your file and never infers anything. Measured honestly, it moves
40.1% of calls to PASS against a cautious one-class policy and **nothing at all**
against a pragmatic one; what it always changes is what the record says a call
did.

**A mode switch.** Half a real session going through a shell means an enforcing
gate stops half of it on day one. `mode: observe` records every decision and
forwards the call anyway, so you can see what the gate would do before it starts
saying no. Same verdict, same reason, same remediation; the record carries
`policy_mode` and `verify` prints a line for every call that was decided and not
enforced. It is a rollout step, not somewhere to stay.

**And one thing servers already tell you.** MCP lets a server publish
`readOnlyHint`, `destructiveHint` and `openWorldHint` about its own tools. Of the
15 tools on three public reference servers, 14 do. `wrap --check` now fills those
in as *proposals* you confirm, together with the scope argument it found in the
schema. MCP is explicit that annotations are hints a client must treat as
untrusted, so they never reach the gate's decision - only your policy draft.

### What the proxy costs per call

`python benchmarks/proxy_overhead.py`

| Configuration | p50 per `tools/call` |
| --- | --- |
| straight to the tool server | 3.10 ms |
| through a proxy that only forwards | 4.26 ms |
| through `agent-safety-gate wrap` | 5.35 ms |

Proxying at all costs 1.16 ms; the gate itself costs 1.09 ms on top. The middle
row exists so the last number is honest: a second process and a second round trip
belong to proxying, not to the decision.

### Wiring the gate to a server we had not used before

`python tools/measure_wiring.py --policy examples/public_server_policy.yaml --tool get_current_time --arguments '{"timezone": "Europe/Warsaw"}'`

Target: [`mcp-server-time`](https://pypi.org/project/mcp-server-time/), from the
reference MCP server collection - a package from outside this repository, wrapped
without changing a line of it.

| Step | Time (three runs) |
| --- | --- |
| `pip install mcp-server-time` | 2.5 s |
| discovery: start it through the gate and list its tools | 1.2-1.6 s |
| first real call through the proxy, ending in a signed record | 1.5-2.1 s |

The human part is not in that table, because it is one decision per tool -
*is `get_current_time` read-only?* - and pretending to stopwatch a person's
judgement would be the wrong kind of benchmark. The whole integration is
[`examples/public_server_policy.yaml`](examples/public_server_policy.yaml):
37 lines, of which 8 declare the two tools and the rest is comments and
thresholds.

## Recording obligations

Article 12 of the EU AI Act requires high-risk AI systems to allow the automatic
recording of events over their lifetime, so that later inspection is possible.

These records are **designed to support** that kind of obligation: each one
carries what was decided, on what input, under which policy version, with a
digest anyone can recompute and a chain that shows whether the file was altered
afterwards. That is an evidence artefact, and it is the sort of artefact such a
requirement asks for.

It is not a compliance assessment, it does not make a system compliant, and no
one here is your legal adviser. Whether your system is in scope, and what your
obligations are, is a question for people who do that for a living.

## Alternatives, and what this is worth

[docs/COMPARISON.md](docs/COMPARISON.md) places the gate among guardrails, MCP
gateways, observability platforms, host permissions and sandboxes - including
what each of them does that this does not, and when not to use this at all.
Short version: they answer "is this content safe" or "what can it touch"; this
answers "was it allowed by a declared policy, provably, offline".

[docs/VALUE.md](docs/VALUE.md) is the appraisal we would want to read before
adopting someone else's safety tool: which of the three pains is actually
removed, which claims are still unproven (no external audit has accepted these
records yet), and what would falsify the premise. The ROI model has no default
numbers, on purpose:

```bash
python tools/roi_model.py --example
```

## Dependency budget

Standard library first. One sentence of justification per dependency, and adding
one means removing something else.

| Dependency | Why |
| --- | --- |
| `cryptography` | Ed25519 signing and verification of records. |
| `PyYAML` | Parsing the one policy file an operator edits. |
| `mcp` (extra `[mcp]`) | The MCP proxy, and only that: the gate, the records and the verifier all work without it. |

That is the entire list, and `tests/test_project_constraints.py` fails if it
grows. No services, no database, no daemon: the proxy is a process and the
records are files. The verifier stays one HTML file.

The AOS kernel decision core is vendored rather than depended on, for reasons
set out in [BOUNDARY.md](BOUNDARY.md).

## What is in here

```text
src/agent_safety_gate/
  gate.py        signals in, PASS/WARN/BLOCK and a signed record out
  signals.py     what was measured, from where, how independently
  policy.py      the one file an operator edits
  records.py     canonical bytes, hash chain, offline verification
  signing.py     Ed25519
  mcp_proxy.py   the MCP integration, the only place that imports the MCP SDK
  cli.py         demo, wrap, hook, eval, explain, verify, calibrate
  integrations.py  the hook/eval/calibrate door: no framework required
verifier/verify.html   one file, no network, drop a record file on it
examples/              demo policy, demo tool server, a wrapped third-party server
benchmarks/            workflow replay and proxy overhead, with their own README
tools/verify_all.sh    everything below, in one command
```

```bash
bash tools/verify_all.sh
```

Runs lint, types, the whole test suite, the vendored-kernel digest check, the
browser verifier in headless Chromium, the benchmark, the claim audit and the
quickstart, verbatim.

## The kernel underneath

The verdict arithmetic comes from
[RafineriaAI/aos-kernel](https://github.com/RafineriaAI/aos-kernel) v0.1.1, a
public demonstrator of deterministic PASS/WARN/BLOCK decisions with replayable
evidence. It is not modified here; see [NOTICE](NOTICE). Records written by this
gate are still accepted by the kernel's own `aos trust verify`, which
`tests/test_kernel_interop.py` checks against the real kernel rather than
against the vendored copy.

## Licence

Not yet chosen. [LICENSE](LICENSE) is a placeholder and
[docs/OWNER_DECISIONS.md](docs/OWNER_DECISIONS.md) sets out the options and what
each one costs. Until then: all rights reserved, evaluation encouraged.

## Not in this version

One action class per tool, which fits named tools and not a general-purpose
shell - see [Usability on a real session](#usability-on-a-real-session).
MCP is the only integration; LangChain is a later phase. Approvals do not expire.
Only the `tools` capability is proxied, so prompts, resources and sampling are
not forwarded. Production key management is out of scope. Open issues, not `TODO`
comments - there are none of those in the code, and a test enforces it.
