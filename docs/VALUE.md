# What this tool is actually worth

An honest appraisal, written by the people who built it, which is exactly why
every claim below is either backed by a command or explicitly marked unproven.
If you catch this page asserting something it cannot show, that is a bug -
`tools/audit_claims.py` enforces the same discipline on the READMEs.

## The three pains, and how far each is actually removed

**1. "Nobody can reconstruct why it was allowed."** Removed for every call that
passes through the gate, and demonstrably: `agent-safety-gate explain` replays
the signals, the arithmetic, the policy version and the remediation from one
record, months later, offline.
*Limit:* only calls the gate saw. A call that reached the tool by another path
left no record, and the chain cannot prove completeness - it proves integrity
of what was recorded, not that everything was recorded.

**2. "I can't delegate, because I don't trust it."** Removed in proportion to
how narrow the tool surface is, and this is measured, not asserted: on named
tools the interruptions land only where the operator wanted to be asked
(`python benchmarks/workflow_replay.py` - 0% false alarms on 61 ordinary
calls), while on one raw shell the same policy interrupted half of a real
session (`benchmarks/README.md`, session replay). The approval mechanism is
bounded - one approval covers exactly one call digest - so delegation does not
decay into a blanket "yes".
*Limit:* a shell-shaped agent gets approval fatigue, not trust. That is the
tool's sharpest known limit and it is printed in the README rather than hidden.

**3. "The auditor asks, and we have nothing to show."** The artefact exists and
survives hostile inspection: signed, chained, verifiable on the auditor's own
machine with one HTML file and no account (`agent-safety-gate demo`, then drop
the file on `verifier/verify.html`).
*Limit - and this is the honest core of the whole page:* **no external auditor
has accepted these records yet.** The format is designed to support recording
obligations (Article 12 language, carefully); whether a real audit accepts it
is a claim only adoption can make. Until then, this pain is "addressed", not
"removed".

## Verification status, in one table

| Claim | Status | Evidence |
| --- | --- | --- |
| Deterministic, replayable decisions | proven | `pytest tests/test_records.py` |
| Tamper-evidence + issuer signature | proven | `pytest tests/test_records.py tests/test_verifier_browser.py` |
| Config-only integration, MCP + hooks + subprocess | proven | `pytest tests/test_mcp_proxy.py tests/test_integrations.py` |
| Five-minute first proof | measured | `bash tools/quickstart_check.sh` |
| Useful on named-tool surfaces | measured on our own + independent traces | `python benchmarks/workflow_replay.py`, `python benchmarks/independent_replay.py` |
| Painful on raw-shell surfaces | measured, published | `benchmarks/README.md` session replay |
| Records accepted by auditors | **unproven** | needs external adoption |
| Catch rate on attacks we did not write | **unproven** | the trace was self-authored; see `benchmarks/README.md` |
| Long-term policy maintenance cost | **unknown** | no deployment is old enough |

## Who gets value on day one, ranked

1. **A team running agents over MCP servers with named tools** - the gate fits
   the surface, PASS is silent, records accumulate. This is the design centre.
2. **A team using Claude Code that wants evidence more than enforcement** -
   hook + `mode: observe` costs nothing visible and produces a signed session
   chain; `calibrate` turns it into a policy later.
3. **A vendor who gets asked "what controls do you have around agents?" in
   security questionnaires** - the demo plus a real records file is a
   pointable answer today, with the caveat above stated plainly.
4. **A team whose agent is one shell tool** - least value; start at
   `observe`, or narrow the tools first. The measurements say so.

## ROI, without the theatre

```bash
python tools/roi_model.py --example
```

The model takes *your* incident rate, audit load and hourly cost, subtracts the
costs the gate adds (setup, policy upkeep, the approvals it will generate), and
prints the net. It has no defaults, because a default would be a marketing
number. It also refuses to model the dominant term - the incident that does not
happen - because nobody has that number, and an ROI story built on it would be
fiction with a spreadsheet.

What the floor looks like: reconstruction time is the one input you can ground
today, because you know what the last "why did the agent do that" cost you. If
that number is zero - you have never had to ask - the gate's value to you today
is the audit artefact and the delegation bound, and the model will tell you so
by going negative.

## What would falsify this tool's premise

Worth writing down, because a premise that cannot fail is not a premise:

* Operators who try `observe` mode and never move to `enforce` - then this is a
  logger with signatures, and the enforcement half earns nothing.
* A real audit that rejects the records as evidence - then the differentiating
  artefact is a curiosity.
* False-alarm rates on real traffic that stay above what `calibrate` can tune
  away - then the fatigue problem is fundamental, not configurational.
* Agent frameworks converging on built-in signed audit trails - then the
  standalone gate's window closes, and only the offline verifier remains
  distinctive.

None of these has happened. All of them could. The measurements that exist so
far - two independent trace replays, one public-server wiring, one session that
built this repository - are consistent with the premise and insufficient to
prove it, which is the correct amount of confidence for a tool with zero
external deployments.
