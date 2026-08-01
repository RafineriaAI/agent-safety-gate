# Where this sits among the alternatives

Nothing here is a benchmark of anyone else's product. Claims about other tools
come from their own documentation and positioning, linked so you can check them;
claims about this one come from commands in this repository. The purpose of the
page is placement, because most of these categories are complements, not
competitors, and buying the wrong category is the expensive mistake.

## The question each category answers

| Category | Examples | The question it answers |
| --- | --- | --- |
| LLM guardrails | [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails), [Guardrails AI](https://www.guardrailsai.com/), [Llama Guard](https://ai.meta.com/research/publications/llama-guard-llm-based-input-output-safeguard-for-human-ai-conversations/), [Lakera Guard](https://www.lakera.ai/) | "Does this *content* look unsafe?" - classify prompts, outputs and intents, catch injection and jailbreaks |
| MCP gateways | [IBM ContextForge](https://github.com/IBM/mcp-context-forge), [Lasso MCP Gateway](https://www.lasso.security/), [TrueFoundry](https://www.truefoundry.com/blog/best-mcp-gateways), [Lunar MCPX](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026) | "How do many agents reach many servers, with auth, quotas and visibility?" - infrastructure: federation, identity, scanning |
| Agent observability | [LangSmith](https://smith.langchain.com/), [Langfuse](https://langfuse.com/), [AgentOps](https://www.agentops.ai/) | "What did my agent do, and how well?" - traces, evals, dashboards |
| Host permissions | [Claude Code permissions & hooks](https://code.claude.com/docs/en/hooks), allow/deny lists in other hosts | "Should this call run right now?" - interactive, local, per-host |
| Sandboxes | containers, VMs, OS-level isolation | "What is it *physically able* to touch?" - hard boundaries |
| **agent-safety-gate** | this repository | "Was this call allowed by a declared policy - and can I **prove** the answer later, offline, to someone who does not trust my infrastructure?" |

## What the others do that this does not

Stated plainly, because pretending otherwise would be the fastest way to lose
the reader who checks:

* **No content analysis.** Nothing here reads a prompt, an output or a command
  string and scores it. A guardrail product will catch an injection attempt in
  the *text*; this gate only refuses the *action* when the policy's signals do
  not cover it. If your worry is toxic output or leaked PII, you want a
  guardrail, not this.
* **No prevention below the process boundary.** A sandbox stops a call from
  physically reaching the filesystem. The gate stops it at the protocol
  boundary and records why - a compromised host that bypasses the proxy bypasses
  the gate. Evidence is not containment.
* **No fleet features.** No multi-tenant auth, no federation, no rate limits,
  no dashboard, no hosted anything. An MCP gateway platform runs your
  infrastructure; this runs one process and writes files.
* **No quality evals.** Observability platforms tell you whether the agent is
  *good*. This tool has no opinion on that, on purpose.

## What this does that we did not find elsewhere

Feature-level statements about this repository, each with the command that
demonstrates it. "We did not find" means: not documented as a feature by the
tools linked above at the time of writing - check their pages, they change.

| Property | Here | Prove it |
| --- | --- | --- |
| Deterministic decisions: identical call, identical bytes, identical digest | yes, byte-for-byte, across processes and platforms | `python -m pytest tests/test_records.py -q` |
| Signed, hash-chained record per decision | Ed25519 per record, `prev_record_sha256` chain | `agent-safety-gate demo` |
| Offline verification **without trusting the producer** | one HTML file, CSP-blocked network, recomputes every digest in the browser | drop `records.jsonl` on `verifier/verify.html` |
| No model anywhere in the decision path | asserted by a test over dependencies and imports | `python -m pytest tests/test_project_constraints.py -q` |
| Decision replayable months later, in words | `explain` names the signals, the arithmetic and the remediation | `agent-safety-gate explain examples/sample_records.jsonl --line 3` |
| Policy calibrated on recorded traffic before enforcement | `observe` mode + `calibrate` on your own records | `agent-safety-gate calibrate <records> --policy <candidate>` |

The nearest neighbours on the evidence question are the observability
platforms, and the difference is trust topology: their trace lives in a
database an operator can edit, and its integrity rests on the platform. This
record file proves its own integrity to a reader with no account anywhere - the
verifier recomputes the digests rather than believing them, and a flipped byte
turns the exact record red.

## Complements, concretely

These compose, and the composition is the sensible deployment:

* **Guardrail + gate**: the guardrail scores content before the model acts; the
  gate records and enforces the action policy afterwards. A guardrail verdict
  could even arrive as an independent signal in a future phase - it would enter
  `decision_input` like any other measured signal, never as the gate's own
  judgement.
* **Sandbox + gate**: the sandbox bounds what is possible, the gate documents
  what was attempted and why it was allowed. Auditors ask the second question.
* **Gateway + gate**: a gateway is an excellent place to *run* a gate; nothing
  in the record format assumes it is alone in the pipeline.
* **Host permissions + gate**: Claude Code's own permission prompts remain the
  interactive layer; the hook integration feeds them (`ask` on WARN) and leaves
  a signed record they do not produce on their own.

## When not to use this

* Your agent's surface is one raw shell and you will not narrow it: the
  [session replay](../benchmarks/README.md) measured the result - half the
  session interrupted, or a gate in permanent observe mode.
* You need content-level protection today: wrong category, see above.
* You cannot run a proxy or a hook in front of the agent at all: the gate can
  only decide about calls it sees.
