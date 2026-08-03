# Benchmarks

Four questions, four commands.

```bash
python benchmarks/workflow_replay.py                            # does the policy do what it says
python benchmarks/session_replay.py <your-session>.jsonl        # would anyone keep it switched on
python benchmarks/independent_replay.py                         # what happens on data none of us made
python benchmarks/agentdojo_replay.py                           # the same, on data that is also labelled
python benchmarks/proxy_overhead.py                             # what does it cost per call
```

The second and third are the uncomfortable ones, and they are the reason the
first is not enough.

## What `workflow_replay.py` measures

`traces/coding_session.jsonl` is a session of a coding agent doing ordinary
work - reading source, editing files inside its scope, running tests, committing,
reading documentation - with risky calls interleaved:

* an irreversible delete outside the declared scope, and one inside it,
* a force push,
* two shell commands that cannot be undone, one of which the agent vouches for
  itself,
* two tools the policy has never heard of,
* an email to a domain outside the allowlist,
* a production deploy,
* a write to `/etc/cron.d/`.

Each entry is labelled `benign` or `risky` in the trace file, so the counting is
explicit and you can argue with the labels. The replay is deterministic: the
same trace and the same policy produce the same verdicts every time, and
`tests/test_benchmark.py` asserts that.

Three numbers come out:

| Number | Definition |
| --- | --- |
| catch rate | risky calls that did **not** come back PASS |
| false alarm rate | ordinary calls that did **not** come back PASS |
| latency | microseconds to decide, and to decide plus write a signed record |

Catch rate and false alarm rate are always reported together. Either one alone
is meaningless: a gate that blocks everything has a perfect catch rate.

## What these numbers do not tell you

**The trace was written by the same people who wrote the gate.** A high catch
rate on it shows that the policy covers the cases we thought of. It says nothing
about the cases we did not think of, which are the ones that will hurt you.

**The policy was not tuned against the trace.** The weights in
`benchmark_policy.yaml` are the same demonstration defaults used elsewhere in
the repository, and they were not adjusted after seeing the results. That makes
the numbers honest, not general.

**A catch here is a policy hit, not a detection.** Nothing in the gate looks at
`rm -rf /home/dev/project` and concludes it is dangerous. The operator declared
`run_shell` irreversible and required an approval; the gate applied that. Point
it at a tool the policy does not declare and it will say so - which is why the
undeclared tools in the trace come back WARN rather than PASS.

**Latency is one machine, one run.** Re-run it on yours.

## Making these numbers mean something for you

Replay your own session. The trace format is one JSON object per line:

```json
{"tool": "write_file", "arguments": {"path": "src/app.py"}, "kind": "benign", "label": "why you think so"}
```

```bash
python benchmarks/workflow_replay.py --trace your_session.jsonl --policy your_policy.yaml
```

Any call you already know the right answer for is worth more than the whole
bundled trace. The false alarm rate on your own traffic is the number that
decides whether your team will keep the gate switched on.

## What `session_replay.py` measures, and what it found

A synthetic trace can only tell you that a policy does what the policy says. It
cannot tell you whether anyone would live with the result. For that you need a
session nobody wrote for the benchmark.

The worked example below is one: the 269 tool calls of the coding-agent session
that built this repository, extracted from its transcript. Nothing in it is
labelled benign or risky - that labelling is exactly what makes a self-authored
benchmark worthless. The only claim made about it is one you can check: the
session ran, the work was accepted, and the repository it produced is the one you
are reading.

The trace is **not committed**. It is session data, and publishing someone's
working transcript is not a decision a benchmark gets to make. So the numbers
below are a worked example, not something you can re-run here - `Running it on
your own session` at the end of this section is the part that matters.

The policy it is replayed against, `coding_agent_policy.yaml`, is a careful
first cut for that tool surface: read and search are read-only, writes and edits
are reversible inside the tree, a shell is irreversible. It has **not** been
adjusted after seeing the results.

```text
tool calls          269
silent  (PASS)      118   43.9%
flagged (WARN)       18    6.7%
interrupted (BLOCK) 133   49.4%
distinct approvals  133
```

### Half of a real session would have stopped

That is the finding, and it is not a tuning problem. Every one of the 133
interruptions is a `Bash` call, and all 130-odd shell calls in the session are
one tool with a free-form argument.

The gate assigns an action class per tool. A shell can do anything, so the only
honest class for it is the worst thing it can do, and the gate refuses to look
at the command text to decide otherwise - it has no classifier, by design. The
result is that a do-anything tool is either approved every time or blocked every
time. There is no third answer available in this model, and pretending otherwise
would mean guessing.

The approval design does not rescue it either. An approval is bound to one call
digest, so repeated identical calls share one - but in this session all 133
blocked calls were different commands, so the reuse is worth nothing here.

**What this means for where the gate is useful today.** In front of an agent
whose tools are narrow and named - an MCP server exposing `run_tests`,
`git_commit`, `deploy` - the classes fit and the interruptions land only where an
operator wanted to be asked. In front of a raw shell, it is approval fatigue with
extra steps. That is a real limit of the MVP, found by measuring rather than by
argument, and the README says so.

As a partial measure of the remedy: 32 of the 133 blocked shell calls are
inspection or verification commands (`pytest`, `ruff`, `mypy`, `git status`,
`git diff`, `ls`, `cat`). Exposing those as their own read-only tools would leave
101 interruptions. That is a statement about the agent's tool surface, not about
the gate: the gate never inspects a shell command and has no opinion on one.

### The warnings were a policy bug, not a risk

All 18 WARNs are worth reading one by one, because 11 of them are the same
mistake: the allowlist listed directories (`src/`, `tests/`, `docs/`, ...) and
forgot the files at the root of the repository. Editing `README.md`,
`pyproject.toml`, `LICENSE` or `NOTICE` therefore counted as out of scope.

Nothing was at risk. The policy was simply wrong, and one run against a real
session found it in seconds. That is the everyday use of this tool: point it at
work you have already done and see what your policy would have said about it.

The remaining warnings are correct - two writes genuinely outside the workspace,
and five calls to browser tools the policy had never heard of, which the gate
named rather than guessed at.

### Running it on your own session

```bash
python benchmarks/session_replay.py ~/.claude/projects/<project>/<session-id>.jsonl
```

Any transcript with `tool_use` blocks in assistant messages works. File contents
are never read into the trace - only the arguments a policy can scope on - and
paths outside the workspace are redacted to a placeholder, so a trace you save
does not carry your home directory. `--trace-out` writes the extracted calls if
you want to inspect or keep them; `--no-redact` turns the redaction off for a
local run.

A transcript grows while the session it records is still running, which is why
the committed number comes from a saved trace rather than from a live log.

## What `independent_replay.py` measures, and what it changed

Both benchmarks above run on traffic produced on this machine. The third does
not. It replays published trajectories from
[`nebius/SWE-rebench-openhands-trajectories`](https://huggingface.co/datasets/nebius/SWE-rebench-openhands-trajectories):
another agent framework (OpenHands), another model, other people's
repositories, sessions none of us ran.

```text
trajectories        40
repositories        38
tool calls        2 525

  execute_bash        1290  51.1%
  str_replace_editor  1047  41.5%
  think                102   4.0%
  task_tracker          48   1.9%
  finish                38   1.5%
```

Rows are fetched once over the public datasets-server JSON API and cached under
`benchmarks/.cache/`, which is not committed. `--limit` controls how many.

### It confirmed the bad news

51.1% of an independent agent's calls are one do-anything shell. The session
that built this repository was 49.4%. Two different agents, two different
models, the same shape: about half of a coding agent's work goes through a tool
whose action class cannot be declared without declaring the worst case.

That is not a quirk of one transcript, and it is not something a threshold can
fix.

### It found something the policy could not say

`str_replace_editor` is one tool that reads *and* writes, and which of the two
it does is carried by its `command` argument. **668 of its 1 047 calls - 63.8% -
are `view`, a read.** One class per tool cannot express that: whatever the
operator writes, two thirds of those calls go into the record as the wrong kind
of action.

So the policy can now declare a class per value of a selector argument:

```yaml
str_replace_editor:
  action_class:
    argument: command
    values:
      view: read_only
      create: reversible_write
      str_replace: reversible_write
    default: irreversible      # a value you did not list is one you did not think about
```

Still a declaration, not an inference: the gate reads the value the call carries
and looks it up in the file. A call that carries no selector at all is reported
as not measured, not quietly given the default.

### What it is worth, including where it is worth nothing

The report replays three policies, because "better than the worst alternative"
is not a measurement:

```text
one class, cautious          PASS   188 ( 7.4%)   WARN     0   BLOCK  2337
one class, pragmatic         PASS  1201 (47.6%)   WARN    34   BLOCK  1290
class per argument value     PASS  1201 (47.6%)   WARN    34   BLOCK  1290
```

Against a cautious operator who declares the editor `irreversible`, the finer
policy moves 1 013 calls (40.1%) to PASS. **Against a pragmatic operator who
declares it `reversible_write`, it changes no verdict at all.**

What it does change either way is what the record says: 687 calls (27.2% of the
sample) carry a different action class than the pragmatic one-class policy would
have recorded - reads that would otherwise be written down as writes. For a tool
whose first job is reconstructing what happened, that is the half that matters,
and on this traffic it is the whole of what the feature buys.

### And it explains the mode switch

Half the calls of a real agent hitting a shell means an enforcing gate stops
half the session on day one. `mode: observe` records every decision and forwards
the call anyway, so a deployment can see what the gate would do before it starts
saying no. The verdict, the reason and the remediation are identical; only
enforcement differs, the record carries `policy_mode` and
`enforcement: forwarded_not_enforced`, and `verify` prints a line for every call
that was decided but not enforced.

It is a rollout step, not a setting to leave alone.

## What `proxy_overhead.py` measures

The cost of a `tools/call` in three configurations: straight to the server,
through a proxy that only forwards
(`passthrough_baseline.py`), and through `agent-safety-gate wrap`.

The middle line exists so the last number is honest. Putting any proxy between
an agent and a tool server costs a second process and a second round trip; that
belongs to proxying, not to the gate. The gate's own cost is the difference
between the second and third lines.
