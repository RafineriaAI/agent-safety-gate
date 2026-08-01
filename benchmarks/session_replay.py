"""Replay a real agent session through the gate and count the interruptions.

    python benchmarks/session_replay.py <transcript.jsonl>

`workflow_replay.py` answers "does the policy do what the policy says". This
answers the question that decides whether anyone keeps the gate switched on:
**how often would it have got in the way of work that was actually fine?**

The input is a Claude Code session transcript - one JSON object per line, with
`tool_use` blocks inside assistant messages. Yours live in
`~/.claude/projects/<project>/<session-id>.jsonl`. Any transcript in that shape
works; the loader ignores everything that is not a tool call.

Three numbers come out, and the third is the one worth arguing about:

* **silent**       - calls the operator would never have seen (PASS),
* **flagged**      - forwarded with a warning (WARN),
* **interruptions** - calls that stopped and needed a human (BLOCK), and the
  number of *distinct* approvals those calls would have needed, which is
  smaller, because an approval is bound to a call digest and repeated identical
  calls reuse one.

Nothing here is labelled benign or risky. That labelling is what makes a
self-authored benchmark worthless. The only claim made about this trace is one
an outsider can check: the session ran, the work was accepted, and the
repository it produced is the one you are reading.

Paths and commands outside the workspace are redacted to a placeholder by
default, so a trace derived from your session does not carry your home
directory. Redaction cannot change a verdict as long as the policy's allowlists
are workspace-relative, which the shipped one is; pass --no-redact to check.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_safety_gate.gate import Gate  # noqa: E402
from agent_safety_gate.policy import Policy, load_policy  # noqa: E402
from agent_safety_gate.records import canonical_json_text  # noqa: E402
from agent_safety_gate.signals import ToolCall  # noqa: E402

DEFAULT_POLICY = REPO_ROOT / "benchmarks" / "coding_agent_policy.yaml"
OUTSIDE = "<outside-workspace>"

#: Arguments that carry a target the policy can scope on. Everything else is
#: dropped: a benchmark has no business reading the contents an agent wrote.
KEPT_ARGUMENTS = ("file_path", "path", "command", "pattern", "url", "notebook_path")

#: Commands that inspect or verify and change nothing an operator would miss.
#: This is a statement about the agent's *tool surface*, not about the gate: the
#: gate has no opinion about shell commands and never inspects one. Counting how
#: many shell calls are these lets the report say what a narrower tool surface
#: would be worth, instead of only that a shell is a problem.
INSPECTION_COMMANDS = (
    "python -m pytest",
    "python -m ruff",
    "python -m mypy",
    "git status",
    "git diff",
    "git log",
    "git ls-files",
    "ls ",
    "cat ",
    "head ",
    "wc ",
    "grep ",
)


@dataclass(frozen=True)
class Entry:
    tool: str
    arguments: dict[str, Any]
    dropped: tuple[str, ...]


def _windows_drive_prefixes(workspace: str) -> list[str]:
    """Both spellings of the workspace root, so either survives normalisation."""
    forward = workspace.replace("\\", "/").rstrip("/")
    return [forward, forward.replace("/", "\\")]


def infer_workspace(transcript: Path) -> str:
    """`~/.claude/projects/D--aos-safety-gate/<id>.jsonl` -> `D:/aos-safety-gate`."""
    name = transcript.resolve().parent.name
    match = re.fullmatch(r"([A-Za-z])--(.+)", name)
    if match:
        return f"{match.group(1).upper()}:/{match.group(2).replace('-', '-')}"
    return ""


def relativise(value: str, workspace: str, redact: bool) -> str:
    """Workspace-relative when inside it; a placeholder when outside."""
    if workspace:
        for prefix in _windows_drive_prefixes(workspace):
            if value.lower().startswith(prefix.lower()):
                trimmed = value[len(prefix) :].lstrip("/\\")
                return trimmed.replace("\\", "/") or "."
    if not redact:
        return value
    tail = re.split(r"[/\\]", value.replace("\\", "/"))[-1]
    return f"{OUTSIDE}/{tail}" if tail else OUTSIDE


def scrub_command(command: str, workspace: str, redact: bool) -> str:
    """Rewrite absolute paths inside a shell command, leaving the command itself."""
    if workspace:
        for prefix in _windows_drive_prefixes(workspace):
            command = command.replace(prefix + "/", "").replace(prefix + "\\", "")
            command = command.replace(prefix, ".")
    if not redact:
        return command
    return re.sub(
        r"[A-Za-z]:[/\\]Users[/\\][^\s\"']+|/(?:home|Users)/[^\s\"']+",
        OUTSIDE,
        command,
    )


def load_trace(path: Path) -> list[Entry]:
    """Load a trace this script wrote earlier, so a run can be repeated exactly.

    A transcript grows while the session it records is still running. A trace
    does not, which is the only way a number from a real session can be quoted.
    """
    entries: list[Entry] = []
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{number}: not valid JSON ({exc.msg})") from exc
        entries.append(
            Entry(
                tool=str(payload["tool"]),
                arguments=dict(payload.get("arguments") or {}),
                dropped=tuple(payload.get("dropped_arguments") or ()),
            )
        )
    return entries


def looks_like_a_trace(path: Path) -> bool:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                return False
            return (
                isinstance(payload, dict)
                and "tool" in payload
                and "arguments" in payload
            )
    return False


def load_entries(transcript: Path, workspace: str, redact: bool = True) -> list[Entry]:
    if not transcript.is_file():
        raise SystemExit(
            f"transcript not found: {transcript}\n"
            "Next step: point this at a session file, for example one under "
            "~/.claude/projects/<project>/, or at a trace this script wrote."
        )
    if looks_like_a_trace(transcript):
        return load_trace(transcript)
    entries: list[Entry] = []
    for number, line in enumerate(
        transcript.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            # Transcripts are append-only logs; one unreadable line is not a
            # reason to refuse the other nine hundred.
            continue
        if not isinstance(payload, dict):
            continue
        message = payload.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = block.get("name")
            raw = block.get("input")
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            kept: dict[str, Any] = {}
            for key in KEPT_ARGUMENTS:
                value = raw.get(key)
                if not isinstance(value, str) or not value:
                    continue
                if key == "command":
                    kept[key] = scrub_command(value, workspace, redact)
                else:
                    kept[key] = relativise(value, workspace, redact)
            dropped = tuple(sorted(set(raw) - set(kept)))
            entries.append(Entry(tool=name, arguments=kept, dropped=dropped))
        del number
    if not entries:
        raise SystemExit(
            f"no tool calls found in {transcript}\n"
            "Next step: check that this is a session transcript with `tool_use` "
            "blocks in assistant messages."
        )
    return entries


@dataclass
class Replay:
    total: int
    verdicts: collections.Counter[str]
    by_tool: dict[str, collections.Counter[str]]
    undeclared: list[str]
    blocked_digests: set[str]
    blocked_reasons: collections.Counter[str]
    blocked_inspection: int
    blocked_shell: int


def is_inspection(command: str) -> bool:
    return command.strip().startswith(INSPECTION_COMMANDS)


def replay(gate: Gate, policy: Policy, entries: list[Entry]) -> Replay:
    verdicts: collections.Counter[str] = collections.Counter()
    by_tool: dict[str, collections.Counter[str]] = collections.defaultdict(
        collections.Counter
    )
    blocked_digests: set[str] = set()
    blocked_reasons: collections.Counter[str] = collections.Counter()
    undeclared: set[str] = set()
    blocked_inspection = 0
    blocked_shell = 0

    for entry in entries:
        call = ToolCall(tool=entry.tool, arguments=entry.arguments, server="session")
        decision = gate.evaluate(call)
        verdicts[decision.verdict] += 1
        by_tool[entry.tool][decision.verdict] += 1
        if policy.rule_for(entry.tool) is None:
            undeclared.add(entry.tool)
        if decision.verdict == "BLOCK":
            blocked_digests.add(call.action_digest)
            for item in decision.remediation:
                blocked_reasons[item.signal_id] += 1
            command = entry.arguments.get("command")
            if isinstance(command, str):
                blocked_shell += 1
                if is_inspection(command):
                    blocked_inspection += 1
    return Replay(
        total=len(entries),
        verdicts=verdicts,
        by_tool=dict(by_tool),
        undeclared=sorted(undeclared),
        blocked_digests=blocked_digests,
        blocked_reasons=blocked_reasons,
        blocked_inspection=blocked_inspection,
        blocked_shell=blocked_shell,
    )


def print_report(result: Replay, policy: Policy, transcript: Path) -> None:
    silent = result.verdicts["PASS"]
    flagged = result.verdicts["WARN"]
    interruptions = result.verdicts["BLOCK"]
    print(f"Session replay: {transcript.name}")
    print(f"  policy              {policy.policy_id} ({policy.source_path})")
    print(f"  tool calls          {result.total}")
    print()
    print(f"  silent (PASS)       {silent:4}  {silent / result.total:6.1%}")
    print(f"  flagged (WARN)      {flagged:4}  {flagged / result.total:6.1%}")
    print(
        f"  interrupted (BLOCK) {interruptions:4}  {interruptions / result.total:6.1%}"
    )
    if interruptions:
        distinct = len(result.blocked_digests)
        print(
            f"  distinct approvals  {distinct:4}  "
            f"an approval is bound to one call digest, so {interruptions} "
            f"blocked calls need {distinct} decisions"
        )
    print()
    print("  by tool")
    for tool in sorted(
        result.by_tool, key=lambda name: -sum(result.by_tool[name].values())
    ):
        counts = result.by_tool[tool]
        total = sum(counts.values())
        mark = " (undeclared)" if tool in result.undeclared else ""
        print(
            f"    {tool:<32} {total:4}   PASS {counts['PASS']:4}  "
            f"WARN {counts['WARN']:4}  BLOCK {counts['BLOCK']:4}{mark}"
        )
    if result.undeclared:
        print()
        print(f"  undeclared tools    {', '.join(result.undeclared)}")
        print(f"                      treated as `unknown_tool: {policy.unknown_tool}`")
    if result.blocked_reasons:
        print()
        print("  what caused the interruptions")
        for signal, count in result.blocked_reasons.most_common():
            print(f"    {signal:<24} {count}")
    if result.blocked_shell:
        print()
        print("  what a narrower tool surface would be worth")
        print(
            f"    {result.blocked_inspection} of the {result.blocked_shell} blocked "
            "shell calls only inspect or verify"
        )
        print("    (pytest, ruff, mypy, git status/diff/log, ls, cat, head, wc, grep).")
        print(
            f"    Exposing those as their own read-only tools would leave "
            f"{result.blocked_shell - result.blocked_inspection} interruptions."
        )
        print("    This is a statement about the agent's tools, not about the gate:")
        print("    the gate never inspects a shell command and has no opinion on one.")
    print()
    print("  Every call in this session ran and the work was accepted. That does")
    print("  not make each one safe; it makes every BLOCK a cost the operator")
    print("  would have paid. See benchmarks/README.md.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "transcript",
        type=Path,
        help="a session transcript, or a trace this script wrote earlier",
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument(
        "--workspace",
        default=None,
        help="absolute path of the agent's working directory; inferred from the "
        "transcript's parent directory name when omitted",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="keep paths outside the workspace verbatim (for local runs)",
    )
    parser.add_argument(
        "--trace-out",
        type=Path,
        default=None,
        help="write the extracted calls as a trace file, to inspect or commit",
    )
    args = parser.parse_args(argv)

    workspace = (
        args.workspace
        if args.workspace is not None
        else infer_workspace(args.transcript)
    )
    entries = load_entries(args.transcript, workspace, redact=not args.no_redact)
    policy = load_policy(args.policy)
    result = replay(Gate(policy), policy, entries)
    print_report(result, policy, args.transcript)

    if args.trace_out is not None:
        args.trace_out.parent.mkdir(parents=True, exist_ok=True)
        args.trace_out.write_text(
            "".join(
                canonical_json_text(
                    {
                        "arguments": entry.arguments,
                        "dropped_arguments": list(entry.dropped),
                        "kind": "session",
                        "label": "real session, not labelled",
                        "tool": entry.tool,
                    }
                )
                + "\n"
                for entry in entries
            ),
            encoding="utf-8",
            newline="\n",
        )
        print()
        print(f"  trace written to {args.trace_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
