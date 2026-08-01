"""Integration points that need no framework at all.

The MCP proxy covers agents whose tools arrive over MCP. It cannot see the
native tools of a host application, and it cannot help a framework that does not
speak MCP. Two commands close that gap without adding a dependency to anything:

* ``eval`` - one call in, one verdict and one signed record out, over argv or
  stdin. Any agent framework that can run a subprocess can gate a call with it.
* ``hook`` - the same decision spoken in the dialect of a Claude Code
  ``PreToolUse`` hook: JSON on stdin, a permission decision on stdout. This is
  the only way to gate Claude Code's *native* tools (Bash, Edit, Write), which
  never pass through an MCP server.

Both append to the same chained record file the proxy writes, so one chain can
tell the whole story of a session regardless of which door a call came through.
Appends are serialised through a lock file, because a host may fire several
hooks at once and a chain with two records claiming the same predecessor is not
a chain.

And ``calibrate`` closes the loop the records open: replay a record file you
already have under a policy you are thinking about, and see which verdicts
would change before you deploy it.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from agent_safety_gate.gate import Decision, Gate
from agent_safety_gate.policy import Policy, PolicyError, load_policy
from agent_safety_gate.records import (
    RecordError,
    append_record,
    read_records,
)
from agent_safety_gate.signals import SELF_ATTESTATION_KEY, ToolCall
from agent_safety_gate.signing import SigningKey

POLICY_ENV: Final = "ASG_POLICY"
RECORDS_ENV: Final = "ASG_RECORDS"
DEFAULT_POLICY_RELATIVE: Final = Path(".agent-safety-gate") / "policy.yaml"

#: How long an append waits for the chain lock, and when a leftover lock from a
#: crashed process is considered abandoned.
LOCK_TIMEOUT_SECONDS: Final = 10.0
LOCK_STALE_SECONDS: Final = 60.0


class IntegrationError(Exception):
    """An error with the next step already in the message."""


# ------------------------------------------------------------ policy lookup


def find_policy(explicit: Path | None, cwd: Path) -> Path:
    """Resolve the policy by convention, so integrations can be zero-flag.

    Order: an explicit ``--policy``, the ``ASG_POLICY`` environment variable,
    then ``.agent-safety-gate/policy.yaml`` under the working directory the
    caller reports. Nothing else - guessing a policy would mean guessing what
    is allowed.
    """
    if explicit is not None:
        return explicit
    from_env = os.environ.get(POLICY_ENV)
    if from_env:
        return Path(from_env)
    conventional = cwd / DEFAULT_POLICY_RELATIVE
    if conventional.is_file():
        return conventional
    raise IntegrationError(
        f"no policy found for {cwd}\n"
        f"Next step: create {conventional}, or point --policy or the "
        f"{POLICY_ENV} environment variable at one. "
        "examples/demo_policy.yaml is a working starting point."
    )


def records_path_for(policy: Policy, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    from_env = os.environ.get(RECORDS_ENV)
    if from_env:
        return Path(from_env)
    base = policy.source_path.parent if policy.source_path else Path.cwd()
    # A policy at the conventional .agent-safety-gate/policy.yaml keeps its
    # records beside it, not nested one level deeper.
    if base.name == ".agent-safety-gate":
        return base / "records.jsonl"
    return base / ".agent-safety-gate" / "records.jsonl"


# ------------------------------------------------------------ chained append


def append_to_chain(
    records_path: Path,
    gate: Gate,
    decision: Decision,
    key: SigningKey,
    mode: str,
) -> dict[str, Any]:
    """Append one record, holding a lock so concurrent hooks cannot fork the chain."""
    lock_path = records_path.with_name(records_path.name + ".lock")
    records_path.parent.mkdir(parents=True, exist_ok=True)
    acquired = _acquire_lock(lock_path)
    try:
        prev: str | None = None
        index = 0
        if records_path.is_file():
            existing = read_records(records_path)
            index = len(existing)
            last = existing[-1].get("record_sha256")
            prev = last if isinstance(last, str) else None
        record = gate.build_record(
            decision,
            key=key,
            chain_index=index,
            prev_record_sha256=prev,
            mode=mode,
        )
        append_record(records_path, record)
        return record
    finally:
        if acquired:
            try:
                lock_path.unlink()
            except OSError:  # pragma: no cover - already removed
                pass


def _acquire_lock(lock_path: Path) -> bool:
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            handle = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(handle)
            return True
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
                if age > LOCK_STALE_SECONDS:
                    lock_path.unlink()
                    continue
            except OSError:
                continue
            if time.monotonic() > deadline:
                raise IntegrationError(
                    f"could not acquire the chain lock at {lock_path}\n"
                    "Next step: if no gate process is running, delete that file; "
                    "it is left over from a crash."
                ) from None
            time.sleep(0.05)


# ---------------------------------------------------------------- eval


@dataclass(frozen=True)
class EvalResult:
    decision: Decision
    record: dict[str, Any]
    records_path: Path
    forwarded: bool


def evaluate_once(
    policy: Policy,
    key: SigningKey,
    tool: str,
    arguments: dict[str, Any],
    records_path: Path,
    *,
    mode: str,
    server: str = "external",
) -> EvalResult:
    gate = Gate(policy)
    decision = gate.evaluate(ToolCall(tool=tool, arguments=arguments, server=server))
    record = append_to_chain(records_path, gate, decision, key, mode)
    return EvalResult(
        decision=decision,
        record=record,
        records_path=records_path,
        forwarded=gate.should_forward(decision),
    )


def eval_payload(result: EvalResult, policy: Policy) -> dict[str, Any]:
    """The machine-readable answer any wrapper can act on."""
    return {
        "enforcement": result.record["enforcement"],
        "forward": result.forwarded,
        "mode": policy.mode,
        "reason": result.decision.reason,
        "record_sha256": result.record["record_sha256"],
        "records_file": str(result.records_path),
        "remediation": [item.as_dict() for item in result.decision.remediation],
        "verdict": result.decision.verdict,
    }


# ---------------------------------------------------------------- hook


def hook_response(result: EvalResult, policy: Policy) -> dict[str, Any] | None:
    """Map a decision onto the Claude Code PreToolUse contract.

    * enforce: PASS -> allow, WARN -> ask (the human sees the reason),
      BLOCK -> deny (the agent sees the reason and the remediation).
    * observe: defer - the normal permission flow decides, the record exists
      either way. Observing must not auto-approve anything: `allow` would
      remove prompts the user would otherwise have seen, which is the opposite
      of a mode whose whole point is changing nothing.

    ``None`` means "print nothing": exit 0 with no JSON is the documented way
    to leave the decision entirely to the normal flow.
    """
    decision = result.decision
    suffix = (
        f" [record {str(result.record['record_sha256'])[:12]} in {result.records_path}]"
    )
    if not policy.enforcing:
        return _hook_decision(
            "defer",
            f"recorded, not enforced: {decision.verdict}. {decision.reason}{suffix}",
        )
    if decision.verdict == "PASS":
        return _hook_decision("allow", decision.reason + suffix)
    if decision.verdict == "WARN":
        return _hook_decision("ask", decision.reason + suffix)
    steps = " ".join(item.action for item in decision.remediation)
    return _hook_decision("deny", f"{decision.reason} {steps}{suffix}".strip())


def _hook_decision(decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def parse_hook_input(raw: str) -> tuple[str, dict[str, Any], Path]:
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntegrationError(
            f"stdin is not valid JSON ({exc.msg})\n"
            "Next step: this command is meant to run as a Claude Code "
            "PreToolUse hook, which pipes the event JSON to stdin."
        ) from exc
    if not isinstance(payload, dict):
        raise IntegrationError("the hook event must be a JSON object")
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise IntegrationError(
            "the hook event has no tool_name\n"
            "Next step: register this command under hooks.PreToolUse; other "
            "hook events do not carry a tool call to gate."
        )
    arguments = payload.get("tool_input")
    if not isinstance(arguments, dict):
        arguments = {}
    cwd = payload.get("cwd")
    return tool, arguments, Path(cwd) if isinstance(cwd, str) and cwd else Path.cwd()


# ------------------------------------------------------------- calibrate


@dataclass(frozen=True)
class Transition:
    line: int
    tool: str
    old: str
    new: str
    reason: str


@dataclass
class Calibration:
    total: int
    replayed: int
    skipped_no_arguments: int
    transitions: list[Transition]
    old_counts: Counter[str]
    new_counts: Counter[str]


def calibrate(records_file: Path, candidate: Policy) -> Calibration:
    """What would this policy have said about calls you already recorded?

    Approvals are checked against the approvals directory as it is *now*: the
    question calibrate answers is "what happens if I deploy this today", not
    "what would have happened then".
    """
    try:
        records = read_records(records_file)
    except RecordError as exc:
        raise IntegrationError(str(exc)) from exc
    gate = Gate(candidate)
    transitions: list[Transition] = []
    old_counts: Counter[str] = Counter()
    new_counts: Counter[str] = Counter()
    replayed = 0
    skipped = 0
    for line, record in enumerate(records, start=1):
        call = record.get("call") or {}
        tool = call.get("tool")
        arguments_json = call.get("arguments_json")
        old = str(record.get("aos_verdict", "?"))
        if not isinstance(tool, str) or not isinstance(arguments_json, str):
            # record_arguments: digest_only - the call cannot be replayed.
            skipped += 1
            continue
        try:
            arguments = json.loads(arguments_json)
        except json.JSONDecodeError:
            skipped += 1
            continue
        # Self-attestation may have arrived via MCP _meta, which the record
        # keeps only as a signal. Reconstruct it so the iron rule still holds
        # on replay.
        meta = None
        for signal in record.get("signals") or []:
            if (
                signal.get("id") == "agent_self_assessment"
                and signal.get("value") == "self_attested"
                and SELF_ATTESTATION_KEY not in arguments
            ):
                meta = {SELF_ATTESTATION_KEY: {"replayed_from_record": True}}
        decision = gate.evaluate(
            ToolCall(tool=tool, arguments=arguments, server="calibrate", meta=meta)
        )
        replayed += 1
        old_counts[old] += 1
        new_counts[decision.verdict] += 1
        if decision.verdict != old:
            transitions.append(
                Transition(
                    line=line,
                    tool=tool,
                    old=old,
                    new=decision.verdict,
                    reason=decision.reason,
                )
            )
    return Calibration(
        total=len(records),
        replayed=replayed,
        skipped_no_arguments=skipped,
        transitions=transitions,
        old_counts=old_counts,
        new_counts=new_counts,
    )


def load_candidate_policy(path: Path) -> Policy:
    try:
        return load_policy(path)
    except PolicyError as exc:
        raise IntegrationError(str(exc)) from exc


def print_calibration(result: Calibration, records_file: Path, policy: Policy) -> None:
    print(f"Calibration: {records_file}")
    print(f"  candidate policy    {policy.policy_id} ({policy.source_path})")
    print(
        f"  records             {result.total} "
        f"({result.replayed} replayed"
        + (
            f", {result.skipped_no_arguments} skipped: arguments not stored"
            if result.skipped_no_arguments
            else ""
        )
        + ")"
    )
    print()
    print("               recorded   candidate")
    for verdict in ("PASS", "WARN", "BLOCK"):
        print(
            f"  {verdict:<8}     {result.old_counts.get(verdict, 0):8} "
            f"   {result.new_counts.get(verdict, 0):9}"
        )
    print()
    if not result.transitions:
        print("  No verdict changes: the candidate decides these calls the same way.")
    else:
        print(f"  {len(result.transitions)} call(s) would change verdict:")
        for item in result.transitions:
            print(f"    line {item.line:<4} {item.tool:<24} {item.old} -> {item.new}")
            print(f"              {item.reason}")
    print()
    print(
        "  Approvals were checked as they exist now; the question answered is "
        '"what happens if I deploy this today".'
    )
    print(
        "  Next step: edit the candidate and re-run, then switch it to "
        "`mode: enforce` when the BLOCK column contains only calls you want "
        "stopped."
    )
