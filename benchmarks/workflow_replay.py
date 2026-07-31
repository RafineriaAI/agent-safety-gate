"""Replay a coding-agent session through the gate and report what it did.

    python benchmarks/workflow_replay.py

The trace in `traces/coding_session.jsonl` is a session of ordinary work - reads,
in-scope edits, test runs, commits - with risky calls interleaved: an
irreversible action outside the declared scope, tools the policy has never heard
of, and a call the agent vouches for itself.

Three numbers come out, and all three are needed to read any of them:

* catch rate      - risky calls that did not come back PASS,
* false alarm rate - ordinary calls that did not come back PASS,
* added latency   - what the gate costs per call.

Read benchmarks/README.md before quoting any of these numbers. They describe
this trace under this policy. A trace written by the same people who wrote the
gate cannot tell you what the gate will do on your traffic.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:  # running from a checkout
    sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_safety_gate.gate import Gate  # noqa: E402
from agent_safety_gate.policy import load_policy  # noqa: E402
from agent_safety_gate.records import canonical_json_text  # noqa: E402
from agent_safety_gate.signals import ToolCall  # noqa: E402
from agent_safety_gate.signing import SigningKey, load_key  # noqa: E402

DEFAULT_TRACE = REPO_ROOT / "benchmarks" / "traces" / "coding_session.jsonl"
DEFAULT_POLICY = REPO_ROOT / "benchmarks" / "benchmark_policy.yaml"
DEFAULT_KEY = REPO_ROOT / "examples" / "demo_signing_key.INSECURE.json"


@dataclass(frozen=True)
class Outcome:
    index: int
    tool: str
    kind: str
    label: str
    verdict: str
    reason: str


def load_trace(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{number}: not valid JSON ({exc.msg})") from exc
    if not entries:
        raise SystemExit(f"{path} is empty")
    return entries


def to_call(entry: dict[str, Any]) -> ToolCall:
    return ToolCall(
        tool=str(entry["tool"]),
        arguments=dict(entry.get("arguments") or {}),
        server="benchmark",
        meta=entry.get("meta"),
    )


def replay(gate: Gate, entries: Sequence[dict[str, Any]]) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for index, entry in enumerate(entries, start=1):
        decision = gate.evaluate(to_call(entry))
        outcomes.append(
            Outcome(
                index=index,
                tool=str(entry["tool"]),
                kind=str(entry.get("kind", "benign")),
                label=str(entry.get("label", "")),
                verdict=decision.verdict,
                reason=decision.reason,
            )
        )
    return outcomes


def measure_latency(
    gate: Gate, entries: Sequence[dict[str, Any]], key: SigningKey, repeats: int
) -> dict[str, float]:
    """Microseconds per call, for the decision alone and with a signed record."""
    calls = [to_call(entry) for entry in entries]
    decision_times: list[float] = []
    record_times: list[float] = []
    for _ in range(repeats):
        for target in calls:
            start = time.perf_counter()
            decision = gate.evaluate(target)
            middle = time.perf_counter()
            gate.build_record(decision, key=key, chain_index=0, prev_record_sha256=None)
            end = time.perf_counter()
            decision_times.append((middle - start) * 1e6)
            record_times.append((end - start) * 1e6)
    decision_times.sort()
    record_times.sort()

    def percentile(values: list[float], fraction: float) -> float:
        position = min(len(values) - 1, int(fraction * len(values)))
        return values[position]

    return {
        "calls_measured": float(len(decision_times)),
        "decision_mean_us": statistics.fmean(decision_times),
        "decision_p50_us": percentile(decision_times, 0.50),
        "decision_p95_us": percentile(decision_times, 0.95),
        "record_mean_us": statistics.fmean(record_times),
        "record_p50_us": percentile(record_times, 0.50),
        "record_p95_us": percentile(record_times, 0.95),
        "record_max_us": record_times[-1],
    }


def summarise(outcomes: Iterable[Outcome]) -> dict[str, Any]:
    items = list(outcomes)
    risky = [item for item in items if item.kind == "risky"]
    benign = [item for item in items if item.kind != "risky"]
    caught = [item for item in risky if item.verdict != "PASS"]
    blocked = [item for item in risky if item.verdict == "BLOCK"]
    alarms = [item for item in benign if item.verdict != "PASS"]
    return {
        "benign_calls": len(benign),
        "blocked_of_risky": len(blocked),
        "caught_of_risky": len(caught),
        "catch_rate": len(caught) / len(risky) if risky else 0.0,
        "false_alarm_rate": len(alarms) / len(benign) if benign else 0.0,
        "false_alarms": [
            {"index": item.index, "tool": item.tool, "verdict": item.verdict}
            for item in alarms
        ],
        "missed": [
            {"index": item.index, "tool": item.tool, "label": item.label}
            for item in risky
            if item.verdict == "PASS"
        ],
        "risky_calls": len(risky),
        "total_calls": len(items),
        "verdicts": {
            verdict: sum(1 for item in items if item.verdict == verdict)
            for verdict in ("PASS", "WARN", "BLOCK")
        },
    }


def print_report(summary: dict[str, Any], latency: dict[str, float] | None) -> None:
    print("Workflow replay")
    print(
        f"  calls               {summary['total_calls']} "
        f"({summary['benign_calls']} ordinary, {summary['risky_calls']} risky)"
    )
    verdicts = summary["verdicts"]
    print(
        f"  verdicts            PASS {verdicts['PASS']}  "
        f"WARN {verdicts['WARN']}  BLOCK {verdicts['BLOCK']}"
    )
    print()
    print(
        f"  catch rate          {summary['catch_rate'] * 100:.1f}%  "
        f"({summary['caught_of_risky']}/{summary['risky_calls']} risky calls not "
        f"passed; {summary['blocked_of_risky']} of them blocked outright)"
    )
    print(
        f"  false alarm rate    {summary['false_alarm_rate'] * 100:.1f}%  "
        f"({len(summary['false_alarms'])}/{summary['benign_calls']} ordinary calls "
        "not passed)"
    )
    for miss in summary["missed"]:
        print(f"    MISSED  #{miss['index']} {miss['tool']}: {miss['label']}")
    for alarm in summary["false_alarms"]:
        print(f"    ALARM   #{alarm['index']} {alarm['tool']} -> {alarm['verdict']}")
    if latency is not None:
        print()
        print(
            f"  decision            mean {latency['decision_mean_us']:.0f} us, "
            f"p50 {latency['decision_p50_us']:.0f} us, "
            f"p95 {latency['decision_p95_us']:.0f} us"
        )
        print(
            f"  + signed record     mean {latency['record_mean_us']:.0f} us, "
            f"p50 {latency['record_p50_us']:.0f} us, "
            f"p95 {latency['record_p95_us']:.0f} us"
        )
        print(f"  measured over       {int(latency['calls_measured'])} calls")
    print()
    print("  These numbers describe this trace under benchmarks/benchmark_policy.yaml.")
    print("  See benchmarks/README.md for what they do not tell you.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, default=DEFAULT_TRACE)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--no-latency", action="store_true")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    entries = load_trace(args.trace)
    gate = Gate(load_policy(args.policy))
    outcomes = replay(gate, entries)
    summary = summarise(outcomes)
    latency = (
        None
        if args.no_latency
        else measure_latency(gate, entries, load_key(args.key), args.repeats)
    )
    print_report(summary, latency)

    if args.json is not None:
        payload = {
            "summary": summary,
            "verdicts_by_call": [
                {
                    "index": item.index,
                    "kind": item.kind,
                    "tool": item.tool,
                    "verdict": item.verdict,
                }
                for item in outcomes
            ],
        }
        args.json.write_text(canonical_json_text(payload) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
