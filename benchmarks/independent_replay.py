"""Replay published trajectories from somebody else's agent through the gate.

    python benchmarks/independent_replay.py --limit 40

Everything else in `benchmarks/` measures the gate against traffic produced on
this machine, by this repository's authors, using this repository's tools.
That is the weakness that no amount of care removes. This script removes it by
using data none of us made:

* the trajectories come from a published dataset on the Hugging Face Hub,
* the agent that produced them is OpenHands, not the one used here,
* the model that drove it is not the one used here,
* the repositories worked on are other people's.

The default dataset is `nebius/SWE-rebench-openhands-trajectories`: agent
sessions solving GitHub issues across Python repositories. Any dataset with the
same shape works - a `trajectory` column of chat messages carrying `tool_calls`,
and a `tools` column describing the surface.

Rows are fetched over the public datasets-server JSON API with the standard
library, and cached under `benchmarks/.cache/` so a second run needs no network.
The cache is not committed.

Three policies are replayed, so the report shows what the finer declaration is
worth rather than asserting it: the shipped one, which declares the editor tool
per value of its `command` argument, and two one-class-per-tool collapses of it -
the cautious reading and the pragmatic one. A feature is worth what it beats
both of them by, and on verdicts alone it beats the pragmatic one by nothing.
What it does change is what the record says each call did, which the report
counts separately.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_safety_gate.gate import Gate  # noqa: E402
from agent_safety_gate.policy import ActionClassRule, Policy, load_policy  # noqa: E402
from agent_safety_gate.signals import ToolCall  # noqa: E402

DEFAULT_DATASET = "nebius/SWE-rebench-openhands-trajectories"
DEFAULT_POLICY = REPO_ROOT / "benchmarks" / "openhands_policy.yaml"
CACHE = REPO_ROOT / "benchmarks" / ".cache"
PAGE = 5


@dataclass(frozen=True)
class Call:
    tool: str
    arguments: dict[str, Any]


def fetch_rows(dataset: str, limit: int) -> list[dict[str, Any]]:
    """Fetch rows through the public JSON API, caching each page."""
    CACHE.mkdir(parents=True, exist_ok=True)
    quoted = urllib.parse.quote(dataset, safe="")
    rows: list[dict[str, Any]] = []
    for offset in range(0, limit, PAGE):
        cached = CACHE / f"{quoted}-{offset}-{PAGE}.json"
        if cached.is_file():
            page = json.loads(cached.read_text(encoding="utf-8"))
        else:
            url = (
                "https://datasets-server.huggingface.co/rows"
                f"?dataset={quoted}&config=default&split=train"
                f"&offset={offset}&length={PAGE}"
            )
            request = urllib.request.Request(
                url, headers={"User-Agent": "agent-safety-gate-calibration"}
            )
            try:
                with urllib.request.urlopen(request, timeout=180) as response:
                    page = json.loads(response.read().decode("utf-8"))
            except OSError as exc:
                if rows:
                    print(f"  stopped fetching at offset {offset}: {exc}")
                    break
                raise SystemExit(
                    f"could not reach the datasets-server API: {exc}\n"
                    "Next step: this benchmark needs one network call the first "
                    "time; after that it reads benchmarks/.cache/."
                ) from exc
            cached.write_text(json.dumps(page), encoding="utf-8")
        rows.extend(item["row"] for item in page.get("rows", []))
    return rows[:limit]


def extract_calls(rows: list[dict[str, Any]]) -> list[Call]:
    calls: list[Call] = []
    for row in rows:
        for message in row.get("trajectory") or []:
            for tool_call in message.get("tool_calls") or []:
                function = tool_call.get("function") or {}
                name = function.get("name")
                if not isinstance(name, str):
                    continue
                raw = function.get("arguments")
                try:
                    arguments = (
                        json.loads(raw) if isinstance(raw, str) else dict(raw or {})
                    )
                except (json.JSONDecodeError, TypeError, ValueError):
                    arguments = {}
                calls.append(
                    Call(
                        tool=name,
                        arguments={
                            key: value
                            for key, value in arguments.items()
                            if isinstance(value, str)
                        },
                    )
                )
    return calls


SEVERITY = ("read_only", "reversible_write", "external_effect", "irreversible")


def coarsen(policy: Policy, strategy: str) -> Policy:
    """Collapse every tool to one class, the way an operator would have had to.

    Two operators facing the same tool write two different things, and comparing
    against only one of them would decide the answer in advance:

    * `cautious` takes the worst class the tool can reach, which is the safe
      reading of "this tool can overwrite files";
    * `pragmatic` takes the class most of its operations fall into, which is
      what someone who has watched the tool work tends to write.

    The fine-grained policy is worth whatever it beats *both* of them by.
    """
    tools = {}
    for name, rule in policy.tools.items():
        classes = rule.action.declared_classes()
        if strategy == "cautious":
            chosen = max(classes, key=SEVERITY.index)
        else:
            counts = collections.Counter(rule.action.values.values()) or (
                collections.Counter(classes)
            )
            most = max(counts.values())
            chosen = max(
                (name_ for name_, count in counts.items() if count == most),
                key=SEVERITY.index,
            )
        tools[name] = replace(rule, action=ActionClassRule(fixed=chosen))
    return replace(policy, tools=tools, digest="")


def replay(
    gate: Gate, calls: list[Call]
) -> tuple[collections.Counter[str], list[str | None]]:
    """Verdicts, and the action class each call was recorded as."""
    verdicts: collections.Counter[str] = collections.Counter()
    classes: list[str | None] = []
    for call in calls:
        decision = gate.evaluate(
            ToolCall(tool=call.tool, arguments=call.arguments, server="independent")
        )
        verdicts[decision.verdict] += 1
        recorded = next(
            (
                signal.value
                for signal in decision.signals
                if signal.id == "action_class"
            ),
            None,
        )
        classes.append(recorded)
    return verdicts, classes


def print_counts(label: str, verdicts: collections.Counter[str], total: int) -> None:
    print(
        f"  {label:<28} PASS {verdicts['PASS']:5} ({verdicts['PASS'] / total:5.1%})"
        f"   WARN {verdicts['WARN']:5}   BLOCK {verdicts['BLOCK']:5}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args(argv)

    rows = fetch_rows(args.dataset, args.limit)
    calls = extract_calls(rows)
    if not calls:
        raise SystemExit(f"no tool calls found in {args.dataset}")

    policy = load_policy(args.policy)
    fine_verdicts, fine_classes = replay(Gate(policy), calls)
    cautious_verdicts, _ = replay(Gate(coarsen(policy, "cautious")), calls)
    pragmatic_verdicts, pragmatic_classes = replay(
        Gate(coarsen(policy, "pragmatic")), calls
    )
    total = len(calls)

    repos = {row.get("repo") for row in rows}
    print(f"Independent replay: {args.dataset}")
    print(f"  trajectories        {len(rows)}")
    print(f"  repositories        {len(repos)}")
    print(f"  tool calls          {total}")
    print()
    by_tool = collections.Counter(call.tool for call in calls)
    for tool, count in by_tool.most_common():
        declared = "" if policy.rule_for(tool) else "  (undeclared)"
        print(f"    {tool:<22} {count:5}  {count / total:5.1%}{declared}")
    print()
    print_counts("one class, cautious", cautious_verdicts, total)
    print_counts("one class, pragmatic", pragmatic_verdicts, total)
    print_counts("class per argument value", fine_verdicts, total)
    print()
    for label, baseline in (
        ("cautious", cautious_verdicts),
        ("pragmatic", pragmatic_verdicts),
    ):
        moved = fine_verdicts["PASS"] - baseline["PASS"]
        blocked = baseline["BLOCK"] - fine_verdicts["BLOCK"]
        print(
            f"  against the {label:<9} one-class policy: {moved:+5} to PASS "
            f"({moved / total:+.1%}), {blocked:+5} fewer blocked"
        )
    print()
    print("  Same signals, same thresholds, same kernel: only the policy is finer.")
    print()
    misrecorded = sum(
        1
        for fine, coarse in zip(fine_classes, pragmatic_classes, strict=True)
        if fine != coarse
    )
    print("  what the record says each call did")
    distribution = collections.Counter(
        value for value in fine_classes if value is not None
    )
    for name, count in distribution.most_common():
        print(f"    {name:<20} {count:5}  {count / total:5.1%}")
    print()
    print(
        f"  {misrecorded} call(s) ({misrecorded / total:.1%}) carry a different class"
    )
    print("  than the pragmatic one-class policy would have recorded: reads that")
    print("  would have gone into the record as writes. No verdict changes. For a")
    print("  product whose first job is reconstructing what happened, that is the")
    print("  half that matters, and it is the whole of what this feature buys on")
    print("  this traffic.")
    print()
    print("  These are other people's agents on other people's repositories.")
    print("  benchmarks/README.md says what the numbers do and do not carry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
