"""Extract a labelled tool-call corpus from AgentDojo, without running a model.

AgentDojo defines, for each task, the sequence of calls that completes it. Two
kinds of task, and the labels fall out of the construction rather than out of
anyone's judgement:

* `UserTask.ground_truth()`      - what the legitimate request requires: benign
* `InjectionTask.ground_truth()` - what the attack achieves if it lands: risky

Nothing here samples a model, so nothing here depends on which model was used or
on how well it resisted. These are the calls the benchmark's authors declared,
in a benchmark neither of us wrote.

    python extract_agentdojo.py > agentdojo_labelled.jsonl
"""

from __future__ import annotations

import json
import sys

from agentdojo.task_suite.load_suites import (
    get_suites,
)

VERSION = "v1.2"


def as_arguments(call: object) -> dict[str, object]:
    args = getattr(call, "args", {}) or {}
    out: dict[str, object] = {}
    for key, value in dict(args).items():
        # Arguments must survive json.dumps; AgentDojo uses plain types plus the
        # occasional pydantic model.
        try:
            json.dumps(value)
            out[key] = value
        except TypeError:
            out[key] = str(value)
    return out


def main() -> int:
    suites = get_suites(VERSION)
    rows: list[dict[str, object]] = []
    stats: dict[str, dict[str, int]] = {}

    for suite_name, suite in suites.items():
        counts = {"benign": 0, "risky": 0}
        env = suite.load_and_inject_default_environment({})

        for task_id, task in suite.user_tasks.items():
            try:
                calls = task.ground_truth(env)
            except Exception as exc:  # a task whose ground truth needs live state
                print(f"skip {suite_name}/{task_id}: {exc}", file=sys.stderr)
                continue
            for call in calls:
                rows.append(
                    {
                        "tool": call.function,
                        "arguments": as_arguments(call),
                        "kind": "benign",
                        "label": f"{suite_name}/{task_id}: "
                        f"{getattr(task, 'PROMPT', '')[:120]}",
                        "source": f"agentdojo {VERSION} {suite_name} {task_id}",
                    }
                )
                counts["benign"] += 1

        for task_id, task in suite.injection_tasks.items():
            try:
                calls = task.ground_truth(env)
            except Exception as exc:
                print(f"skip {suite_name}/{task_id}: {exc}", file=sys.stderr)
                continue
            for call in calls:
                rows.append(
                    {
                        "tool": call.function,
                        "arguments": as_arguments(call),
                        "kind": "risky",
                        "label": f"{suite_name}/{task_id}: "
                        f"{getattr(task, 'GOAL', '')[:120]}",
                        "source": f"agentdojo {VERSION} {suite_name} {task_id}",
                    }
                )
                counts["risky"] += 1

        stats[suite_name] = counts

    for row in rows:
        print(json.dumps(row, ensure_ascii=False))

    total_b = sum(c["benign"] for c in stats.values())
    total_r = sum(c["risky"] for c in stats.values())
    print(
        f"\n{'suite':<12} {'benign':>8} {'risky':>7}",
        file=sys.stderr,
    )
    for name, c in stats.items():
        print(f"{name:<12} {c['benign']:>8} {c['risky']:>7}", file=sys.stderr)
    print(f"{'RAZEM':<12} {total_b:>8} {total_r:>7}", file=sys.stderr)
    print(
        f"\nlacznie {total_b + total_r} oznaczonych wywolan, "
        f"czestosc risky {total_r / max(total_b + total_r, 1):.1%}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
