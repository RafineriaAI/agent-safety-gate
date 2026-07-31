"""The benchmark has to be deterministic, and the README has to match it.

Acceptance criterion 6.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agent_safety_gate.gate import Gate
from agent_safety_gate.policy import load_policy
from tests.conftest import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "benchmarks"))

from workflow_replay import (  # noqa: E402
    DEFAULT_POLICY,
    DEFAULT_TRACE,
    load_trace,
    replay,
    summarise,
)


def test_the_trace_is_a_realistic_session() -> None:
    entries = load_trace(DEFAULT_TRACE)
    benign = [entry for entry in entries if entry["kind"] == "benign"]
    risky = [entry for entry in entries if entry["kind"] == "risky"]
    assert len(benign) >= 50, "the point is a session of ordinary work"
    assert len(risky) >= 3
    tools = {str(entry["tool"]) for entry in benign}
    assert {"read_file", "write_file", "run_tests"} <= tools
    labels = {str(entry["label"]) for entry in risky}
    assert any("outside the declared scope" in label for label in labels)
    assert any("never heard of" in label for label in labels)
    assert any("vouches for itself" in label for label in labels)


def test_replay_is_deterministic() -> None:
    entries = load_trace(DEFAULT_TRACE)
    gate = Gate(load_policy(DEFAULT_POLICY))
    first = [item.verdict for item in replay(gate, entries)]
    for _ in range(5):
        assert [item.verdict for item in replay(gate, entries)] == first


def test_summary_matches_the_numbers_in_both_readmes() -> None:
    entries = load_trace(DEFAULT_TRACE)
    gate = Gate(load_policy(DEFAULT_POLICY))
    summary = summarise(replay(gate, entries))

    for name in ("README.md", "README.pl.md"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert f"{summary['total_calls']} " in text
        assert f"{summary['benign_calls']} " in text
        assert f"{summary['risky_calls']} " in text
        assert f"{summary['catch_rate'] * 100:.0f}%" in text, (
            f"{name} does not quote the measured catch rate"
        )
        assert f"{summary['false_alarm_rate'] * 100:.0f}%" in text, (
            f"{name} does not quote the measured false alarm rate"
        )
        assert f"{summary['caught_of_risky']}/{summary['risky_calls']}" in text
        assert f"{len(summary['false_alarms'])}/{summary['benign_calls']}" in text


def test_the_benchmark_runs_as_one_command(tmp_path: Path) -> None:
    output = tmp_path / "summary.json"
    completed = subprocess.run(
        [
            sys.executable,
            "benchmarks/workflow_replay.py",
            "--no-latency",
            "--json",
            str(output),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stderr
    # Both numbers, always together: either one alone is meaningless.
    assert "catch rate" in completed.stdout
    assert "false alarm rate" in completed.stdout
    assert output.is_file()


def test_the_benchmark_readme_says_what_the_numbers_do_not_mean() -> None:
    text = (REPO_ROOT / "benchmarks" / "README.md").read_text(encoding="utf-8")
    assert "written by the same people who wrote the gate" in text
    assert "not tuned" in text
