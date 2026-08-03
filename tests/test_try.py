"""`try` replays an operator's own log without asking them to change anything.

The command exists because of a circle: you cannot judge the gate without a
policy, and you cannot write a policy without knowing your own tool surface.
These tests hold the two halves of that - it reads the shapes a real log
arrives in, and it refuses to report verdicts it has not earned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_safety_gate.cli import main
from agent_safety_gate.records import read_records
from tests.conftest import DEMO_KEY_FILE, DEMO_POLICY


def write_log(path: Path, entries: list[dict[str, object]]) -> Path:
    path.write_text(
        "\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8"
    )
    return path


# -- the three shapes an exported log arrives in ---------------------------


@pytest.mark.parametrize(
    ("entry", "tool"),
    [
        ({"tool": "run_shell", "arguments": {"command": "ls"}}, "run_shell"),
        (
            {"type": "tool_use", "name": "run_shell", "input": {"command": "ls"}},
            "run_shell",
        ),
        (
            {"function": {"name": "run_shell", "arguments": '{"command": "ls"}'}},
            "run_shell",
        ),
    ],
    ids=["own-trace", "anthropic-tool-use", "openai-tool-calls"],
)
def test_reads_every_shape_a_log_arrives_in(
    tmp_path: Path, entry: dict[str, object], tool: str
) -> None:
    log = write_log(tmp_path / "log.jsonl", [entry])
    out = tmp_path / "out"
    assert main(["try", str(log), "--out", str(out), "--key", str(DEMO_KEY_FILE)]) == 0
    records = read_records(out / "records.jsonl")
    assert [r["call"]["tool"] for r in records] == [tool]


def test_reads_a_json_array_as_well_as_jsonl(tmp_path: Path) -> None:
    log = tmp_path / "log.json"
    log.write_text(
        json.dumps(
            [
                {"tool": "read_file", "arguments": {"path": "src/a.py"}},
                {"tool": "run_shell", "arguments": {"command": "pwd"}},
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    assert main(["try", str(log), "--out", str(out), "--key", str(DEMO_KEY_FILE)]) == 0
    assert len(read_records(out / "records.jsonl")) == 2


def test_a_log_with_no_tool_calls_says_what_a_call_looks_like(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = write_log(tmp_path / "log.jsonl", [{"role": "user", "content": "hello"}])
    assert main(["try", str(log), "--out", str(tmp_path / "out")]) == 2
    assert "no tool calls found" in capsys.readouterr().err


# -- what it will and will not claim ---------------------------------------


def test_a_drafted_policy_withholds_verdicts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verdicts from a guessed policy describe the guess, not the agent.

    Reporting them would be the wrong number to read first, and the number an
    operator would quote.
    """
    log = write_log(
        tmp_path / "log.jsonl",
        [{"tool": "some_internal_tool", "arguments": {"x": 1}}],
    )
    out = tmp_path / "out"
    assert main(["try", str(log), "--out", str(out), "--key", str(DEMO_KEY_FILE)]) == 0
    captured = capsys.readouterr().out
    assert "verdicts are withheld" in captured
    assert "1 tool(s) in your log are undeclared" in captured
    assert "PASS" not in captured
    assert (out / "drafted_policy.yaml").is_file()


def test_a_supplied_policy_reports_verdicts_per_tool(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = write_log(
        tmp_path / "log.jsonl",
        [
            {"tool": "fetch_url", "arguments": {"url": "https://docs.example.com/a"}},
            {"tool": "run_shell", "arguments": {"command": "rm -rf /"}},
        ],
    )
    out = tmp_path / "out"
    assert (
        main(
            [
                "try",
                str(log),
                "--policy",
                str(DEMO_POLICY),
                "--out",
                str(out),
                "--key",
                str(DEMO_KEY_FILE),
            ]
        )
        == 0
    )
    captured = capsys.readouterr().out
    assert "By tool, worst first:" in captured
    assert "verdicts are withheld" not in captured


def test_the_draft_assumes_the_worst_and_says_so(tmp_path: Path) -> None:
    """A draft that guessed `read_only` would report a clean bill of health
    for an agent it knows nothing about."""
    log = write_log(tmp_path / "log.jsonl", [{"tool": "wire_money", "arguments": {}}])
    out = tmp_path / "out"
    assert main(["try", str(log), "--out", str(out), "--key", str(DEMO_KEY_FILE)]) == 0
    drafted = (out / "drafted_policy.yaml").read_text(encoding="utf-8")
    assert "action_class: irreversible" in drafted
    assert "IS A GUESS" in drafted
    assert "mode: observe" in drafted


# -- it must not do anything to the operator's system ----------------------


def test_nothing_is_enforced_and_the_chain_is_written(tmp_path: Path) -> None:
    log = write_log(
        tmp_path / "log.jsonl",
        [{"tool": "run_shell", "arguments": {"command": "rm -rf /"}}],
    )
    out = tmp_path / "out"
    assert (
        main(
            [
                "try",
                str(log),
                "--policy",
                str(DEMO_POLICY),
                "--out",
                str(out),
                "--key",
                str(DEMO_KEY_FILE),
            ]
        )
        == 0
    )
    records = read_records(out / "records.jsonl")
    assert records[0]["enforcement"] == "forwarded_not_enforced"
    assert (out / "verify.html").is_file()


def test_a_second_run_replaces_the_records_rather_than_appending(
    tmp_path: Path,
) -> None:
    log = write_log(tmp_path / "log.jsonl", [{"tool": "read_file", "arguments": {}}])
    out = tmp_path / "out"
    argv = ["try", str(log), "--out", str(out), "--key", str(DEMO_KEY_FILE)]
    assert main(argv) == 0
    assert main(argv) == 0
    assert len(read_records(out / "records.jsonl")) == 1
