"""What the four commands actually print.

Acceptance criterion 7 is here: `explain` must give a cause and a step someone
can take, not an error code.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_safety_gate.cli import main
from agent_safety_gate.records import read_records
from tests.conftest import DEMO_KEY_FILE, FIXED_TIME, REPO_ROOT, SAMPLE_RECORDS


@pytest.fixture
def demo_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    directory = tmp_path / "demo"
    assert (
        main(
            [
                "demo",
                "--output-dir",
                str(directory),
                "--key",
                str(DEMO_KEY_FILE),
                "--fixed-time",
                FIXED_TIME,
            ]
        )
        == 0
    )
    capsys.readouterr()
    return directory


def test_demo_produces_everything_needed_for_the_first_proof(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "demo"
    assert (
        main(["demo", "--output-dir", str(directory), "--key", str(DEMO_KEY_FILE)]) == 0
    )
    output = capsys.readouterr().out

    records = read_records(directory / "records.jsonl")
    assert [record["aos_verdict"] for record in records] == ["PASS", "WARN", "BLOCK"]
    assert (directory / "verify.html").is_file()
    assert (directory / "demo_policy.yaml").is_file()
    # The last thing the user reads has to be the next thing they do.
    assert "verify.html" in output
    assert "drop records.jsonl" in output
    assert "Nothing is uploaded" in output


def test_demo_scenario_is_recognisable_not_synthetic(demo_dir: Path) -> None:
    records = read_records(demo_dir / "records.jsonl")
    blocked = records[-1]
    assert blocked["call"]["tool"] == "run_shell"
    assert "rm -rf" in blocked["call"]["arguments_json"]
    assert "git push --force" in blocked["call"]["arguments_json"]


@pytest.mark.parametrize("line", [1, 2, 3])
def test_explain_gives_a_cause_and_a_step(
    demo_dir: Path, capsys: pytest.CaptureFixture[str], line: int
) -> None:
    assert main(["explain", str(demo_dir / "records.jsonl"), "--line", str(line)]) == 0
    output = capsys.readouterr().out
    assert "Why" in output
    assert "What was measured" in output
    assert "What it added up to" in output
    assert "What to do" in output
    # A verdict is never a bare code: the reason names what decided it.
    record = read_records(demo_dir / "records.jsonl")[line - 1]
    assert str(record["reason"])[:40] in output
    for signal in record["signals"]:
        assert str(signal["id"]) in output


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (2, "widen tools.write_file.scope"),
        (3, "approvals"),
    ],
)
def test_explain_remediation_is_actionable(
    demo_dir: Path, capsys: pytest.CaptureFixture[str], line: int, expected: str
) -> None:
    assert main(["explain", str(demo_dir / "records.jsonl"), "--line", str(line)]) == 0
    output = capsys.readouterr().out
    assert expected in output


def test_explain_for_a_pass_says_there_is_nothing_to_do(
    demo_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["explain", str(demo_dir / "records.jsonl"), "--line", "1"]) == 0
    assert "Nothing: every signal was measured" in capsys.readouterr().out


def test_explain_by_digest_prefix(
    demo_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    records = read_records(demo_dir / "records.jsonl")
    prefix = str(records[2]["record_sha256"])[:10]
    assert main(["explain", str(demo_dir / "records.jsonl"), "--record", prefix]) == 0
    assert "run_shell" in capsys.readouterr().out


def test_verify_passes_and_fails_where_it_should(
    demo_dir: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = demo_dir / "records.jsonl"
    assert main(["verify", str(path)]) == 0
    assert "Chain intact" in capsys.readouterr().out

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[1])
    payload["aos_verdict"] = "PASS"
    lines[1] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    damaged = tmp_path / "damaged.jsonl"
    damaged.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["verify", str(damaged)]) == 1
    output = capsys.readouterr().out
    assert "VERIFICATION FAILED on line(s): 2" in output
    assert "explain" in output


def test_verify_can_require_a_specific_key(
    demo_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = demo_dir / "records.jsonl"
    key = json.loads(DEMO_KEY_FILE.read_text(encoding="utf-8"))
    assert main(["verify", str(path), "--public-key", key["public_key_base64"]]) == 0
    capsys.readouterr()
    assert main(["verify", str(path), "--public-key", "AAAA" * 11]) == 1
    assert "pinned" in capsys.readouterr().out


def test_missing_file_is_an_error_with_a_next_step(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["verify", str(tmp_path / "nope.jsonl")]) == 2
    assert "Next step" in capsys.readouterr().err


def test_committed_sample_verifies(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", str(SAMPLE_RECORDS)]) == 0
    assert "Chain intact" in capsys.readouterr().out


def test_wrap_check_reports_the_wiring(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_safety_gate.cli",
            "wrap",
            "--policy",
            "examples/demo_policy.yaml",
            "--records",
            str(tmp_path / "records.jsonl"),
            "--key",
            str(DEMO_KEY_FILE),
            "--check",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stderr
    assert "demo_tool_server.py" in completed.stdout
    assert "unknown:   warn" in completed.stdout
    assert "upstream exposes 6 tool(s)" in completed.stdout
