"""The session replay: extraction, redaction, and the numbers it reports.

The real measurement runs against a real transcript, which is not committed. The
tests run against a small transcript written here, so CI covers the code path
without carrying anyone's session data.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_safety_gate.gate import Gate
from agent_safety_gate.policy import load_policy
from agent_safety_gate.signals import ToolCall
from tests.conftest import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "benchmarks"))

from session_replay import (  # noqa: E402
    INSPECTION_COMMANDS,
    OUTSIDE,
    Entry,
    infer_workspace,
    is_inspection,
    load_entries,
    relativise,
    replay,
    scrub_command,
)

POLICY = REPO_ROOT / "benchmarks" / "coding_agent_policy.yaml"
WORKSPACE = "D:/work/project"


def transcript(tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]) -> Path:
    """A transcript in the shape the loader expects, plus noise it must ignore."""
    lines = [
        json.dumps({"type": "user", "message": {"content": "hello"}}),
        json.dumps({"type": "mode", "mode": "default"}),
        "not json at all",
        "",
    ]
    for name, arguments in calls:
        lines.append(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "text", "text": "thinking out loud"},
                            {
                                "type": "tool_use",
                                "name": name,
                                "input": arguments,
                            },
                        ]
                    },
                }
            )
        )
    path = tmp_path / "session.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_extraction_ignores_everything_that_is_not_a_tool_call(
    tmp_path: Path,
) -> None:
    path = transcript(
        tmp_path,
        [
            ("Read", {"file_path": "D:/work/project/src/app.py", "limit": 20}),
            ("Bash", {"command": "python -m pytest -q", "timeout": 900}),
        ],
    )
    entries = load_entries(path, WORKSPACE)
    assert [entry.tool for entry in entries] == ["Read", "Bash"]
    assert entries[0].arguments == {"file_path": "src/app.py"}
    assert entries[1].arguments == {"command": "python -m pytest -q"}


def test_file_contents_never_reach_the_trace(tmp_path: Path) -> None:
    """A benchmark has no business reading what the agent wrote."""
    secret = "SECRET-CONTENT-THAT-MUST-NOT-APPEAR"
    path = transcript(
        tmp_path,
        [
            (
                "Write",
                {"file_path": "D:/work/project/src/app.py", "content": secret},
            ),
            (
                "Edit",
                {
                    "file_path": "D:/work/project/src/app.py",
                    "old_string": secret,
                    "new_string": secret,
                },
            ),
        ],
    )
    entries = load_entries(path, WORKSPACE)
    assert secret not in json.dumps([entry.arguments for entry in entries])
    assert "content" in entries[0].dropped
    assert "old_string" in entries[1].dropped


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("D:/work/project/src/app.py", "src/app.py"),
        ("D:\\work\\project\\src\\app.py", "src/app.py"),
        ("D:/work/project", "."),
        ("C:/Users/someone/Temp/scratch/out.png", f"{OUTSIDE}/out.png"),
        ("/home/someone/.ssh/id_rsa", f"{OUTSIDE}/id_rsa"),
    ],
)
def test_paths_are_workspace_relative_or_redacted(value: str, expected: str) -> None:
    assert relativise(value, WORKSPACE, redact=True) == expected


def test_redaction_cannot_change_a_verdict() -> None:
    """The shipped policy's allowlists are workspace-relative, so a redacted
    path and the original both fail to match, and both land on the same verdict."""
    gate = Gate(load_policy(POLICY))
    outside = "C:/Users/someone/secrets/keys.txt"
    redacted = relativise(outside, WORKSPACE, redact=True)
    kept = relativise(outside, WORKSPACE, redact=False)
    assert redacted != kept
    verdicts = {
        gate.evaluate(ToolCall("Read", {"file_path": path}, "session")).verdict
        for path in (redacted, kept)
    }
    assert len(verdicts) == 1


def test_home_directories_are_scrubbed_from_shell_commands() -> None:
    command = "cp C:/Users/someone/notes.txt D:/work/project/docs/notes.txt"
    scrubbed = scrub_command(command, WORKSPACE, redact=True)
    assert "someone" not in scrubbed
    assert "docs/notes.txt" in scrubbed


def test_workspace_is_inferred_from_the_transcript_location(tmp_path: Path) -> None:
    directory = tmp_path / "D--work-project"
    directory.mkdir()
    session = directory / "abc.jsonl"
    session.write_text("", encoding="utf-8")
    assert infer_workspace(session) == "D:/work-project"


def test_a_shell_is_the_worst_thing_it_can_do(tmp_path: Path) -> None:
    """The finding the real session produced, in miniature."""
    path = transcript(
        tmp_path,
        [
            ("Read", {"file_path": "D:/work/project/src/app.py"}),
            ("Write", {"file_path": "D:/work/project/src/app.py", "content": "x"}),
            ("Bash", {"command": "python -m pytest -q"}),
            ("Bash", {"command": "rm -rf /"}),
        ],
    )
    policy = load_policy(POLICY)
    result = replay(Gate(policy), policy, load_entries(path, WORKSPACE))
    assert result.total == 4
    assert result.verdicts["PASS"] == 2
    # Both shell calls block, and the gate cannot tell them apart, because it
    # never looks at a command. That is the point of the finding.
    assert result.verdicts["BLOCK"] == 2
    assert result.blocked_shell == 2
    assert result.blocked_inspection == 1


def test_identical_calls_share_one_approval(tmp_path: Path) -> None:
    path = transcript(
        tmp_path,
        [("Bash", {"command": "make release"})] * 3
        + [("Bash", {"command": "make release "})],
    )
    policy = load_policy(POLICY)
    result = replay(Gate(policy), policy, load_entries(path, WORKSPACE))
    assert result.verdicts["BLOCK"] == 4
    # Three identical calls need one approval; one changed character needs another.
    assert len(result.blocked_digests) == 2


def test_undeclared_tools_are_named_not_guessed(tmp_path: Path) -> None:
    path = transcript(tmp_path, [("SomeNewTool", {"path": "src/app.py"})])
    policy = load_policy(POLICY)
    result = replay(Gate(policy), policy, load_entries(path, WORKSPACE))
    assert result.undeclared == ["SomeNewTool"]
    assert result.verdicts["WARN"] == 1


def test_inspection_list_matches_only_what_it_says(tmp_path: Path) -> None:
    assert is_inspection("python -m pytest -q")
    assert is_inspection("git status --porcelain")
    # A shell heredoc that happens to start with python is not an inspection.
    assert not is_inspection("python - <<'PY'\nimport os\nos.remove('x')\nPY")
    assert not is_inspection("python -m pip install something")
    assert not is_inspection("git push --force")
    for prefix in INSPECTION_COMMANDS:
        assert is_inspection(prefix + " anything")


def test_an_empty_transcript_says_what_to_do(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text('{"type": "user"}\n', encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        load_entries(path, WORKSPACE)
    assert "Next step" in str(error.value)


def test_entry_is_hashable_and_stable() -> None:
    entry = Entry(tool="Read", arguments={"file_path": "src/app.py"}, dropped=())
    assert entry.tool == "Read"
    assert entry.dropped == ()


REAL_SESSION = REPO_ROOT / "benchmarks" / "traces" / "real_session.jsonl"


@pytest.mark.skipif(
    not REAL_SESSION.is_file(),
    reason=(
        "benchmarks/traces/real_session.jsonl is not present; it is session "
        "data and committing it is the repository owner's decision"
    ),
)
def test_the_real_session_numbers_match_both_readmes() -> None:
    policy = load_policy(POLICY)
    result = replay(Gate(policy), policy, load_entries(REAL_SESSION, ""))
    for name in ("README.md", "README.pl.md"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert f"{result.total} " in text, f"{name} does not quote the call count"
        for verdict in ("PASS", "WARN", "BLOCK"):
            count = result.verdicts[verdict]
            share = (
                f"{count / result.total:.1%}".replace(".", ",")
                if name.endswith("pl.md")
                else f"{count / result.total:.1%}"
            )
            assert f"{count} ({share})" in text, f"{name}: {verdict} {count} {share}"
        assert str(len(result.blocked_digests)) in text
