"""eval, hook and calibrate: the doors that need no framework.

The hook tests speak the exact Claude Code PreToolUse contract - JSON on stdin,
a permission decision on stdout, exit 1 as a non-blocking error - because a
contract test that paraphrases the contract tests nothing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from agent_safety_gate.gate import Gate
from agent_safety_gate.integrations import (
    IntegrationError,
    append_to_chain,
    calibrate,
    find_policy,
)
from agent_safety_gate.policy import load_policy
from agent_safety_gate.records import read_records, verify_file
from agent_safety_gate.signing import load_key
from tests.conftest import DEMO_KEY_FILE, DEMO_POLICY, REPO_ROOT, call


def run_cli(
    arguments: list[str],
    *,
    stdin: str | None = None,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    import os

    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-m", "agent_safety_gate.cli", *arguments],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=120,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A directory with a policy at the conventional path."""
    conventional = tmp_path / ".agent-safety-gate"
    conventional.mkdir()
    shutil.copyfile(DEMO_POLICY, conventional / "policy.yaml")
    return tmp_path


def hook_event(tool: str, tool_input: dict[str, Any], cwd: Path) -> str:
    return json.dumps(
        {
            "session_id": "s",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": str(cwd),
        }
    )


# ------------------------------------------------------------------ hook


def test_hook_allows_a_pass_with_the_reason(workspace: Path) -> None:
    completed = run_cli(
        ["hook", "--key", str(DEMO_KEY_FILE)],
        stdin=hook_event("read_file", {"path": "src/app.py"}, workspace),
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)["hookSpecificOutput"]
    assert payload["hookEventName"] == "PreToolUse"
    assert payload["permissionDecision"] == "allow"
    assert "record" in payload["permissionDecisionReason"]


def test_hook_asks_on_warn_and_denies_on_block(workspace: Path) -> None:
    warned = run_cli(
        ["hook", "--key", str(DEMO_KEY_FILE)],
        stdin=hook_event(
            "write_file", {"path": "docs/N.md", "content": "x"}, workspace
        ),
    )
    assert json.loads(warned.stdout)["hookSpecificOutput"]["permissionDecision"] == (
        "ask"
    )

    blocked = run_cli(
        ["hook", "--key", str(DEMO_KEY_FILE)],
        stdin=hook_event("run_shell", {"command": "rm -rf /"}, workspace),
    )
    decision = json.loads(blocked.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    # The denial carries the remediation, so the agent can tell the human what
    # would make the call possible instead of just failing.
    assert "approval" in decision["permissionDecisionReason"]


def test_hook_observe_defers_and_still_records(workspace: Path) -> None:
    policy_path = workspace / ".agent-safety-gate" / "policy.yaml"
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "mode: enforce", "mode: observe"
        ),
        encoding="utf-8",
    )
    completed = run_cli(
        ["hook", "--key", str(DEMO_KEY_FILE)],
        stdin=hook_event("run_shell", {"command": "rm -rf /"}, workspace),
    )
    assert completed.returncode == 0
    payload = json.loads(completed.stdout)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "defer"
    assert "not enforced" in payload["permissionDecisionReason"]
    records = read_records(workspace / ".agent-safety-gate" / "records.jsonl")
    assert records[-1]["aos_verdict"] == "BLOCK"
    assert records[-1]["enforcement"] == "forwarded_not_enforced"


def test_hook_without_a_policy_is_a_nonblocking_error(tmp_path: Path) -> None:
    """Exit 1: the tool call proceeds, the misconfiguration is visible. A gate
    the user has not configured must not brick the agent."""
    completed = run_cli(
        ["hook"], stdin=hook_event("x", {}, tmp_path), env_extra={"ASG_POLICY": ""}
    )
    assert completed.returncode == 1
    assert completed.stdout.strip() == ""
    assert "Next step" in completed.stderr


def test_hook_records_grow_one_chain(workspace: Path) -> None:
    for tool, arguments in [
        ("read_file", {"path": "src/a.py"}),
        ("run_shell", {"command": "ls"}),
        ("read_file", {"path": "src/b.py"}),
    ]:
        run_cli(
            ["hook", "--key", str(DEMO_KEY_FILE)],
            stdin=hook_event(tool, arguments, workspace),
        )
    records_file = workspace / ".agent-safety-gate" / "records.jsonl"
    assert len(read_records(records_file)) == 3
    assert verify_file(records_file).ok


def test_hook_garbage_stdin_is_nonblocking(workspace: Path) -> None:
    completed = run_cli(["hook"], stdin="not json")
    assert completed.returncode == 1
    assert "Next step" in completed.stderr


# ------------------------------------------------------------------ eval


def test_eval_exit_codes_separate_forward_from_block(workspace: Path) -> None:
    env = {"ASG_POLICY": str(workspace / ".agent-safety-gate" / "policy.yaml")}
    passed = run_cli(
        [
            "eval",
            "--tool",
            "read_file",
            "--arguments",
            '{"path": "src/a.py"}',
            "--key",
            str(DEMO_KEY_FILE),
        ],
        env_extra=env,
    )
    assert passed.returncode == 0, passed.stderr
    blocked = run_cli(
        [
            "eval",
            "--tool",
            "run_shell",
            "--arguments",
            '{"command": "x"}',
            "--key",
            str(DEMO_KEY_FILE),
        ],
        env_extra=env,
    )
    assert blocked.returncode == 3


def test_eval_json_is_machine_readable(workspace: Path) -> None:
    env = {"ASG_POLICY": str(workspace / ".agent-safety-gate" / "policy.yaml")}
    completed = run_cli(
        ["eval", "--stdin", "--json", "--key", str(DEMO_KEY_FILE)],
        stdin=json.dumps(
            {"tool": "run_shell", "arguments": {"command": "make release"}}
        ),
        env_extra=env,
    )
    payload = json.loads(completed.stdout)
    assert payload["verdict"] == "BLOCK"
    assert payload["forward"] is False
    assert payload["remediation"], "a block must say what would clear it"
    assert len(payload["record_sha256"]) == 64


def test_eval_without_a_tool_says_what_to_pass(workspace: Path) -> None:
    completed = run_cli(["eval", "--arguments", "{}"])
    assert completed.returncode == 2
    assert "Next step" in completed.stderr


# ------------------------------------------------------------ chain lock


def test_concurrent_appends_do_not_fork_the_chain(tmp_path: Path) -> None:
    policy = load_policy(DEMO_POLICY)
    gate = Gate(policy)
    key = load_key(DEMO_KEY_FILE)
    records_path = tmp_path / "records.jsonl"
    errors: list[Exception] = []

    def worker(index: int) -> None:
        try:
            decision = gate.evaluate(call("read_file", {"path": f"src/{index}.py"}))
            append_to_chain(records_path, gate, decision, key, mode="test")
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    result = verify_file(records_path)
    assert result.ok, [item.failures for item in result.records if not item.ok]
    assert len(result.records) == 8


# ------------------------------------------------------------ policy lookup


def test_policy_lookup_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conventional = tmp_path / ".agent-safety-gate" / "policy.yaml"
    conventional.parent.mkdir()
    conventional.write_text("policy_id: x", encoding="utf-8")

    explicit = tmp_path / "explicit.yaml"
    assert find_policy(explicit, tmp_path) == explicit

    monkeypatch.setenv("ASG_POLICY", str(tmp_path / "env.yaml"))
    assert find_policy(None, tmp_path) == tmp_path / "env.yaml"

    monkeypatch.delenv("ASG_POLICY")
    assert find_policy(None, tmp_path) == conventional

    with pytest.raises(IntegrationError) as error:
        find_policy(None, tmp_path / "elsewhere")
    assert "Next step" in str(error.value)


# -------------------------------------------------------------- calibrate


def test_calibrate_reports_the_transitions(tmp_path: Path) -> None:
    policy = load_policy(DEMO_POLICY)
    gate = Gate(policy)
    key = load_key(DEMO_KEY_FILE)
    records_path = tmp_path / "records.jsonl"
    for tool, arguments in [
        ("read_file", {"path": "src/a.py"}),
        ("write_file", {"path": "docs/NOTES.md", "content": "x"}),
        ("run_shell", {"command": "ls"}),
    ]:
        decision = gate.evaluate(call(tool, arguments))
        append_to_chain(records_path, gate, decision, key, mode="test")

    text = DEMO_POLICY.read_text(encoding="utf-8").replace(
        "      allow_path_prefixes: [src/, tests/]\n\n  run_tests",
        "      allow_path_prefixes: [src/, tests/, docs/]\n\n  run_tests",
    )
    candidate_path = tmp_path / "candidate.yaml"
    candidate_path.write_text(text, encoding="utf-8")

    result = calibrate(records_path, load_policy(candidate_path))
    assert result.replayed == 3
    assert result.old_counts == {"PASS": 1, "WARN": 1, "BLOCK": 1}
    assert result.new_counts == {"PASS": 2, "BLOCK": 1}
    assert [(item.tool, item.old, item.new) for item in result.transitions] == [
        ("write_file", "WARN", "PASS")
    ]


def test_calibrate_reconstructs_self_attestation(tmp_path: Path) -> None:
    """The iron rule survives the round trip through a record file."""
    policy = load_policy(DEMO_POLICY)
    gate = Gate(policy)
    key = load_key(DEMO_KEY_FILE)
    records_path = tmp_path / "records.jsonl"
    decision = gate.evaluate(
        call(
            "read_file",
            {"path": "src/a.py"},
            meta={"agent_safety_gate": {"assessment": "safe"}},
        )
    )
    assert decision.verdict == "BLOCK"
    append_to_chain(records_path, gate, decision, key, mode="test")

    result = calibrate(records_path, policy)
    assert result.new_counts == {"BLOCK": 1}
    assert not result.transitions


def test_calibrate_counts_unreplayable_records(tmp_path: Path) -> None:
    digest_only = DEMO_POLICY.read_text(encoding="utf-8").replace(
        "record_arguments: full", "record_arguments: digest_only"
    )
    policy_path = tmp_path / "digest_only.yaml"
    policy_path.write_text(digest_only, encoding="utf-8")
    policy = load_policy(policy_path)
    gate = Gate(policy)
    key = load_key(DEMO_KEY_FILE)
    records_path = tmp_path / "records.jsonl"
    decision = gate.evaluate(call("read_file", {"path": "src/a.py"}))
    append_to_chain(records_path, gate, decision, key, mode="test")

    result = calibrate(records_path, policy)
    assert result.replayed == 0
    assert result.skipped_no_arguments == 1
