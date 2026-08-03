"""The decision table, and the two rules that must never bend.

Each row of the table is a case an operator can describe in one sentence. If a
weight in examples/demo_policy.yaml changes, these tests are where the change
becomes visible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_safety_gate.gate import Gate
from agent_safety_gate.policy import Policy, load_policy
from agent_safety_gate.records import canonical_json_bytes
from agent_safety_gate.signals import SIGNAL_APPROVAL_PRESENT, approvals_root
from tests.conftest import call


@pytest.mark.parametrize(
    ("tool", "arguments", "expected", "why"),
    [
        ("read_file", {"path": "src/app.py"}, "PASS", "declared, in scope, read only"),
        ("fetch_url", {"url": "https://docs.example.com/x"}, "PASS", "allowed domain"),
        (
            "write_file",
            {"path": "src/app.py", "content": "x"},
            "PASS",
            "in scope write",
        ),
        ("read_file", {"path": "/etc/shadow"}, "WARN", "read outside the scope"),
        (
            "write_file",
            {"path": "docs/NOTES.md", "content": "x"},
            "WARN",
            "write outside",
        ),
        (
            "write_file",
            {"path": "../../.ssh/config", "content": "x"},
            "WARN",
            "escapes upward",
        ),
        ("fetch_url", {"url": "https://evil.example.net/x"}, "WARN", "other domain"),
        ("unknown_tool", {"anything": 1}, "WARN", "no policy entry at all"),
        ("run_shell", {"command": "ls"}, "BLOCK", "irreversible without approval"),
        (
            "send_email",
            {"to": "x@example.com", "subject": "s", "body": "b"},
            "BLOCK",
            "external effect without approval",
        ),
    ],
)
def test_decision_table(
    gate: Gate, tool: str, arguments: dict[str, Any], expected: str, why: str
) -> None:
    decision = gate.evaluate(call(tool, arguments))
    assert decision.verdict == expected, f"{why}: {decision.reason}"


def test_pass_requires_every_signal_measured_and_independent(gate: Gate) -> None:
    """The iron rule: PASS is only available when nothing is missing."""
    decision = gate.evaluate(call("read_file", {"path": "src/app.py"}))
    assert decision.verdict == "PASS"
    assert all(signal.measured for signal in decision.signals)
    assert all(signal.independent for signal in decision.signals)


def test_self_attestation_can_only_tighten(gate: Gate) -> None:
    """A call the agent vouches for is blocked, even when it would have passed."""
    clean = gate.evaluate(call("read_file", {"path": "src/app.py"}))
    attested = gate.evaluate(
        call(
            "read_file",
            {"path": "src/app.py"},
            meta={"agent_safety_gate": {"assessment": "safe"}},
        )
    )
    assert clean.verdict == "PASS"
    assert attested.verdict == "BLOCK"
    assert attested.kernel_input["metadata_complete"] is False
    assert "self-attestation" in attested.reason


def test_self_attestation_in_arguments_is_also_caught(gate: Gate) -> None:
    decision = gate.evaluate(
        call("read_file", {"path": "src/app.py", "agent_safety_gate": "trust me"})
    )
    assert decision.verdict == "BLOCK"


def test_missing_signal_feeds_uncertainty_not_a_guess(gate: Gate) -> None:
    """An undeclared tool produces uncertainty, never an invented action class."""
    decision = gate.evaluate(call("some_new_tool", {"x": 1}))
    signals = {signal.id: signal for signal in decision.signals}
    assert signals["action_class"].measured is False
    assert signals["action_class"].value is None
    assert decision.kernel_input["score"] == 0
    assert decision.kernel_input["uncertainty"] > 0
    assert decision.verdict == "WARN"


def test_unknown_tool_can_be_configured_to_block(
    policy_path: Path, tmp_path: Path
) -> None:
    text = policy_path.read_text(encoding="utf-8").replace(
        "unknown_tool: warn", "unknown_tool: block"
    )
    strict_path = tmp_path / "strict.yaml"
    strict_path.write_text(text, encoding="utf-8")
    decision = Gate(load_policy(strict_path)).evaluate(call("some_new_tool", {"x": 1}))
    assert decision.verdict == "BLOCK"


def test_independent_approval_unblocks_exactly_one_call(
    gate: Gate, policy: Policy
) -> None:
    blocked = gate.evaluate(call("run_shell", {"command": "make release"}))
    assert blocked.verdict == "BLOCK"

    directory = approvals_root(policy)
    directory.mkdir(parents=True, exist_ok=True)
    digest = call("run_shell", {"command": "make release"}).action_digest
    (directory / f"{digest}.json").write_text('{"approved_by": "operator"}', "utf-8")

    approved = gate.evaluate(call("run_shell", {"command": "make release"}))
    signals = {signal.id: signal for signal in approved.signals}
    # A bare `approved_by` binds what was approved and not who by, and the
    # record now says which of the two it got.
    assert signals[SIGNAL_APPROVAL_PRESENT].value == "present_unattributed"
    assert signals[SIGNAL_APPROVAL_PRESENT].independent is True
    # The approval is bound to the arguments: one changed character and it is
    # a different call again.
    other = gate.evaluate(call("run_shell", {"command": "make release "}))
    assert other.verdict == "BLOCK"


def test_approval_alone_is_not_enough_when_scope_is_unmeasured(
    gate: Gate, policy: Policy
) -> None:
    """run_shell has no scope block, so even an approved call stays a WARN."""
    directory = approvals_root(policy)
    directory.mkdir(parents=True, exist_ok=True)
    target = call("run_shell", {"command": "make release"})
    (directory / f"{target.action_digest}.json").write_text("{}", "utf-8")
    assert gate.evaluate(target).verdict == "WARN"


def test_broken_approval_file_does_not_count(gate: Gate, policy: Policy) -> None:
    directory = approvals_root(policy)
    directory.mkdir(parents=True, exist_ok=True)
    target = call("run_shell", {"command": "make release"})
    (directory / f"{target.action_digest}.json").write_text("not json", "utf-8")
    decision = gate.evaluate(target)
    assert decision.verdict == "BLOCK"
    assert "not readable JSON" in "".join(signal.detail for signal in decision.signals)


def test_decision_is_byte_identical_across_repeats(gate: Gate) -> None:
    """Acceptance criterion 1, in process: identical input, identical bytes."""
    target = call("write_file", {"path": "docs/NOTES.md", "content": "x"})
    first = canonical_json_bytes(gate.evaluate(target).decision_material)
    digests = set()
    for _ in range(100):
        decision = gate.evaluate(target)
        assert canonical_json_bytes(decision.decision_material) == first
        digests.add(decision.decision_hash)
    assert len(digests) == 1


def test_argument_order_does_not_change_the_decision(gate: Gate) -> None:
    one = gate.evaluate(call("write_file", {"path": "src/a.py", "content": "x"}))
    two = gate.evaluate(call("write_file", {"content": "x", "path": "src/a.py"}))
    assert one.decision_hash == two.decision_hash


def test_changing_a_threshold_changes_the_decision_digest(
    gate: Gate, policy_path: Path, tmp_path: Path
) -> None:
    """The policy is part of the input, so recalibration is visible in the digest."""
    target = call("read_file", {"path": "src/app.py"})
    before = gate.evaluate(target).decision_hash
    text = policy_path.read_text(encoding="utf-8").replace("limit: 7000", "limit: 6000")
    other_path = tmp_path / "other.yaml"
    other_path.write_text(text, encoding="utf-8")
    after = Gate(load_policy(other_path)).evaluate(target).decision_hash
    assert before != after


def test_record_carries_everything_needed_to_replay(gate: Gate, demo_key: Any) -> None:
    decision = gate.evaluate(call("run_shell", {"command": "rm -rf /"}))
    record = gate.build_record(
        decision,
        key=demo_key,
        chain_index=0,
        prev_record_sha256=None,
        recorded_at="2026-07-31T09:00:00Z",
    )
    assert record["aos_verdict"] == "BLOCK"
    assert record["finding_count"] == len(decision.deficits)
    assert record["remediation"], "a blocked call must say what to do about it"
    assert json.loads(record["call"]["arguments_json"]) == {"command": "rm -rf /"}
    assert record["decision_material"]["kernel_input"]["metadata_complete"] is True
