"""Three gaps a hostile reading of the records found, and what closes them.

Each test names the attack or the question it answers, because the point of
these features is not that they exist but that a specific unanswerable question
became answerable - and that the parts still unanswerable say so.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_safety_gate.anchoring import (
    Anchor,
    AnchorError,
    anchors_path_for,
    chain_head_digest,
    check_anchor,
    read_anchors,
    write_anchors,
)
from agent_safety_gate.cli import main
from agent_safety_gate.gate import Gate
from agent_safety_gate.policy import Policy
from agent_safety_gate.records import read_records, verify_chain
from agent_safety_gate.signals import SIGNAL_APPROVAL_PRESENT, ToolCall, approval_path
from tests.conftest import DEMO_KEY_FILE, FIXED_TIME


@pytest.fixture
def demo_dir(tmp_path: Path) -> Path:
    """A fresh three-record chain to answer questions against."""
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
    return directory


def call(tool: str, arguments: dict[str, object]) -> ToolCall:
    return ToolCall(tool=tool, arguments=arguments, server="demo-tools")


# -- 1. approver identity ---------------------------------------------------


def write_approval(
    policy: Policy, target: ToolCall, payload: dict[str, object]
) -> None:
    path = approval_path(policy, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def approval_signal(gate: Gate, target: ToolCall) -> object:
    return {s.id: s for s in gate.evaluate(target).signals}[SIGNAL_APPROVAL_PRESENT]


def test_an_approval_naming_nobody_is_recorded_as_naming_nobody(
    gate: Gate, policy: Policy
) -> None:
    """`{"approved_by": "me"}` was a valid approval and said nothing.

    It still counts - refusing it would break every deployment that has one -
    but the record no longer reads the same as one that names a person.
    """
    target = call("run_shell", {"command": "make release"})
    write_approval(policy, target, {"approved_by": "me"})
    signal = approval_signal(gate, target)
    assert signal.value == "present_unattributed"  # type: ignore[attr-defined]
    assert "no approver_id" in signal.detail  # type: ignore[attr-defined]


def test_an_approval_with_an_identity_and_a_reason_is_recorded_as_such(
    gate: Gate, policy: Policy
) -> None:
    target = call("run_shell", {"command": "make release"})
    write_approval(
        policy,
        target,
        {"approver_id": "ada@example.com", "acceptance_reason": "change CR-4417"},
    )
    signal = approval_signal(gate, target)
    assert signal.value == "present"  # type: ignore[attr-defined]
    assert "ada@example.com" in signal.detail  # type: ignore[attr-defined]
    assert "ada@example.com" in signal.source  # type: ignore[attr-defined]


def test_an_unattributed_approval_still_unblocks(gate: Gate, policy: Policy) -> None:
    """The distinction is recorded, not enforced.

    Turning it into a refusal would be a policy decision taken on someone
    else's behalf, and would break existing approvals on upgrade.
    """
    target = call("run_shell", {"command": "make release"})
    blocked = gate.evaluate(target)
    write_approval(policy, target, {"approved_by": "me"})
    assert gate.evaluate(target).verdict != blocked.verdict


# -- 2. WARN resolution -----------------------------------------------------


def test_a_warn_that_nobody_answered_is_distinguishable_from_one_that_was(
    demo_dir: Path,
) -> None:
    """Before this, both looked identical on disk. That made the whole
    warn-and-let-a-person-decide mechanism unfalsifiable."""
    records_path = demo_dir / "records.jsonl"
    before = read_records(records_path)
    warn_line = next(
        i for i, r in enumerate(before, 1) if r.get("aos_verdict") == "WARN"
    )

    assert (
        main(
            [
                "resolve",
                str(records_path),
                "--line",
                str(warn_line),
                "--by",
                "ada@example.com",
                "--outcome",
                "allowed",
                "--reason",
                "inside the documented area",
                "--key",
                str(DEMO_KEY_FILE),
            ]
        )
        == 0
    )

    after = read_records(records_path)
    assert len(after) == len(before) + 1
    resolution = after[-1]
    assert resolution["record_kind"] == "warn_resolution"
    assert (
        resolution["resolves_record_sha256"] == before[warn_line - 1]["record_sha256"]
    )
    assert resolution["resolution"]["resolved_by"] == "ada@example.com"
    # The gate was told a name. It did not check one.
    assert resolution["identity_assurance"] == "self_declared"


def test_the_warn_it_answers_is_left_alone(demo_dir: Path) -> None:
    """Append, never edit: a record that rewrote history to say it had been
    reviewed would be worth nothing."""
    records_path = demo_dir / "records.jsonl"
    before = read_records(records_path)
    warn_line = next(
        i for i, r in enumerate(before, 1) if r.get("aos_verdict") == "WARN"
    )
    original = dict(before[warn_line - 1])

    main(
        [
            "resolve",
            str(records_path),
            "--line",
            str(warn_line),
            "--by",
            "ada",
            "--outcome",
            "denied",
            "--reason",
            "no",
            "--key",
            str(DEMO_KEY_FILE),
        ]
    )
    assert read_records(records_path)[warn_line - 1] == original


def test_a_resolution_keeps_the_chain_verifiable(demo_dir: Path) -> None:
    records_path = demo_dir / "records.jsonl"
    warn_line = next(
        i
        for i, r in enumerate(read_records(records_path), 1)
        if r.get("aos_verdict") == "WARN"
    )
    main(
        [
            "resolve",
            str(records_path),
            "--line",
            str(warn_line),
            "--by",
            "ada",
            "--outcome",
            "allowed",
            "--reason",
            "ok",
            "--key",
            str(DEMO_KEY_FILE),
        ]
    )
    result = verify_chain(read_records(records_path), path=records_path)
    assert result.ok, [c.detail for r in result.records for c in r.failures]


def test_only_a_warn_can_be_resolved(
    demo_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A PASS needed no decision and a BLOCK was refused. Neither waits on
    anybody, and offering to resolve them would invite a fiction."""
    records_path = demo_dir / "records.jsonl"
    pass_line = next(
        i
        for i, r in enumerate(read_records(records_path), 1)
        if r.get("aos_verdict") == "PASS"
    )
    assert (
        main(
            [
                "resolve",
                str(records_path),
                "--line",
                str(pass_line),
                "--by",
                "ada",
                "--outcome",
                "allowed",
                "--reason",
                "x",
                "--key",
                str(DEMO_KEY_FILE),
            ]
        )
        == 2
    )
    assert "not a WARN" in capsys.readouterr().err


# -- 3. anchoring -----------------------------------------------------------


def test_the_anchor_commits_to_the_chain_head(demo_dir: Path) -> None:
    records = read_records(demo_dir / "records.jsonl")
    assert chain_head_digest(records) == records[-1]["record_sha256"]


def test_an_anchor_for_a_different_chain_is_rejected(demo_dir: Path) -> None:
    """The check that matters: an anchor is only evidence about the file it
    actually commits to."""
    records = read_records(demo_dir / "records.jsonl")
    foreign = {
        "type": "rfc3161",
        "value": "",
        "status": "anchored",
        "committed_sha256": "0" * 64,
    }
    result = check_anchor(foreign, records)
    assert not result.ok
    assert "different chain" in result.detail


def test_an_anchor_says_how_much_of_the_file_it_covers(demo_dir: Path) -> None:
    """Records written after an anchor are not covered by it, and a reader who
    is not told that will assume otherwise."""
    records = read_records(demo_dir / "records.jsonl")
    entry = {
        "type": "rfc3161",
        "value": "",
        "status": "anchored",
        "committed_sha256": records[0]["record_sha256"],
    }
    result = check_anchor(entry, records)
    assert "not covered" in result.detail


def test_anchors_round_trip_on_disk(tmp_path: Path) -> None:
    records_path = tmp_path / "records.jsonl"
    path = anchors_path_for(records_path)
    anchor = Anchor(
        type="rfc3161",
        value="AAAA",
        status="anchored",
        tsa_url="https://example.invalid/tsr",
        committed_sha256="a" * 64,
        obtained_at="2026-08-03T00:00:00Z",
    )
    write_anchors(path, [anchor.to_dict()])
    entries = read_anchors(path)
    assert entries[0]["committed_sha256"] == "a" * 64
    assert entries[0]["tsa_url"] == "https://example.invalid/tsr"


def test_an_empty_chain_cannot_be_anchored() -> None:
    with pytest.raises(AnchorError):
        chain_head_digest([])
