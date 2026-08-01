"""The three changes that came out of measuring independent data.

* an action class declared per value of a selector argument, because real tools
  multiplex a read and a write behind one name;
* `mode: observe`, because a gate that interrupts half a session on day one is
  a gate nobody switches on;
* policy proposals from a server's own MCP annotations, which are hints and are
  treated as hints.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_safety_gate.gate import ENFORCEMENT_OBSERVED, Gate
from agent_safety_gate.policy import PolicyError, load_policy
from tests.conftest import REPO_ROOT, call

EDITOR_POLICY = """
policy_id: editor
policy_version: "1.0.0"
tools:
  editor:
    action_class:
      argument: command
      values:
        view: read_only
        create: reversible_write
      default: irreversible
    scope:
      argument: path
      allow_path_prefixes: [src/]
"""


def write(tmp_path: Path, text: str, name: str = "policy.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# -- action class per argument value ------------------------------------


@pytest.fixture
def editor_gate(tmp_path: Path) -> Gate:
    return Gate(load_policy(write(tmp_path, EDITOR_POLICY)))


@pytest.mark.parametrize(
    ("command", "expected_class", "expected_verdict"),
    [
        ("view", "read_only", "PASS"),
        ("create", "reversible_write", "PASS"),
        # Not listed, so it gets the default the operator wrote down, and an
        # irreversible call with no approval is blocked.
        ("undo_edit", "irreversible", "BLOCK"),
    ],
)
def test_class_follows_the_selector_argument(
    editor_gate: Gate, command: str, expected_class: str, expected_verdict: str
) -> None:
    decision = editor_gate.evaluate(
        call("editor", {"command": command, "path": "src/app.py"})
    )
    signals = {signal.id: signal for signal in decision.signals}
    assert signals["action_class"].value == expected_class
    assert decision.verdict == expected_verdict


def test_a_missing_selector_is_not_measured_rather_than_defaulted(
    editor_gate: Gate,
) -> None:
    """The default is for values the operator listed against; a call that
    carries no selector at all was not measured, and says so."""
    decision = editor_gate.evaluate(call("editor", {"path": "src/app.py"}))
    signals = {signal.id: signal for signal in decision.signals}
    assert signals["action_class"].measured is False
    assert signals["action_class"].value is None
    assert "not measured" in signals["action_class"].detail
    assert decision.kernel_input["score"] == 0
    assert decision.kernel_input["uncertainty"] > 0
    assert decision.verdict == "WARN"


def test_an_unresolvable_class_makes_the_approval_unknown_too(
    editor_gate: Gate,
) -> None:
    decision = editor_gate.evaluate(call("editor", {"path": "src/app.py"}))
    signals = {signal.id: signal for signal in decision.signals}
    assert signals["approval_present"].measured is False


def test_scope_still_applies_to_the_read(editor_gate: Gate) -> None:
    decision = editor_gate.evaluate(
        call("editor", {"command": "view", "path": "/etc/shadow"})
    )
    assert decision.verdict == "WARN"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            EDITOR_POLICY.replace("      default: irreversible\n", ""),
            "default",
        ),
        (
            EDITOR_POLICY.replace("        view: read_only", "        view: nonsense"),
            "read_only",
        ),
        (
            EDITOR_POLICY.replace(
                "      values:\n        view: read_only\n"
                "        create: reversible_write\n",
                "      values: {}\n",
            ),
            "is empty",
        ),
    ],
)
def test_a_broken_per_argument_class_says_what_to_write(
    tmp_path: Path, text: str, expected: str
) -> None:
    with pytest.raises(PolicyError) as error:
        load_policy(write(tmp_path, text))
    message = str(error.value)
    assert "Next step:" in message
    assert expected in message


def test_the_scalar_form_still_works(tmp_path: Path) -> None:
    policy = load_policy(
        write(
            tmp_path,
            'policy_id: t\npolicy_version: "1"\ntools:\n  x:\n'
            "    action_class: irreversible\n",
        )
    )
    rule = policy.rule_for("x")
    assert rule is not None
    assert rule.action.resolve({}) == (
        "irreversible",
        "declared in the policy as irreversible",
    )
    assert rule.approval_required_for("irreversible") is True


# -- observe mode --------------------------------------------------------


OBSERVE_POLICY = (
    'policy_id: o\npolicy_version: "1"\nmode: observe\n'
    "tools:\n  sh:\n    action_class: irreversible\n"
)
ENFORCE_POLICY = OBSERVE_POLICY.replace("mode: observe\n", "")


def test_observe_records_the_same_verdict_and_forwards_anyway(
    tmp_path: Path, demo_key: object
) -> None:
    observing = Gate(load_policy(write(tmp_path, OBSERVE_POLICY, "observe.yaml")))
    enforcing = Gate(load_policy(write(tmp_path, ENFORCE_POLICY, "enforce.yaml")))
    target = call("sh", {"x": "1"})

    observed = observing.evaluate(target)
    enforced = enforcing.evaluate(target)

    # The decision is identical. Only what the proxy does with it differs.
    assert observed.verdict == enforced.verdict == "BLOCK"
    assert observed.decision_hash == enforced.decision_hash
    assert observing.should_forward(observed) is True
    assert enforcing.should_forward(enforced) is False
    assert observing.enforcement_for(observed) == ENFORCEMENT_OBSERVED
    assert enforcing.enforcement_for(enforced) == "rejected"


def test_the_record_says_it_was_not_enforced(tmp_path: Path, demo_key: object) -> None:
    gate = Gate(load_policy(write(tmp_path, OBSERVE_POLICY, "observe.yaml")))
    decision = gate.evaluate(call("sh", {"x": "1"}))
    record = gate.build_record(
        decision,
        key=demo_key,  # type: ignore[arg-type]
        chain_index=0,
        prev_record_sha256=None,
        recorded_at="2026-08-01T00:00:00Z",
    )
    assert record["policy_mode"] == "observe"
    assert record["enforcement"] == ENFORCEMENT_OBSERVED
    assert record["aos_verdict"] == "BLOCK"
    # The remediation is still there: observing is not the same as approving.
    assert record["remediation"]


def test_mode_is_not_part_of_the_decision_digest(tmp_path: Path) -> None:
    """Two deployments of the same policy must compare, whatever they enforce."""
    observing = load_policy(write(tmp_path, OBSERVE_POLICY, "observe.yaml"))
    enforcing = load_policy(write(tmp_path, ENFORCE_POLICY, "enforce.yaml"))
    assert observing.digest == enforcing.digest


def test_an_unknown_mode_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as error:
        load_policy(write(tmp_path, OBSERVE_POLICY.replace("observe", "maybe")))
    assert "enforce, observe" in str(error.value)


def test_enforce_is_the_default(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, ENFORCE_POLICY))
    assert policy.mode == "enforce"
    assert policy.enforcing is True


# -- annotations are hints ----------------------------------------------


@pytest.mark.parametrize(
    ("annotations", "expected"),
    [
        ({"readOnlyHint": True}, "read_only"),
        ({"readOnlyHint": False, "destructiveHint": True}, "irreversible"),
        ({"readOnlyHint": False, "destructiveHint": False}, "reversible_write"),
        (
            {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
            "external_effect",
        ),
        # Nothing declared is nothing proposed. The gate does not fill the gap.
        (None, None),
        ({}, None),
        ({"idempotentHint": True}, None),
    ],
)
def test_annotations_map_to_a_proposal_only_when_they_say_something(
    annotations: dict[str, bool] | None, expected: str | None
) -> None:
    pytest.importorskip("mcp")
    from agent_safety_gate.mcp_proxy import class_from_annotations

    assert class_from_annotations(annotations) == expected


def test_the_skeleton_labels_a_proposal_as_a_proposal() -> None:
    pytest.importorskip("mcp")
    from agent_safety_gate.mcp_proxy import policy_skeleton

    skeleton = policy_skeleton(
        ["git_reset", "mystery"],
        [
            {
                "name": "git_reset",
                "annotations": {"readOnlyHint": False, "destructiveHint": True},
                "scope_argument": "repo_path",
            },
            {"name": "mystery", "annotations": None, "scope_argument": None},
        ],
    )
    assert "action_class: irreversible" in skeleton
    assert "PROPOSED" in skeleton
    assert "argument: repo_path" in skeleton
    # A tool the server says nothing about gets no class at all.
    assert "mystery:\n    action_class:  #" in skeleton
    assert "so the class is yours" in skeleton


def test_the_scope_argument_comes_from_the_schema() -> None:
    pytest.importorskip("mcp")
    from agent_safety_gate.mcp_proxy import scope_argument_for

    assert scope_argument_for({"properties": {"repo_path": {}, "message": {}}}) == (
        "repo_path"
    )
    assert scope_argument_for({"properties": {"url": {}}}) == "url"
    assert scope_argument_for({"properties": {"message": {}}}) is None
    assert scope_argument_for(None) is None


def test_the_shipped_openhands_policy_matches_the_measured_surface() -> None:
    """The policy in benchmarks/ describes somebody else's agent, so it has to
    keep describing it: these five tools are what the published trajectories
    actually call."""
    policy = load_policy(REPO_ROOT / "benchmarks" / "openhands_policy.yaml")
    assert set(policy.tools) == {
        "str_replace_editor",
        "execute_bash",
        "think",
        "finish",
        "task_tracker",
    }
    editor = policy.tools["str_replace_editor"]
    assert editor.action.argument == "command"
    assert editor.action.resolve({"command": "view"})[0] == "read_only"
    assert editor.action.resolve({"command": "str_replace"})[0] == "reversible_write"
    assert editor.action.default == "irreversible"
