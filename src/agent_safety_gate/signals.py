"""Control signals: what the gate measured, from where, and how independently.

Two rules govern this module, and both are load-bearing:

1. **A signal produced by the gated agent never counts in favour of PASS.**
   Anything the agent attaches to its own call is recorded with
   ``independent=false`` and can only make the decision stricter.
2. **A signal that was not measured is reported as not measured.** The gate does
   not invent a value, a class or a severity for something it did not observe.
   Missing signals feed uncertainty, and uncertainty is what produces WARN.

Nothing here looks at the *content* of a call to decide whether it "looks
dangerous". There is no classifier, no heuristic and no model. The action class
of a tool comes from the operator's policy or it is unknown.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from agent_safety_gate.policy import Policy, ToolRule
from agent_safety_gate.records import canonical_json_text, sha256_hex, sha256_hex_text

SIGNAL_POLICY_COVERAGE: Final = "policy_coverage"
SIGNAL_ACTION_CLASS: Final = "action_class"
SIGNAL_SCOPE_MATCH: Final = "scope_match"
SIGNAL_APPROVAL_PRESENT: Final = "approval_present"
SIGNAL_AGENT_SELF_ASSESSMENT: Final = "agent_self_assessment"

SIGNAL_IDS: Final = (
    SIGNAL_ACTION_CLASS,
    SIGNAL_AGENT_SELF_ASSESSMENT,
    SIGNAL_APPROVAL_PRESENT,
    SIGNAL_POLICY_COVERAGE,
    SIGNAL_SCOPE_MATCH,
)

#: Reserved key. If the gated agent attaches this to a call - in MCP ``_meta``
#: or in the arguments - the gate reads it as the agent vouching for itself.
SELF_ATTESTATION_KEY: Final = "agent_safety_gate"

SOURCE_GATE: Final = "agent-safety-gate (observation)"
SOURCE_AGENT: Final = "gated agent (call metadata)"


@dataclass(frozen=True)
class Signal:
    """One measurement about one call."""

    id: str
    value: str | None
    source: str
    independent: bool
    measured: bool
    detail: str

    def as_observation(self) -> dict[str, Any]:
        """The part that goes into the decision input digest."""
        return {
            "id": self.id,
            "independent": self.independent,
            "measured": self.measured,
            "source": self.source,
            "value": self.value,
        }


@dataclass(frozen=True)
class ToolCall:
    """One ``tools/call`` as seen by the gate."""

    tool: str
    arguments: Mapping[str, Any]
    server: str = "upstream"
    meta: Mapping[str, Any] | None = None

    @property
    def arguments_json(self) -> str:
        return canonical_json_text(dict(self.arguments))

    @property
    def arguments_sha256(self) -> str:
        return sha256_hex_text(self.arguments_json)

    @property
    def action_digest(self) -> str:
        """Identity of this exact call. An approval is bound to this digest."""
        return sha256_hex(
            {"arguments_sha256": self.arguments_sha256, "tool": self.tool}
        )

    def self_attestation(self) -> Any | None:
        for container in (self.meta, self.arguments):
            if isinstance(container, Mapping) and SELF_ATTESTATION_KEY in container:
                return container[SELF_ATTESTATION_KEY]
        return None


def approvals_root(policy: Policy) -> Path:
    """Where independent approvals live.

    Relative paths resolve against the policy file, not the working directory,
    so a proxy started from anywhere reads the same directory.
    """
    configured = Path(policy.approvals_dir)
    if configured.is_absolute() or policy.source_path is None:
        return configured
    return policy.source_path.parent / configured


def approval_path(policy: Policy, call: ToolCall) -> Path:
    return approvals_root(policy) / f"{call.action_digest}.json"


def _coverage_signal(rule: ToolRule | None, policy: Policy) -> Signal:
    covered = rule is not None
    return Signal(
        id=SIGNAL_POLICY_COVERAGE,
        value="covered" if covered else "absent",
        source=f"policy:{policy.policy_id}@{policy.digest[:12]}",
        independent=True,
        measured=True,
        detail=(
            "the policy declares this tool"
            if covered
            else "the policy has no entry for this tool"
        ),
    )


def _action_class_signal(
    rule: ToolRule | None, policy: Policy, call: ToolCall
) -> Signal:
    source = f"policy:{policy.policy_id}@{policy.digest[:12]}"
    if rule is None:
        return Signal(
            id=SIGNAL_ACTION_CLASS,
            value=None,
            source=source,
            independent=True,
            measured=False,
            detail=(
                "not measured: the action class comes from the policy, and the "
                "policy has no entry for this tool"
            ),
        )
    resolved, detail = rule.action.resolve(call.arguments)
    return Signal(
        id=SIGNAL_ACTION_CLASS,
        value=resolved,
        source=source,
        independent=True,
        measured=resolved is not None,
        detail=detail,
    )


def _scope_signal(rule: ToolRule | None, call: ToolCall, policy: Policy) -> Signal:
    source = f"policy:{policy.policy_id}@{policy.digest[:12]}"
    if rule is None:
        return Signal(
            id=SIGNAL_SCOPE_MATCH,
            value=None,
            source=source,
            independent=True,
            measured=False,
            detail="not measured: no policy entry declares a scope for this tool",
        )
    if rule.scope is None:
        return Signal(
            id=SIGNAL_SCOPE_MATCH,
            value=None,
            source=source,
            independent=True,
            measured=False,
            detail=(
                f"not measured: tools.{rule.name} has no `scope:` block, so the "
                "gate cannot tell an in-scope call from an out-of-scope one"
            ),
        )
    target = call.arguments.get(rule.scope.argument)
    if not isinstance(target, str) or not target.strip():
        return Signal(
            id=SIGNAL_SCOPE_MATCH,
            value=None,
            source=source,
            independent=True,
            measured=False,
            detail=(
                f"not measured: the call has no string argument "
                f"`{rule.scope.argument}` to compare against the allowlist"
            ),
        )
    in_scope = rule.scope.matches(target)
    return Signal(
        id=SIGNAL_SCOPE_MATCH,
        value="in_scope" if in_scope else "out_of_scope",
        source=f"{source} allowlist [{rule.scope.describe()}]",
        independent=True,
        measured=True,
        detail=(
            f"{rule.scope.argument}={target!r} is "
            f"{'inside' if in_scope else 'outside'} the declared scope "
            f"({rule.scope.describe()})"
        ),
    )


def _approval_signal(
    rule: ToolRule | None,
    call: ToolCall,
    policy: Policy,
    action_class: str | None,
) -> Signal:
    if rule is None or action_class is None:
        return Signal(
            id=SIGNAL_APPROVAL_PRESENT,
            value=None,
            source=f"policy:{policy.policy_id}@{policy.digest[:12]}",
            independent=True,
            measured=False,
            detail=(
                "not measured: without a policy entry the gate does not know "
                "whether this call needs an approval"
                if rule is None
                else "not measured: the action class of this call could not be "
                "resolved, so whether it needs an approval is unknown"
            ),
        )
    if not rule.approval_required_for(action_class):
        return Signal(
            id=SIGNAL_APPROVAL_PRESENT,
            value="not_required",
            source=f"policy:{policy.policy_id}@{policy.digest[:12]}",
            independent=True,
            measured=True,
            detail=f"tools.{rule.name} does not require an approval",
        )
    path = approval_path(policy, call)
    if not path.is_file():
        return Signal(
            id=SIGNAL_APPROVAL_PRESENT,
            value="absent",
            source=f"approvals_dir:{policy.approvals_dir}",
            independent=True,
            measured=True,
            detail=f"no approval file for this exact call at {path.name}",
        )
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return Signal(
            id=SIGNAL_APPROVAL_PRESENT,
            value="absent",
            source=f"approvals_dir:{policy.approvals_dir}",
            independent=True,
            measured=True,
            detail=(
                f"approval file {path.name} is not readable JSON, so it does not "
                "count as an approval"
            ),
        )
    if not isinstance(payload, dict):
        return Signal(
            id=SIGNAL_APPROVAL_PRESENT,
            value="absent",
            source=f"approvals_dir:{policy.approvals_dir}",
            independent=True,
            measured=True,
            detail=f"approval file {path.name} must contain a JSON object",
        )
    return Signal(
        id=SIGNAL_APPROVAL_PRESENT,
        value="present",
        source=(
            f"approvals_dir:{policy.approvals_dir}"
            f"#{sha256_hex_text(path.read_text(encoding='utf-8'))[:12]}"
        ),
        independent=True,
        measured=True,
        detail=(
            f"an approval bound to this exact call exists at {path.name}. "
            "Independence of this signal is a deployment property: the gated "
            "agent must not be able to write to the approvals directory."
        ),
    )


def _self_assessment_signal(call: ToolCall) -> Signal:
    claim = call.self_attestation()
    if claim is None:
        return Signal(
            id=SIGNAL_AGENT_SELF_ASSESSMENT,
            value="absent",
            source=SOURCE_GATE,
            independent=True,
            measured=True,
            detail=(
                f"the call carries no `{SELF_ATTESTATION_KEY}` claim; this "
                "observation is made by the gate, not by the agent"
            ),
        )
    return Signal(
        id=SIGNAL_AGENT_SELF_ASSESSMENT,
        value="self_attested",
        source=SOURCE_AGENT,
        independent=False,
        measured=True,
        detail=(
            f"the gated agent attached a `{SELF_ATTESTATION_KEY}` claim to its "
            "own call. The gate records it as evidence about the agent, never "
            "as evidence for the action."
        ),
    )


def collect_signals(policy: Policy, call: ToolCall) -> tuple[Signal, ...]:
    """Measure every MVP signal for one call, in a stable order."""
    rule = policy.rule_for(call.tool)
    action_class_signal = _action_class_signal(rule, policy, call)
    signals = (
        action_class_signal,
        _self_assessment_signal(call),
        _approval_signal(rule, call, policy, action_class_signal.value),
        _coverage_signal(rule, policy),
        _scope_signal(rule, call, policy),
    )
    return tuple(sorted(signals, key=lambda signal: signal.id))
