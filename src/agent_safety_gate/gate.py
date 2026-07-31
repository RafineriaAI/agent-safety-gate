"""The decision: signals in, PASS/WARN/BLOCK and a signed record out.

The verdict itself is not computed here. This module is a *policy adapter*: it
turns measured signals into the bounded numbers the AOS kernel accepts
(``score``, ``uncertainty``, ``limit``, ``warn_margin``, ``metadata_complete``),
asks the kernel, and records what happened. The weights and thresholds live in
the operator's policy file; the arithmetic that turns them into a verdict lives
in the kernel. BOUNDARY.md draws that line explicitly.

Determinism is a property of the whole path: no clock, no randomness and no
floating-point number enters a decision. The timestamp lives in the record
envelope, outside ``input_sha256`` and ``decision_hash``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Final

from agent_safety_gate._vendor.aos_kernel.aos_public_core import (
    SCORE_SCALE,
    build_signal_evidence,
    parse_signal,
)
from agent_safety_gate.policy import Policy
from agent_safety_gate.records import (
    ADAPTER_NAME,
    CALL_INPUT_FORMAT,
    GATE_RECORD_SCHEMA,
    KERNEL_RECORD_SCHEMA,
    sha256_hex,
    sign_record,
)
from agent_safety_gate.signals import (
    SIGNAL_ACTION_CLASS,
    SIGNAL_AGENT_SELF_ASSESSMENT,
    SIGNAL_APPROVAL_PRESENT,
    SIGNAL_POLICY_COVERAGE,
    SIGNAL_SCOPE_MATCH,
    Signal,
    ToolCall,
    collect_signals,
)
from agent_safety_gate.signing import SigningKey

ADAPTER_VERSION: Final = "agent-safety-gate/0.1.0"

DECISION_BY_VERDICT: Final = {
    "PASS": "CALL_ALLOWED",
    "WARN": "CALL_REVIEW_REQUIRED",
    "BLOCK": "CALL_BLOCKED",
}
ACTION_BY_VERDICT: Final = {
    "PASS": "forward_call",
    "WARN": "forward_call_with_warning",
    "BLOCK": "reject_call",
}
ENFORCEMENT_BY_VERDICT: Final = {
    "PASS": "forwarded",
    "WARN": "forwarded_with_warning",
    "BLOCK": "rejected",
}


@dataclass(frozen=True)
class Contribution:
    """What one signal added to the bounded numbers, and why."""

    signal_id: str
    score: int
    uncertainty: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "score": self.score,
            "signal_id": self.signal_id,
            "uncertainty": self.uncertainty,
        }


@dataclass(frozen=True)
class Remediation:
    """A named problem and the concrete step that clears it."""

    signal_id: str
    problem: str
    action: str
    command: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "action": self.action,
            "problem": self.problem,
            "signal_id": self.signal_id,
        }
        if self.command is not None:
            payload["command"] = self.command
        return payload


@dataclass(frozen=True)
class Decision:
    """A complete, replayable decision about one tool call."""

    verdict: str
    reason: str
    call: ToolCall
    signals: tuple[Signal, ...]
    contributions: tuple[Contribution, ...]
    deficits: tuple[str, ...]
    remediation: tuple[Remediation, ...]
    kernel_input: dict[str, Any]
    kernel_evidence: dict[str, Any]
    decision_input: dict[str, Any]
    input_sha256: str
    decision_material: dict[str, Any]
    decision_hash: str

    @property
    def enforcement(self) -> str:
        return ENFORCEMENT_BY_VERDICT[self.verdict]

    @property
    def allowed(self) -> bool:
        return self.verdict != "BLOCK"


def _signal_by_id(signals: Sequence[Signal], signal_id: str) -> Signal:
    for signal in signals:
        if signal.id == signal_id:
            return signal
    raise KeyError(signal_id)  # pragma: no cover - signal set is fixed


class Gate:
    """Evaluates tool calls against one policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    # -- scoring ---------------------------------------------------------

    def _contributions(
        self, signals: Sequence[Signal], call: ToolCall
    ) -> tuple[Contribution, ...]:
        policy = self.policy
        coverage = _signal_by_id(signals, SIGNAL_POLICY_COVERAGE)
        action_class = _signal_by_id(signals, SIGNAL_ACTION_CLASS)
        scope = _signal_by_id(signals, SIGNAL_SCOPE_MATCH)
        approval = _signal_by_id(signals, SIGNAL_APPROVAL_PRESENT)
        self_assessment = _signal_by_id(signals, SIGNAL_AGENT_SELF_ASSESSMENT)
        items: list[Contribution] = []

        if coverage.value == "absent":
            uncertainty = policy.coverage_absent_uncertainty
            reason = (
                f"no policy entry for `{call.tool}`, so the action class, the "
                "scope and the approval requirement are all unknown"
            )
            if policy.unknown_tool == "block":
                uncertainty += policy.unknown_tool_extra_uncertainty
                reason += " (unknown_tool: block)"
            items.append(
                Contribution(
                    signal_id=SIGNAL_POLICY_COVERAGE,
                    score=0,
                    uncertainty=uncertainty,
                    reason=reason,
                )
            )
        else:
            declared = str(action_class.value)
            items.append(
                Contribution(
                    signal_id=SIGNAL_ACTION_CLASS,
                    score=policy.action_class_weights[declared],
                    uncertainty=0,
                    reason=f"declared action class `{declared}`",
                )
            )
            if scope.value == "out_of_scope":
                items.append(
                    Contribution(
                        signal_id=SIGNAL_SCOPE_MATCH,
                        score=policy.scope_mismatch_weight,
                        uncertainty=0,
                        reason="the call targets a resource outside the declared scope",
                    )
                )
            elif not scope.measured:
                items.append(
                    Contribution(
                        signal_id=SIGNAL_SCOPE_MATCH,
                        score=0,
                        uncertainty=policy.scope_unmeasured_uncertainty,
                        reason="scope was not measured for this call",
                    )
                )
            if approval.value == "absent":
                items.append(
                    Contribution(
                        signal_id=SIGNAL_APPROVAL_PRESENT,
                        score=policy.approval_missing_weight,
                        uncertainty=0,
                        reason=(
                            "the policy requires an independent approval and "
                            "none exists for this call"
                        ),
                    )
                )

        if not self_assessment.independent:
            items.append(
                Contribution(
                    signal_id=SIGNAL_AGENT_SELF_ASSESSMENT,
                    score=0,
                    uncertainty=0,
                    reason=(
                        "a critical signal came from the gated agent itself; "
                        "the required metadata is therefore not independent"
                    ),
                )
            )
        return tuple(items)

    # -- decision --------------------------------------------------------

    def evaluate(self, call: ToolCall) -> Decision:
        policy = self.policy
        signals = collect_signals(policy, call)
        contributions = self._contributions(signals, call)
        self_assessment = _signal_by_id(signals, SIGNAL_AGENT_SELF_ASSESSMENT)

        score = min(SCORE_SCALE, sum(item.score for item in contributions))
        uncertainty = min(SCORE_SCALE, sum(item.uncertainty for item in contributions))
        kernel_input = {
            "limit": policy.limit,
            "metadata_complete": self_assessment.independent,
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "score": score,
            "signal_id": f"tool-call:{call.action_digest[:16]}",
            "uncertainty": uncertainty,
            "warn_margin": policy.warn_margin,
        }
        evidence = asdict(build_signal_evidence(parse_signal(dict(kernel_input))))
        verdict = str(evidence["verdict"])

        deficits = self._deficits(signals, call)
        remediation = self._remediation(signals, call)
        reason = self._reason(verdict, deficits)

        decision_input = {
            "arguments_sha256": call.arguments_sha256,
            "policy_digest": policy.digest,
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "signals": [signal.as_observation() for signal in signals],
            "tool": call.tool,
        }
        input_sha256 = sha256_hex(decision_input)
        decision_material = {
            "input_sha256": input_sha256,
            "kernel_audit_id": evidence["audit_id"],
            "kernel_input": kernel_input,
            "reason": reason,
            "verdict": verdict,
        }
        return Decision(
            verdict=verdict,
            reason=reason,
            call=call,
            signals=signals,
            contributions=contributions,
            deficits=deficits,
            remediation=remediation,
            kernel_input=kernel_input,
            kernel_evidence=evidence,
            decision_input=decision_input,
            input_sha256=input_sha256,
            decision_material=decision_material,
            decision_hash=sha256_hex(decision_material),
        )

    # -- human-facing text ----------------------------------------------

    def _deficits(self, signals: Sequence[Signal], call: ToolCall) -> tuple[str, ...]:
        coverage = _signal_by_id(signals, SIGNAL_POLICY_COVERAGE)
        scope = _signal_by_id(signals, SIGNAL_SCOPE_MATCH)
        approval = _signal_by_id(signals, SIGNAL_APPROVAL_PRESENT)
        self_assessment = _signal_by_id(signals, SIGNAL_AGENT_SELF_ASSESSMENT)
        items: list[str] = []
        if not self_assessment.independent:
            items.append(
                "the gated agent attached its own safety claim to this call "
                "(self-attestation, never counted in favour of the call)"
            )
        if coverage.value == "absent":
            items.append(f"the policy has no entry for tool `{call.tool}`")
        else:
            if scope.value == "out_of_scope":
                items.append(scope.detail)
            elif not scope.measured:
                items.append(
                    "the scope of this call could not be measured "
                    f"({scope.detail.removeprefix('not measured: ')})"
                )
            if approval.value == "absent":
                items.append(
                    "no independent approval exists for this "
                    f"`{_signal_by_id(signals, SIGNAL_ACTION_CLASS).value}` call"
                )
        return tuple(items)

    def _remediation(
        self, signals: Sequence[Signal], call: ToolCall
    ) -> tuple[Remediation, ...]:
        policy = self.policy
        coverage = _signal_by_id(signals, SIGNAL_POLICY_COVERAGE)
        action_class = _signal_by_id(signals, SIGNAL_ACTION_CLASS)
        scope = _signal_by_id(signals, SIGNAL_SCOPE_MATCH)
        approval = _signal_by_id(signals, SIGNAL_APPROVAL_PRESENT)
        self_assessment = _signal_by_id(signals, SIGNAL_AGENT_SELF_ASSESSMENT)
        policy_file = policy.source_path.name if policy.source_path else "policy.yaml"
        items: list[Remediation] = []

        if not self_assessment.independent:
            items.append(
                Remediation(
                    signal_id=SIGNAL_AGENT_SELF_ASSESSMENT,
                    problem=(
                        "the call carries an `agent_safety_gate` claim written "
                        "by the gated agent"
                    ),
                    action=(
                        "Remove that key from the call. The gate never accepts "
                        "the agent's own assessment in favour of an action; if "
                        "a human decided this call is fine, record it as an "
                        "approval instead."
                    ),
                )
            )
        if coverage.value == "absent":
            items.append(
                Remediation(
                    signal_id=SIGNAL_POLICY_COVERAGE,
                    problem=f"tool `{call.tool}` is not declared in {policy_file}",
                    action=(
                        f"Add a policy entry for `{call.tool}` with an action "
                        "class of read_only, reversible_write, irreversible or "
                        "external_effect, and a `scope:` block if the tool "
                        "takes a path or a URL."
                    ),
                    command=(
                        f"# in {policy_file}\n"
                        "tools:\n"
                        f"  {call.tool}:\n"
                        "    action_class: read_only"
                    ),
                )
            )
            return tuple(items)

        rule = policy.rule_for(call.tool)
        if (
            scope.value == "out_of_scope"
            and rule is not None
            and rule.scope is not None
        ):
            target = call.arguments.get(rule.scope.argument)
            items.append(
                Remediation(
                    signal_id=SIGNAL_SCOPE_MATCH,
                    problem=(
                        f"{rule.scope.argument}={target!r} is outside the "
                        f"declared scope ({rule.scope.describe()})"
                    ),
                    action=(
                        "Either keep the call inside the declared scope, or "
                        f"widen tools.{call.tool}.scope in {policy_file} if this "
                        "target is genuinely part of the job."
                    ),
                    command=(
                        f"# in {policy_file}\n"
                        f"tools:\n  {call.tool}:\n    scope:\n"
                        f"      argument: {rule.scope.argument}\n"
                        "      allow_path_prefixes: ["
                        + ", ".join(rule.scope.allow_path_prefixes)
                        + ", <add the missing prefix>]"
                    ),
                )
            )
        elif not scope.measured and rule is not None:
            argument_names = sorted(call.arguments)
            example_argument = argument_names[0] if argument_names else "path"
            items.append(
                Remediation(
                    signal_id=SIGNAL_SCOPE_MATCH,
                    problem=scope.detail.removeprefix("not measured: "),
                    action=(
                        f"Add a `scope:` block to tools.{call.tool} in "
                        f"{policy_file} naming the argument that carries the "
                        "target and the prefixes or domains that are allowed."
                    ),
                    command=(
                        f"# in {policy_file}\n"
                        f"tools:\n  {call.tool}:\n    scope:\n"
                        f"      argument: {example_argument}\n"
                        "      allow_path_prefixes: [src/]"
                    ),
                )
            )
        if approval.value == "absent":
            # Written relative to the policy file, exactly as the policy
            # declares it: an absolute path here would make the record depend
            # on where the gate happens to be installed.
            directory = policy.approvals_dir.rstrip("/")
            items.append(
                Remediation(
                    signal_id=SIGNAL_APPROVAL_PRESENT,
                    problem=(
                        f"`{call.tool}` is declared `{action_class.value}` and "
                        "requires an independent approval, which is missing"
                    ),
                    action=(
                        "If a human really wants this exact call to run, write "
                        "an approval file bound to its action digest, in the "
                        "approvals directory next to the policy file. The "
                        "approval covers these arguments only: change one "
                        "character and the digest no longer matches."
                    ),
                    command=(
                        f"mkdir -p {directory} && "
                        f'printf \'{{"approved_by":"me"}}\' > '
                        f"{directory}/{call.action_digest}.json"
                    ),
                )
            )
        return tuple(items)

    def _reason(self, verdict: str, deficits: Sequence[str]) -> str:
        if verdict == "PASS":
            return (
                "Every control signal was measured and came from a source other "
                "than the gated agent."
            )
        joined = "; ".join(deficits) if deficits else "uncertainty above the margin"
        if verdict == "WARN":
            return f"Forwarded with a warning because {joined}."
        return f"Blocked because {joined}."

    # -- record ----------------------------------------------------------

    def build_record(
        self,
        decision: Decision,
        *,
        key: SigningKey,
        chain_index: int,
        prev_record_sha256: str | None,
        mode: str = "mcp_proxy",
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        """Build one signed, chained record. Envelope order: sign, then digest."""
        call = decision.call
        policy = self.policy
        # `arguments_json` is a canonical JSON *string*, not a nested object:
        # hashing it as UTF-8 bytes is the only way a browser can reproduce
        # Python's digest for arbitrary tool arguments. Under
        # `record_arguments: digest_only` it is null, and the decision stays
        # bound to the arguments through `decision_input.arguments_sha256`.
        arguments_json: str | None = (
            call.arguments_json if policy.record_arguments == "full" else None
        )
        record: dict[str, Any] = {
            "action": ACTION_BY_VERDICT[decision.verdict],
            "adapter": ADAPTER_NAME,
            "adapter_version": ADAPTER_VERSION,
            "aos_verdict": decision.verdict,
            "call": {
                "action_digest": call.action_digest,
                "arguments_json": arguments_json,
                "arguments_recorded": policy.record_arguments,
                "arguments_sha256": call.arguments_sha256,
                "server": call.server,
                "tool": call.tool,
            },
            "chain_index": chain_index,
            "decision": DECISION_BY_VERDICT[decision.verdict],
            "decision_hash": decision.decision_hash,
            "decision_input": decision.decision_input,
            "decision_material": decision.decision_material,
            "enforcement": decision.enforcement,
            "finding_count": len(decision.deficits),
            "gate_schema_version": GATE_RECORD_SCHEMA,
            "input_format": CALL_INPUT_FORMAT,
            "input_sha256": decision.input_sha256,
            "kernel_evidence": decision.kernel_evidence,
            "mode": mode,
            "policy_digest": policy.digest,
            "prev_record_sha256": prev_record_sha256,
            "reason": decision.reason,
            "recorded_at": recorded_at or _now(),
            "remediation": [item.as_dict() for item in decision.remediation],
            "schema_version": KERNEL_RECORD_SCHEMA,
            "score_contributions": [item.as_dict() for item in decision.contributions],
            "signals": [
                {
                    "detail": signal.detail,
                    "id": signal.id,
                    "independent": signal.independent,
                    "measured": signal.measured,
                    "source": signal.source,
                    "value": signal.value,
                }
                for signal in decision.signals
            ],
            "source_commit": call.action_digest[:40],
            "source_kind": "agent_tool_call",
            "source_ref": f"mcp://{call.server}/{call.tool}",
            "status": "ok",
            "tool": "agent-safety-gate",
        }
        return sign_record(record, key)


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_gate(policy: Policy) -> Gate:
    return Gate(policy)


def decision_summary(decision: Decision) -> Mapping[str, Any]:
    """Compact summary used by the CLI and the proxy annotation."""
    return {
        "action_digest": decision.call.action_digest,
        "decision_hash": decision.decision_hash,
        "reason": decision.reason,
        "tool": decision.call.tool,
        "verdict": decision.verdict,
    }
