from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, TypeAlias

REFERENCE_IMPLEMENTATION_ONLY = True
SCORE_SCALE = 10_000
DEFAULT_POLICY_ID = "demo_gate_policy_v1"
DEFAULT_POLICY_VERSION = "1.0.0"
REQUIRED_SIGNAL_FIELDS = frozenset(
    {
        "signal_id",
        "score",
        "uncertainty",
        "limit",
        "warn_margin",
        "metadata_complete",
    }
)
OPTIONAL_SIGNAL_FIELDS = frozenset({"policy_id", "policy_version"})

Verdict: TypeAlias = Literal["PASS", "WARN", "BLOCK"]


def derive_verdict(upper_bound: float, limit: float, warn_margin: float) -> Verdict:
    return _derive_verdict_decimal(
        _decimal_from_number("upper_bound", upper_bound),
        _decimal_from_number("limit", limit),
        _decimal_from_number("warn_margin", warn_margin),
    )


def _derive_verdict_decimal(
    upper_bound: Decimal,
    limit: Decimal,
    warn_margin: Decimal,
) -> Verdict:
    if upper_bound > limit:
        return "BLOCK"
    if upper_bound > limit - warn_margin:
        return "WARN"
    return "PASS"


def _require_finite(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


def _decimal_from_number(name: str, value: object) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{name} must be finite") from exc
    if not result.is_finite():
        raise ValueError(f"{name} must be finite")
    return result


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_tag(value: Any) -> str:
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"sha256:{digest}"


def _canonical_demo_payload(
    value: float,
    uncertainty: float,
    limit: float,
    verdict: Verdict,
) -> bytes:
    return canonical_json_bytes(
        {
            "limit": value_to_json_number(limit),
            "uncertainty": value_to_json_number(uncertainty),
            "value": value_to_json_number(value),
            "verdict": verdict,
        }
    )


def value_to_json_number(value: float) -> float:
    return float(value)


@dataclass(frozen=True, slots=True)
class DemoAuditRecord:
    value: float
    uncertainty: float
    limit: float
    verdict: Verdict
    audit_digest: str

    def verify_demo_digest(self) -> bool:
        payload = _canonical_demo_payload(
            self.value,
            self.uncertainty,
            self.limit,
            self.verdict,
        )
        expected = hashlib.sha256(payload).hexdigest()
        return self.audit_digest == expected


class DemoIntervalGate:
    """Limited demonstrator of PASS/WARN/BLOCK interval gating.

    This is not a production delivery format.
    """

    def __init__(self, limit: float, warn_margin: float) -> None:
        self.limit = _require_finite("limit", limit)
        self.warn_margin = _require_finite("warn_margin", warn_margin)
        if self.warn_margin < 0:
            raise ValueError("warn_margin must be non-negative")
        if self.warn_margin >= self.limit:
            raise ValueError("warn_margin must be lower than limit")

    def evaluate(
        self,
        value: float,
        uncertainty: float,
    ) -> DemoAuditRecord:
        value = _require_finite("value", value)
        uncertainty = _require_finite("uncertainty", uncertainty)
        if uncertainty < 0:
            raise ValueError("uncertainty must be non-negative")

        _require_finite("upper_bound", value + uncertainty)
        verdict = _derive_verdict_decimal(
            _decimal_from_number("value", value)
            + _decimal_from_number("uncertainty", uncertainty),
            _decimal_from_number("limit", self.limit),
            _decimal_from_number("warn_margin", self.warn_margin),
        )
        payload = _canonical_demo_payload(value, uncertainty, self.limit, verdict)
        digest = hashlib.sha256(payload).hexdigest()

        return DemoAuditRecord(
            value=value,
            uncertainty=uncertainty,
            limit=self.limit,
            verdict=verdict,
            audit_digest=digest,
        )


@dataclass(frozen=True, slots=True)
class DemoSignal:
    signal_id: str
    score: int
    uncertainty: int
    limit: int
    warn_margin: int
    metadata_complete: bool
    policy_id: str = DEFAULT_POLICY_ID
    policy_version: str = DEFAULT_POLICY_VERSION


@dataclass(frozen=True, slots=True)
class DemoEvidence:
    schema_version: str
    signal_id: str
    verdict: Verdict
    reason: str
    audit_id: str
    input_digest: str
    policy_id: str
    policy_version: str
    replayable: bool
    claim_boundary: dict[str, bool]
    input: dict[str, Any]


def require_nat(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def require_text(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a non-empty string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must be a non-empty string")
    return normalized


def parse_signal(payload: dict[str, Any]) -> DemoSignal:
    allowed = REQUIRED_SIGNAL_FIELDS | OPTIONAL_SIGNAL_FIELDS
    unexpected = sorted(set(payload).difference(allowed))
    if unexpected:
        raise ValueError("unexpected field(s): " + ", ".join(unexpected))

    for field in REQUIRED_SIGNAL_FIELDS:
        if field not in payload:
            raise ValueError(f"missing required field: {field}")

    metadata_complete = payload["metadata_complete"]
    if not isinstance(metadata_complete, bool):
        raise ValueError("metadata_complete must be boolean")

    signal = DemoSignal(
        signal_id=require_text("signal_id", payload["signal_id"]),
        score=require_nat("score", payload["score"]),
        uncertainty=require_nat("uncertainty", payload["uncertainty"]),
        limit=require_nat("limit", payload["limit"]),
        warn_margin=require_nat("warn_margin", payload["warn_margin"]),
        metadata_complete=metadata_complete,
        policy_id=require_text(
            "policy_id",
            payload.get("policy_id", DEFAULT_POLICY_ID),
        ),
        policy_version=require_text(
            "policy_version",
            payload.get("policy_version", DEFAULT_POLICY_VERSION),
        ),
    )
    validate_signal_bounds(signal)
    return signal


def validate_signal_bounds(signal: DemoSignal) -> None:
    for name in ("score", "uncertainty", "limit"):
        if getattr(signal, name) > SCORE_SCALE:
            raise ValueError(f"{name} exceeds SCORE_SCALE")

    if signal.warn_margin >= signal.limit:
        raise ValueError("warn_margin must be lower than limit")

    if signal.score + signal.uncertainty > 2 * SCORE_SCALE:
        raise ValueError("score plus uncertainty exceeds bounded demo range")


def derive_signal_verdict(signal: DemoSignal) -> tuple[Verdict, str]:
    if not signal.metadata_complete:
        return "BLOCK", "Required metadata is incomplete."

    upper_bound = signal.score + signal.uncertainty
    safe_limit = signal.limit - signal.warn_margin

    if upper_bound <= safe_limit:
        return "PASS", "Score plus uncertainty is inside the safe envelope."

    if upper_bound <= signal.limit:
        return "WARN", "Score plus uncertainty requires review."

    return "BLOCK", "Score plus uncertainty exceeds the allowed envelope."


def build_signal_evidence(signal: DemoSignal) -> DemoEvidence:
    verdict, reason = derive_signal_verdict(signal)
    input_payload = asdict(signal)
    input_digest = sha256_tag(input_payload)
    evidence_material = {
        "input_digest": input_digest,
        "policy_id": signal.policy_id,
        "policy_version": signal.policy_version,
        "reason": reason,
        "schema_version": "aos-demo-evidence/v1",
        "signal_id": signal.signal_id,
        "verdict": verdict,
    }

    return DemoEvidence(
        schema_version="aos-demo-evidence/v1",
        signal_id=signal.signal_id,
        verdict=verdict,
        reason=reason,
        audit_id=sha256_tag(evidence_material),
        input_digest=input_digest,
        policy_id=signal.policy_id,
        policy_version=signal.policy_version,
        replayable=True,
        claim_boundary={
            "external_validation_claim": False,
            "production_use_claim": False,
            "regulated_use_claim": False,
        },
        input=input_payload,
    )


def verify_signal_evidence(evidence_payload: dict[str, Any]) -> dict[str, Any]:
    if "input" not in evidence_payload:
        raise ValueError("evidence packet has no input field")

    input_payload = evidence_payload["input"]
    if not isinstance(input_payload, dict):
        raise ValueError("evidence input must be an object")

    replayed = asdict(build_signal_evidence(parse_signal(input_payload)))
    checked_fields = (
        "schema_version",
        "signal_id",
        "verdict",
        "reason",
        "audit_id",
        "input_digest",
        "policy_id",
        "policy_version",
        "replayable",
        "claim_boundary",
        "input",
    )
    mismatches = [
        {
            "field": field,
            "expected": replayed[field],
            "observed": evidence_payload.get(field),
        }
        for field in checked_fields
        if evidence_payload.get(field) != replayed[field]
    ]

    return {
        "valid": not mismatches,
        "mismatches": mismatches,
        "replayed": replayed,
    }
