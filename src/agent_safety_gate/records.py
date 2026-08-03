"""Decision records: canonical bytes, hash chain, and offline verification.

A record is one JSON object per line of a JSONL file. It is deliberately
compatible with the AOS kernel workflow-record schema, so the kernel's own
``aos trust emit`` / ``aos trust verify`` still accept a record produced here
(see ``tests/test_kernel_interop.py``). The kernel validator only rejects
*missing* fields, so the gate adds its own keys on top:

* ``prev_record_sha256`` links each record to the previous one (the chain),
* ``signature`` authenticates the issuer,
* ``decision_input`` / ``decision_material`` make the decision digests
  recomputable by anyone, offline, without this package.

Everything that is hashed is a string, integer, boolean, null, array or object.
Floating-point numbers are rejected on purpose: Python and JavaScript do not
agree on how to render every float, and the browser verifier has to reproduce
Python's bytes exactly. Tool arguments are therefore stored as
``call.arguments_json`` - one canonical JSON string - which both sides hash as
UTF-8 bytes rather than re-serialising.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from agent_safety_gate._vendor.aos_kernel.aos_public_core import (
    canonical_json_bytes as _kernel_canonical_json_bytes,
)
from agent_safety_gate.signing import SigningKey, verify_signature

#: Schema of the kernel-compatible envelope. Do not change without re-running
#: ``tests/test_kernel_interop.py``.
KERNEL_RECORD_SCHEMA: Final = "aos-developer-workflow-record/v1"
#: Schema of the gate-specific fields carried inside that envelope.
GATE_RECORD_SCHEMA: Final = "agent-safety-gate-record/v1"
CALL_INPUT_FORMAT: Final = "agent-safety-gate-call/v1"
ADAPTER_NAME: Final = "agent_safety_gate"

_HEX64 = frozenset("0123456789abcdef")


class RecordError(Exception):
    """Raised when a record cannot be built, read or canonicalised."""


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise RecordError(
            f"floating-point number at {path} cannot be hashed reproducibly.\n"
            "Next step: store the value as a string, or let the gate record it "
            "inside call.arguments_json."
        )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RecordError(f"non-string object key at {path}: {key!r}")
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no spaces, UTF-8, no floats.

    Delegates to the vendored kernel canonicaliser so that gate digests and
    kernel digests are produced by exactly one implementation.
    """
    _reject_floats(value)
    encoded: bytes = _kernel_canonical_json_bytes(value)
    return encoded


def canonical_json_text(value: Any) -> str:
    """Canonical JSON as text. Used for ``call.arguments_json``.

    Floats are permitted here because the result is stored and hashed as an
    opaque string, never re-serialised by the verifier.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(value: Any) -> str:
    """SHA-256 of the canonical JSON encoding of ``value``."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_hex_text(value: str) -> str:
    """SHA-256 of the UTF-8 bytes of ``value``."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def is_sha256_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX64 for character in value)
    )


def record_hash_material(record: Mapping[str, Any]) -> dict[str, Any]:
    """Everything the record digest covers: the record minus its own digest.

    Identical to the kernel's rule, which is why a gate record and the kernel
    agree on ``record_sha256``.
    """
    return {key: value for key, value in record.items() if key != "record_sha256"}


def signature_material(record: Mapping[str, Any]) -> dict[str, Any]:
    """Everything the signature covers: the record minus digest and signature."""
    return {
        key: value
        for key, value in record.items()
        if key not in {"record_sha256", "signature"}
    }


def compute_record_sha256(record: Mapping[str, Any]) -> str:
    return sha256_hex(record_hash_material(record))


def sign_record(record: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Attach the signature, then the record digest, in that order.

    Order matters: the digest covers the signature, so a record cannot be
    re-signed without changing its place in the chain.
    """
    message = canonical_json_bytes(signature_material(record))
    record["signature"] = {
        "alg": "Ed25519",
        "key_label": key.label,
        "public_key": key.public_key_base64,
        "signed_material_sha256": hashlib.sha256(message).hexdigest(),
        "value": key.sign(message),
    }
    record["record_sha256"] = compute_record_sha256(record)
    return record


@dataclass(frozen=True)
class RecordCheck:
    """One named check over one record."""

    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class RecordVerification:
    """Verification outcome for one record in a chain."""

    line: int
    record_sha256: str | None
    verdict: str | None
    tool: str | None
    checks: tuple[RecordCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    @property
    def failures(self) -> tuple[RecordCheck, ...]:
        return tuple(check for check in self.checks if not check.ok)


@dataclass
class ChainVerification:
    """Verification outcome for a whole JSONL file."""

    path: Path | None
    records: list[RecordVerification] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.parse_errors and all(item.ok for item in self.records)

    @property
    def failed_lines(self) -> list[int]:
        return [item.line for item in self.records if not item.ok]


def iter_record_lines(text: str) -> Iterator[tuple[int, str]]:
    for index, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            yield index, line


def read_records(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL record file, with an actionable message on bad input."""
    if not path.is_file():
        raise RecordError(
            f"record file not found: {path}\n"
            "Next step: run `agent-safety-gate demo` to produce one."
        )
    records: list[dict[str, Any]] = []
    for line_number, line in iter_record_lines(path.read_text(encoding="utf-8")):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RecordError(
                f"{path}:{line_number}: line is not valid JSON ({exc.msg}).\n"
                "Next step: each line of a record file is exactly one JSON "
                "object; check whether the file was edited or concatenated."
            ) from exc
        if not isinstance(payload, dict):
            raise RecordError(
                f"{path}:{line_number}: line must be a JSON object, "
                f"got {type(payload).__name__}."
            )
        records.append(payload)
    if not records:
        raise RecordError(
            f"record file is empty: {path}\n"
            "Next step: run `agent-safety-gate demo` to produce records."
        )
    return records


def append_record(path: Path, record: Mapping[str, Any]) -> None:
    """Append one record as a single JSONL line with LF endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = canonical_json_text(record) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)


def write_records(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(canonical_json_text(record) + "\n" for record in records)
    path.write_text(text, encoding="utf-8", newline="\n")


def last_record_sha256(path: Path) -> str | None:
    """Digest of the last record already in ``path``, or ``None`` if new.

    This is how a proxy resumes an existing chain across restarts without a
    database: the file is the state.
    """
    if not path.is_file():
        return None
    records = read_records(path)
    value = records[-1].get("record_sha256")
    return value if isinstance(value, str) else None


def _check(name: str, ok: bool, detail: str) -> RecordCheck:
    return RecordCheck(name=name, ok=ok, detail=detail)


def verify_record(
    record: Mapping[str, Any],
    line: int,
    expected_prev: str | None,
    pinned_public_key: str | None = None,
) -> RecordVerification:
    """Run every offline check the browser verifier also runs."""
    checks: list[RecordCheck] = []

    claimed_digest = record.get("record_sha256")
    if not is_sha256_hex(claimed_digest):
        checks.append(
            _check("record_digest", False, "record_sha256 is missing or malformed")
        )
        computed_digest = None
    else:
        try:
            computed_digest = compute_record_sha256(record)
        except RecordError as exc:
            computed_digest = None
            checks.append(_check("record_digest", False, str(exc)))
        else:
            checks.append(
                _check(
                    "record_digest",
                    computed_digest == claimed_digest,
                    "record content matches record_sha256"
                    if computed_digest == claimed_digest
                    else (
                        "record content does not match record_sha256 "
                        f"(computed {computed_digest})"
                    ),
                )
            )

    observed_prev = record.get("prev_record_sha256")
    if expected_prev is None:
        chain_ok = observed_prev is None
        chain_detail = (
            "first record correctly declares no predecessor"
            if chain_ok
            else (
                "first record should have prev_record_sha256 null, got "
                f"{observed_prev!r}"
            )
        )
    else:
        chain_ok = observed_prev == expected_prev
        chain_detail = (
            "links to the previous record"
            if chain_ok
            else (
                "prev_record_sha256 does not match the previous record "
                f"(expected {expected_prev})"
            )
        )
    checks.append(_check("chain_link", chain_ok, chain_detail))

    if record.get("record_kind") == "warn_resolution":
        # A resolution answers a decision, it is not one: there is no call, no
        # signals and no arithmetic to re-derive. Everything above - digest,
        # chain link, signature - has already been checked and is what makes it
        # evidence. Running the call-shaped checks here would fail a record that
        # is exactly as it should be.
        target = record.get("resolves_record_sha256")
        checks.append(
            _check(
                "resolution_target",
                is_sha256_hex(target),
                "names the record it resolves"
                if is_sha256_hex(target)
                else "resolves_record_sha256 is missing or malformed",
            )
        )
        return RecordVerification(
            line=line,
            record_sha256=claimed_digest if isinstance(claimed_digest, str) else None,
            verdict=None,
            tool=None,
            checks=tuple(checks),
        )

    call = record.get("call")
    if not isinstance(call, dict) or "arguments_json" not in call:
        checks.append(
            _check("arguments_digest", False, "call.arguments_json is missing")
        )
    elif call["arguments_json"] is None:
        # `record_arguments: digest_only`. The arguments were not stored, but
        # the decision is still bound to them through decision_input.
        checks.append(
            _check(
                "arguments_digest",
                True,
                "arguments were not recorded (record_arguments: digest_only); "
                "the decision is still bound to their digest",
            )
        )
    elif not isinstance(call["arguments_json"], str):
        checks.append(
            _check("arguments_digest", False, "call.arguments_json must be a string")
        )
    else:
        expected_arguments_digest = sha256_hex_text(call["arguments_json"])
        ok = call.get("arguments_sha256") == expected_arguments_digest
        checks.append(
            _check(
                "arguments_digest",
                ok,
                "recorded arguments match their digest"
                if ok
                else "call.arguments_json does not match call.arguments_sha256",
            )
        )

    decision_input = record.get("decision_input")
    if isinstance(decision_input, dict):
        try:
            expected_input_digest = sha256_hex(decision_input)
        except RecordError as exc:
            checks.append(_check("decision_input_digest", False, str(exc)))
        else:
            ok = record.get("input_sha256") == expected_input_digest
            checks.append(
                _check(
                    "decision_input_digest",
                    ok,
                    "decision input matches input_sha256"
                    if ok
                    else "decision_input does not match input_sha256",
                )
            )
    else:
        checks.append(
            _check("decision_input_digest", False, "decision_input is missing")
        )

    decision_material = record.get("decision_material")
    if isinstance(decision_material, dict):
        try:
            expected_decision_digest = sha256_hex(decision_material)
        except RecordError as exc:
            checks.append(_check("decision_digest", False, str(exc)))
        else:
            ok = record.get("decision_hash") == expected_decision_digest
            checks.append(
                _check(
                    "decision_digest",
                    ok,
                    "decision material matches decision_hash"
                    if ok
                    else "decision_material does not match decision_hash",
                )
            )
    else:
        checks.append(_check("decision_digest", False, "decision_material is missing"))

    signature = record.get("signature")
    if not isinstance(signature, dict):
        checks.append(_check("signature", False, "record is not signed"))
    else:
        public_key = signature.get("public_key")
        value = signature.get("value")
        if not isinstance(public_key, str) or not isinstance(value, str):
            checks.append(_check("signature", False, "signature fields are malformed"))
        else:
            try:
                message = canonical_json_bytes(signature_material(record))
            except RecordError as exc:
                checks.append(_check("signature", False, str(exc)))
            else:
                ok = verify_signature(public_key, value, message)
                checks.append(
                    _check(
                        "signature",
                        ok,
                        f"Ed25519 signature valid for key {public_key}"
                        if ok
                        else "Ed25519 signature does not verify",
                    )
                )
                if pinned_public_key is not None:
                    pinned_ok = public_key == pinned_public_key
                    checks.append(
                        _check(
                            "pinned_key",
                            pinned_ok,
                            "signed by the pinned public key"
                            if pinned_ok
                            else (
                                "signed by a different key than the pinned one "
                                f"({public_key})"
                            ),
                        )
                    )

    verdict = record.get("aos_verdict")
    call_tool = call.get("tool") if isinstance(call, dict) else None
    return RecordVerification(
        line=line,
        record_sha256=claimed_digest if isinstance(claimed_digest, str) else None,
        verdict=verdict if isinstance(verdict, str) else None,
        tool=call_tool if isinstance(call_tool, str) else None,
        checks=tuple(checks),
    )


def verify_chain(
    records: Sequence[Mapping[str, Any]],
    path: Path | None = None,
    pinned_public_key: str | None = None,
) -> ChainVerification:
    result = ChainVerification(path=path)
    expected_prev: str | None = None
    for index, record in enumerate(records):
        verification = verify_record(
            record,
            line=index + 1,
            expected_prev=expected_prev,
            pinned_public_key=pinned_public_key,
        )
        result.records.append(verification)
        # Continue from what the record claims, so a break is reported once at
        # the damaged record instead of cascading down the rest of the file.
        claimed = record.get("record_sha256")
        expected_prev = claimed if isinstance(claimed, str) else None
    return result


def verify_file(path: Path, pinned_public_key: str | None = None) -> ChainVerification:
    return verify_chain(
        read_records(path), path=path, pinned_public_key=pinned_public_key
    )
