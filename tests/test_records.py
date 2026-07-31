"""Canonical bytes, the chain, tamper evidence, and cross-process determinism.

Acceptance criteria 1 and 2 live here.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from agent_safety_gate.gate import Gate
from agent_safety_gate.records import (
    RecordError,
    canonical_json_bytes,
    compute_record_sha256,
    read_records,
    sha256_hex,
    verify_chain,
    verify_file,
    write_records,
)
from agent_safety_gate.signing import SigningKey, generate_key
from tests.conftest import DEMO_KEY_FILE, FIXED_TIME, REPO_ROOT, call


def build_chain(gate: Gate, key: SigningKey, path: Path) -> list[dict[str, object]]:
    calls = [
        call("fetch_url", {"url": "https://docs.example.com/setup"}),
        call("write_file", {"path": "docs/NOTES.md", "content": "x"}),
        call("run_shell", {"command": "rm -rf /home/dev/project"}),
    ]
    records: list[dict[str, object]] = []
    previous: str | None = None
    for index, target in enumerate(calls):
        record = gate.build_record(
            gate.evaluate(target),
            key=key,
            chain_index=index,
            prev_record_sha256=previous,
            mode="demo",
            recorded_at=FIXED_TIME,
        )
        previous = str(record["record_sha256"])
        records.append(record)
    write_records(path, records)
    return records


def test_canonical_json_matches_the_kernel_encoding() -> None:
    value = {"b": 1, "a": [1, {"z": None, "y": True}], "unicode": "gęślą jaźń"}
    assert canonical_json_bytes(value) == (
        b'{"a":[1,{"y":true,"z":null}],"b":1,"unicode":"g\xc4\x99\xc5\x9bl\xc4\x85 '
        b'ja\xc5\xba\xc5\x84"}'
    )


def test_floats_are_refused_with_a_next_step() -> None:
    with pytest.raises(RecordError) as error:
        canonical_json_bytes({"latency": 1.5})
    assert "Next step" in str(error.value)


def test_chain_and_signatures_verify(
    gate: Gate, demo_key: SigningKey, tmp_path: Path
) -> None:
    path = tmp_path / "records.jsonl"
    build_chain(gate, demo_key, path)
    result = verify_file(path)
    assert result.ok
    assert [item.verdict for item in result.records] == ["PASS", "WARN", "BLOCK"]


def test_pinned_key_check(gate: Gate, demo_key: SigningKey, tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    build_chain(gate, demo_key, path)
    assert verify_file(path, pinned_public_key=demo_key.public_key_base64).ok
    other = generate_key()
    wrong = verify_file(path, pinned_public_key=other.public_key_base64)
    assert not wrong.ok
    assert any(check.name == "pinned_key" for check in wrong.records[0].failures)


def test_signature_fails_against_the_wrong_public_key(
    gate: Gate, demo_key: SigningKey, tmp_path: Path
) -> None:
    """Acceptance criterion 3."""
    path = tmp_path / "records.jsonl"
    records = build_chain(gate, demo_key, path)
    record = dict(records[0])
    signature = cast(
        "dict[str, Any]", dict(cast("Mapping[str, Any]", record["signature"]))
    )
    signature["public_key"] = generate_key().public_key_base64
    record["signature"] = signature
    record["record_sha256"] = compute_record_sha256(record)
    result = verify_chain([record])
    failures = {check.name for check in result.records[0].failures}
    assert failures == {"signature"}


@pytest.mark.parametrize("target_line", [1, 2, 3])
def test_a_single_changed_byte_is_reported_on_the_right_record(
    gate: Gate, demo_key: SigningKey, tmp_path: Path, target_line: int
) -> None:
    """Acceptance criterion 2: the break is named, not just detected."""
    path = tmp_path / "records.jsonl"
    build_chain(gate, demo_key, path)
    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[target_line - 1])
    payload["reason"] = payload["reason"] + "."
    lines[target_line - 1] = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    result = verify_file(path)
    assert not result.ok
    assert target_line in result.failed_lines
    failures = {check.name for check in result.records[target_line - 1].failures}
    assert "record_digest" in failures
    assert "signature" in failures


def test_removing_a_record_breaks_the_link(
    gate: Gate, demo_key: SigningKey, tmp_path: Path
) -> None:
    path = tmp_path / "records.jsonl"
    build_chain(gate, demo_key, path)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    result = verify_file(path)
    assert not result.ok
    assert result.failed_lines == [2]
    assert {check.name for check in result.records[1].failures} == {"chain_link"}


def test_decision_input_digest_is_recomputable_without_this_package(
    gate: Gate, demo_key: SigningKey, tmp_path: Path
) -> None:
    """Anyone with SHA-256 and a JSON canonicaliser can redo this."""
    path = tmp_path / "records.jsonl"
    build_chain(gate, demo_key, path)
    for record in read_records(path):
        assert sha256_hex(record["decision_input"]) == record["input_sha256"]
        assert sha256_hex(record["decision_material"]) == record["decision_hash"]


def test_empty_and_malformed_files_explain_themselves(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(RecordError) as error:
        read_records(empty)
    assert "Next step" in str(error.value)

    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"a": 1}\nnot json\n', encoding="utf-8")
    with pytest.raises(RecordError) as error:
        read_records(broken)
    assert ":2:" in str(error.value)


def test_two_processes_produce_the_same_bytes(tmp_path: Path) -> None:
    """Acceptance criterion 1, across processes: same command, same file."""
    outputs = []
    for index in range(2):
        directory = tmp_path / f"run{index}"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_safety_gate.cli",
                "demo",
                "--output-dir",
                str(directory),
                "--key",
                str(DEMO_KEY_FILE),
                "--fixed-time",
                FIXED_TIME,
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append((directory / "records.jsonl").read_bytes())
    assert outputs[0] == outputs[1]


def test_the_committed_sample_is_what_the_code_produces(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "tools/regenerate_examples.py", "--check"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
