"""The kernel still accepts what the gate writes.

Acceptance criterion 2, second half. This deliberately runs the *real* AOS
kernel CLI rather than the vendored copy: testing a copy against itself would
prove nothing about compatibility.

The kernel is not a runtime dependency of this package, so the test is skipped
with a visible reason when it is not installed. CI installs it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agent_safety_gate.gate import Gate
from agent_safety_gate.signing import SigningKey
from tests.conftest import FIXED_TIME, call

pytestmark = pytest.mark.skipif(
    shutil.which("aos") is None,
    reason=(
        "the aos-kernel CLI is not installed; install it from "
        "https://github.com/RafineriaAI/aos-kernel to run the interop test"
    ),
)


def write_single_record(path: Path, record: dict[str, object]) -> None:
    path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def run_aos(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aos_cli.cli", *arguments],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("read_file", {"path": "src/app.py"}),
        ("write_file", {"path": "docs/NOTES.md", "content": "x"}),
        ("run_shell", {"command": "rm -rf /home/dev/project"}),
    ],
)
def test_kernel_accepts_gate_records(
    gate: Gate,
    demo_key: SigningKey,
    tmp_path: Path,
    tool: str,
    arguments: dict[str, object],
) -> None:
    record = gate.build_record(
        gate.evaluate(call(tool, arguments)),
        key=demo_key,
        chain_index=0,
        prev_record_sha256=None,
        recorded_at=FIXED_TIME,
    )
    record_path = tmp_path / "record.jsonl"
    wrapper_path = tmp_path / "trusted.json"
    write_single_record(record_path, record)

    emitted = run_aos(
        "trust", "emit", "--record", str(record_path), "--output", str(wrapper_path)
    )
    assert emitted.returncode == 0, emitted.stderr
    verified = run_aos(
        "trust", "verify", "--input", str(wrapper_path), "--record", str(record_path)
    )
    assert verified.returncode == 0, verified.stderr
    assert "UNSIGNED_NOT_OFFICIAL" in verified.stdout


def test_kernel_detects_a_tampered_gate_record(
    gate: Gate, demo_key: SigningKey, tmp_path: Path
) -> None:
    record = gate.build_record(
        gate.evaluate(call("run_shell", {"command": "ls"})),
        key=demo_key,
        chain_index=0,
        prev_record_sha256=None,
        recorded_at=FIXED_TIME,
    )
    record_path = tmp_path / "record.jsonl"
    wrapper_path = tmp_path / "trusted.json"
    write_single_record(record_path, record)
    assert (
        run_aos(
            "trust", "emit", "--record", str(record_path), "--output", str(wrapper_path)
        ).returncode
        == 0
    )

    record["aos_verdict"] = "PASS"
    write_single_record(record_path, record)
    verified = run_aos(
        "trust", "verify", "--input", str(wrapper_path), "--record", str(record_path)
    )
    assert verified.returncode != 0
    assert "TAMPERED" in verified.stdout


def test_the_chain_fields_are_the_ones_the_kernel_hashes(
    gate: Gate, demo_key: SigningKey
) -> None:
    """prev_record_sha256 and signature live inside what record_sha256 covers."""
    from agent_safety_gate.records import record_hash_material

    record = gate.build_record(
        gate.evaluate(call("read_file", {"path": "src/app.py"})),
        key=demo_key,
        chain_index=1,
        prev_record_sha256="0" * 64,
        recorded_at=FIXED_TIME,
    )
    material = record_hash_material(record)
    assert "prev_record_sha256" in material
    assert "signature" in material
    assert "record_sha256" not in material
