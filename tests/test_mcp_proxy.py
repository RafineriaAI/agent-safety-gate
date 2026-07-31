"""End to end through the real MCP proxy.

Acceptance criterion 4: three calls through a wrapped server produce PASS, WARN
and BLOCK, headless, with no code change on either side. The upstream server in
`examples/demo_tool_server.py` knows nothing about the gate, and the client in
`examples/mcp_demo_client.py` is an ordinary MCP client.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agent_safety_gate.records import read_records, verify_file
from tests.conftest import DEMO_KEY_FILE, REPO_ROOT

pytest.importorskip(
    "mcp", reason='install the extra: pip install "agent-safety-gate[mcp]"'
)


@pytest.fixture(scope="module")
def proxy_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    records = tmp_path_factory.mktemp("mcp") / "records.jsonl"
    completed = subprocess.run(
        [
            sys.executable,
            "examples/mcp_demo_client.py",
            "--records",
            str(records),
            "--key",
            str(DEMO_KEY_FILE),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout, records


def test_three_calls_produce_three_verdicts(proxy_run: tuple[str, Path]) -> None:
    output, records_path = proxy_run
    verdicts = [str(record["aos_verdict"]) for record in read_records(records_path)]
    assert verdicts == ["PASS", "WARN", "BLOCK"]
    assert "PASS  fetch_url" in output
    assert "WARN  write_file" in output
    assert "BLOCK run_shell" in output


def test_pass_is_forwarded_untouched(proxy_run: tuple[str, Path]) -> None:
    output, _ = proxy_run
    # The upstream page came back verbatim, injection and all: the gate does not
    # edit what the agent sees.
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in output


def test_warn_is_forwarded_with_the_warning_attached(
    proxy_run: tuple[str, Path],
) -> None:
    output, records_path = proxy_run
    assert "wrote 15 bytes to docs/NOTES.md" in output
    assert "[agent-safety-gate WARN]" in output
    record = read_records(records_path)[1]
    assert record["enforcement"] == "forwarded_with_warning"


def test_block_never_reaches_the_tool(proxy_run: tuple[str, Path]) -> None:
    output, records_path = proxy_run
    assert "BLOCKED by agent-safety-gate" in output
    assert "<output of: rm -rf" not in output
    record = read_records(records_path)[2]
    assert record["enforcement"] == "rejected"
    assert record["remediation"]


def test_the_proxy_chain_verifies(proxy_run: tuple[str, Path]) -> None:
    _, records_path = proxy_run
    result = verify_file(records_path)
    assert result.ok, [item.failures for item in result.records if not item.ok]


def test_a_restarted_proxy_continues_the_same_chain(
    proxy_run: tuple[str, Path], tmp_path: Path
) -> None:
    """The record file is the only state; there is no daemon and no database."""
    _, records_path = proxy_run
    resumed = tmp_path / "resumed.jsonl"
    resumed.write_bytes(records_path.read_bytes())
    completed = subprocess.run(
        [
            sys.executable,
            "examples/mcp_demo_client.py",
            "--records",
            str(resumed),
            "--key",
            str(DEMO_KEY_FILE),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    # mcp_demo_client starts a fresh file, so the resumed run is what proves the
    # chain logic: append to an existing file and re-verify.
    assert verify_file(resumed).ok


def test_proxy_resume_appends_without_breaking_the_chain(tmp_path: Path) -> None:
    from agent_safety_gate.gate import Gate
    from agent_safety_gate.mcp_proxy import ProxyState
    from agent_safety_gate.policy import load_policy
    from agent_safety_gate.records import append_record
    from agent_safety_gate.signing import load_key
    from tests.conftest import DEMO_POLICY, call

    records = tmp_path / "records.jsonl"
    policy = load_policy(DEMO_POLICY)
    gate = Gate(policy)
    key = load_key(DEMO_KEY_FILE)

    for index, target in enumerate(
        [call("read_file", {"path": "src/a.py"}), call("run_shell", {"command": "ls"})]
    ):
        state = ProxyState.resume(records)
        assert state.chain_index == index
        append_record(
            records,
            gate.build_record(
                gate.evaluate(target),
                key=key,
                chain_index=state.chain_index,
                prev_record_sha256=state.prev_record_sha256,
            ),
        )
    assert verify_file(records).ok
    assert len(read_records(records)) == 2
