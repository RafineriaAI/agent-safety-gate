"""Shared fixtures. Every test that needs a decision builds it from a real
policy file, so the tests exercise the same path an operator does."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from agent_safety_gate.gate import Gate
from agent_safety_gate.policy import Policy, load_policy
from agent_safety_gate.signals import ToolCall
from agent_safety_gate.signing import SigningKey, load_key

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"
DEMO_POLICY = EXAMPLES / "demo_policy.yaml"
DEMO_KEY_FILE = EXAMPLES / "demo_signing_key.INSECURE.json"
SAMPLE_RECORDS = EXAMPLES / "sample_records.jsonl"
FIXED_TIME = "2026-07-31T09:00:00Z"


@pytest.fixture
def demo_key() -> SigningKey:
    return load_key(DEMO_KEY_FILE)


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    """A copy of the demo policy, so relative paths resolve inside tmp_path."""
    destination = tmp_path / "demo_policy.yaml"
    shutil.copyfile(DEMO_POLICY, destination)
    return destination


@pytest.fixture
def policy(policy_path: Path) -> Policy:
    return load_policy(policy_path)


@pytest.fixture
def gate(policy: Policy) -> Gate:
    return Gate(policy)


def call(tool: str, arguments: dict[str, Any], **kwargs: Any) -> ToolCall:
    return ToolCall(
        tool=tool,
        arguments=arguments,
        server=kwargs.pop("server", "demo-tools"),
        meta=kwargs.pop("meta", None),
    )
