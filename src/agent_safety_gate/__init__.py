"""agent-safety-gate: a decision gate for agent tool calls.

Before a tool call runs, the gate checks whether the control signals around it
are complete and independent, returns PASS / WARN / BLOCK, and writes a signed,
chained record that anyone can verify offline.

It does not review the agent's work, does not judge the quality of an action and
contains no language model. It marks or cuts off paths that cannot be audited.
"""

from __future__ import annotations

from agent_safety_gate.gate import Decision, Gate, build_gate
from agent_safety_gate.policy import Policy, PolicyError, load_policy
from agent_safety_gate.records import (
    ChainVerification,
    RecordError,
    verify_chain,
    verify_file,
)
from agent_safety_gate.signals import Signal, ToolCall, collect_signals

__version__ = "0.1.0"

__all__ = [
    "ChainVerification",
    "Decision",
    "Gate",
    "Policy",
    "PolicyError",
    "RecordError",
    "Signal",
    "ToolCall",
    "__version__",
    "build_gate",
    "collect_signals",
    "load_policy",
    "verify_chain",
    "verify_file",
]
