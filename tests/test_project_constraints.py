"""Constraints that are easy to state and easy to break later.

Acceptance criteria 10 and 11: no language model anywhere in the gate, and a
dependency list that cannot quietly grow. Plus the smaller promises this
repository makes about itself.
"""

from __future__ import annotations

import ast
import importlib.metadata
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

SOURCE = REPO_ROOT / "src" / "agent_safety_gate"
VENDOR = SOURCE / "_vendor"
CODE_DIRECTORIES = (
    SOURCE,
    REPO_ROOT / "tests",
    REPO_ROOT / "tools",
    REPO_ROOT / "benchmarks",
    REPO_ROOT / "examples",
)

#: Anything that would mean a model is being asked what to do.
MODEL_CLIENTS = (
    "openai",
    "anthropic",
    "google.generativeai",
    "google-genai",
    "cohere",
    "mistralai",
    "litellm",
    "langchain",
    "llama_index",
    "transformers",
    "huggingface",
    "ollama",
    "vertexai",
    "boto3",
)


def requirements() -> dict[str | None, set[str]]:
    """Installed metadata, grouped by extra. `None` is the runtime group.

    Read from the installed distribution rather than from pyproject.toml, so the
    test checks what a user actually gets from `pip install`.
    """
    grouped: dict[str | None, set[str]] = {}
    for entry in importlib.metadata.requires("agent-safety-gate") or []:
        requirement, _, marker = entry.partition(";")
        extra_match = re.search(r"extra\s*==\s*['\"]([^'\"]+)['\"]", marker)
        extra = extra_match.group(1) if extra_match else None
        name = re.split(r"[<>=!\[ ]", requirement.strip())[0].lower()
        grouped.setdefault(extra, set()).add(name)
    return grouped


def own_python_files() -> list[Path]:
    files: list[Path] = []
    for directory in CODE_DIRECTORIES:
        for path in directory.rglob("*.py"):
            if VENDOR in path.parents:
                continue
            files.append(path)
    return files


def test_runtime_dependencies_are_exactly_the_budget() -> None:
    assert requirements()[None] == {"cryptography", "pyyaml"}


def test_optional_dependencies_are_exactly_the_budget() -> None:
    groups = requirements()
    assert set(groups) == {None, "mcp", "dev"}
    assert groups["mcp"] == {"mcp"}
    assert groups["dev"] == {"mypy", "pytest", "ruff"}


def test_every_dependency_is_justified_in_both_readmes() -> None:
    for name in ("cryptography", "PyYAML", "mcp"):
        for readme in ("README.md", "README.pl.md"):
            text = (REPO_ROOT / readme).read_text(encoding="utf-8")
            assert f"`{name}`" in text, f"{name} has no justification in {readme}"


@pytest.mark.parametrize("client", MODEL_CLIENTS)
def test_no_language_model_client_is_declared(client: str) -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert client not in text.lower()


def test_no_language_model_client_is_imported() -> None:
    offenders: list[str] = []
    for path in own_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                root = module.split(".")[0].lower()
                if root in {name.split(".")[0] for name in MODEL_CLIENTS}:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {module}")
    assert not offenders, offenders


def test_the_gate_makes_no_network_calls() -> None:
    """The proxy talks to a child process over stdio. Nothing here dials out."""
    forbidden = ("import requests", "import httpx", "import socket", "urllib.request")
    offenders: list[str] = []
    for path in SOURCE.rglob("*.py"):
        if VENDOR in path.parents:
            continue
        text = path.read_text(encoding="utf-8")
        offenders.extend(
            f"{path.relative_to(REPO_ROOT)}: {needle}"
            for needle in forbidden
            if needle in text
        )
    assert not offenders, offenders


def test_nothing_is_rounded() -> None:
    """No float ever reaches a digest, so no rounding rule can differ.

    Python's round() is banker's rounding, which would break digest parity with
    other implementations. The gate works in integers end to end and calls it
    nowhere; this test is what keeps that true.
    """
    offenders: list[str] = []
    for path in SOURCE.rglob("*.py"):
        if VENDOR in path.parents:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"(?<![.\w])round\s*\(", line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert not offenders, offenders


def test_no_todo_markers_in_code() -> None:
    """Unfinished work belongs in issues. The licence placeholder is the one
    deliberate exception, and it is a document, not code."""
    # Written with separators the formatter cannot join back together, so
    # that this file is not its own first offender.
    markers = tuple("TO_DO FIX_ME XX_X HA_CK".replace("_", "").split())
    pattern = re.compile(r"\b(" + "|".join(markers) + r")\b")
    offenders: list[str] = []
    for path in own_python_files() + [
        REPO_ROOT / "verifier" / "verify.html",
        *(REPO_ROOT / "tools").glob("*.sh"),
    ]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}"
                )
    assert not offenders, offenders


def test_the_vendored_kernel_is_unmodified() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/check_vendor.py"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_the_kernel_copy_is_not_edited_here() -> None:
    """If the kernel needs a change, it happens upstream."""
    vendored = (VENDOR / "aos_kernel" / "aos_public_core.py").read_text(
        encoding="utf-8"
    )
    assert "agent_safety_gate" not in vendored


def test_the_committed_demo_key_announces_itself() -> None:
    key = (REPO_ROOT / "examples" / "demo_signing_key.INSECURE.json").read_text("utf-8")
    assert "DEMO KEY - DO NOT USE IN PRODUCTION" in key
    assert "INSECURE" in "examples/demo_signing_key.INSECURE.json"


def test_the_licence_is_stated_the_same_way_everywhere() -> None:
    """The licence lives in five files. They drift silently, so they are held
    together here.

    This replaces the placeholder tripwire that used to fail once a licence was
    chosen. Its job is the same: no file may claim something the others do not.
    """
    licence = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in licence
    assert "Version 2.0, January 2004" in licence
    assert "PLACEHOLDER" not in licence

    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license = "Apache-2.0"' in pyproject

    for readme in ("README.md", "README.pl.md"):
        text = (REPO_ROOT / readme).read_text(encoding="utf-8")
        assert "Apache-2.0" in text, readme
        assert "Not yet chosen" not in text, readme
        assert "Jeszcze nie wybrana" not in text, readme

    # The vendored kernel's own terms travel with it and must stay quoted.
    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "Upstream NOTICE (RafineriaAI/aos-kernel)" in notice
    assert "Apache License, Version 2.0" in notice
