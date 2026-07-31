"""The claims audit, and proof that it can fail.

Acceptance criterion 9. A check that never fires is worse than no check, so this
runs the auditor against documents that break each rule on purpose.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "tools"))

from audit_claims import audit  # noqa: E402


def test_the_shipped_readmes_pass() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/audit_claims.py"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "## Chain\n\nThe hash chain is unforgeable.\n",
            "unforgeable",
        ),
        (
            "## Compliance\n\nThis guarantees compliance with the EU AI Act.\n",
            "guarantee compliance",
        ),
        (
            "## Speed\n\nThe gate adds 0.2 ms per call.\n",
            "no command that reproduces it",
        ),
        (
            "## Catch\n\nIt catches 99% of dangerous calls.\n",
            "no command that reproduces it",
        ),
    ],
)
def test_the_auditor_catches_what_it_is_for(
    tmp_path: Path, text: str, expected: str
) -> None:
    document = tmp_path / "README.md"
    document.write_text(text, encoding="utf-8")
    problems = audit(document)
    assert any(expected in problem for problem in problems), problems


@pytest.mark.parametrize(
    "text",
    [
        "## Signatures\n\nAn Ed25519 signature is unforgeable "
        "without the private key.\n",
        "## Compliance\n\nIt does not guarantee compliance with anything.\n",
        "## Speed\n\nThe gate adds 0.2 ms per call.\n\n"
        "`python benchmarks/proxy_overhead.py`\n",
    ],
)
def test_the_auditor_leaves_honest_text_alone(tmp_path: Path, text: str) -> None:
    document = tmp_path / "README.md"
    document.write_text(text, encoding="utf-8")
    assert audit(document) == []


def test_both_readmes_lead_with_the_pain_not_the_architecture() -> None:
    """The first screen is an incident, and 'what this is NOT' comes early."""
    for name, negative in (
        ("README.md", "## What this is NOT"),
        ("README.pl.md", "## Czym to NIE jest"),
    ):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        headings = [line for line in text.splitlines() if line.startswith("## ")]
        assert negative in headings[:3], f"{name}: {headings[:4]}"
        first_screen = text[:1200]
        assert "BLOCK" in first_screen
        for architecture_word in ("schema_version", "SHA-256", "dataclass"):
            assert architecture_word not in first_screen, name


def test_both_readmes_carry_the_three_how_tos_before_the_boundary() -> None:
    for name, how_tos in (
        (
            "README.md",
            (
                "## Wrap your own MCP server",
                "## Read a decision",
                "## Verify a chain offline",
            ),
        ),
        (
            "README.pl.md",
            (
                "## Opakuj własny serwer MCP",
                "## Przeczytaj decyzję",
                "## Zweryfikuj łańcuch offline",
            ),
        ),
    ):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        positions = [text.index(heading) for heading in how_tos]
        assert positions == sorted(positions), name
        decides = text.index(
            "## How it decides" if name == "README.md" else "## Jak podejmuje decyzję"
        )
        assert max(positions) < decides, (
            f"{name}: architecture comes before the how-tos"
        )


def test_demonstration_defaults_are_labelled_in_both_readmes() -> None:
    for name, phrase in (
        ("README.md", "demonstration defaults"),
        ("README.pl.md", "wartości demonstracyjne"),
    ):
        assert phrase in (REPO_ROOT / name).read_text(encoding="utf-8").lower()


def test_the_polish_readme_is_a_translation_not_a_summary() -> None:
    english = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    polish = (REPO_ROOT / "README.pl.md").read_text(encoding="utf-8")
    assert len(polish) > 0.8 * len(english)
    english_headings = [line for line in english.splitlines() if line.startswith("## ")]
    polish_headings = [line for line in polish.splitlines() if line.startswith("## ")]
    assert len(polish_headings) >= len(english_headings)


def test_the_ai_act_wording_stays_careful() -> None:
    for name, phrase in (
        ("README.md", "designed to support"),
        ("README.pl.md", "zaprojektowane, by wspierać"),
    ):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert phrase in text
        assert "Article 12" in text or "Artykuł 12" in text
