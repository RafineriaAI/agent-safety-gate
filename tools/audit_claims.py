"""Audit what the documentation claims.

    python tools/audit_claims.py

Three rules, all of them things this project said it would not do:

1. **"unforgeable" belongs to signatures only.** A hash chain is tamper-evident.
   Calling it unforgeable would be a stronger claim than the mathematics
   supports.
2. **No compliance guarantees.** Records are designed to support recording
   obligations. They do not make anything compliant.
3. **Every measured number is reproducible.** A section of prose that claims a
   percentage or a duration must also carry the command that produces it.
   Numbers inside code blocks are not claims, and are ignored.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCUMENTS = ("README.md", "README.pl.md")

FORBIDDEN = (
    (r"guarantees?\s+compliance", "claims to guarantee compliance"),
    (r"ensures?\s+compliance", "claims to ensure compliance"),
    (r"fully\s+compliant", "claims full compliance"),
    (r"compliant\s+with\s+the\s+EU\s+AI\s+Act", "claims compliance with the AI Act"),
    (r"gwarantuje\s+zgodno", "claims to guarantee compliance (pl)"),
    (r"zapewnia\s+zgodno", "claims to ensure compliance (pl)"),
    (r"w\s+pe.ni\s+zgodn", "claims full compliance (pl)"),
    (r"\b100%\s+(safe|secure|bezpieczn)", "claims something is completely safe"),
    (r"military.grade|bank.grade|klasy\s+bankowej", "marketing-grade adjective"),
)

# "does not guarantee compliance" is the opposite of a compliance claim, and
# this repository says it in several places on purpose.
NEGATED = re.compile(r"\b(not|never|no|nie|bez|zadn\w*|żadn\w*)\b\s*$", re.IGNORECASE)

UNFORGEABLE = re.compile(r"\b(unforgeable|niepodrabialn\w*)\b", re.IGNORECASE)
SIGNATURE_CONTEXT = re.compile(
    r"signature|signed|private key|Ed25519|podpis\w*|klucz\w* prywatn\w*",
    re.IGNORECASE,
)

MEASURED = re.compile(
    r"\d+(?:[.,]\d+)?\s*(?:%|ms\b|us\b|µs\b|s\b|seconds\b|sekund\w*|minutes\b|minut\w*)",
    re.IGNORECASE,
)
COMMAND = re.compile(
    r"(agent-safety-gate\s+\w+|python\s+(?:tools|benchmarks)/|bash\s+tools/)"
)


def strip_code_blocks(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def sections(text: str) -> list[tuple[str, str]]:
    parts = re.split(r"^##\s+(.+)$", text, flags=re.MULTILINE)
    result: list[tuple[str, str]] = []
    for index in range(1, len(parts), 2):
        result.append((parts[index].strip(), parts[index + 1]))
    return result


def audit(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    prose = strip_code_blocks(text)
    problems: list[str] = []

    for pattern, description in FORBIDDEN:
        for match in re.finditer(pattern, prose, re.IGNORECASE):
            preceding = prose[max(0, match.start() - 40) : match.start()]
            preceding = re.sub(r"[*_`\s]+$", " ", preceding)
            if NEGATED.search(preceding):
                continue
            line = prose[: match.start()].count("\n") + 1
            problems.append(f"{path.name}: {description} (near line {line})")

    for match in UNFORGEABLE.finditer(prose):
        window = prose[max(0, match.start() - 300) : match.end() + 300]
        if not SIGNATURE_CONTEXT.search(window):
            line = prose[: match.start()].count("\n") + 1
            problems.append(
                f"{path.name}: 'unforgeable' used outside a signature context "
                f"(near line {line}); a hash chain is tamper-evident, not unforgeable"
            )

    for title, body in sections(text):
        prose_body = strip_code_blocks(body)
        numbers = MEASURED.findall(prose_body)
        if not numbers:
            continue
        if not COMMAND.search(body):
            problems.append(
                f"{path.name}: section '{title}' states a measured value but "
                "carries no command that reproduces it"
            )
    return problems


def main() -> int:
    problems: list[str] = []
    for name in DOCUMENTS:
        path = REPO_ROOT / name
        if not path.is_file():
            problems.append(f"{name} is missing")
            continue
        problems.extend(audit(path))

    if problems:
        print("ERROR: documentation claims audit failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "Next step: either remove the claim, or add the command that backs "
            "it up in the same section.",
            file=sys.stderr,
        )
        return 1
    print(f"claims audit passed for {', '.join(DOCUMENTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
