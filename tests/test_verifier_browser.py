"""The browser verifier, run in a real headless browser.

Acceptance criterion 5. Two claims are checked:

* the shipped page turns green on an intact chain and red on the exact record
  that was damaged;
* the JavaScript canonicaliser produces the same bytes and the same digests as
  Python for 200 generated values. A verifier that disagrees with the producer
  by one byte would be worse than no verifier at all.
"""

from __future__ import annotations

import json
import random
import sys
from typing import Any

import pytest

from agent_safety_gate.records import canonical_json_bytes, sha256_hex
from tests.conftest import REPO_ROOT, SAMPLE_RECORDS

sys.path.insert(0, str(REPO_ROOT / "tools"))

from browser_check import BrowserUnavailable, run_in_browser  # noqa: E402

PARITY_VECTOR_COUNT = 200


def _random_string(rng: random.Random) -> str:
    alphabets = [
        "abcdefghijklmnopqrstuvwxyz0123456789",
        " \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        "ąćęłńóśźż ĄĆĘŁŃÓŚŹŻ",
        "日本語 中文 한국어",
        "",
        "€→∞ 😀 𝄞",
    ]
    alphabet = rng.choice(alphabets)
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))


def _random_value(rng: random.Random, depth: int = 0) -> Any:
    choices = ["int", "str", "bool", "null"]
    if depth < 3:
        choices += ["list", "dict"]
    kind = rng.choice(choices)
    if kind == "int":
        return rng.randint(-(2**31), 2**31)
    if kind == "str":
        return _random_string(rng)
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "null":
        return None
    if kind == "list":
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {
        _random_string(rng) or f"k{index}": _random_value(rng, depth + 1)
        for index in range(rng.randint(0, 4))
    }


def build_parity_vectors() -> list[Any]:
    """Deterministic vectors, plus the awkward cases picked by hand."""
    rng = random.Random(20260731)
    vectors: list[Any] = [
        {},
        [],
        0,
        -1,
        "",
        None,
        True,
        {"a": {"b": {"c": [1, 2, 3]}}},
        {"": "empty key"},
        {"0": 0, "1": 1, "10": 10, "2": 2},
        {"A": 1, "Z": 1, "a": 1, "z": 1, "é": 1, "中": 1},
        {"quote": '"', "backslash": "\\", "newline": "\n", "tab": "\t"},
        {"control": chr(1), "del": chr(127), "nul": chr(0)},
        {"emoji": "😀", "astral_key_😀": "value"},
        {"nbsp": " ", "rtl": "עברית", "combining": "é"},
        {"big": 9007199254740991, "small": -9007199254740991},
    ]
    while len(vectors) < PARITY_VECTOR_COUNT:
        vectors.append(_random_value(rng))
    return vectors[:PARITY_VECTOR_COUNT]


@pytest.fixture(scope="module")
def browser_report() -> dict[str, Any]:
    try:
        return run_in_browser(
            SAMPLE_RECORDS.read_text(encoding="utf-8"), None, build_parity_vectors()
        )
    except BrowserUnavailable as exc:
        pytest.skip(str(exc))


def test_the_page_verifies_the_committed_sample(browser_report: dict[str, Any]) -> None:
    assert browser_report.get("ok"), browser_report.get("error")
    report = browser_report["report"]
    assert report["ok"]
    assert [record["verdict"] for record in report["records"]] == [
        "PASS",
        "WARN",
        "BLOCK",
    ]
    for record in report["records"]:
        names = {check["name"] for check in record["checks"] if check["ok"]}
        assert {"record_digest", "chain_link", "signature"} <= names


def test_javascript_and_python_agree_byte_for_byte(
    browser_report: dict[str, Any],
) -> None:
    vectors = build_parity_vectors()
    parity = browser_report["parity"]
    assert len(parity) == PARITY_VECTOR_COUNT
    for index, (value, observed) in enumerate(zip(vectors, parity, strict=True)):
        expected_bytes = canonical_json_bytes(value).decode("utf-8")
        assert observed["canonical"] == expected_bytes, f"vector {index}"
        assert observed["sha256"] == sha256_hex(value), f"vector {index}"


@pytest.mark.parametrize("damaged_line", [1, 2, 3])
def test_the_page_turns_red_on_the_damaged_record(damaged_line: int) -> None:
    lines = SAMPLE_RECORDS.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[damaged_line - 1])
    payload["reason"] = "nothing to see here"
    lines[damaged_line - 1] = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    try:
        report = run_in_browser("\n".join(lines) + "\n", None, [])
    except BrowserUnavailable as exc:
        pytest.skip(str(exc))
    assert report["ok"]
    result = report["report"]
    assert not result["ok"]
    failing = [record["line"] for record in result["records"] if not record["ok"]]
    assert failing == [damaged_line]
    failed_checks = {
        check["name"]
        for check in result["records"][damaged_line - 1]["checks"]
        if not check["ok"]
    }
    assert "record_digest" in failed_checks
    assert "signature" in failed_checks


def test_the_page_can_pin_a_key() -> None:
    text = SAMPLE_RECORDS.read_text(encoding="utf-8")
    try:
        wrong = run_in_browser(text, "A" * 43 + "=", [])
    except BrowserUnavailable as exc:
        pytest.skip(str(exc))
    assert not wrong["report"]["ok"]
    assert any(
        check["name"] == "pinned_key" and not check["ok"]
        for check in wrong["report"]["records"][0]["checks"]
    )


def test_the_verifier_is_one_self_contained_file() -> None:
    """It has to stay something you can email to an auditor."""
    page = (REPO_ROOT / "verifier" / "verify.html").read_text(encoding="utf-8")
    for forbidden in ("<script src=", "<link ", "@import", "fetch(", "XMLHttpRequest"):
        assert forbidden not in page, f"verify.html must not contain {forbidden}"
    assert "default-src 'none'" in page
    assert len(page.encode("utf-8")) < 60_000
