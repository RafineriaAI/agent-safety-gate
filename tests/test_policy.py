"""Policy loading, and the promise that every error names the fix."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_safety_gate.policy import PolicyError, load_policy, normalize_path

VALID = """
policy_id: t
policy_version: "1"
tools:
  read_file:
    action_class: read_only
    scope:
      argument: path
      allow_path_prefixes: [src/]
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_minimal_policy_loads(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, VALID))
    assert policy.policy_id == "t"
    assert policy.rule_for("read_file") is not None
    assert policy.rule_for("nothing") is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "policy_id: t\npolicy_version: '1'\ntools:\n  x:\n    action_class: nope\n",
            "read_only",
        ),
        (
            "policy_id: t\npolicy_version: '1'\nthresholds:\n"
            "  limit: 100\n  warn_margin: 200\n",
            "lower than",
        ),
        ("policy_id: t\npolicy_version: '1'\nunknown_tool: maybe\n", "warn, block"),
        (
            "policy_id: t\npolicy_version: '1'\ntools:\n  x:\n"
            "    action_class: read_only\n"
            "    scope:\n      argument: path\n",
            "allows nothing",
        ),
        ("policy_version: '1'\n", "policy_id"),
    ],
)
def test_every_policy_error_carries_a_next_step(
    tmp_path: Path, text: str, expected: str
) -> None:
    with pytest.raises(PolicyError) as error:
        load_policy(write(tmp_path, text))
    message = str(error.value)
    assert "Next step:" in message
    assert expected in message


def test_bad_yaml_points_at_the_line(tmp_path: Path) -> None:
    path = write(tmp_path, "policy_id: t\ntools:\n  x:\n   - broken\n  y: [1,\n")
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    message = str(error.value)
    assert "Next step:" in message
    assert "policy.yaml:" in message


def test_missing_file_says_where_to_start(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as error:
        load_policy(tmp_path / "nothing.yaml")
    assert "examples/demo_policy.yaml" in str(error.value)


def test_policy_digest_ignores_formatting_but_not_values(tmp_path: Path) -> None:
    first = load_policy(write(tmp_path, VALID))
    reformatted = tmp_path / "reformatted.yaml"
    reformatted.write_text(
        VALID.replace("policy_id: t", "# a comment\npolicy_id:   t"), encoding="utf-8"
    )
    assert load_policy(reformatted).digest == first.digest

    changed = tmp_path / "c.yaml"
    changed.write_text(VALID.replace("src/", "lib/"), encoding="utf-8")
    assert load_policy(changed).digest != first.digest


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("src/app.py", "src/app.py"),
        ("src\\app.py", "src/app.py"),
        ("./src/./app.py", "src/app.py"),
        ("src/../src/app.py", "src/app.py"),
        ("../secrets", None),
        ("src/../../secrets", None),
    ],
)
def test_path_normalisation_is_platform_independent(
    value: str, expected: str | None
) -> None:
    assert normalize_path(value) == expected


def test_scope_matching_is_literal(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, VALID))
    rule = policy.rule_for("read_file")
    assert rule is not None and rule.scope is not None
    assert rule.scope.matches("src/app.py")
    assert not rule.scope.matches("srcx/app.py")
    assert not rule.scope.matches("/etc/passwd")


def test_domain_matching_covers_subdomains_only(tmp_path: Path) -> None:
    text = """
policy_id: t
policy_version: "1"
tools:
  fetch:
    action_class: read_only
    scope:
      argument: url
      allow_domains: [example.com]
"""
    rule = load_policy(write(tmp_path, text)).rule_for("fetch")
    assert rule is not None and rule.scope is not None
    assert rule.scope.matches("https://docs.example.com/x")
    assert rule.scope.matches("https://example.com")
    assert not rule.scope.matches("https://example.com.evil.net/x")
    assert not rule.scope.matches("https://notexample.com/x")
