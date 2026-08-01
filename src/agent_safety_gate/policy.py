"""The one file an operator edits.

The policy is data, not code: it declares which tools exist, what class of action
each one performs, where each one is allowed to act, and which thresholds turn
signals into PASS / WARN / BLOCK. Nothing in this module inspects the content of
a call to guess whether it looks dangerous - the gate has no classifier and no
model. If the policy does not declare something, the gate reports that it does
not know, and the missing signal feeds uncertainty.

Every threshold and weight shipped here is a *demonstration default*. See
BOUNDARY.md: the same defaults can be right for one deployment and wrong for the
next, so they are meant to be calibrated, not adopted.
"""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import yaml

from agent_safety_gate.records import sha256_hex

ACTION_CLASSES: Final = (
    "read_only",
    "reversible_write",
    "irreversible",
    "external_effect",
)
#: Classes for which an independent human approval is required unless the tool
#: entry says otherwise. Demonstration default.
APPROVAL_BY_DEFAULT: Final = frozenset({"irreversible", "external_effect"})
UNKNOWN_TOOL_MODES: Final = ("warn", "block")
#: What the proxy does with a BLOCK. `enforce` refuses the call; `observe`
#: records the same verdict and forwards it anyway, which is how a real
#: deployment gets to see what the gate would do before it starts saying no.
ENFORCEMENT_MODES: Final = ("enforce", "observe")
RECORD_ARGUMENTS_MODES: Final = ("full", "digest_only")

DEFAULT_LIMIT: Final = 7000
DEFAULT_WARN_MARGIN: Final = 2000
DEFAULT_ACTION_CLASS_WEIGHTS: Final[dict[str, int]] = {
    "read_only": 1000,
    "reversible_write": 2000,
    "irreversible": 4000,
    "external_effect": 4000,
}
DEFAULT_SCOPE_MISMATCH: Final = 4500
DEFAULT_APPROVAL_MISSING: Final = 3500
DEFAULT_COVERAGE_ABSENT: Final = 5500
DEFAULT_SCOPE_UNMEASURED: Final = 1500
DEFAULT_UNKNOWN_TOOL_EXTRA: Final = 2000


class PolicyError(Exception):
    """Raised when a policy file cannot be loaded. Always carries a next step."""


@dataclass(frozen=True)
class ScopeRule:
    """Where a tool is allowed to act. Matching is literal, never fuzzy."""

    argument: str
    allow_path_prefixes: tuple[str, ...] = ()
    allow_domains: tuple[str, ...] = ()

    def describe(self) -> str:
        parts: list[str] = []
        if self.allow_path_prefixes:
            parts.append("paths " + ", ".join(self.allow_path_prefixes))
        if self.allow_domains:
            parts.append("domains " + ", ".join(self.allow_domains))
        return "; ".join(parts) if parts else "nothing allowed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "allow_domains": list(self.allow_domains),
            "allow_path_prefixes": list(self.allow_path_prefixes),
            "argument": self.argument,
        }

    def matches(self, value: str) -> bool:
        return self._matches_path(value) or self._matches_domain(value)

    def _matches_path(self, value: str) -> bool:
        if not self.allow_path_prefixes:
            return False
        normalized = normalize_path(value)
        if normalized is None:
            return False
        for prefix in self.allow_path_prefixes:
            normalized_prefix = prefix.replace("\\", "/")
            if normalized_prefix.endswith("/"):
                if normalized.startswith(normalized_prefix):
                    return True
            elif normalized == normalized_prefix or normalized.startswith(
                normalized_prefix + "/"
            ):
                return True
        return False

    def _matches_domain(self, value: str) -> bool:
        if not self.allow_domains:
            return False
        host = extract_host(value)
        if host is None:
            return False
        for domain in self.allow_domains:
            candidate = domain.lower().lstrip(".")
            if host == candidate or host.endswith("." + candidate):
                return True
        return False


def normalize_path(value: str) -> str | None:
    """Normalise a path deterministically on every platform.

    ``posixpath`` is used on purpose: ``os.path`` would normalise differently on
    Windows and the same call would then hash to a different decision on a
    different machine. A path that still escapes upwards after normalisation is
    reported as unmatchable rather than silently allowed.
    """
    candidate = value.replace("\\", "/").strip()
    if not candidate:
        return None
    normalized = posixpath.normpath(candidate)
    if normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


def extract_host(value: str) -> str | None:
    parts = urlsplit(value if "//" in value else "//" + value)
    host = parts.hostname
    return host.lower() if host else None


@dataclass(frozen=True)
class ActionClassRule:
    """How one call's action class is decided. Declared, never inferred.

    Real agent tools rarely do one thing. An editor tool with a ``command``
    argument covers `view` (a read) and `str_replace` (a write) under one name,
    and in independent trajectories about two thirds of its calls are the read.
    Forcing one class per tool would record all of them as writes.

    So the operator may declare a class per value of a selector argument. That
    is still a declaration: the gate reads the value the call carries and looks
    it up, and it never inspects anything else to decide.
    """

    fixed: str | None = None
    argument: str | None = None
    values: Mapping[str, str] = field(default_factory=dict)
    default: str | None = None

    def resolve(self, arguments: Mapping[str, Any]) -> tuple[str | None, str]:
        """The class for this call, or ``None`` when it could not be measured."""
        if self.fixed is not None:
            return self.fixed, f"declared in the policy as {self.fixed}"
        assert self.argument is not None
        selector = arguments.get(self.argument)
        if not isinstance(selector, str) or not selector.strip():
            return None, (
                f"not measured: the policy selects the action class by "
                f"`{self.argument}`, and this call carries no such string argument"
            )
        listed = self.values.get(selector)
        if listed is not None:
            return listed, f"declared for {self.argument}={selector!r} as {listed}"
        return self.default, (
            f"declared as the default for {self.argument}={selector!r}, "
            "a value the policy does not list"
        )

    def declared_classes(self) -> tuple[str, ...]:
        if self.fixed is not None:
            return (self.fixed,)
        classes = set(self.values.values())
        if self.default is not None:
            classes.add(self.default)
        return tuple(sorted(classes))

    def as_dict(self) -> Any:
        if self.fixed is not None:
            return self.fixed
        return {
            "argument": self.argument,
            "default": self.default,
            "values": dict(sorted(self.values.items())),
        }


@dataclass(frozen=True)
class ToolRule:
    """What the operator declared about one tool."""

    name: str
    action: ActionClassRule
    requires_approval: bool | None = None
    scope: ScopeRule | None = None

    def approval_required_for(self, action_class: str) -> bool:
        """Explicit declaration wins; otherwise the class decides."""
        if self.requires_approval is not None:
            return self.requires_approval
        return action_class in APPROVAL_BY_DEFAULT

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"action_class": self.action.as_dict()}
        if self.requires_approval is not None:
            payload["requires_approval"] = self.requires_approval
        if self.scope is not None:
            payload["scope"] = self.scope.as_dict()
        return payload


@dataclass(frozen=True)
class Upstream:
    """The MCP server being wrapped. Configuration only - no code changes."""

    label: str
    command: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    env: Mapping[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "args": list(self.args),
            "command": list(self.command),
            "env": dict(self.env or {}),
            "label": self.label,
        }


@dataclass(frozen=True)
class Policy:
    """A loaded, validated policy plus its digest.

    ``digest`` is taken over the normalised policy, so reformatting the YAML or
    editing a comment does not change decision digests, while changing a
    threshold does.
    """

    policy_id: str
    policy_version: str
    limit: int
    warn_margin: int
    action_class_weights: Mapping[str, int]
    scope_mismatch_weight: int
    approval_missing_weight: int
    coverage_absent_uncertainty: int
    scope_unmeasured_uncertainty: int
    unknown_tool_extra_uncertainty: int
    unknown_tool: str
    record_arguments: str
    approvals_dir: str
    mode: str
    tools: Mapping[str, ToolRule]
    upstream: Upstream | None
    source_path: Path | None = None
    digest: str = ""

    def __post_init__(self) -> None:
        # Computed once: the digest goes into every signal source and every
        # decision input, and hashing the whole policy per signal was the single
        # largest cost per call.
        if not self.digest:
            object.__setattr__(self, "digest", sha256_hex(self.as_canonical_dict()))

    def rule_for(self, tool: str) -> ToolRule | None:
        return self.tools.get(tool)

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    def as_canonical_dict(self) -> dict[str, Any]:
        """The decision-relevant policy.

        `mode` is deliberately absent: it changes what the proxy does with a
        verdict, never the verdict, so the same call decides identically under
        both modes and the digests stay comparable. Which mode was in force is
        recorded in the record envelope instead.
        """
        return {
            "approvals_dir": self.approvals_dir,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "record_arguments": self.record_arguments,
            "thresholds": {
                "limit": self.limit,
                "warn_margin": self.warn_margin,
            },
            "tools": {
                name: rule.as_dict() for name, rule in sorted(self.tools.items())
            },
            "uncertainty": {
                "policy_coverage_absent": self.coverage_absent_uncertainty,
                "scope_unmeasured": self.scope_unmeasured_uncertainty,
                "unknown_tool_extra": self.unknown_tool_extra_uncertainty,
            },
            "unknown_tool": self.unknown_tool,
            "weights": {
                "action_class": dict(sorted(self.action_class_weights.items())),
                "approval_missing": self.approval_missing_weight,
                "scope_mismatch": self.scope_mismatch_weight,
            },
        }


def _fail(message: str, next_step: str) -> PolicyError:
    return PolicyError(f"{message}\nNext step: {next_step}")


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _fail(
            f"`{where}` must be a mapping, got {type(value).__name__}",
            f"write `{where}:` followed by indented `key: value` lines.",
        )
    return value


def _require_int(value: Any, where: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(
            f"`{where}` must be a whole number, got {value!r}",
            f"use an integer between 0 and 10000, for example `{where}: {default}`.",
        )
    if not 0 <= value <= 10_000:
        raise _fail(
            f"`{where}` must be between 0 and 10000, got {value}",
            "the kernel works on a bounded 0..10000 scale.",
        )
    return int(value)


def _require_str(value: Any, where: str, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise _fail(
            f"`{where}` must be a non-empty string, got {value!r}",
            f"for example `{where}: my-value`.",
        )
    return value.strip()


def _require_str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise _fail(
            f"`{where}` must be a list of strings",
            f"write it as a YAML list:\n  {where}:\n    - src/\n    - tests/",
        )
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise _fail(
                f"`{where}[{index}]` must be a non-empty string, got {item!r}",
                "remove the empty entry or replace it with a value.",
            )
        items.append(item.strip())
    return tuple(items)


def _parse_scope(value: Any, tool: str) -> ScopeRule | None:
    if value is None:
        return None
    payload = _require_mapping(value, f"tools.{tool}.scope")
    argument = _require_str(payload.get("argument"), f"tools.{tool}.scope.argument")
    prefixes = _require_str_list(
        payload.get("allow_path_prefixes"), f"tools.{tool}.scope.allow_path_prefixes"
    )
    domains = _require_str_list(
        payload.get("allow_domains"), f"tools.{tool}.scope.allow_domains"
    )
    if not prefixes and not domains:
        raise _fail(
            f"`tools.{tool}.scope` allows nothing",
            "add `allow_path_prefixes:` or `allow_domains:`, or delete the "
            "`scope:` block so the gate reports scope as not measured.",
        )
    return ScopeRule(
        argument=argument, allow_path_prefixes=prefixes, allow_domains=domains
    )


def _require_action_class(value: Any, where: str) -> str:
    action_class = _require_str(value, where)
    if action_class not in ACTION_CLASSES:
        raise _fail(
            f"`{where}` is {action_class!r}, which is not one of "
            f"{', '.join(ACTION_CLASSES)}",
            f"pick one of: {', '.join(ACTION_CLASSES)}.",
        )
    return action_class


def _parse_action_class(value: Any, tool: str) -> ActionClassRule:
    where = f"tools.{tool}.action_class"
    if value is None:
        raise _fail(
            f"`{where}` is missing",
            f"declare what {tool} does: one of {', '.join(ACTION_CLASSES)}. The "
            "gate does not guess what a tool does, and a guessed class would be "
            "worse than no entry.",
        )
    if isinstance(value, str):
        return ActionClassRule(fixed=_require_action_class(value, where))

    payload = _require_mapping(value, where)
    argument = _require_str(payload.get("argument"), f"{where}.argument")
    values_payload = _require_mapping(payload.get("values"), f"{where}.values")
    if not values_payload:
        raise _fail(
            f"`{where}.values` is empty",
            "list the values of "
            f"`{argument}` you want to classify, for example:\n"
            f"  {where}:\n    argument: {argument}\n"
            "    values:\n      view: read_only\n      create: reversible_write\n"
            "    default: irreversible",
        )
    values = {
        str(key): _require_action_class(item, f"{where}.values.{key}")
        for key, item in values_payload.items()
    }
    if payload.get("default") is None:
        raise _fail(
            f"`{where}.default` is missing",
            f"say what an unlisted value of `{argument}` means. Leaving it out "
            "would make the gate guess, which it will not do. Use "
            f"`default: irreversible` if you want the safe answer.",
        )
    return ActionClassRule(
        argument=argument,
        values=values,
        default=_require_action_class(payload.get("default"), f"{where}.default"),
    )


def _parse_tool(name: str, value: Any) -> ToolRule:
    payload = _require_mapping(value, f"tools.{name}")
    action = _parse_action_class(payload.get("action_class"), name)
    requires_approval = payload.get("requires_approval")
    if requires_approval is not None and not isinstance(requires_approval, bool):
        classes = ", ".join(action.declared_classes())
        raise _fail(
            f"`tools.{name}.requires_approval` must be true or false, "
            f"got {requires_approval!r}",
            "write `requires_approval: true` or remove the line, in which case "
            f"the action class decides ({classes}).",
        )
    return ToolRule(
        name=name,
        action=action,
        requires_approval=requires_approval,
        scope=_parse_scope(payload.get("scope"), name),
    )


def _parse_upstream(value: Any) -> Upstream | None:
    if value is None:
        return None
    payload = _require_mapping(value, "upstream")
    command = _require_str_list(payload.get("command"), "upstream.command")
    if not command:
        raise _fail(
            "`upstream.command` is empty",
            "point it at the MCP server you want to wrap, for example:\n"
            "  upstream:\n    label: my-tools\n"
            "    command: [python, -m, my_mcp_server]",
        )
    env_payload = _require_mapping(payload.get("env"), "upstream.env")
    env = {str(key): str(item) for key, item in env_payload.items()}
    return Upstream(
        label=_require_str(payload.get("label"), "upstream.label", "upstream"),
        command=command,
        args=_require_str_list(payload.get("args"), "upstream.args"),
        env=env or None,
    )


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file. Every error names the fix."""
    if not path.is_file():
        raise _fail(
            f"policy file not found: {path}",
            "copy examples/demo_policy.yaml to that path and edit the `tools:` "
            "section.",
        )
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f"{path}:{mark.line + 1}:{mark.column + 1}" if mark else str(path)
        problem = getattr(exc, "problem", None) or "invalid YAML"
        raise _fail(
            f"{location}: {problem}",
            "check indentation at that line. A tool entry looks like:\n"
            "  tools:\n"
            "    read_file:\n"
            "      action_class: read_only\n"
            "      scope:\n"
            "        argument: path\n"
            "        allow_path_prefixes: [src/]",
        ) from exc

    document = _require_mapping(raw, "policy file")
    if not document:
        raise _fail(
            f"policy file is empty: {path}",
            "start from examples/demo_policy.yaml.",
        )

    thresholds = _require_mapping(document.get("thresholds"), "thresholds")
    weights = _require_mapping(document.get("weights"), "weights")
    action_weights_raw = _require_mapping(
        weights.get("action_class"), "weights.action_class"
    )
    uncertainty = _require_mapping(document.get("uncertainty"), "uncertainty")

    action_class_weights = dict(DEFAULT_ACTION_CLASS_WEIGHTS)
    for name, value in action_weights_raw.items():
        if name not in ACTION_CLASSES:
            raise _fail(
                f"`weights.action_class.{name}` is not a known action class",
                f"known classes: {', '.join(ACTION_CLASSES)}.",
            )
        action_class_weights[name] = _require_int(
            value, f"weights.action_class.{name}", DEFAULT_ACTION_CLASS_WEIGHTS[name]
        )

    limit = _require_int(thresholds.get("limit"), "thresholds.limit", DEFAULT_LIMIT)
    warn_margin = _require_int(
        thresholds.get("warn_margin"), "thresholds.warn_margin", DEFAULT_WARN_MARGIN
    )
    if warn_margin >= limit:
        raise _fail(
            f"`thresholds.warn_margin` ({warn_margin}) must be lower than "
            f"`thresholds.limit` ({limit})",
            "the WARN band is the range between limit - warn_margin and limit; "
            "it cannot swallow the whole scale.",
        )

    unknown_tool = _require_str(
        document.get("unknown_tool"), "unknown_tool", "warn"
    ).lower()
    if unknown_tool not in UNKNOWN_TOOL_MODES:
        raise _fail(
            f"`unknown_tool` is {unknown_tool!r}",
            f"use one of: {', '.join(UNKNOWN_TOOL_MODES)}.",
        )

    mode = _require_str(document.get("mode"), "mode", "enforce").lower()
    if mode not in ENFORCEMENT_MODES:
        raise _fail(
            f"`mode` is {mode!r}",
            f"use one of: {', '.join(ENFORCEMENT_MODES)}. `observe` records "
            "every decision and forwards the call anyway; use it to see what "
            "the gate would do before it starts saying no.",
        )

    record_arguments = _require_str(
        document.get("record_arguments"), "record_arguments", "full"
    ).lower()
    if record_arguments not in RECORD_ARGUMENTS_MODES:
        raise _fail(
            f"`record_arguments` is {record_arguments!r}",
            f"use one of: {', '.join(RECORD_ARGUMENTS_MODES)}.",
        )

    tools_payload = _require_mapping(document.get("tools"), "tools")
    tools = {
        str(name): _parse_tool(str(name), value)
        for name, value in tools_payload.items()
    }

    return Policy(
        policy_id=_require_str(document.get("policy_id"), "policy_id"),
        policy_version=_require_str(document.get("policy_version"), "policy_version"),
        limit=limit,
        warn_margin=warn_margin,
        action_class_weights=action_class_weights,
        scope_mismatch_weight=_require_int(
            weights.get("scope_mismatch"),
            "weights.scope_mismatch",
            DEFAULT_SCOPE_MISMATCH,
        ),
        approval_missing_weight=_require_int(
            weights.get("approval_missing"),
            "weights.approval_missing",
            DEFAULT_APPROVAL_MISSING,
        ),
        coverage_absent_uncertainty=_require_int(
            uncertainty.get("policy_coverage_absent"),
            "uncertainty.policy_coverage_absent",
            DEFAULT_COVERAGE_ABSENT,
        ),
        scope_unmeasured_uncertainty=_require_int(
            uncertainty.get("scope_unmeasured"),
            "uncertainty.scope_unmeasured",
            DEFAULT_SCOPE_UNMEASURED,
        ),
        unknown_tool_extra_uncertainty=_require_int(
            uncertainty.get("unknown_tool_extra"),
            "uncertainty.unknown_tool_extra",
            DEFAULT_UNKNOWN_TOOL_EXTRA,
        ),
        unknown_tool=unknown_tool,
        record_arguments=record_arguments,
        mode=mode,
        approvals_dir=_require_str(
            document.get("approvals_dir"),
            "approvals_dir",
            ".agent-safety-gate/approvals",
        ),
        tools=tools,
        upstream=_parse_upstream(document.get("upstream")),
        source_path=path,
    )
