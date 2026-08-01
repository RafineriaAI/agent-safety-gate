"""MCP proxy: put the gate in front of a tool server without touching either side.

The agent's MCP client connects to this process instead of the real server. Every
``tools/call`` is evaluated first:

* ``PASS``  - forwarded unchanged,
* ``WARN``  - forwarded, with the warning attached to the response and written
  to the record,
* ``BLOCK`` - refused, with the reason and the remediation in the error.

Under ``mode: observe`` a blocked call is forwarded anyway and the response says
so. The verdict and the record are identical either way; only enforcement
differs. That is how a deployment finds out what the gate would do before it
starts saying no, and the proxy says loudly at startup that it is not enforcing.

Everything else about the session (tool list, schemas, results) is passed
through untouched. The gate does not rewrite tool descriptions and does not try
to improve the agent's behaviour: changing what the agent sees would make the
recorded session a different session from the one that actually happened.

Only the ``tools`` capability is proxied in this MVP. Prompts, resources and
sampling are not forwarded, so an agent that needs them should not be pointed at
the proxy yet.

This module is the only part of the package that imports the MCP SDK. It is
available through the ``[mcp]`` extra:

    pip install "agent-safety-gate[mcp]"
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from agent_safety_gate.gate import Gate
from agent_safety_gate.policy import Policy
from agent_safety_gate.records import append_record, last_record_sha256, read_records
from agent_safety_gate.signals import ToolCall
from agent_safety_gate.signing import SigningKey

PROXY_NAME: Final = "agent-safety-gate"
ANNOTATION_KEY: Final = "agent_safety_gate"


class ProxyDependencyError(Exception):
    """Raised when the MCP SDK is not installed."""


def _require_mcp() -> Any:
    try:
        import mcp  # noqa: F401
        from mcp import types
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by hand
        raise ProxyDependencyError(
            "the MCP proxy needs the MCP SDK, which is an optional extra.\n"
            'Next step: pip install "agent-safety-gate[mcp]"'
        ) from exc
    return types


@dataclass
class ProxyState:
    """Chain position and record file. The file is the only state that exists."""

    records_path: Path
    prev_record_sha256: str | None
    chain_index: int

    @classmethod
    def resume(cls, records_path: Path) -> ProxyState:
        """Continue an existing chain, or start a new one. No database."""
        if not records_path.is_file():
            return cls(
                records_path=records_path, prev_record_sha256=None, chain_index=0
            )
        records = read_records(records_path)
        previous = records[-1].get("record_sha256")
        return cls(
            records_path=records_path,
            prev_record_sha256=previous if isinstance(previous, str) else None,
            chain_index=len(records),
        )


class GateProxy:
    """Wraps one upstream MCP server."""

    def __init__(
        self,
        policy: Policy,
        key: SigningKey,
        records_path: Path,
        *,
        mode: str = "mcp_proxy",
    ) -> None:
        if policy.upstream is None:
            raise ValueError(
                "the policy has no `upstream:` block, so there is no server to "
                "wrap.\nNext step: add the command that starts your MCP server:\n"
                "  upstream:\n    label: my-tools\n"
                "    command: [python, -m, my_mcp_server]"
            )
        self.policy = policy
        self.gate = Gate(policy)
        self.key = key
        self.mode = mode
        self.state = ProxyState.resume(records_path)
        self._lock = asyncio.Lock()

    # -- decision + record ------------------------------------------------

    async def evaluate_and_record(self, call: ToolCall) -> tuple[Any, dict[str, Any]]:
        decision = self.gate.evaluate(call)
        async with self._lock:
            record = self.gate.build_record(
                decision,
                key=self.key,
                chain_index=self.state.chain_index,
                prev_record_sha256=self.state.prev_record_sha256,
                mode=self.mode,
            )
            append_record(self.state.records_path, record)
            self.state.prev_record_sha256 = str(record["record_sha256"])
            self.state.chain_index += 1
        return decision, record

    def annotation(self, decision: Any, record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            ANNOTATION_KEY: {
                "enforcement": self.gate.enforcement_for(decision),
                "mode": self.policy.mode,
                "record_sha256": record["record_sha256"],
                "records_file": str(self.state.records_path),
                "reason": decision.reason,
                "verdict": decision.verdict,
            }
        }

    def block_text(self, decision: Any, record: Mapping[str, Any]) -> str:
        lines = [
            f"BLOCKED by {PROXY_NAME}: {decision.reason}",
            "",
            f"tool:      {decision.call.tool}",
            f"record:    {record['record_sha256']}",
            f"file:      {self.state.records_path}",
        ]
        if decision.remediation:
            lines.append("")
            lines.append("To make this call possible:")
            for item in decision.remediation:
                lines.append(f"  - {item.action}")
                if item.command:
                    for command_line in item.command.splitlines():
                        lines.append(f"      {command_line}")
        lines.append("")
        lines.append(
            f"Explain this decision: agent-safety-gate explain "
            f"{self.state.records_path} --record {record['record_sha256'][:12]}"
        )
        return "\n".join(lines)

    def observed_text(self, decision: Any, record: Mapping[str, Any]) -> str:
        return (
            f"[{PROXY_NAME} WOULD HAVE BLOCKED - mode: observe] {decision.reason} "
            f"The call was forwarded because this policy is not enforcing. "
            f"(record {str(record['record_sha256'])[:12]}, "
            f"file {self.state.records_path})"
        )

    def warn_text(self, decision: Any, record: Mapping[str, Any]) -> str:
        return (
            f"[{PROXY_NAME} WARN] {decision.reason} "
            f"(record {str(record['record_sha256'])[:12]}, "
            f"file {self.state.records_path})"
        )

    # -- serving ----------------------------------------------------------

    async def serve(self) -> None:
        """Run until the client disconnects."""
        types = _require_mcp()
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.server.lowlevel import Server
        from mcp.server.stdio import stdio_server

        upstream_config = self.policy.upstream
        assert upstream_config is not None
        parameters = StdioServerParameters(
            command=upstream_config.command[0],
            args=[*upstream_config.command[1:], *upstream_config.args],
            env=dict(upstream_config.env) if upstream_config.env else None,
            cwd=str(self.policy.source_path.parent)
            if self.policy.source_path
            else None,
        )

        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(stdio_client(parameters))
            upstream = await stack.enter_async_context(ClientSession(read, write))
            await upstream.initialize()
            if not self.policy.enforcing:
                print(
                    f"[{PROXY_NAME}] mode: observe - every decision is recorded "
                    "and NOTHING is blocked. Switch to `mode: enforce` in "
                    f"{self.policy.source_path} when you have seen enough.",
                    file=sys.stderr,
                )
            server: Any = Server(PROXY_NAME)

            @server.list_tools()  # type: ignore[untyped-decorator]
            async def list_tools() -> list[Any]:
                result = await upstream.list_tools()
                self._report_undeclared(result.tools)
                return list(result.tools)

            # Input validation is left to the upstream server on purpose: the
            # gate must see and record every call the agent attempted, including
            # malformed ones.
            @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
            async def call_tool(name: str, arguments: dict[str, Any]) -> Any:
                meta = self._request_meta(server)
                call = ToolCall(
                    tool=name,
                    arguments=arguments,
                    server=upstream_config.label,
                    meta=meta,
                )
                decision, record = await self.evaluate_and_record(call)
                if not self.gate.should_forward(decision):
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text", text=self.block_text(decision, record)
                            )
                        ],
                        isError=True,
                        _meta=self.annotation(decision, record),
                    )
                result = await upstream.call_tool(name, arguments)
                content = list(result.content)
                if decision.verdict == "BLOCK":
                    # observe mode: the call ran, and the response says so.
                    content.append(
                        types.TextContent(
                            type="text", text=self.observed_text(decision, record)
                        )
                    )
                elif decision.verdict == "WARN":
                    content.append(
                        types.TextContent(
                            type="text", text=self.warn_text(decision, record)
                        )
                    )
                return types.CallToolResult(
                    content=content,
                    structuredContent=result.structuredContent,
                    isError=bool(result.isError),
                    _meta=self.annotation(decision, record),
                )

            read_stream, write_stream = await stack.enter_async_context(stdio_server())
            await server.run(
                read_stream, write_stream, server.create_initialization_options()
            )

    def _request_meta(self, server: Any) -> dict[str, Any] | None:
        """Read the ``_meta`` the agent attached to this call, if any."""
        try:
            context = server.request_context
        except LookupError:  # pragma: no cover - only outside a request
            return None
        meta = getattr(context, "meta", None)
        if meta is None:
            return None
        dumped = meta.model_dump(exclude_none=True)
        return dict(dumped) if isinstance(dumped, dict) else None

    def _report_undeclared(self, tools: Sequence[Any]) -> None:
        """Tell the operator which upstream tools the policy does not declare."""
        undeclared = sorted(
            tool.name for tool in tools if self.policy.rule_for(tool.name) is None
        )
        if not undeclared:
            return
        print(
            f"[{PROXY_NAME}] {len(undeclared)} upstream tool(s) are not declared "
            f"in {self.policy.source_path}: {', '.join(undeclared)}",
            file=sys.stderr,
        )
        print(
            f"[{PROXY_NAME}] calls to them will be treated as "
            f"`unknown_tool: {self.policy.unknown_tool}`.",
            file=sys.stderr,
        )


async def _describe_upstream_tools(policy: Policy) -> list[dict[str, Any]]:
    _require_mcp()
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    upstream_config = policy.upstream
    assert upstream_config is not None
    parameters = StdioServerParameters(
        command=upstream_config.command[0],
        args=[*upstream_config.command[1:], *upstream_config.args],
        env=dict(upstream_config.env) if upstream_config.env else None,
        cwd=str(policy.source_path.parent) if policy.source_path else None,
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            described: list[dict[str, Any]] = []
            for tool in result.tools:
                annotations = tool.annotations
                described.append(
                    {
                        "annotations": annotations.model_dump(exclude_none=True)
                        if annotations is not None
                        else None,
                        "name": tool.name,
                        "scope_argument": scope_argument_for(tool.inputSchema),
                    }
                )
            return described


#: How a server's own annotations map onto the four action classes. MCP defines
#: these as *hints*: the specification says a client must treat them as
#: untrusted and use them for interface decisions, not as security guarantees.
#: So they are used in exactly one place - proposing a policy entry that the
#: operator then confirms - and never by the gate when it decides.
def class_from_annotations(annotations: Mapping[str, Any] | None) -> str | None:
    """The class a server's annotations suggest, or None when it declares nothing."""
    if not annotations:
        return None
    read_only = annotations.get("readOnlyHint")
    destructive = annotations.get("destructiveHint")
    open_world = annotations.get("openWorldHint")
    if read_only is True:
        return "read_only"
    if read_only is not False:
        return None
    if destructive is True:
        return "irreversible"
    if open_world is True:
        return "external_effect"
    if destructive is False:
        return "reversible_write"
    return None


#: Argument names that carry something a scope allowlist can match. Taken from
#: the inputSchema of real public servers rather than invented: `repo_path` is
#: every tool in the reference git server, `url` is the fetch server, `path` and
#: `file_path` are the common file-tool spelling.
SCOPE_ARGUMENT_NAMES: Final = (
    "path",
    "file_path",
    "repo_path",
    "notebook_path",
    "directory",
    "url",
)


def scope_argument_for(schema: Mapping[str, Any] | None) -> str | None:
    properties = (schema or {}).get("properties")
    if not isinstance(properties, dict):
        return None
    for name in SCOPE_ARGUMENT_NAMES:
        if name in properties:
            return name
    return None


def inspect_upstream(policy: Policy) -> tuple[list[str], list[str]]:
    """Start the upstream server, list its tools, and say which are undeclared.

    This is the first thing anyone wiring the gate to an unfamiliar server needs
    to know, and reading someone else's server code to find out is the slow way.
    """
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr, force=True)
    described = describe_upstream(policy)
    names = [str(tool["name"]) for tool in described]
    undeclared = [name for name in names if policy.rule_for(name) is None]
    return names, undeclared


def describe_upstream(policy: Policy) -> list[dict[str, Any]]:
    """Every upstream tool with its annotations and a scopeable argument."""
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr, force=True)
    return asyncio.run(_describe_upstream_tools(policy))


def policy_skeleton(
    undeclared: Sequence[str],
    described: Sequence[Mapping[str, Any]] = (),
) -> str:
    """A block to paste into the policy. It declares nothing on its own.

    Where the server publishes annotations, the matching class is filled in as a
    *proposal* and labelled as one. MCP defines annotations as hints from a
    source a client must treat as untrusted, so a human confirming them is the
    whole point; the gate never reads them when it decides.
    """
    details = {str(tool["name"]): tool for tool in described}
    lines = ["tools:"]
    for name in undeclared:
        tool = details.get(name, {})
        proposed = class_from_annotations(tool.get("annotations"))
        scope_argument = tool.get("scope_argument")
        lines.append(f"  {name}:")
        if proposed:
            lines.append(
                f"    action_class: {proposed}"
                "    # PROPOSED by the server's own annotations - confirm it"
            )
        else:
            lines.append(
                "    action_class:  # read_only | reversible_write | irreversible "
                "| external_effect"
            )
            lines.append(
                "    #              this server declares nothing about this tool, "
                "so the class is yours"
            )
        if scope_argument:
            lines.append("    scope:")
            lines.append(f"      argument: {scope_argument}")
            lines.append(
                "      allow_path_prefixes: []  # fill in, or delete the scope block"
            )
        else:
            lines.append(
                "    # scope:      # no argument in the schema looks like a path "
                "or a URL"
            )
    return "\n".join(lines)


def default_records_path(policy: Policy) -> Path:
    base = policy.source_path.parent if policy.source_path else Path.cwd()
    return base / ".agent-safety-gate" / "records.jsonl"


def run_proxy(
    policy: Policy,
    key: SigningKey,
    records_path: Path | None = None,
    *,
    mode: str = "mcp_proxy",
) -> None:
    # The SDK logs every request at INFO. A proxy that prints a paragraph per
    # tool call buries the one line the operator cares about.
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr, force=True)
    proxy = GateProxy(
        policy, key, records_path or default_records_path(policy), mode=mode
    )
    asyncio.run(proxy.serve())


def last_chain_digest(records_path: Path) -> str | None:
    return last_record_sha256(records_path)
