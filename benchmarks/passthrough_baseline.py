"""A gateless MCP proxy. It exists only so that a number in the README is honest.

Putting any proxy between an agent and a tool server costs a second process and
a second round trip. That cost belongs to proxying, not to the gate. This file
is the control group: identical plumbing to `agent_safety_gate.mcp_proxy`, with
no decision, no record and no signature.

It is never a safety component. It forwards everything, always.

    python benchmarks/passthrough_baseline.py <server-script> <cwd>
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import AsyncExitStack
from typing import Any

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


async def serve(script: str, cwd: str) -> None:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr, force=True)
    parameters = StdioServerParameters(command=sys.executable, args=[script], cwd=cwd)
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(parameters))
        upstream = await stack.enter_async_context(ClientSession(read, write))
        await upstream.initialize()
        server: Any = Server("passthrough-baseline")

        @server.list_tools()  # type: ignore[untyped-decorator]
        async def list_tools() -> list[types.Tool]:
            return list((await upstream.list_tools()).tools)

        @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
        async def call_tool(name: str, arguments: dict[str, object]) -> object:
            result = await upstream.call_tool(name, arguments)
            return types.CallToolResult(
                content=list(result.content),
                structuredContent=result.structuredContent,
                isError=bool(result.isError),
            )

        read_stream, write_stream = await stack.enter_async_context(stdio_server())
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    asyncio.run(serve(sys.argv[1], sys.argv[2]))
