"""Measure how long it takes to put the gate in front of an unfamiliar MCP server.

    pip install mcp-server-time
    python tools/measure_wiring.py \
        --policy examples/public_server_policy.yaml \
        --tool get_current_time \
        --arguments '{"timezone": "Europe/Warsaw"}'

Two phases are timed:

* **discovery** - start the upstream server through the gate and list what it
  exposes, which is what tells you what you have to declare;
* **first decision** - one real `tools/call` through the proxy, ending in a
  signed record on disk.

What this does not measure is the human minute spent deciding that
`get_current_time` is `read_only`. That number is in the README next to the
14-line policy it produced, because pretending a person is not in the loop would
be the wrong kind of benchmark.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_safety_gate.policy import load_policy  # noqa: E402
from agent_safety_gate.records import read_records  # noqa: E402


async def first_decision(
    policy_path: Path, records: Path, tool: str, arguments: dict[str, Any]
) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agent_safety_gate.cli",
            "wrap",
            "--policy",
            str(policy_path),
            "--records",
            str(records),
        ],
        cwd=str(REPO_ROOT),
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool(tool, arguments)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--arguments", default="{}")
    parser.add_argument("--records", type=Path, default=None)
    args = parser.parse_args(argv)

    from agent_safety_gate.mcp_proxy import inspect_upstream

    records = args.records or (REPO_ROOT / ".agent-safety-gate" / "wiring.jsonl")
    if records.exists():
        records.unlink()

    started = time.perf_counter()
    policy = load_policy(args.policy)
    names, undeclared = inspect_upstream(policy)
    discovered = time.perf_counter()
    asyncio.run(
        first_decision(args.policy, records, args.tool, json.loads(args.arguments))
    )
    finished = time.perf_counter()

    record = read_records(records)[0]
    upstream_command = " ".join(policy.upstream.command) if policy.upstream else "-"
    print(f"upstream:          {upstream_command}")
    print(f"tools discovered:  {', '.join(names)}")
    print(f"still undeclared:  {', '.join(undeclared) or '(none)'}")
    print()
    print(f"discovery:         {discovered - started:.1f} s")
    print(f"first decision:    {finished - discovered:.1f} s")
    print(f"total:             {finished - started:.1f} s")
    print()
    print(f"first record:      {record['record_sha256']}")
    print(f"verdict:           {record['aos_verdict']} on {record['call']['tool']}")
    print(f"file:              {records}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
