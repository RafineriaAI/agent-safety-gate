"""What the gate costs per call in a real MCP round trip.

    python benchmarks/proxy_overhead.py

Three sessions of identical `tools/call` requests against the same tool server:

1. straight to the server,
2. through `benchmarks/passthrough_baseline.py`, a proxy that forwards and does
   nothing else,
3. through `agent-safety-gate wrap`.

Session 2 exists so that the published number is honest. Line 1 to line 2 is
what any proxy costs: one more process and one more round trip. Line 2 to line 3
is the gate itself - decision, signed record, appended line.

The kernel decides in microseconds. If line 2 to line 3 is large, that is a
defect in this proxy, not something to leave out of the README.

Needs the MCP extra:  pip install "agent-safety-gate[mcp]"
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = REPO_ROOT / "benchmarks"
EXAMPLES = REPO_ROOT / "examples"
POLICY = EXAMPLES / "demo_policy.yaml"
KEY = EXAMPLES / "demo_signing_key.INSECURE.json"
SERVER = EXAMPLES / "demo_tool_server.py"


async def time_session(parameters: StdioServerParameters, calls: int) -> list[float]:
    samples: list[float] = []
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # One warm-up call: the first request pays for start-up on both
            # sides, which is not a per-call cost.
            await session.call_tool("read_file", {"path": "src/warmup.py"})
            for index in range(calls):
                start = time.perf_counter()
                await session.call_tool("read_file", {"path": f"src/module{index}.py"})
                samples.append((time.perf_counter() - start) * 1e6)
    return samples


def describe(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "mean_us": statistics.fmean(ordered),
        "p50_us": ordered[len(ordered) // 2],
        "p95_us": ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))],
    }


async def run(calls: int, rounds: int) -> int:
    direct = StdioServerParameters(
        command=sys.executable, args=[str(SERVER)], cwd=str(EXAMPLES)
    )
    passthrough = StdioServerParameters(
        command=sys.executable,
        args=[str(BENCHMARKS / "passthrough_baseline.py"), str(SERVER), str(EXAMPLES)],
        cwd=str(EXAMPLES),
    )
    with tempfile.TemporaryDirectory() as directory:
        gated = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "agent_safety_gate.cli",
                "wrap",
                "--policy",
                str(POLICY),
                "--records",
                str(Path(directory) / "records.jsonl"),
                "--key",
                str(KEY),
            ],
            cwd=str(REPO_ROOT),
        )
        # Rounds are interleaved so that a busy moment on the machine does not
        # land entirely on one of the three configurations.
        samples: dict[str, list[float]] = {"direct": [], "passthrough": [], "gated": []}
        for _ in range(rounds):
            for name, parameters in (
                ("direct", direct),
                ("passthrough", passthrough),
                ("gated", gated),
            ):
                samples[name].extend(await time_session(parameters, calls))

    results = {name: describe(values) for name, values in samples.items()}
    total = calls * rounds
    print(f"MCP round trip, {total} calls per configuration")
    for label, name in (
        ("server alone       ", "direct"),
        ("+ bare proxy       ", "passthrough"),
        ("+ agent-safety-gate", "gated"),
    ):
        row = results[name]
        print(
            f"  {label}  mean {row['mean_us'] / 1000:6.2f} ms   "
            f"p50 {row['p50_us'] / 1000:6.2f} ms   p95 {row['p95_us'] / 1000:6.2f} ms"
        )
    print()
    proxy_cost = results["passthrough"]["p50_us"] - results["direct"]["p50_us"]
    gate_cost = results["gated"]["p50_us"] - results["passthrough"]["p50_us"]
    print(f"  cost of proxying at all   {proxy_cost / 1000:.2f} ms (p50)")
    print(f"  cost of the gate itself   {gate_cost / 1000:.2f} ms (p50)")
    print()
    print(
        "  One machine, one run, stdio transport. Re-run it on yours before quoting it."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calls", type=int, default=60)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args(argv)
    return asyncio.run(run(args.calls, args.rounds))


if __name__ == "__main__":
    raise SystemExit(main())
