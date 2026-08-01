# Plugging the gate into what you already run

Three doors into the same gate. All of them write to the same kind of chained,
signed record file, all of them are configuration only, and none of them
requires a change in the agent or in the tools.

| Door | Covers | Wiring |
| --- | --- | --- |
| MCP proxy (`wrap`) | any MCP client x any MCP server | one policy file + one changed address |
| Claude Code hook (`hook`) | Claude Code's **native** tools (Bash, Edit, Write, ...) | one entry in `settings.json` |
| Subprocess (`eval`) | any framework that can run a process | one function in your code |

Pick by where the calls you care about actually flow. An MCP proxy cannot see a
host application's native tools; a hook cannot see another framework's calls.

## Policy discovery

All three doors resolve the policy the same way, so the common case needs no
flags:

1. `--policy <path>` if given,
2. the `ASG_POLICY` environment variable,
3. `.agent-safety-gate/policy.yaml` under the working directory.

Records go next to the policy (`.agent-safety-gate/records.jsonl`) unless
`--records` or `ASG_RECORDS` says otherwise. Concurrent calls append through a
lock file, so parallel tool calls cannot fork the chain.

## Claude Code (hooks - native tools)

This is the integration the [session replay](../benchmarks/README.md) argues
for: in the session that built this repository, every interruption came through
`Bash` - a native tool no MCP proxy can see.

`.claude/settings.json` in your project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "agent-safety-gate hook" }
        ]
      }
    ]
  }
}
```

Then put a policy at `.agent-safety-gate/policy.yaml` (start from
`examples/demo_policy.yaml`, declare Claude Code's tool names: `Bash`, `Edit`,
`Write`, `Read`, `Glob`, `Grep`; `benchmarks/coding_agent_policy.yaml` is a
worked example for exactly this surface).

How verdicts map onto the hook contract:

| Policy mode | PASS | WARN | BLOCK |
| --- | --- | --- | --- |
| `enforce` | `allow` (no prompt) | `ask` (prompt with the reason) | `deny` (reason + remediation) |
| `observe` | `defer` | `defer` | `defer` - recorded, nothing changes |

Two properties worth knowing:

* **`allow` on PASS is the anti-fatigue half.** Calls that are declared, in
  scope and reversible stop prompting; prompts concentrate on WARN and on
  whatever your policy does not cover.
* **A misconfigured gate never bricks the agent.** No policy found, unreadable
  stdin, a broken YAML - the hook exits 1, which the contract defines as
  non-blocking: the call proceeds through the normal permission flow and the
  error is logged with a next step.

Start in `mode: observe`, work normally for a day, then:

```bash
agent-safety-gate calibrate .agent-safety-gate/records.jsonl --policy candidate.yaml
```

and switch to `enforce` when the BLOCK column contains only calls you want
stopped.

## Claude Desktop, Cursor, Windsurf (MCP servers)

Every application that consumes MCP servers through an `mcpServers`-style
configuration can point at the proxy instead of the server. Nothing in the
application changes:

```json
{
  "mcpServers": {
    "my-tools": {
      "command": "agent-safety-gate",
      "args": ["wrap", "--policy", "/abs/path/policy.yaml"]
    }
  }
}
```

The same JSON shape works in Claude Desktop (`claude_desktop_config.json`),
Cursor (`.cursor/mcp.json`), Windsurf (`mcp_config.json`) and Claude Code
(`.mcp.json`) - the proxy is a standard stdio MCP server from the client's
point of view. `agent-safety-gate wrap --policy ... --check` will start the
upstream server and draft the tool entries for you, using the server's own MCP
annotations as labelled proposals.

## Any other agent (subprocess)

`eval` is the framework-neutral primitive: one call in, one verdict and one
signed record out.

```bash
agent-safety-gate eval --tool write_file --arguments '{"path": "src/a.py"}' --json
```

Exit codes: `0` forward, `3` blocked, `2` error. `--json` prints the verdict,
the reason, the remediation and the record digest. From Python:

```python
import json, subprocess


def gated(tool: str, arguments: dict) -> dict:
    completed = subprocess.run(
        ["agent-safety-gate", "eval", "--stdin", "--json"],
        input=json.dumps({"tool": tool, "arguments": arguments}),
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)  # act on ["forward"] / ["reason"]
```

Wrap your framework's tool executor with that function and every call leaves a
record, whatever the framework is. This is also the escape hatch for LangChain
until a first-class integration exists (phase 2): a LangChain `BaseTool` wrapper
around `gated()` is a dozen lines of your code, not ours.

## One chain, several doors

All doors append to the same file when pointed at the same records path, and a
record says which door it came through (`mode`: `mcp_proxy`,
`claude_code_hook`, `eval`, `demo`). `agent-safety-gate verify` and the browser
verifier treat them identically, because they are identical - the envelope, the
signature and the chain do not care how the call arrived.
