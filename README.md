# agent-safety-gate

A decision gate for agent tool calls. Before a call runs, it checks whether the
control signals around it are complete and independent of the agent, returns
PASS / WARN / BLOCK, and writes a signed, replayable record.

The verdict arithmetic comes from the AOS kernel, vendored unmodified; see
[NOTICE](NOTICE) and [BOUNDARY.md](BOUNDARY.md). Documentation follows the code.
