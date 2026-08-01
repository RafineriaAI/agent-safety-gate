#!/usr/bin/env bash
# Everything this repository claims about itself, in one command.
#
#   bash tools/verify_all.sh
#
# Each step is one promise this repository makes. If a step fails, its name
# says which promise broke.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PYTHON="${PYTHON:-python}"
FAILED=()
STEP=0

run_step() {
  local name="$1"
  shift
  STEP=$((STEP + 1))
  printf '\n=== %d. %s\n' "$STEP" "$name"
  if "$@"; then
    printf '    ok\n'
  else
    printf '    FAILED: %s\n' "$name"
    FAILED+=("$name")
  fi
}

printf 'agent-safety-gate: full verification\n'
printf 'python: %s\n' "$("$PYTHON" --version 2>&1)"

run_step "lint (ruff check)" "$PYTHON" -m ruff check .
run_step "format (ruff format --check)" "$PYTHON" -m ruff format --check .
run_step "types (mypy, strict)" "$PYTHON" -m mypy

# Criteria 1-7, 10, 11 live in the test suite: determinism, tamper evidence,
# signatures, end-to-end MCP, the browser verifier and its digest parity,
# explain output, the dependency budget and the absence of any model client.
run_step "tests (all acceptance criteria with a test)" "$PYTHON" -m pytest -q

run_step "vendored kernel is unmodified" "$PYTHON" tools/check_vendor.py
run_step "committed sample matches the code" "$PYTHON" tools/regenerate_examples.py --check
run_step "documentation claims audit" "$PYTHON" tools/audit_claims.py
run_step "workflow benchmark, deterministic" "$PYTHON" benchmarks/workflow_replay.py --no-latency

# The independent replay needs one network call the first time, then reads its
# cache. It reports rather than fails when neither is available.
if [ -d benchmarks/.cache ] || [ "${ASG_ALLOW_NETWORK:-0}" = "1" ]; then
  run_step "independent replay (published trajectories)"     "$PYTHON" benchmarks/independent_replay.py
else
  printf '
=== -. independent replay
    skipped: no benchmarks/.cache and ASG_ALLOW_NETWORK is not 1
'
fi

# The real-session replay needs a trace derived from someone's transcript.
# Committing that is the repository owner's decision, so this step reports
# rather than fails when the trace is absent.
if [ -f benchmarks/traces/real_session.jsonl ]; then
  run_step "real session replay" "$PYTHON" benchmarks/session_replay.py     benchmarks/traces/real_session.jsonl
else
  printf '
=== -. real session replay
    skipped: benchmarks/traces/real_session.jsonl is not present
'
fi
run_step "README quickstart, verbatim, in a clean venv" bash tools/quickstart_check.sh

printf '\n============================================\n'
if [ ${#FAILED[@]} -eq 0 ]; then
  printf 'All %d steps passed.\n' "$STEP"
  exit 0
fi
printf '%d of %d steps failed:\n' "${#FAILED[@]}" "$STEP"
for name in "${FAILED[@]}"; do
  printf '  - %s\n' "$name"
done
exit 1
