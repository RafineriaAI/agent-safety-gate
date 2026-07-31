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
