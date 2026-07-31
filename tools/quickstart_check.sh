#!/usr/bin/env bash
# Run the README quickstart verbatim in a clean environment, and time it.
#
#   bash tools/quickstart_check.sh
#
# The commands are extracted from README.md between the quickstart markers and
# executed exactly as written. A quickstart that has drifted from the code is a
# barrier to entry, not documentation, so this runs in CI.
#
# Time-to-first-proof is measured to the point that matters: a blocked
# irreversible action, verified in a browser, with the signature checking out.
# The browser step runs headless here; a person doing it by hand also has to
# drag a file onto a page.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="$REPO_ROOT/README.md"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

extract_quickstart() {
  awk '
    /<!-- quickstart:begin -->/ { inside = 1; next }
    /<!-- quickstart:end -->/   { inside = 0 }
    inside && /^```/           { fence = !fence; next }
    inside && fence            { print }
  ' "$README"
}

COMMANDS="$(extract_quickstart)"
if [ -z "$COMMANDS" ]; then
  echo "ERROR: no quickstart block found in README.md" >&2
  echo "Next step: keep the commands between <!-- quickstart:begin --> and" >&2
  echo "<!-- quickstart:end --> in a bash code fence." >&2
  exit 1
fi

echo "Quickstart commands, taken verbatim from README.md:"
echo "$COMMANDS" | sed 's/^/    /'
echo

echo "Creating a clean virtual environment..."
python -m venv "$WORK/venv"
if [ -d "$WORK/venv/Scripts" ]; then
  VENV_BIN="$WORK/venv/Scripts"
else
  VENV_BIN="$WORK/venv/bin"
fi
export PATH="$VENV_BIN:$PATH"
PYTHON="$VENV_BIN/python"

cd "$REPO_ROOT"
START="$("$PYTHON" -c 'import time; print(time.time())')"

DEMO_OUTPUT="$WORK/demo.txt"
# The commands run exactly as printed, in order, in the clean environment.
set +e
# shellcheck disable=SC2086
bash -c "set -euo pipefail
$COMMANDS" >"$DEMO_OUTPUT" 2>&1
STATUS=$?
set -e
if [ $STATUS -ne 0 ]; then
  echo "ERROR: the README quickstart failed:" >&2
  cat "$DEMO_OUTPUT" >&2
  exit 1
fi

RECORDS="$(grep -E '^Records:' "$DEMO_OUTPUT" | head -1 | sed 's/^Records:[[:space:]]*//')"
VERIFIER="$(grep -E '^Verifier:' "$DEMO_OUTPUT" | head -1 | sed 's/^Verifier:[[:space:]]*//')"
if [ -z "$RECORDS" ] || [ ! -f "$RECORDS" ]; then
  echo "ERROR: the demo did not report a record file it wrote." >&2
  cat "$DEMO_OUTPUT" >&2
  exit 1
fi

grep -q "BLOCK" "$DEMO_OUTPUT" || {
  echo "ERROR: the demo did not block anything, which is the point of it." >&2
  cat "$DEMO_OUTPUT" >&2
  exit 1
}

echo "Verifying the produced records in a headless browser..."
BROWSER_OUTPUT="$WORK/browser.json"
if ! "$PYTHON" "$REPO_ROOT/tools/browser_check.py" \
      --records "$RECORDS" --output "$BROWSER_OUTPUT"; then
  echo "ERROR: the browser did not verify the records the demo just wrote." >&2
  cat "$BROWSER_OUTPUT" 2>/dev/null >&2 || true
  exit 1
fi
END="$("$PYTHON" -c 'import time; print(time.time())')"

"$PYTHON" - "$BROWSER_OUTPUT" <<'PY'
import json
import sys

report = json.loads(open(sys.argv[1], encoding="utf-8").read())["report"]
blocked = [r for r in report["records"] if r["verdict"] == "BLOCK"]
if not report["ok"] or not blocked:
    raise SystemExit("the browser did not report a verified blocked record")
for record in blocked:
    signature = [c for c in record["checks"] if c["name"] == "signature"]
    if not signature or not signature[0]["ok"]:
        raise SystemExit("the blocked record's signature did not verify")
print(f"  browser verified {len(report['records'])} record(s), "
      f"{len(blocked)} of them blocked, signatures valid")
PY

SECONDS_TAKEN="$("$PYTHON" -c "print(f'{$END - $START:.1f}')")"
echo
echo "Quickstart passed."
echo "  records:  $RECORDS"
echo "  verifier: $VERIFIER"
echo "  time-to-first-proof: ${SECONDS_TAKEN} s"
echo "    (pip install, demo, and a headless browser verifying a blocked"
echo "     irreversible action with a valid signature; virtual environment"
echo "     creation is not counted, a user installs into one they have)"
