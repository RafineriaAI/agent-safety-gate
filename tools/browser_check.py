"""Run verifier/verify.html in a headless browser and report what it found.

Used by the test suite and by tools/verify_all.sh. It answers two questions:

1. Does the real page verify a real record file, and does it turn red on a
   damaged one?
2. Does the JavaScript canonicaliser produce the same bytes as Python for a
   large set of generated values? A verifier that disagrees with the producer
   by one byte is worse than no verifier.

The page is copied to a temporary file with one extra script appended. That
script only feeds input to the page's own public entry points
(``window.AGENT_SAFETY_GATE_VERIFIER``) and prints the result, so the code under
test is the shipped code, not a copy of it. Nothing test-shaped lives in
verify.html itself.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "verifier" / "verify.html"
# Markers must survive HTML serialisation by --dump-dom, so no angle brackets.
MARKER_START = "@@AGENT-SAFETY-GATE-RESULT@@"
MARKER_END = "@@END@@"

CHROME_CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "msedge",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)


class BrowserUnavailable(Exception):
    """Raised when no headless Chromium-family browser can be found."""


def find_browser() -> str:
    override = os.environ.get("ASG_CHROME")
    if override:
        if Path(override).is_file() or shutil.which(override):
            return override
        raise BrowserUnavailable(
            f"ASG_CHROME is set to {override!r}, which is not usable"
        )
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    for cache in (
        Path.home() / "AppData" / "Local" / "ms-playwright",
        Path.home() / ".cache" / "ms-playwright",
    ):
        if cache.is_dir():
            for binary in sorted(cache.glob("chromium*/**/headless_shell*")) + sorted(
                cache.glob("chromium*/**/chrome*")
            ):
                if binary.is_file() and binary.suffix in {"", ".exe"}:
                    return str(binary)
    raise BrowserUnavailable(
        "no Chromium-family browser found.\n"
        "Next step: install Google Chrome, Chromium or Edge, or point ASG_CHROME "
        "at the binary."
    )


def _js_string(value: str) -> str:
    return json.dumps(value).replace("</", "<\\/")


def build_harness(records_text: str, pinned_key: str | None, vectors: list[Any]) -> str:
    page = VERIFIER.read_text(encoding="utf-8")
    script = f"""
<script>
(async function () {{
  const api = window.AGENT_SAFETY_GATE_VERIFIER;
  const out = {{ ok: false }};
  try {{
    const text = {_js_string(records_text)};
    const pin = {_js_string(pinned_key) if pinned_key else "null"};
    const vectors = {json.dumps(vectors)};
    const report = await api.verifyText(text, pin);
    const parity = [];
    for (let i = 0; i < vectors.length; i++) {{
      parity.push({{
        canonical: api.canonicalize(vectors[i]),
        sha256: await api.sha256Hex(vectors[i])
      }});
    }}
    out.ok = true;
    out.report = report;
    out.parity = parity;
  }} catch (error) {{
    out.error = String(error && error.stack ? error.stack : error);
  }}
  const node = document.createElement("pre");
  node.id = "asg-machine-output";
  node.textContent = "{MARKER_START}" + btoa(
    String.fromCharCode.apply(
      null, Array.from(new TextEncoder().encode(JSON.stringify(out)))
    )
  ) + "{MARKER_END}";
  document.body.appendChild(node);
}})();
</script>
"""
    return page.replace("</body>", script + "</body>")


def run_in_browser(
    records_text: str,
    pinned_key: str | None = None,
    vectors: list[Any] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    browser = find_browser()
    harness = build_harness(records_text, pinned_key, vectors or [])
    with tempfile.TemporaryDirectory() as directory:
        page_path = Path(directory) / "harness.html"
        page_path.write_text(harness, encoding="utf-8")
        profile = Path(directory) / "profile"
        command = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--user-data-dir={profile}",
            "--virtual-time-budget=20000",
            "--dump-dom",
            page_path.resolve().as_uri(),
        ]
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    match = re.search(
        re.escape(MARKER_START) + r"([A-Za-z0-9+/=]+)" + re.escape(MARKER_END),
        completed.stdout,
    )
    if not match:
        raise BrowserUnavailable(
            "the headless browser produced no verifier output.\n"
            f"exit code: {completed.returncode}\n"
            f"stderr: {completed.stderr[:2000]}"
        )
    payload: dict[str, Any] = json.loads(
        base64.b64decode(match.group(1)).decode("utf-8")
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--pin", default=None)
    parser.add_argument("--vectors", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    vectors = (
        json.loads(args.vectors.read_text(encoding="utf-8")) if args.vectors else []
    )
    try:
        payload = run_in_browser(
            args.records.read_text(encoding="utf-8"), args.pin, vectors
        )
    except BrowserUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    if not payload.get("ok"):
        return 1
    return 0 if payload.get("report", {}).get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
