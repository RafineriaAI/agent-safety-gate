"""Regenerate examples/sample_records.jsonl, or check that it is still current.

The committed sample is the file the README tells a reader to drop into
verify.html. It is produced by the shipped `demo` command with a committed demo
key and a fixed timestamp, so it is reproducible byte for byte on any machine:

    python tools/regenerate_examples.py            # rewrite the sample
    python tools/regenerate_examples.py --check    # fail if it drifted

`--check` runs in CI. A sample that no longer matches the code is worse than no
sample, because it is the first artefact anyone looks at.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"
SAMPLE = EXAMPLES / "sample_records.jsonl"
DEMO_KEY = EXAMPLES / "demo_signing_key.INSECURE.json"
FIXED_TIME = "2026-07-31T09:00:00Z"


def generate(destination: Path) -> Path:
    with tempfile.TemporaryDirectory() as directory:
        output_dir = Path(directory) / "demo"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_safety_gate.cli",
                "demo",
                "--output-dir",
                str(output_dir),
                "--key",
                str(DEMO_KEY),
                "--fixed-time",
                FIXED_TIME,
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        if completed.returncode != 0:
            raise SystemExit(f"demo failed:\n{completed.stdout}\n{completed.stderr}")
        produced = output_dir / "records.jsonl"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(produced, destination)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    if not args.check:
        generate(SAMPLE)
        print(f"wrote {SAMPLE}")
        return 0

    with tempfile.TemporaryDirectory() as directory:
        candidate = generate(Path(directory) / "records.jsonl")
        if not SAMPLE.is_file():
            print(f"ERROR: {SAMPLE} is missing.", file=sys.stderr)
            print("Next step: python tools/regenerate_examples.py", file=sys.stderr)
            return 1
        if candidate.read_bytes() != SAMPLE.read_bytes():
            print(
                f"ERROR: {SAMPLE.relative_to(REPO_ROOT)} no longer matches what "
                "the current code produces.",
                file=sys.stderr,
            )
            print("Next step: python tools/regenerate_examples.py", file=sys.stderr)
            return 1
    print(f"{SAMPLE.relative_to(REPO_ROOT)} is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
