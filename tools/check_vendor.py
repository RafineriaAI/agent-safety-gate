"""Check that the vendored kernel file is the file it says it is.

    python tools/check_vendor.py
    AOS_KERNEL_REPO=/path/to/aos-kernel python tools/check_vendor.py

Without a kernel checkout this verifies the digest against the manifest. With
one, it also compares the file byte for byte against upstream, which is the
claim the NOTICE actually makes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = REPO_ROOT / "src" / "agent_safety_gate" / "_vendor" / "aos_kernel"
MANIFEST = VENDOR_DIR / "vendor_manifest.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    upstream_repo = os.environ.get("AOS_KERNEL_REPO")
    failures: list[str] = []

    for name, expected in sorted(manifest["files"].items()):
        path = VENDOR_DIR / name
        if not path.is_file():
            failures.append(f"{name} is missing from {VENDOR_DIR}")
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected["sha256"]:
            failures.append(
                f"{name} has digest {digest}, manifest says {expected['sha256']}"
            )
        if len(data) != expected["size"]:
            failures.append(
                f"{name} is {len(data)} bytes, manifest says {expected['size']}"
            )
        if upstream_repo:
            source = Path(upstream_repo) / expected["upstream_path"]
            if not source.is_file():
                failures.append(f"upstream file not found: {source}")
            elif source.read_bytes() != data:
                failures.append(
                    f"{name} differs from upstream {expected['upstream_path']}"
                )

    # The digest is quoted in three places a reader might look at; they must not
    # drift apart.
    for document in (VENDOR_DIR / "VENDOR.md", REPO_ROOT / "NOTICE"):
        text = document.read_text(encoding="utf-8")
        for name, expected in manifest["files"].items():
            if expected["sha256"] not in text:
                failures.append(f"{document.name} does not quote the digest of {name}")
        if manifest["upstream_commit"] not in text:
            failures.append(f"{document.name} does not quote the upstream commit")

    if failures:
        print(
            "ERROR: the vendored kernel copy is not what it claims to be:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "Next step: re-copy the file from the pinned upstream commit and "
            "update vendor_manifest.json, NOTICE and VENDOR.md together.",
            file=sys.stderr,
        )
        return 1

    checked = "digest and upstream bytes" if upstream_repo else "digest"
    print(
        f"vendored kernel verified ({checked}): "
        f"{manifest['upstream_repository']} @ {manifest['upstream_commit'][:12]}"
    )
    if not upstream_repo:
        print(
            "  set AOS_KERNEL_REPO to also compare the file byte for byte "
            "against an upstream checkout"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
