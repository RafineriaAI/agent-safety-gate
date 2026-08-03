"""External anchoring: a timestamp somebody else signed.

The chain proves that this file has not been edited. It does not prove that this
file is the whole session, because whoever holds the signing key can drop a
record and re-sign the rest - `verify` says so in its own output. Closing that
needs a witness outside the operator's control.

This module adds the cheaper half of it: an RFC 3161 timestamp over the chain
head, obtained from a Time Stamping Authority run by somebody else. What it
buys, precisely:

* a record cannot be back-dated: the token binds the chain head to a time the
  TSA signed, and the TSA is not the operator;
* a chain cannot be rebuilt later and passed off as old, because the rebuilt
  head will not match any token.

What it does **not** buy, and this is the part vendors skip: a TSA is stateless.
It signs what you send and keeps no register of it. Delete a record and its
token goes with it. Omission stays invisible. Only an append-only log the
operator cannot edit - a transparency log - closes that, and this module does
not pretend to be one.

The on-disk shape follows `draft-marques-asqav-compliance-receipts`, so that an
anchor written here is readable by anything that already understands that
profile:

    {"anchors": [{"type": "rfc3161", "value": "<base64 DER>", "status": "anchored"}]}
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: A public, free TSA that needs no account. Overridable: an operator with a
#: WebTrust-audited authority should use it, and the record says which was used.
DEFAULT_TSA = "https://freetsa.org/tsr"

TIMESTAMP_QUERY = "application/timestamp-query"
TIMESTAMP_REPLY = "application/timestamp-reply"


class AnchorError(Exception):
    """An anchoring step failed. The message carries the next step."""


@dataclass(frozen=True)
class Anchor:
    """One anchor entry, in the shape the compliance-receipts profile uses."""

    type: str
    value: str
    status: str
    tsa_url: str
    committed_sha256: str
    obtained_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "status": self.status,
            # Not in the profile, kept because an auditor asking "who signed
            # this" should not have to parse DER to find out.
            "tsa_url": self.tsa_url,
            "committed_sha256": self.committed_sha256,
            "obtained_at": self.obtained_at,
        }


def anchors_path_for(records: Path) -> Path:
    """Anchors live beside the records, never inside them.

    Inside would change every digest the moment an anchor arrived, which would
    make the chain unverifiable against records written before it.
    """
    return records.with_suffix(records.suffix + ".anchors.json")


def _openssl(args: list[str], stdin: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *args], input=stdin, capture_output=True, check=False
        )
    except FileNotFoundError as exc:
        raise AnchorError(
            "openssl was not found on PATH.\n"
            "Next step: install openssl, or anchor from a machine that has it. "
            "RFC 3161 tokens are built and checked with it."
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise AnchorError(
            f"openssl {args[0]} {args[1] if len(args) > 1 else ''} failed: "
            f"{detail[-1] if detail else 'no detail'}"
        )
    return result.stdout


def build_query(digest_hex: str) -> bytes:
    """A timestamp request over a digest we already have.

    `-digest` sends the hash itself, so the records never leave the machine -
    only 32 bytes that reveal nothing about what they summarise.
    """
    return _openssl(["ts", "-query", "-digest", digest_hex, "-sha256", "-cert"])


def post_query(query: bytes, tsa_url: str, timeout: float = 30.0) -> bytes:
    request = urllib.request.Request(
        tsa_url, data=query, headers={"Content-Type": TIMESTAMP_QUERY}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return bytes(response.read())
    except urllib.error.URLError as exc:
        raise AnchorError(
            f"could not reach the timestamp authority at {tsa_url}: {exc.reason}\n"
            "Next step: check the URL and that this machine has outbound access, "
            "or pass --tsa-url for an authority you can reach. Anchoring is the "
            "only part of this tool that needs a network."
        ) from exc


def reply_is_granted(reply: bytes) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as handle:
        handle.write(reply)
        path = Path(handle.name)
    try:
        text = _openssl(["ts", "-reply", "-in", str(path), "-text"]).decode(
            "utf-8", "replace"
        )
    finally:
        path.unlink(missing_ok=True)
    return "Status: Granted" in text


def reply_timestamp(reply: bytes) -> str | None:
    with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as handle:
        handle.write(reply)
        path = Path(handle.name)
    try:
        text = _openssl(["ts", "-reply", "-in", str(path), "-text"]).decode(
            "utf-8", "replace"
        )
    finally:
        path.unlink(missing_ok=True)
    for line in text.splitlines():
        if line.strip().startswith("Time stamp:"):
            return line.split(":", 1)[1].strip()
    return None


def chain_head_digest(records: list[dict[str, Any]]) -> str:
    """What gets anchored: the last record's digest.

    One token covers the whole file, because each record already commits to the
    one before it. Anchoring every record would cost a round trip each and prove
    nothing extra about the ones already chained.
    """
    if not records:
        raise AnchorError("there are no records to anchor")
    head = records[-1].get("record_sha256")
    if not isinstance(head, str) or len(head) != 64:
        raise AnchorError("the last record has no usable record_sha256")
    return head


def anchor_records(records: list[dict[str, Any]], tsa_url: str = DEFAULT_TSA) -> Anchor:
    digest = chain_head_digest(records)
    reply = post_query(build_query(digest), tsa_url)
    granted = reply_is_granted(reply)
    return Anchor(
        type="rfc3161",
        value=base64.b64encode(reply).decode("ascii"),
        status="anchored" if granted else "failed",
        tsa_url=tsa_url,
        committed_sha256=digest,
        obtained_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def write_anchors(path: Path, anchors: list[dict[str, Any]]) -> None:
    """Append-only by convention: callers pass prior entries through unchanged.

    Rewriting an earlier anchor would destroy the only thing it is for.
    """
    path.write_text(
        json.dumps({"anchors": anchors}, indent=2) + chr(10), encoding="utf-8"
    )


def read_anchors(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnchorError(f"{path.name} is not readable JSON: {exc}") from exc
    entries = payload.get("anchors") if isinstance(payload, dict) else None
    return [e for e in entries or [] if isinstance(e, dict)]


@dataclass(frozen=True)
class AnchorCheck:
    """What an anchor was found to prove, or not."""

    ok: bool
    detail: str
    timestamp: str | None = None


def check_anchor(entry: dict[str, Any], records: list[dict[str, Any]]) -> AnchorCheck:
    if entry.get("type") != "rfc3161":
        return AnchorCheck(False, f"unsupported anchor type {entry.get('type')!r}")
    if entry.get("status") != "anchored":
        return AnchorCheck(False, f"anchor status is {entry.get('status')!r}")

    committed = entry.get("committed_sha256")
    digests = [r.get("record_sha256") for r in records]
    if committed not in digests:
        return AnchorCheck(
            False,
            "the anchored digest is not any record in this file: the anchor "
            "belongs to a different chain, or records after it were removed",
        )

    # How much of the file this anchor speaks for is a fact about the digest,
    # not about the token. Report it either way: a reader looking at a broken
    # anchor still needs to know how much it was meant to cover.
    position = digests.index(committed) + 1
    coverage = f"chain head at record {position} of {len(records)}"
    trailing = len(records) - position
    if trailing:
        coverage += (
            f"; {trailing} record(s) were written after it and are not covered "
            "by this anchor"
        )

    try:
        reply = base64.b64decode(str(entry.get("value", "")), validate=True)
    except (ValueError, TypeError):
        return AnchorCheck(False, f"anchor value is not valid base64; {coverage}")

    # A malformed token is a failed check, not a crash. A verifier that dies on
    # bad input is worse than one that says the input is bad, because the first
    # thing an adversary tries is bad input.
    try:
        granted = reply_is_granted(reply)
        stamped = reply_timestamp(reply) if granted else None
    except AnchorError as exc:
        return AnchorCheck(False, f"the token could not be read: {exc}; {coverage}")
    if not granted:
        return AnchorCheck(
            False, f"the timestamp authority did not grant this token; {coverage}"
        )

    return AnchorCheck(True, coverage, stamped)


def digest_of_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
