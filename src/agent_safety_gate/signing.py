"""Ed25519 signing of gate decision records.

Claim discipline, used consistently across this repository:

* The hash chain (``prev_record_sha256``) is **tamper-evident**. It shows that a
  record file was altered. It does not say who wrote it.
* The Ed25519 signature is **issuer authentication**. It is unforgeable without
  the private key, and it is the only place where the word "unforgeable" is
  allowed to appear.

Neither property is identity assurance on its own: a signature proves that the
holder of a key signed the record, not who that holder is. Pin the public key
you expect (``--public-key`` in the CLI, the pin field in ``verify.html``) to
turn "signed by some key" into "signed by the key I expect".
"""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

SIGNATURE_ALGORITHM: Final = "Ed25519"
KEY_FILE_SCHEMA: Final = "agent-safety-gate-key/v1"
DEMO_KEY_LABEL: Final = "DEMO KEY - DO NOT USE IN PRODUCTION"


class SigningError(Exception):
    """Raised when a key cannot be loaded, created or used."""


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 key pair plus the label that travels into every record."""

    private_key: Ed25519PrivateKey
    label: str
    path: Path | None = None

    @property
    def public_key_base64(self) -> str:
        return encode_public_key(self.private_key.public_key())

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private_key.sign(message)).decode("ascii")


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def decode_public_key(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise SigningError(
            f"public key is not valid base64: {value!r}\n"
            "Next step: copy the value of signature.public_key from a record."
        ) from exc
    if len(raw) != 32:
        raise SigningError(
            f"public key must decode to 32 bytes, got {len(raw)}\n"
            "Next step: copy the value of signature.public_key from a record."
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def generate_key(label: str = DEMO_KEY_LABEL) -> SigningKey:
    return SigningKey(private_key=Ed25519PrivateKey.generate(), label=label)


def save_key(key: SigningKey, path: Path) -> Path:
    """Write a key file with owner-only permissions where the OS supports it."""
    raw_private = key.private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    payload = {
        "alg": SIGNATURE_ALGORITHM,
        "label": key.label,
        "private_key_base64": base64.b64encode(raw_private).decode("ascii"),
        "public_key_base64": key.public_key_base64,
        "schema_version": KEY_FILE_SCHEMA,
        "warning": (
            "This file contains a private key in clear text. It exists so that "
            "the demo runs offline with zero setup. Production key management "
            "is out of scope for this MVP."
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return path


def load_key(path: Path) -> SigningKey:
    if not path.is_file():
        raise SigningError(
            f"signing key not found: {path}\n"
            "Next step: run `agent-safety-gate demo` once to create a demo key, "
            "or pass --key with a path to an existing key file."
        )
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SigningError(
            f"signing key file is not valid JSON: {path} (line {exc.lineno})\n"
            "Next step: delete the file and re-run `agent-safety-gate demo` to "
            "regenerate a demo key."
        ) from exc
    if not isinstance(payload, dict):
        raise SigningError(f"signing key file must contain a JSON object: {path}")
    if payload.get("alg") != SIGNATURE_ALGORITHM:
        raise SigningError(
            f"unsupported signing algorithm {payload.get('alg')!r} in {path}\n"
            f"Next step: this build only signs with {SIGNATURE_ALGORITHM}."
        )
    encoded = payload.get("private_key_base64")
    if not isinstance(encoded, str):
        raise SigningError(f"signing key file has no private_key_base64: {path}")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"private_key_base64 is not valid base64: {path}") from exc
    if len(raw) != 32:
        raise SigningError(
            f"private_key_base64 must decode to 32 bytes, got {len(raw)}: {path}"
        )
    label = payload.get("label")
    return SigningKey(
        private_key=Ed25519PrivateKey.from_private_bytes(raw),
        label=label if isinstance(label, str) and label else DEMO_KEY_LABEL,
        path=path,
    )


def load_or_create_key(
    path: Path, label: str = DEMO_KEY_LABEL
) -> tuple[SigningKey, bool]:
    """Load ``path``, creating a demo key there on first use.

    Returns the key and whether it was created by this call, so the CLI can tell
    the user that a demo key now exists on disk.
    """
    if path.is_file():
        return load_key(path), False
    key = generate_key(label)
    save_key(key, path)
    return load_key(path), True


def verify_signature(
    public_key_base64: str, signature_base64: str, message: bytes
) -> bool:
    try:
        public_key = decode_public_key(public_key_base64)
        signature = base64.b64decode(signature_base64, validate=True)
    except (SigningError, ValueError, TypeError):
        return False
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
