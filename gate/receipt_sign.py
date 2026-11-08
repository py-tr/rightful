"""Signed run receipts: every shared demo run ("Share this result") is signed with the demo server's Ed25519 key, so a
reviewer can keep the JSON and check offline that not one byte of it changed since the server wrote it.

What the signature proves: the record is exactly what this server wrote (summary, every proof line with the identity
server's own events, the policy hash, the conversation). What it does not prove: anything about the server itself; it
is the operator's key, not an independent notary. Verify with `python -m gate.verify_receipt <file.json> --url <site>`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

UNSIGNED_FIELDS = ("signature", "other", "published")   # attached at serve time: the paired column (itself signed)
                                                         # and the Object Storage URL of this same signed record


def canonical(record: dict) -> bytes:
    """The exact bytes that are signed: the record without its signature, keys sorted, no whitespace, UTF-8."""
    body = {k: v for k, v in record.items() if k not in UNSIGNED_FIELDS}
    # ensure_ascii=True (review 11-08 m3): every character escaped to ASCII, so a lone surrogate a visitor sends cannot
    # make signing raise; fixed before the first production signature, since changing it later voids every receipt
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def key_id(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


class Signer:
    def __init__(self, key_path: str):
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._key = Ed25519PrivateKey.generate()
            os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
            pem = self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_b64, self.key_id = _b64(raw), key_id(raw)

    def sign(self, record: dict) -> dict:
        return {"alg": "Ed25519", "key_id": self.key_id, "public_key": self.public_b64,
                "signed": "the record without 'signature' and 'other', JSON with sorted keys and no whitespace",
                "sig": _b64(self._key.sign(canonical(record)))}

    def public(self) -> dict:
        return {"alg": "Ed25519", "key_id": self.key_id, "public_key": self.public_b64}


def verify(record: dict, trusted_public_b64: str | None = None) -> tuple[bool, str]:
    """(ok, reason). With trusted_public_b64 (fetched from the site), the record must also be signed by that key."""
    sig = record.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
        return False, "no Ed25519 signature on this record"
    pub_b64 = sig.get("public_key", "")
    if trusted_public_b64 and pub_b64 != trusted_public_b64:
        return False, "signed by a different key than the site publishes"
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(sig.get("sig", "")), canonical(record))
    except (InvalidSignature, ValueError):
        return False, "signature does not match: the record was changed after it was signed"
    return True, f"valid (key {sig.get('key_id')})"
