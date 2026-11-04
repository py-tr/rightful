"""Canonical form of a request, and the hash a receipt is bound to.

The broker hashes exactly what it will forward: method, path, the sorted query, and the canonical JSON body.
Fields the broker overrides (for example a password the agent typed) are blanked before hashing, so the
hash names the operation, not a secret.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


class CanonError(ValueError):
    """The body is not acceptable JSON (bad syntax, duplicate keys, NaN, or not UTF-8)."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise CanonError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise CanonError(f"non-standard number {name}")


def parse_json(body: bytes) -> Any:
    """Strict JSON: UTF-8, no duplicate keys, no NaN or Infinity. An empty body is None."""
    if not body:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CanonError("body is not UTF-8") from e
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except json.JSONDecodeError as e:
        raise CanonError(f"invalid JSON: {e.msg}") from e


def canonical_json(value: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8. None (no body) is the empty byte string."""
    if value is None:
        return b""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def request_hash(method: str, path: str, query: Iterable[tuple[str, str]], canonical_body: bytes) -> str:
    """SHA-256 over the request exactly as the broker will forward it."""
    q = "&".join(f"{k}={v}" for k, v in sorted(query))
    h = hashlib.sha256()
    for part in (method.upper().encode(), path.encode(), q.encode()):
        h.update(part)
        h.update(b"\n")
    h.update(canonical_body)
    return h.hexdigest()
