"""Hash-chained, append-only ledger of every gate decision.

Each entry carries the previous entry's hash, so any edit, reorder or deletion inside the file breaks the chain.
Truncation at the end cannot be seen from the file alone, so `head()` is exported to an anchor kept elsewhere
(Object Storage in deployment) and `verify(expected_head=...)` checks against it.
If an append fails, the caller must treat the action as denied (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any

GENESIS = "0" * 64


class LedgerError(RuntimeError):
    pass


def _entry_hash(prev: str, seq: int, ts: float, kind: str, data: Any) -> str:
    body = json.dumps({"seq": seq, "ts": ts, "kind": kind, "data": data}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: str, clock=time.time):
        self.path, self._clock, self._lock = path, clock, threading.Lock()
        self._seq, self._head = 0, GENESIS
        if os.path.exists(path):
            ok, problem, seq, head = verify(path)
            if not ok:
                raise LedgerError(f"existing ledger is broken: {problem}")
            self._seq, self._head = seq, head

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            seq, ts = self._seq + 1, round(self._clock(), 6)
            h = _entry_hash(self._head, seq, ts, kind, data)
            entry = {"seq": seq, "ts": ts, "kind": kind, "data": data, "prev": self._head, "hash": h}
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                raise LedgerError(f"ledger append failed: {e}") from e
            self._seq, self._head = seq, h
            return entry

    def head(self) -> dict:
        return {"seq": self._seq, "hash": self._head}


def verify(path: str, expected_head: dict | None = None) -> tuple[bool, str, int, str]:
    """Returns (ok, problem, last_seq, last_hash)."""
    prev, seq = GENESIS, 0
    try:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                e = json.loads(line)
                if e["seq"] != seq + 1:
                    return False, f"line {n}: sequence {e['seq']} after {seq}", seq, prev
                if e["prev"] != prev:
                    return False, f"line {n}: broken link", seq, prev
                if _entry_hash(prev, e["seq"], e["ts"], e["kind"], e["data"]) != e["hash"]:
                    return False, f"line {n}: entry was modified", seq, prev
                prev, seq = e["hash"], e["seq"]
    except (OSError, ValueError, KeyError) as e:
        return False, f"unreadable ledger: {e}", seq, prev
    if expected_head and (expected_head["seq"] != seq or expected_head["hash"] != prev):
        return False, f"does not match the anchor (file ends at seq {seq}, anchor says {expected_head['seq']})", seq, prev
    return True, "", seq, prev
