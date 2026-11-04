"""Single-use receipts, held by the broker only.

A receipt is minted only after the account owner approved on the registered device. It is bound to one run, one
operation, one user and one exact request hash, and it expires quickly. The agent never sees a receipt or its id:
after approval the agent simply sends the same request again, and the broker finds the matching receipt itself.
Redeeming burns it in one atomic step BEFORE anything is forwarded, so two concurrent identical requests cannot
both succeed, and a receipt stays burned even if the identity server then fails.
"""
from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  op TEXT NOT NULL,
  user TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  approver TEXT NOT NULL,
  channel TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  used_at REAL
);
CREATE INDEX IF NOT EXISTS receipts_match ON receipts (run_id, op, user, request_hash);
"""


@dataclass(frozen=True)
class Redemption:
    ok: bool
    reason: str               # "ok" | "no_receipt" | "used" | "expired"
    receipt_id: str | None


class ReceiptStore:
    def __init__(self, path: str = ":memory:", clock=time.time, skew_seconds: float = 0.0):
        self._clock, self._skew = clock, skew_seconds
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.executescript(SCHEMA)

    def mint(self, run_id: str, op: str, user: str, request_hash: str, approver: str, channel: str,
             ttl_seconds: float) -> str:
        if not all((run_id, op, user, request_hash, approver, channel)) or ttl_seconds <= 0:
            raise ValueError("a receipt needs a run, operation, user, request hash, approver, channel and a TTL > 0")
        rid = "rcpt_" + secrets.token_urlsafe(18)
        now = self._clock()
        with self._lock:
            self._db.execute("INSERT INTO receipts (id, run_id, op, user, request_hash, approver, channel, "
                             "created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                             (rid, run_id, op, user, request_hash, approver, channel, now, now + ttl_seconds))
        return rid

    def redeem(self, run_id: str, op: str, user: str, request_hash: str) -> Redemption:
        """Atomically burn one matching, unused, unexpired receipt, or report why there is none."""
        now = self._clock()
        key = (run_id, op, user, request_hash)
        with self._lock:
            row = self._db.execute(
                "UPDATE receipts SET used_at = ? WHERE id = (SELECT id FROM receipts WHERE run_id = ? AND op = ? "
                "AND user = ? AND request_hash = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at "
                "LIMIT 1) AND used_at IS NULL RETURNING id",
                (now, *key, now - self._skew)).fetchone()
            if row:
                return Redemption(True, "ok", row[0])
            rows = self._db.execute("SELECT id, used_at, expires_at FROM receipts WHERE run_id = ? AND op = ? AND "
                                    "user = ? AND request_hash = ?", key).fetchall()
        if any(u is not None for _, u, _ in rows):
            return Redemption(False, "used", next(i for i, u, _ in rows if u is not None))
        if rows:
            return Redemption(False, "expired", rows[0][0])
        return Redemption(False, "no_receipt", None)

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
