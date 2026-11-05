"""Single-use receipts, held by the broker only.

A receipt is minted only after the approver (by policy: the owner, or the manager when the owner's device is the
thing in question) approved on a registered device. It is bound to one run, one operation, one user and one exact
request hash, and it expires quickly. The agent never sees a receipt or its id: after approval the agent simply sends
the same request again, and the broker finds the matching receipt itself.

Redeeming burns it in one atomic step BEFORE anything is forwarded, so two concurrent identical requests cannot
both succeed, and a receipt stays burned even if the identity server then fails.

Cooling-off: a receipt may become usable only after a delay (manager-approved recoveries). During that window the
owner can cancel it from any of their devices, including the one said to be lost.
"""
from __future__ import annotations

import json
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
  not_before REAL NOT NULL,
  expires_at REAL NOT NULL,
  used_at REAL,
  cancelled INTEGER NOT NULL DEFAULT 0,
  snapshot TEXT
);
CREATE INDEX IF NOT EXISTS receipts_match ON receipts (run_id, op, user, request_hash);
"""


@dataclass(frozen=True)
class Redemption:
    ok: bool
    reason: str      # "ok" | "no_receipt" | "used" | "expired" | "cooling_off" | "cancelled"
    receipt_id: str | None
    snapshot: dict | None = None     # the account's email/manager at approval time (None if none was stored)
    retry_after: float | None = None  # cooling_off: seconds until the receipt ripens


class ReceiptStore:
    def __init__(self, path: str = ":memory:", clock=time.time, skew_seconds: float = 0.0):
        self._clock, self._skew = clock, skew_seconds
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.executescript(SCHEMA)
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(receipts)")}
        if "snapshot" not in cols:                  # a database created before snapshots were stored
            self._db.execute("ALTER TABLE receipts ADD COLUMN snapshot TEXT")

    def mint(self, run_id: str, op: str, user: str, request_hash: str, approver: str, channel: str,
             ttl_seconds: float, delay_seconds: float = 0.0, snapshot: dict | None = None) -> str:
        """ttl_seconds counts from the end of the cooling-off delay. The snapshot (what the approver saw) lives in the
        receipt itself, so it survives a broker restart (review finding #4)."""
        if not all((run_id, op, user, request_hash, approver, channel)) or ttl_seconds <= 0 or delay_seconds < 0:
            raise ValueError("a receipt needs a run, operation, user, request hash, approver, channel and a TTL > 0")
        rid = "rcpt_" + secrets.token_urlsafe(18)
        now = self._clock()
        snap = json.dumps(snapshot, sort_keys=True) if snapshot is not None else None
        with self._lock:
            self._db.execute("INSERT INTO receipts (id, run_id, op, user, request_hash, approver, channel, "
                             "created_at, not_before, expires_at, snapshot) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                             (rid, run_id, op, user, request_hash, approver, channel, now, now + delay_seconds,
                              now + delay_seconds + ttl_seconds, snap))
        return rid

    def redeem(self, run_id: str, op: str, user: str, request_hash: str) -> Redemption:
        """Atomically burn one matching, unused, uncancelled, ripe, unexpired receipt, or report why there is none."""
        now = self._clock()
        key = (run_id, op, user, request_hash)
        with self._lock:
            row = self._db.execute(
                "UPDATE receipts SET used_at = ? WHERE id = (SELECT id FROM receipts WHERE run_id = ? AND op = ? "
                "AND user = ? AND request_hash = ? AND used_at IS NULL AND cancelled = 0 AND not_before <= ? "
                "AND expires_at > ? ORDER BY created_at LIMIT 1) AND used_at IS NULL AND cancelled = 0 "
                "RETURNING id, snapshot",
                (now, *key, now, now - self._skew)).fetchone()
            if row:
                return Redemption(True, "ok", row[0], json.loads(row[1]) if row[1] is not None else None)
            rows = self._db.execute("SELECT id, used_at, expires_at, not_before, cancelled FROM receipts WHERE "
                                    "run_id = ? AND op = ? AND user = ? AND request_hash = ?", key).fetchall()
        for rid, used, exp, nb, canc in rows:
            if canc:
                return Redemption(False, "cancelled", rid)
        for rid, used, exp, nb, canc in rows:
            if used is not None:
                return Redemption(False, "used", rid)
        for rid, used, exp, nb, canc in rows:
            if nb > now:
                return Redemption(False, "cooling_off", rid, retry_after=round(nb - now, 1))
        if rows:
            return Redemption(False, "expired", rows[0][0])
        return Redemption(False, "no_receipt", None)

    def redeem_unbound(self, run_id: str) -> Redemption:
        """EVALUATION ABLATION ONLY (the gate calls it only in the 'unbound' mode): burn any ripe receipt of this run,
        whatever operation, user or request it was approved for. Shows what binding to the exact request buys."""
        now = self._clock()
        with self._lock:
            row = self._db.execute(
                "UPDATE receipts SET used_at = ? WHERE id = (SELECT id FROM receipts WHERE run_id = ? AND used_at IS "
                "NULL AND cancelled = 0 AND not_before <= ? AND expires_at > ? ORDER BY created_at LIMIT 1) "
                "RETURNING id, snapshot", (now, run_id, now, now - self._skew)).fetchone()
        if row:
            return Redemption(True, "ok", row[0], json.loads(row[1]) if row[1] is not None else None)
        return Redemption(False, "no_receipt", None)

    def cancel_for_user(self, user: str) -> int:
        """The owner pressed cancel: every pending receipt on their account dies."""
        with self._lock:
            return self._db.execute("UPDATE receipts SET cancelled = 1 WHERE user = ? AND used_at IS NULL "
                                    "AND cancelled = 0", (user,)).rowcount

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
