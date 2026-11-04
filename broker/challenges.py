"""Challenge-on-denial: a denied write becomes a pending approval; the push goes to the account owner's registered
device through Keycloak's CIBA flow; an approval mints a receipt for exactly the denied request in this run.

The phone shows the binding message: <match number>-<action>-<username>-<first 8 hex of the request hash>
(Keycloak limits it to 50 characters with no spaces). Pushes are rate-limited per user, and a flood returns
"rate_limited" instead of sending more, so approval fatigue cannot be manufactured.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass

from gate import ReceiptStore

SAFE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class Challenge:
    id: str
    run_id: str
    operation: str
    user_id: str
    username: str
    request_hash: str
    label: str
    number: str
    binding: str
    approver: str = ""               # username whose device gets the push (decided by policy, never by the agent)
    receipt_kind: str = "owner"
    status: str = "created"          # created | sent | approved | denied | expired | rate_limited | human_only
    auth_req_id: str | None = None
    receipt_minted: bool = False


def binding_message(number: str, label: str, username: str, request_hash: str) -> str:
    msg = f"{number}-{SAFE.sub('', label)}-{SAFE.sub('', username)}-{request_hash[:8]}"
    return msg[:50]


class Challenges:
    def __init__(self, keycloak, receipts: ReceiptStore, ttl_seconds: float = 180, max_sends: int = 3,
                 window_seconds: float = 600, clock=time.time):
        self.kc, self.receipts, self.ttl = keycloak, receipts, ttl_seconds
        self.max_sends, self.window, self._clock = max_sends, window_seconds, clock
        self._lock = threading.Lock()
        self._by_id: dict[str, Challenge] = {}
        self._sends: dict[str, list[float]] = {}

    def create(self, run_id: str, challenge: dict) -> Challenge:
        username = self.kc.username(challenge["user"])
        kind = challenge.get("receipt_kind", "owner")
        # The approver is a policy decision. "owner": the target's own device. "manager"/"contact": the target's
        # manager from the directory, because the owner's device (or contact) is the thing in question.
        approver, human_only = username, False
        if kind in ("manager", "contact"):
            mgr = self.kc.manager_of(challenge["user"])
            approver = mgr or ""
            human_only = not mgr or mgr == username
        number = f"{secrets.randbelow(90) + 10}"
        c = Challenge("chl_" + secrets.token_urlsafe(10), run_id, challenge["operation"], challenge["user"], username,
                      challenge["request_hash"], challenge["label"], number,
                      binding_message(number, challenge["label"], username, challenge["request_hash"]),
                      approver=approver, receipt_kind=kind, status="human_only" if human_only else "created")
        with self._lock:
            self._by_id[c.id] = c
        return c

    def get(self, cid: str, run_id: str) -> Challenge | None:
        c = self._by_id.get(cid)
        return c if c and c.run_id == run_id else None   # a run cannot touch another run's challenge

    def send(self, cid: str, run_id: str) -> Challenge | None:
        c = self.get(cid, run_id)
        if c is None or c.status not in ("created", "rate_limited"):
            return c
        now = self._clock()
        with self._lock:
            recent = [t for t in self._sends.get(c.approver, []) if now - t < self.window]
            if len(recent) >= self.max_sends:
                c.status = "rate_limited"
                self._sends[c.approver] = recent
                return c
            recent.append(now)
            self._sends[c.approver] = recent
        c.auth_req_id = self.kc.ciba_start(c.approver, c.binding)
        c.status = "sent"
        return c

    def poll(self, cid: str, run_id: str) -> Challenge | None:
        c = self.get(cid, run_id)
        if c is None or c.status != "sent":
            return c
        state = self.kc.ciba_poll(c.auth_req_id)
        if state == "approved" and not c.receipt_minted:
            self.receipts.mint(c.run_id, c.operation, c.user_id, c.request_hash, approver=c.approver,
                               channel=f"ciba:{c.receipt_kind}", ttl_seconds=self.ttl)
            c.receipt_minted, c.status = True, "approved"
        elif state in ("denied", "expired"):
            c.status = state
        return c
