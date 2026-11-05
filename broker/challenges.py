"""Challenge-on-denial: a denied write becomes a pending approval; the push goes to the approver's registered device
through Keycloak's CIBA flow; an approval mints a receipt for exactly the denied request in this run.

Consent-fatigue design (Microsoft's red team ranks consent fatigue as the most exploited agent failure):
- number matching, and the push names the target: <number>-<action>-<username>.<id prefix>-<request hash prefix>
  (Keycloak limits it to 50 characters with no spaces);
- the approver is policy, never the model: the owner, or the manager when the owner's device or contact is the thing
  in question; no usable manager -> human only;
- pushes are rate-limited per approver; a flood returns "rate_limited" instead of sending more;
- manager-approved receipts ripen only after a cooling-off delay (longer for privileged users), and the owner is
  notified on every device, including the one said to be lost, with a cancel button;
- a declined push puts that account on human-only for the agent (the decline tripwire): nothing re-asks.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

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
    why: str = ""
    auth_req_id: str | None = None
    receipt_minted: bool = False
    snapshot: dict = field(default_factory=dict)   # email and manager at approval, re-checked at execution


def binding_message(number: str, label: str, username: str, user_id: str, request_hash: str) -> str:
    msg = f"{number}-{SAFE.sub('', label)}-{SAFE.sub('', username)}.{user_id[:4]}-{request_hash[:8]}"
    return msg[:50]


class Challenges:
    def __init__(self, keycloak, receipts: ReceiptStore, ttl_seconds: float = 180, max_sends: int = 3,
                 window_seconds: float = 600, clock=time.time, pack: dict | None = None,
                 notify=lambda username, text, cancel_id=None: None, ledger=None, min_poll_interval: float = 1.0):
        self.kc, self.receipts, self.ttl = keycloak, receipts, ttl_seconds
        self.min_poll_interval = min_poll_interval
        self._last_poll: dict[str, float] = {}
        self.max_sends, self.window, self._clock = max_sends, window_seconds, clock
        self.pack = pack or {}
        self.notify = notify
        self.ledger = ledger
        self._lock = threading.Lock()
        self._by_id: dict[str, Challenge] = {}
        self._sends: dict[str, list[float]] = {}
        self._declined: dict[str, float] = {}       # user id -> time of the owner's/manager's decline
        self._cancel: dict[str, str] = {}           # sha256(cancel id) -> user id
        # The safety state is rebuilt from the ledger, so a broker restart never resets it (review finding #4): the
        # decline tripwire, the per-approver push rate limit, and the owner's cancel buttons.
        for e in (ledger.entries() if ledger is not None else []):
            d = e["data"]
            if e["kind"] == "tripwire":
                self._declined[d["user"]] = max(self._declined.get(d["user"], 0), e["ts"])
            elif e["kind"] == "push_sent":
                self._sends.setdefault(d["approver"], []).append(e["ts"])
            elif e["kind"] == "cancel_offered":
                self._cancel[d["cancel_hash"]] = d["user"]
            elif e["kind"] == "cancel_used":
                self._cancel.pop(d["cancel_hash"], None)

    def _record(self, kind: str, data: dict) -> None:
        if self.ledger is not None:
            self.ledger.append(kind, data)

    def _trip(self, user_id: str, why: str) -> None:
        self._declined[user_id] = self._clock()
        self._record("tripwire", {"user": user_id, "why": why})

    def _delay(self, kind: str, user_id: str) -> float:
        if kind not in ("manager", "contact"):
            return 0.0                              # the owner approving on their own device: no delay
        cfg = self.pack.get("cooling_off_seconds", {"default": 60, "privileged": 600})
        attr = self.pack.get("privileged_attribute", "privileged")
        privileged = self.kc.attribute(user_id, attr) in ("true", "yes", "1")
        return float(cfg.get("privileged" if privileged else "default", 60))

    def create(self, run_id: str, challenge: dict) -> Challenge:
        uid = challenge["user"]
        username = self.kc.username(uid)
        kind = challenge.get("receipt_kind", "owner")
        approver, human_only, why = username, False, ""
        if kind in ("manager", "contact"):
            mgr = self.kc.manager_of(uid)
            approver = mgr or ""
            if not mgr or mgr == username:
                human_only, why = True, "no independent manager on record"
        trip = self.pack.get("decline_tripwire_seconds", 86400)
        if uid in self._declined and self._clock() - self._declined[uid] < trip:
            human_only, why = True, "a recent approval request on this account was declined"
        number = f"{secrets.randbelow(90) + 10}"
        c = Challenge("chl_" + secrets.token_urlsafe(10), run_id, challenge["operation"], uid, username,
                      challenge["request_hash"], challenge["label"], number,
                      binding_message(number, challenge["label"], username, uid, challenge["request_hash"]),
                      approver=approver, receipt_kind=kind, status="human_only" if human_only else "created", why=why)
        with self._lock:
            self._by_id[c.id] = c
        return c

    def get(self, cid: str, run_id: str) -> Challenge | None:
        c = self._by_id.get(cid)
        return c if c and c.run_id == run_id else None   # a run cannot touch another run's challenge

    def find(self, run_id: str, operation: str, user_id: str, request_hash: str) -> Challenge | None:
        for c in self._by_id.values():
            if (c.run_id, c.operation, c.user_id, c.request_hash) == (run_id, operation, user_id, request_hash) \
                    and c.receipt_minted:
                return c
        return None

    def declined_before(self, run_id: str, operation: str, user_id: str, request_hash: str) -> bool:
        """Did the approver already say no to exactly this request in this run?"""
        return any((c.run_id, c.operation, c.user_id, c.request_hash) == (run_id, operation, user_id, request_hash)
                   and c.status == "denied" for c in self._by_id.values())

    def send(self, cid: str, run_id: str) -> Challenge | None:
        c = self.get(cid, run_id)
        if c is None:
            return c
        now = self._clock()
        with self._lock:
            if c.status not in ("created", "rate_limited", "unavailable"):   # under the lock: one push per challenge
                return c
            recent = [t for t in self._sends.get(c.approver, []) if now - t < self.window]
            if len(recent) >= self.max_sends:
                c.status = "rate_limited"
                self._sends[c.approver] = recent
                return c
            recent.append(now)
            self._sends[c.approver] = recent
            c.status = "sending"
        try:
            c.auth_req_id = self.kc.ciba_start(c.approver, c.binding)
        except Exception:
            c.status = "unavailable"                  # nothing was sent; the attempt still counts for the rate limit
            raise
        c.status = "sent"
        self._record("push_sent", {"approver": c.approver, "user": c.user_id, "challenge": c.id})
        return c

    def poll(self, cid: str, run_id: str) -> Challenge | None:
        c = self.get(cid, run_id)
        if c is None or c.status != "sent":
            return c
        with self._lock:                            # a tight script loop never hammers Keycloak's CIBA endpoint
            now = self._clock()
            if now - self._last_poll.get(c.id, float("-inf")) < self.min_poll_interval:
                return c
            self._last_poll[c.id] = now
        state = self.kc.ciba_poll(c.auth_req_id)
        if state == "approved" and not c.receipt_minted:
            # Network reads first, then check-and-mint under one lock: two concurrent polls of one approval mint
            # exactly one receipt (review finding #5).
            delay = self._delay(c.receipt_kind, c.user_id)
            snapshot = self.kc.user_snapshot(c.user_id)
            with self._lock:
                if c.receipt_minted:
                    return c
                self.receipts.mint(c.run_id, c.operation, c.user_id, c.request_hash, approver=c.approver,
                                   channel=f"ciba:{c.receipt_kind}", ttl_seconds=self.ttl, delay_seconds=delay,
                                   snapshot=snapshot)
                c.snapshot, c.receipt_minted, c.status = snapshot, True, "approved"
            if delay > 0:                           # tell the owner everywhere, with a way to stop it
                cancel_id = "cnl_" + secrets.token_urlsafe(10)
                h = hashlib.sha256(cancel_id.encode()).hexdigest()
                self._cancel[h] = c.user_id
                self._record("cancel_offered", {"cancel_hash": h, "user": c.user_id, "challenge": c.id})
                self.notify(c.username, f"{c.approver} approved '{c.operation}' on your account. It runs in "
                                        f"{int(delay)} s unless you cancel. If you did not ask for this, cancel now.",
                            cancel_id)
        elif state in ("denied", "expired"):
            with self._lock:
                if c.status != "sent":
                    return c
                c.status = state
            if state == "denied":
                self._trip(c.user_id, "approver declined")     # the decline tripwire
        return c

    def expire_now(self, binding: str) -> bool:
        """The demo's "the owner doesn't answer" button: the push for this binding message expires at once, as it would
        after its timeout (an expiry, not a decline: no tripwire, the agent may try again or escalate)."""
        with self._lock:
            for c in self._by_id.values():
                if c.binding == binding and c.status == "sent":
                    c.status = "expired"
                    return True
        return False

    def number_for(self, challenge_id: str) -> str | None:
        c = self._by_id.get(challenge_id)
        return c.number if c else None

    def cancel(self, cancel_id: str) -> int:
        """The owner pressed cancel (from any device): every pending receipt on the account dies; human-only follows."""
        h = hashlib.sha256(cancel_id.encode()).hexdigest()
        with self._lock:
            uid = self._cancel.pop(h, None)
        if uid is None:
            return 0
        self._record("cancel_used", {"cancel_hash": h, "user": uid})
        self._trip(uid, "owner cancelled")
        return self.receipts.cancel_for_user(uid)
