"""The gate: one decision per request from the sandbox. Authorization is not a model output.

Order for a write: parse strictly -> find and burn a matching receipt -> write the ledger -> only then forward.
Any failure on that path denies (fail closed). Reads and console assets pass without a receipt; anything the policy
pack does not describe is denied. The agent never receives a token, a receipt, or a secret.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from .grammar import OVERRIDE_PLACEHOLDER, Operation, Reject, parse
from .ledger import Ledger, LedgerError
from .receipts import ReceiptStore

WRITE_METHODS = ("PUT", "POST", "DELETE")


@dataclass
class Decision:
    allow: bool
    outcome: str                      # allowed_read | allowed_static | allowed_write | denied_* (see below)
    reason: str = ""
    op: Operation | None = None
    forward: dict | None = None       # what the proxy sends upstream (it adds the broker's own session)
    challenge: dict | None = None     # when a write needs the owner's approval
    quarantine: str | None = None     # reason, if this run must be stopped and its worker destroyed
    oob_secret: str | None = field(default=None, repr=False)  # goes to the owner's device, never to the agent
    ledger_seq: int | None = None

    def agent_view(self) -> dict:
        """The only thing the sandbox is told. No receipt, no token, no secret."""
        v: dict[str, Any] = {"allowed": self.allow, "outcome": self.outcome, "reason": self.reason}
        if self.challenge:
            v["challenge_required"] = {"operation": self.challenge["operation"], "user": self.challenge["user"]}
        if self.quarantine:
            v["quarantined"] = True
        return v


class Gate:
    def __init__(self, pack: dict, receipts: ReceiptStore, ledger: Ledger, max_unapproved_writes: int = 3,
                 secret_factory=lambda: secrets.token_urlsafe(12)):
        self.pack, self.receipts, self.ledger = pack, receipts, ledger
        self.max_unapproved = max_unapproved_writes
        self._secret = secret_factory
        self._unapproved: dict[str, int] = {}

    def _log(self, kind: str, data: dict) -> int:
        return self.ledger.append(kind, data)["seq"]

    def _deny(self, outcome: str, reason: str, run_id: str, method: str, target: str, op: Operation | None = None,
              challenge: dict | None = None, quarantine: str | None = None) -> Decision:
        data = {"run": run_id, "method": method, "target": target[:300], "outcome": outcome, "reason": reason}
        if op:
            data.update({"op": op.name, "user": op.user, "request_hash": op.request_hash})
        if quarantine:
            data["quarantine"] = quarantine
        try:
            seq = self._log("decision", data)
        except LedgerError:
            seq = None  # still denied: a denial never depends on the ledger being up
        return Decision(False, outcome, reason, op, None, challenge, quarantine, None, seq)

    def decide(self, method: str, target: str, body: bytes, run_id: str) -> Decision:
        method = method.upper()
        try:
            op = parse(self.pack, method, target, body)
        except Reject as r:
            q = f"{r.kind} {method} request" if method in WRITE_METHODS else None
            return self._deny(f"denied_{r.kind}", r.reason, run_id, method, target, quarantine=q)

        if op.kind in ("read", "static"):
            try:
                seq = self._log("decision", {"run": run_id, "method": method, "target": target[:300],
                                             "outcome": f"allowed_{op.kind}"}) if op.kind == "read" else None
            except LedgerError as e:
                return Decision(False, "denied_ledger_down", str(e), op)
            fwd = {"method": method, "path": op.path, "query": list(op.query), "body": b"",
                   "headers": {"Accept": "application/json"}}
            return Decision(True, f"allowed_{op.kind}", "", op, fwd, ledger_seq=seq)

        # A write: it needs a receipt minted after the owner's approval for exactly this request in this run.
        red = self.receipts.redeem(run_id, op.name, op.user, op.request_hash)
        if not red.ok:
            n = self._unapproved[run_id] = self._unapproved.get(run_id, 0) + 1
            q = f"{n} unapproved write attempts in this run" if n >= self.max_unapproved else None
            challenge = None
            if red.reason == "no_receipt" and not q:
                challenge = {"operation": op.name, "user": op.user, "request_hash": op.request_hash,
                             "label": op.label, "receipt_kind": op.receipt}
            return self._deny(f"denied_{red.reason}", "this change needs the account owner's approval"
                              if red.reason == "no_receipt" else f"receipt {red.reason}",
                              run_id, method, target, op, challenge, q)

        if op.kind == "composite":
            steps = list(self.pack["composites"][op.name]["steps"])
            try:
                seq = self._log("executed", {"run": run_id, "op": op.name, "user": op.user, "steps": steps,
                                             "request_hash": op.request_hash, "receipt": red.receipt_id})
            except LedgerError as e:
                return Decision(False, "denied_ledger_down", f"receipt burned, nothing executed: {e}", op)
            return Decision(True, "allowed_composite", "", op,
                            {"composite": op.name, "user": op.user, "steps": steps, "receipt": red.receipt_id},
                            ledger_seq=seq)

        # Burned. Build exactly what was approved; replace override fields (e.g. the password) with broker values.
        secret = None
        fwd_body = op.canonical_body
        if op.overrides:
            body_obj = json.loads(op.canonical_body)
            for name, kind in op.overrides.items():
                if kind == "broker_secret" and body_obj.get(name) == OVERRIDE_PLACEHOLDER:
                    secret = secret or self._secret()
                    body_obj[name] = secret
            fwd_body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        try:
            seq = self._log("executed", {"run": run_id, "method": method, "path": op.path, "op": op.name,
                                         "user": op.user, "request_hash": op.request_hash, "receipt": red.receipt_id,
                                         "secret_out_of_band": secret is not None})
        except LedgerError as e:
            return Decision(False, "denied_ledger_down", f"receipt burned, nothing forwarded: {e}", op)
        headers = {"Accept": "application/json"}
        if fwd_body:
            headers["Content-Type"] = "application/json"
        fwd = {"method": method, "path": op.path, "query": list(op.query), "body": fwd_body, "headers": headers}
        return Decision(True, "allowed_write", "", op, fwd, oob_secret=secret, ledger_seq=seq)
