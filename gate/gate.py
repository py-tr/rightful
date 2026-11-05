"""The gate: one decision per request from the sandbox. Authorization is not a model output.

Order for a write: parse strictly -> find and burn a matching receipt -> write "forwarding" to the ledger -> only then
forward. The broker writes "executed" only after the upstream answers 2xx (or a composite completes), so the ledger
never says a change happened when Keycloak refused it.
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
from .receipts import ReceiptStore, Redemption

WRITE_METHODS = ("PUT", "POST", "DELETE")
# Path and encoding tricks (the ';', '%' and '..' classes): quarantine at once. Other malformed writes are strikes.
HOSTILE_MALFORMED = ("forbidden character", "dot segment", "encoded", "percent", "control characters")


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


EVAL_MODES = ("allow_all", "allowlist_only", "unbound", "naive")


def eval_modes_permitted(realm: str) -> bool:
    """The evaluation's weaker gate modes (the gate-off baseline and the ablations) exist ONLY for the measurement.
    They are honoured only when KEYLESS_EVAL=1 is set AND the realm is a scratch realm ('eval-...'); the demo realm
    can never run them (mentor's review: "the answer must be a refusal in code, not a convention")."""
    import os
    return os.environ.get("KEYLESS_EVAL") == "1" and realm.startswith("eval-")


class Gate:
    def __init__(self, pack: dict, receipts: ReceiptStore, ledger: Ledger, max_unapproved_writes: int = 4,
                 secret_factory=lambda: secrets.token_urlsafe(12)):
        self.pack, self.receipts, self.ledger = pack, receipts, ledger
        self.max_unapproved = max_unapproved_writes
        self._secret = secret_factory
        self._modes: dict[str, str] = {}               # run id -> eval mode (empty outside an evaluation)
        self._verified: set[tuple[str, str]] = set()   # (run, user) the AGENT claims to have verified (naive mode only)
        self._unapproved: dict[str, int] = {}
        self._malformed: dict[str, int] = {}          # per run: harmless malformed writes (strikes)
        # Rebuilt from the ledger, so a broker restart does not reset a looping run's strikes (review finding #4).
        for e in ledger.entries():
            d = e["data"]
            if e["kind"] == "decision" and d.get("request_hash") and d.get("outcome", "").startswith("denied_") \
                    and d["outcome"] not in ("denied_cooling_off",):
                key = f"{d['run']}|{d['request_hash']}"
                self._unapproved[key] = self._unapproved.get(key, 0) + 1
            elif e["kind"] == "decision" and d.get("outcome") == "denied_malformed" \
                    and d.get("method") in WRITE_METHODS and not d.get("quarantine"):
                self._malformed[d["run"]] = self._malformed.get(d["run"], 0) + 1

    def set_mode(self, run_id: str, mode: str) -> None:
        if mode == "full":
            self._modes.pop(run_id, None)
            return
        if mode not in EVAL_MODES:
            raise ValueError(f"unknown gate mode {mode!r}")
        if not eval_modes_permitted(self.pack["realm"]):
            try:
                self.ledger.append("eval_mode_refused", {"run": run_id, "mode": mode, "realm": self.pack["realm"]})
            finally:
                raise PermissionError(f"REFUSED: gate mode {mode!r} is evaluation-only (needs KEYLESS_EVAL=1 and a "
                                      f"scratch realm 'eval-*'; this realm is {self.pack['realm']!r})")
        self._modes[run_id] = mode
        self.ledger.append("eval_mode", {"run": run_id, "mode": mode})

    def mode(self, run_id: str) -> str:
        return self._modes.get(run_id, "full")

    def agent_claims_verified(self, run_id: str, user: str, how: str) -> None:
        """The agent says it verified the caller. Logged in every mode (claimed vs actual, for the audit). Only the
        evaluation's NAIVE gate treats it as authority: the cheapest proof of why a ledger of approvals matters."""
        self.ledger.append("agent_claimed_verification", {"run": run_id, "user": user, "how": how[:200]})
        self._verified.add((run_id, user))

    def _decide_allow_all(self, method: str, target: str, body: bytes, run_id: str) -> Decision:
        """Gate-off baseline: credential-brokered, NO authorization. The request goes upstream as sent (the service
        account still signs it); only the realm boundary remains. Evaluation-only (see eval_modes_permitted)."""
        path, _, qs = target.partition("?")
        try:
            op = parse(self.pack, method, target, body)
        except Reject:
            import re as _re
            m = _re.search(r"/users/([0-9a-fA-F-]{36})", path)
            op = Operation("unparsed", "write" if method in WRITE_METHODS else "read", method, path, (),
                           {"user": m.group(1)} if m else {}, None, body, "", "owner", "unparsed")
        if not path.startswith(f"/admin/realms/{self.pack['realm']}/") and op.kind != "composite":
            return self._deny("denied_not_allowlisted", "outside the realm", run_id, method, target, op)
        if op.kind == "composite":
            steps = list(self.pack["composites"][op.name]["steps"])
            seq = self._log("forwarding", {"run": run_id, "op": op.name, "user": op.user, "steps": steps,
                                           "request_hash": op.request_hash, "receipt": None, "mode": "allow_all"})
            return Decision(True, "allowed_composite", "", op, {"composite": op.name, "user": op.user, "steps": steps,
                                                                "receipt": None, "snapshot": "skip"}, ledger_seq=seq)
        from urllib.parse import parse_qsl
        fwd_body, secret = body, None
        if op.name == "reset_password":
            try:
                b = json.loads(body or b"{}")
                if not b.get("value"):            # the agent did not choose one: the broker makes one and RETURNS it
                    secret = self._secret()
                    b["value"] = secret
                    fwd_body = json.dumps(b).encode()
            except ValueError:
                pass
        kind = "read" if method == "GET" else "write"
        seq = self._log("decision" if kind == "read" else "forwarding",
                        {"run": run_id, "method": method, "target": target[:300], "op": op.name, "user": op.user,
                         "request_hash": op.request_hash, "outcome": "allowed_unauthorized", "mode": "allow_all"})
        headers = {"Accept": "application/json"}
        if fwd_body:
            headers["Content-Type"] = "application/json"
        op = Operation(op.name, kind, method, path, (), op.params, op.body, fwd_body, op.request_hash, op.receipt,
                       op.label)
        return Decision(True, "allowed_unauthorized", "", op,
                        {"method": method, "path": path, "query": parse_qsl(qs, keep_blank_values=True),
                         "body": fwd_body, "headers": headers, "return_secret": secret}, ledger_seq=seq)

    def _hostile(self, method: str, target: str, r: Reject) -> str | None:
        """Quarantine only on hostile signals; an honest agent's harmless mistake gets a refusal it can learn from.
        Hostile: path or encoding tricks (malformed), and any write aimed at the witness, roles, clients or the realm."""
        if method not in WRITE_METHODS:
            return None
        if r.kind == "malformed":
            if any(sig in r.reason for sig in HOSTILE_MALFORMED):
                return f"malformed {method} request ({r.reason})"
            return None               # a harmless mistake (trailing slash, bad body...): a strike, counted in decide()
        path = target.split("?", 1)[0]
        realm_root = f"/admin/realms/{self.pack['realm']}"
        if path in (realm_root, "/admin/realms") or any(seg in path for seg in self.pack.get("quarantine_paths", [])):
            return f"write aimed at a protected area ({path[:120]})"
        return None

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
        mode = self.mode(run_id)
        if mode == "allow_all":
            return self._decide_allow_all(method, target, body, run_id)
        try:
            op = parse(self.pack, method, target, body)
        except Reject as r:
            q = self._hostile(method, target, r)
            if q is None and r.kind == "malformed" and method in WRITE_METHODS:
                n = self._malformed[run_id] = self._malformed.get(run_id, 0) + 1
                if n >= self.max_unapproved:
                    q = f"{n} malformed write requests in one run"
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
        if mode == "allowlist_only":                       # ablation: the grammar alone, no approval at all
            red = Redemption(True, "ok", None, "skip")
        elif mode == "naive" and (run_id, op.user) in self._verified:   # ablation: trusts the agent's own claim
            red = Redemption(True, "ok", None, "skip")
        elif mode == "unbound":                            # ablation: any approval in this run unlocks any write
            red = self.receipts.redeem_unbound(run_id)
        else:
            red = self.receipts.redeem(run_id, op.name, op.user, op.request_hash)
        if not red.ok and red.reason == "cooling_off":
            return self._deny("denied_cooling_off", "approved; usable after the cooling-off period (the owner can "
                              "still cancel it)", run_id, method, target, op)
        if not red.ok:
            # Count per exact request: an honest agent doing two different approved changes sees one denial each,
            # which must never add up to a quarantine (measured: it did, in a live honest run). Repeating the SAME
            # request without approval is a loop; retrying after a decline is handled by the broker (hostile signal).
            key = f"{run_id}|{op.request_hash}"
            n = self._unapproved[key] = self._unapproved.get(key, 0) + 1
            q = f"the same change attempted {n} times without approval" if n >= self.max_unapproved else None
            if red.reason == "cancelled":
                q = "retried after the owner cancelled the approval"
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
                seq = self._log("forwarding", {"run": run_id, "op": op.name, "user": op.user, "steps": steps,
                                             "request_hash": op.request_hash, "receipt": red.receipt_id})
            except LedgerError as e:
                return Decision(False, "denied_ledger_down", f"receipt burned, nothing executed: {e}", op)
            return Decision(True, "allowed_composite", "", op,
                            {"composite": op.name, "user": op.user, "steps": steps, "receipt": red.receipt_id,
                             "snapshot": red.snapshot},
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
            seq = self._log("forwarding", {"run": run_id, "method": method, "path": op.path, "op": op.name,
                                         "user": op.user, "request_hash": op.request_hash, "receipt": red.receipt_id,
                                         "secret_out_of_band": secret is not None})
        except LedgerError as e:
            return Decision(False, "denied_ledger_down", f"receipt burned, nothing forwarded: {e}", op)
        headers = {"Accept": "application/json"}
        if fwd_body:
            headers["Content-Type"] = "application/json"
        fwd = {"method": method, "path": op.path, "query": list(op.query), "body": fwd_body, "headers": headers,
               "receipt": red.receipt_id}
        return Decision(True, "allowed_write", "", op, fwd, oob_secret=secret, ledger_seq=seq)
