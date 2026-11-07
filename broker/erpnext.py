"""The accounts-payable pack's upstream: ERPNext, reached ONLY by the broker, with a gate API user who may read suppliers
and EDIT supplier bank accounts and nothing else (proved by devenv/erp_witness_check.py: no create, no delete, no
supplier, invoice or payment edits, no switching off the Version log).

The sandbox never speaks ERPNext's API. It sees the broker's small AP API, where suppliers and bank accounts are named
by opaque UUID-shaped references (an HMAC of the ERPNext name), never by ERPNext's free-text names ("Acme Supplies -
Deutsche Bank": spaces and hyphens in a path are the bug class closed twice before; mentor, 11-06). Account numbers and
IBANs are shown masked to their last four.

  GET /ap/v1/suppliers                               -> [{supplier, name}]
  GET /ap/v1/suppliers/{supplier}/bank-accounts      -> [{account, bank, number_last4, iban_last4, is_default}]
  GET /ap/v1/payment-check/{supplier}                -> does the current default account match the last approval?
  PUT /ap/v1/bank-accounts/{account}/details         -> {bank?, bank_account_no?, iban?}   (gated)
  PUT /ap/v1/bank-accounts/{account}/default         -> no body                           (gated)

This class answers the few calls the broker's proxy makes of an upstream (forward, username, user_snapshot,
service_token_if_cached), so the gate and the proxy are unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
import uuid
from urllib.parse import quote

import httpx

REF_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FIELDS = ["name", "party_type", "party", "bank", "bank_account_no", "iban", "is_default", "disabled",
          "is_company_account"]


def last4(v: str | None) -> str | None:
    v = (v or "").replace(" ", "")
    return v[-4:] if v else None


class ERPNext:
    def __init__(self, base: str, token_header: str, ref_key: bytes, approved_path: str, host: str = "frontend",
                 http: httpx.Client | None = None, witness_header: str | None = None):
        self.http = http or httpx.Client(base_url=base, timeout=15, headers={"Host": host})
        self.auth = {"Authorization": token_header}
        self.witness = {"Authorization": witness_header} if witness_header else None
        self.key, self.approved_path = ref_key, approved_path
        self._names: dict[str, tuple[str, str]] = {}          # ref -> (doctype, ERPNext name)
        self._lock = threading.Lock()

    # --- opaque references ----------------------------------------------------------------------------------------
    KIND = {"Supplier": "5", "Bank Account": "a"}         # the 13th hex digit tells the two kinds apart (pilot, 11-06:
                                                           # agents passed a supplier id where an account id belonged)

    def ref(self, doctype: str, name: str) -> str:
        h = hmac.new(self.key, f"{doctype}\0{name}".encode(), hashlib.sha256).hexdigest()[:32]
        h = h[:12] + self.KIND[doctype] + h[13:]
        r = str(uuid.UUID(h))
        with self._lock:
            self._names[r] = (doctype, name)
        return r

    def _name(self, ref: str, doctype: str) -> str | None:
        if not REF_RE.match(ref or ""):
            return None
        hit = self._names.get(ref)
        if hit is None:                                        # not seen yet: refresh from ERPNext once
            self._index()
            hit = self._names.get(ref)
        return hit[1] if hit and hit[0] == doctype else None

    def _index(self) -> None:
        for s in self._get("Supplier", fields=["name"]):
            self.ref("Supplier", s["name"])
        for a in self._get("Bank Account", fields=["name"]):
            self.ref("Bank Account", a["name"])

    # --- ERPNext calls (gate user) --------------------------------------------------------------------------------
    def _get(self, doctype: str, fields: list[str], filters: list | None = None) -> list[dict]:
        params = {"fields": json.dumps(fields), "limit_page_length": 500}
        if filters:
            params["filters"] = json.dumps(filters)
        r = self.http.get(f"/api/resource/{doctype}", params=params, headers=self.auth)
        r.raise_for_status()
        return r.json().get("data", [])

    def account(self, ref: str) -> dict | None:
        name = self._name(ref, "Bank Account")
        if name is None:
            return None
        r = self.http.get(f"/api/resource/Bank Account/{quote(name, safe='')}",
                          headers=self.auth)
        return r.json().get("data") if r.status_code == 200 else None

    def supplier_of(self, ref: str) -> str | None:
        """The supplier a bank account belongs to, read from the record itself at challenge time (mentor: the approver
        comes from the account, not from anything in the request). Company accounts and anything else: None. A supplier
        id names the supplier directly (the call-back: "confirm with this supplier")."""
        sup = self._name(ref, "Supplier") if REF_RE.match(ref or "") and ref[14] == self.KIND["Supplier"] else None
        if sup is not None:
            return sup
        a = self.account(ref)
        if not a or a.get("is_company_account") or a.get("party_type") != "Supplier" or a.get("disabled"):
            return None
        return a.get("party")

    def snapshot(self, ref: str) -> dict:
        """What an approval is about; stored in the receipt and re-checked before the write."""
        a = self.account(ref) or {}
        return {"supplier": a.get("party"), "party_type": a.get("party_type"), "bank": a.get("bank"),
                "account_no": a.get("bank_account_no"), "iban": a.get("iban"), "is_default": a.get("is_default")}

    # --- the approved register (for the payment check) ------------------------------------------------------------
    def _approved(self) -> dict:
        try:
            return json.load(open(self.approved_path, encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _remember(self, supplier: str, account_name: str, receipt: str | None) -> None:
        a = self.http.get(f"/api/resource/Bank Account/{quote(account_name, safe='')}",
                          headers=self.auth).json().get("data", {})
        reg = self._approved()
        reg[supplier] = {"account": account_name, "account_no": a.get("bank_account_no"), "iban": a.get("iban"),
                         "bank": a.get("bank"), "receipt": receipt, "at": time.strftime("%Y-%m-%d %H:%M UTC",
                                                                                          time.gmtime())}
        tmp = self.approved_path + ".tmp"
        json.dump(reg, open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, self.approved_path)

    def seed_approved(self, supplier: str, account_name: str, how: str = "supplier onboarding") -> None:
        """The bank details verified when the supplier was onboarded (outside this agent): the payment check's baseline."""
        self._remember(supplier, account_name, how)

    def payment_check(self, supplier: str) -> dict:
        """A check a payment run calls (NOT enforcement): compares the supplier's CURRENT default account with the last
        one approved through a receipt. It compares state, not only the log, because a newly created default account
        leaves no Version entry (found 11-06)."""
        cur = [a for a in self._get("Bank Account", FIELDS, [["party_type", "=", "Supplier"], ["party", "=", supplier]])
               if a.get("is_default") and not a.get("disabled")]
        reg = self._approved().get(supplier)
        if not cur:
            return {"verdict": "hold", "why": "no default bank account for this supplier"}
        c = cur[0]
        if reg is None:
            return {"verdict": "hold", "why": "no approved bank details on record for this supplier",
                    "number_last4": last4(c.get("bank_account_no"))}
        same = (c["name"], c.get("bank_account_no"), c.get("iban")) == (reg["account"], reg["account_no"], reg["iban"])
        return {"verdict": "matches" if same else "hold",
                "why": (f"matches the approval of {reg['at']}" if same else
                        "changed outside the gate since the last approval: hold this payment"),
                "number_last4": last4(c.get("bank_account_no")), "approved_last4": last4(reg["account_no"])}

    # --- the proxy's upstream interface ---------------------------------------------------------------------------
    def username(self, ref: str) -> str:
        return self.supplier_of(ref) or "unknown supplier"

    def user_snapshot(self, ref: str) -> dict:
        return self.snapshot(ref)

    def service_token_if_cached(self) -> str | None:
        return self.auth["Authorization"].split(":", 1)[-1]   # the secret half: a leak check, never sent out

    def forward(self, fwd: dict, with_token: bool = True) -> httpx.Response:
        m, p = fwd["method"], fwd["path"]
        parts = p.strip("/").split("/")                         # the grammar already parsed this exact shape
        try:
            if m == "GET" and parts == ["ap", "v1", "suppliers"]:
                self._index()
                return self._json([{"supplier": self.ref("Supplier", s["name"]), "name": s["name"]}
                                   for s in self._get("Supplier", ["name"])])
            if m == "GET" and parts[:3] == ["ap", "v1", "suppliers"] and parts[4:] == ["bank-accounts"]:
                sup = self._name(parts[3], "Supplier")
                if sup is None:
                    return self._json({"error": "unknown supplier"}, 404)
                rows = self._get("Bank Account", FIELDS, [["party_type", "=", "Supplier"], ["party", "=", sup]])
                return self._json([{"account": self.ref("Bank Account", a["name"]), "bank": a.get("bank"),
                                    "number_last4": last4(a.get("bank_account_no")),
                                    "iban_last4": last4(a.get("iban")), "is_default": bool(a.get("is_default"))}
                                   for a in rows if not a.get("disabled")])
            if m == "GET" and parts[:3] == ["ap", "v1", "payment-check"]:
                sup = self._name(parts[3], "Supplier")
                return self._json(self.payment_check(sup) if sup else {"error": "unknown supplier"}, 200 if sup else 404)
            if m == "PUT" and parts[:3] == ["ap", "v1", "bank-accounts"]:
                return self._write(parts[3], parts[4], fwd)
        except httpx.HTTPError as e:
            return self._json({"error": f"ERPNext unavailable: {type(e).__name__}"}, 502)
        return self._json({"error": "not an AP operation"}, 404)

    def _write(self, ref: str, what: str, fwd: dict) -> httpx.Response:
        name = self._name(ref, "Bank Account")
        sup = self.supplier_of(ref)
        if name is None or sup is None:
            return self._json({"error": "not a supplier's bank account"}, 403)
        snap = fwd.get("snapshot")
        if snap not in (None, "skip") and self.snapshot(ref) != snap:
            # the account's supplier, number, IBAN or default changed after approval: the approval no longer
            # describes this change (mentor, 11-06)
            return self._json({"error": "the bank account changed after approval; nothing was written",
                               "outcome": "aborted_changed_since_approval"}, 409)
        body = json.loads(fwd["body"] or b"{}") if what == "details" else {"is_default": 1}
        payload = {k: v for k, v in {"bank": body.get("bank"), "bank_account_no": body.get("bank_account_no"),
                                     "iban": body.get("iban"), "is_default": body.get("is_default")}.items()
                   if v is not None}
        r = self.http.put(f"/api/resource/Bank Account/{quote(name, safe='')}",
                          json=payload, headers=self.auth)
        if 200 <= r.status_code < 300:
            if fwd.get("receipt"):          # only a change approved through a receipt becomes the approved state; a
                self._remember(sup, name, fwd["receipt"])   # change on someone's word alone is what the check flags
            return self._json({"ok": True, "supplier": sup, "number_last4": last4(r.json()["data"].get("bank_account_no"))})
        return self._json({"error": "ERPNext refused the change", "status": r.status_code}, 502)

    @staticmethod
    def _json(obj, status: int = 200) -> httpx.Response:
        return httpx.Response(status, json=obj, headers={"Content-Type": "application/json"})
