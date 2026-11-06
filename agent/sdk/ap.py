"""The accounts-payable library the agent's scripts import inside the sandbox. It holds NO credential and never sees
ERPNext: every call goes to the broker's small AP API through the per-task edge. Suppliers and bank accounts are opaque
ids; account numbers and IBANs come back as their last four digits only.

A change to a supplier's bank details needs the approval of the contact registered for that supplier at onboarding, on
their own device. When the broker refuses a change it returns the challenge: send it, tell the person the number to
choose, wait, then call the SAME function again.
"""
from __future__ import annotations

from helpdesk import (_c, _result, challenge_status, escalate, get_ticket, record_verification,  # noqa: F401
                      send_challenge, verify_caller, wait_for_approval)


# --- reads ------------------------------------------------------------------------------------------------------
def find_supplier(query: str) -> list[dict]:
    """Suppliers whose name contains `query` (case-insensitive): [{supplier, name}]."""
    r = _c().get("/ap/v1/suppliers")
    r.raise_for_status()
    q = query.lower()
    return [s for s in r.json() if q in s["name"].lower()]


def bank_accounts(supplier: str) -> list[dict]:
    """The supplier's bank accounts: [{account, bank, number_last4, iban_last4, is_default}]."""
    r = _c().get(f"/ap/v1/suppliers/{supplier}/bank-accounts")
    r.raise_for_status()
    return r.json()


def payment_check(supplier: str) -> dict:
    """Before paying: does the supplier's current default account match the last approved bank details?
    -> {verdict: 'matches' | 'hold', why, number_last4, ...}"""
    r = _c().get(f"/ap/v1/payment-check/{supplier}")
    return _result(r)


def _is_supplier(i: str) -> bool:
    return isinstance(i, str) and len(i) == 36 and i[14] == "5"


def _wrong_id(i: str) -> dict | None:
    if _is_supplier(i):
        return {"ok": False, "reason": "that is a supplier id; pass an account id from bank_accounts(supplier)"}
    return None


# --- changes (each needs the supplier contact's approval) -------------------------------------------------------
def change_bank_details(account: str, bank: str | None = None, bank_account_no: str | None = None,
                        iban: str | None = None) -> dict:
    """Change the bank name, account number and/or IBAN of an existing supplier bank account."""
    if (w := _wrong_id(account)):
        return w
    body = {k: v for k, v in {"bank": bank, "bank_account_no": bank_account_no, "iban": iban}.items() if v is not None}
    return _result(_c().put(f"/ap/v1/bank-accounts/{account}/details", json=body))


def set_default(account: str) -> dict:
    """Make this existing supplier bank account the one payments go to."""
    if (w := _wrong_id(account)):
        return w
    return _result(_c().put(f"/ap/v1/bank-accounts/{account}/default"))


def confirm_with_supplier(account: str) -> dict:
    """Call-back: sends a confirmation push to the contact registered for this supplier (pass the supplier id or one of
    its account ids) at onboarding.
    Returns {'challenge', 'number'}: then send_challenge(challenge) and wait_for_approval(challenge)."""
    return verify_caller(account)
