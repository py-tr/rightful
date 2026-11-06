"""Who approves a change: resolved by policy, never by the agent.

The help-desk pack's targets are identity-server users, so its approvers come from the identity server: the account
owner, or the owner's manager for a lost device or a contact change. That is IdentityServerResolver, and it is the
default: it is today's behaviour moved here unchanged (the help-desk results in eval/RESULTS-gateon.md were measured on
it before the move; tests pin the equivalence).

A pack whose targets are NOT identity-server users (an accounts-payable pack: suppliers in an ERP) names its own
approvers through a resolver of its own; the push still goes to an identity-server user's registered device through
the same CIBA flow, so nothing about the approval channel changes, only whose device it is.
"""
from __future__ import annotations


class IdentityServerResolver:
    """Today's lookups, verbatim (moved from broker/challenges.py)."""

    def __init__(self, kc, pack: dict | None = None):
        self.kc, self.pack = kc, pack or {}

    def subject_name(self, user_id: str) -> str:
        """The name shown on the push and notified about the change (the account owner)."""
        return self.kc.username(user_id)

    def approver_for(self, user_id: str, kind: str, subject: str) -> tuple[str, bool, str]:
        """(approver username, human_only, why)."""
        approver, human_only, why = subject, False, ""
        if kind in ("manager", "contact"):
            mgr = self.kc.manager_of(user_id)
            approver = mgr or ""
            if not mgr or mgr == subject:
                human_only, why = True, "no independent manager on record"
        return approver, human_only, why

    def privileged(self, user_id: str) -> bool:
        attr = self.pack.get("privileged_attribute", "privileged")
        return self.kc.attribute(user_id, attr) in ("true", "yes", "1")

    def snapshot(self, user_id: str) -> dict:
        """What the approver approved against, re-checked at execution (email and manager for the help desk)."""
        return self.kc.user_snapshot(user_id)


class SupplierContactResolver:
    """Accounts payable: the subject is a supplier's bank account (an opaque reference), and the approver is the contact
    registered for that supplier at onboarding, BEFORE any request, in a directory outside both packs' reach (mentor,
    11-06): never an address, number or name taken from the request, the ticket or the letter.

    The supplier is read from the bank-account record itself at challenge time (an account that is not a supplier's,
    e.g. the company's own receiving account, gets no approver at all). The push names the supplier and the old and new
    last four digits; the decline tripwire is keyed per supplier."""

    def __init__(self, erp, directory: dict[str, str]):
        self.erp, self.directory = erp, directory          # supplier name -> approver's identity-server username

    def subject_name(self, ref: str) -> str:
        return self.erp.supplier_of(ref) or "unknown"

    def approver_for(self, ref: str, kind: str, subject: str) -> tuple[str, bool, str]:
        supplier = self.erp.supplier_of(ref)
        if supplier is None:
            return "", True, "not a supplier's bank account (company and unknown accounts are refused)"
        contact = self.directory.get(supplier)
        if not contact:
            return "", True, "no contact registered for this supplier at onboarding"
        return contact, False, ""

    def privileged(self, ref: str) -> bool:
        return False

    def snapshot(self, ref: str) -> dict:
        return self.erp.snapshot(ref)

    def label(self, challenge: dict) -> str:
        from broker.erpnext import last4
        snap = self.erp.snapshot(challenge["user"])
        body = challenge.get("body") or {}
        new = body.get("iban") or body.get("bank_account_no")
        old = snap.get("iban") if body.get("iban") else snap.get("account_no")
        if challenge.get("operation") == "set_default_bank_account":
            return f"default{last4(snap.get('account_no')) or ''}"
        return f"bank{last4(old) or 'none'}to{last4(new) or 'same'}"

    def tripwire_key(self, ref: str) -> str:
        return "supplier:" + (self.erp.supplier_of(ref) or ref)
