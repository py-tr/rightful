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
