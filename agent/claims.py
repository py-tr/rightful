"""Claimed vs actual: before the agent's reply reaches the caller, any claim that an account change was made is
checked against the ledger for this run. A claim with no matching executed action is held (the caller is told the
change did not happen). The model can say anything; what the caller is told about their account comes from the log.
"""
from __future__ import annotations

import json
import re

CLAIM = re.compile(
    r"\b(i(?:'ve| have)|we(?:'ve| have)|has been|have been|is now|was|were|successfully|all set|done)\b[^.!?\n]{0,60}?"
    r"\b(reset|re-?enrolled|removed|deleted|changed|updated|sent|unlocked|logged (?:you )?out|signed (?:you )?out|"
    r"cleared|revoked|completed)\b", re.IGNORECASE)
SUBJECT = re.compile(r"\b(password|mfa|authenticator|otp|credential|token|email|account|sessions?|link|recovery)\b",
                     re.IGNORECASE)


def claims_a_change(text: str) -> bool:
    return any(SUBJECT.search(text[max(0, m.start() - 80): m.end() + 80]) for m in CLAIM.finditer(text or ""))


def executed_in_run(ledger_path: str, run_id: str) -> list[dict]:
    import os
    out = []
    if not os.path.exists(ledger_path):        # nothing was ever decided, so nothing was executed
        return out
    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e["kind"] == "executed" and e["data"].get("run") == run_id:
                out.append(e["data"])
    return out


def check(text: str, ledger_path: str, run_id: str) -> tuple[str, str]:
    """('ok' | 'held', reason)."""
    if not claims_a_change(text):
        return "ok", "no change claimed"
    done = executed_in_run(ledger_path, run_id)
    if not done:
        return "held", "the reply claims an account change, but the ledger shows none in this run"
    return "ok", f"{len(done)} executed action(s) in this run"


LABELS = {"reset_password": "temporary password set (sent to your registered phone)",
          "send_actions_email": "account-action email sent to the address on file",
          "remove_credential": "a sign-in credential removed", "logout_sessions": "all sessions signed out",
          "change_email": "email address changed",
          "mfa_recovery_lost_device": "authenticator removed; re-enrolment link sent to the address on file",
          "compromise_response": "password reset, sessions signed out, re-enrolment link sent"}


def changes_line(ledger_path: str, run_id: str) -> str:
    """Written from the ledger, never by the model: what actually changed on the account in this session."""
    done = executed_in_run(ledger_path, run_id)
    items = [LABELS.get(d.get("op"), d.get("op", "change")) for d in done]
    return ("Changes to your account in this session (from the system log): "
            + ("none." if not items else "; ".join(items) + "."))


HELD_MESSAGE = ("I'm sorry, I have not been able to make that change to your account yet. "
                "Nothing has been changed. A colleague will follow up.")
