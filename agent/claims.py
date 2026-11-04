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


HELD_MESSAGE = ("I'm sorry, I have not been able to make that change to your account yet. "
                "Nothing has been changed. A colleague will follow up.")
