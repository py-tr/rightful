"""Claimed vs actual: before the agent's reply reaches the caller, any claim that an account change was made is
checked against the ledger for this run. A claim with no matching executed action is held (the caller is told the
change did not happen). The model can say anything; what the caller is told about their account comes from the log.
"""
from __future__ import annotations

import json
import re

VERB = re.compile(r"\b(reset|re-?enrolled|removed|deleted|changed|updated|sent|unlocked|logged (?:you )?out|"
                  r"signed (?:you )?out|cleared|revoked|completed|triggered|issued|initiated)\b", re.IGNORECASE)
MARK = re.compile(r"\b(i(?:'ve| have)?|we(?:'ve| have)?|has been|have been|had been|is now|was|were|successfully|"
                  r"all set|done)\b|[✅✔]", re.IGNORECASE)   # bare "I"/"we": the simple past; a checkmark: done
STATE = re.compile(r"\b(password|e-?mail)\b[^.!?\n,;]{0,40}\bis now\b", re.IGNORECASE)   # "your email is now x@y"
SUBJECT = re.compile(r"\b(password|mfa|authenticator|otp|credential|token|e-?mail|account|sessions?|link|recovery)\b",
                     re.IGNORECASE)
# A negation or a condition BEFORE the verb, in the same clause, means it is not a claim ("Nothing has been changed",
# "I have not reset", "once approved, it will be reset"). After the verb it does not ("reset, no action needed").
NEGATION = re.compile(r"\b(not|no|nothing|never|neither|nor|cannot|unable|until|once|if|when|after|before|without|"
                      r"will|would|can|could|should|shall|may|might|must|need|needs|want|wants|let me|please|"
                      r"able to|going to|about to|try|trying|whether|rather|the moment|the instant|as soon as|"
                      r"on approval)\b|n't\b|'ll\b|'d\b|→|->", re.IGNORECASE)
# ("approved" is deliberately NOT a condition word: "your push was approved and I've reset it" is the classic lie.)
SENTENCE = re.compile(r"[^.!?;\n]+[.!?]?")
CLAUSE_BREAK = re.compile(r"[,:()–—]|\s-\s")


# Things an agent legitimately sends or updates that are not account changes ("I've re-sent the push").
NOT_ACCOUNT_OBJECT = re.compile(r"^\W*(?:the |a |an |another |your |my |it |them |this |that |\w+ ){0,3}"
                                r"(push|challenge|verification|escalation|ticket|request|note|notification|inc-?\d+|"
                                r"approval|prompt|message|lead|team)\b", re.IGNORECASE)
NOTHING_AFTER = re.compile(r"^\s*(nothing|no\b|none\b)", re.IGNORECASE)
INFINITIVE = re.compile(r"\bto\s+(?!the\b|your\b|a\b|an\b|my\b|our\b|their\b|his\b|her\b|its\b)[\w-]+"
                        r"(?:\s+[\w-]+){0,3}\s*$|\bto\s*$", re.IGNORECASE)


def claims_a_change(text: str) -> bool:
    """Does the reply say an account change HAPPENED? Judged per sentence (mentor's review: the first version held
    honest refusals such as "Nothing has been changed on your account"; measured on 12,657 stored model replies).
    A claim needs: an account subject in the sentence, a completed-change marker in the verb's own clause, no negation
    or condition anywhere earlier in the sentence, and an object that is the account (not the push or the ticket)."""
    for s in SENTENCE.finditer(text or ""):
        sent = s.group(0)
        if not SUBJECT.search(sent) or sent.rstrip().endswith("?"):      # a question is not a claim
            continue
        for v in VERB.finditer(sent):
            starts = [m.end() for m in CLAUSE_BREAK.finditer(sent, 0, v.start())]
            clause = sent[(starts[-1] if starts else 0): v.start()]
            after = sent[v.end():]
            if not (MARK.search(clause) or MARK.search(sent[: v.start()])) or NEGATION.search(sent[: v.start()]):
                continue
            if INFINITIVE.search(sent[: v.start()]):        # "a note to re-verify and then reset" (an intention)
                continue
            if NOT_ACCOUNT_OBJECT.match(after) or NOTHING_AFTER.match(after):
                continue
            return True
        for st in STATE.finditer(sent):
            if not NEGATION.search(sent[: st.end()]):
                return True
    return False


def executed_in_run(ledger_path: str, run_id: str) -> list[dict]:
    import os
    out = []
    if not os.path.exists(ledger_path):        # nothing was ever decided, so nothing was executed
        return out
    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            # Only what the broker recorded AFTER Keycloak accepted it. "forwarding" (written at receipt burn) and
            # "upstream_failed" never count: a change that was refused did not happen.
            if e["kind"] in ("executed", "partially_executed") and e["data"].get("run") == run_id:
                out.append({**e["data"], "partial": e["kind"] == "partially_executed"})
    return out


def check(text: str, ledger_path: str, run_id: str) -> tuple[str, str]:
    """('ok' | 'held', reason)."""
    if not claims_a_change(text):
        return "ok", "no change claimed"
    done = executed_in_run(ledger_path, run_id)
    if not done:
        return "held", "the reply claims an account change, but the ledger shows none in this run"
    return "ok", f"{len(done)} executed action(s) in this run"


CORRECTION = "[Correction from the system log: no change was made to your account in this session.]"
BANNER = ("[System log: no change was made to your account in this session. Anything below that says otherwise "
          "is not correct.]")


def annotate(text: str, ledger_path: str, run_id: str) -> tuple[str, str, str]:
    """The detector is an ANNOTATOR, not a gate (mentor's review): the model's reply is kept, and only a sentence that
    claims a change the ledger does not show is replaced with a visible correction, so a caller never reads a
    confident lie a few lines above a footer that contradicts it. A false hold now costs a redundant note.
    Returns (verdict 'ok' | 'corrected', delivered text, reason)."""
    if not claims_a_change(text):
        return "ok", text, "no change claimed"
    done = executed_in_run(ledger_path, run_id)
    if done:
        return "ok", text, f"{len(done)} executed action(s) in this run"
    out, last, n, prev_end = [], 0, 0, None
    for s in SENTENCE.finditer(text):
        if not claims_a_change(s.group(0)):
            continue
        gap = text[last:s.start()]
        lead = s.group(0)[: len(s.group(0)) - len(s.group(0).lstrip())]     # keep a leading space or bullet indent
        if prev_end == last and not gap.strip():
            out.append(gap)                                  # adjacent claims share one correction
        else:
            out.append(gap + lead + CORRECTION)
        last = prev_end = s.end()
        n += 1
    out.append(text[last:])
    # A reply caught claiming a change is suspect as a whole (a recap list can repeat the claim in forms the detector
    # misses), so the caller is warned before reading it, not only in place.
    return "corrected", BANNER + "\n\n" + "".join(out), f"{n} sentence(s) claimed a change the ledger does not show"


LABELS = {"reset_password": "temporary password set (sent to your registered phone)",
          "send_actions_email": "account-action email sent to the address on file",
          "remove_credential": "a sign-in credential removed", "logout_sessions": "all sessions signed out",
          "change_email": "email address changed",
          "mfa_recovery_lost_device": "authenticator removed; re-enrolment link sent to the address on file",
          "compromise_response": "password reset, sessions signed out, re-enrolment link sent"}


def changes_line(ledger_path: str, run_id: str) -> str:
    """Written from the ledger, never by the model: what actually changed on the account in this session."""
    done = executed_in_run(ledger_path, run_id)
    items = [(f"{d.get('op')} stopped part-way (done: {', '.join(d.get('steps_done', []))})" if d["partial"]
              else LABELS.get(d.get("op"), d.get("op", "change"))) for d in done]
    return ("Changes to your account in this session (from the system log): "
            + ("none." if not items else "; ".join(items) + "."))


HELD_MESSAGE = ("I'm sorry, I have not been able to make that change to your account yet. "
                "Nothing has been changed. A colleague will follow up.")
