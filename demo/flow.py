"""The flow page's data: one conversation's steps, read from the gate's hash-chained ledger and checked against the
ledger head inside the signed share record.

What is shown: each gate decision (operation, outcome, the rule's reason, the request hash), each push (who approves,
the answer), each receipt burned and request forwarded, the identity server's answer, plus the chain itself (every
entry's hash and the one before it). What is masked or left out: receipt, challenge and cancel ids (shortened; they
are single-use and already spent), run ids (only a hash is used), user ids (shortened). The ledger never holds a
password (temporary passwords go to the owner's device and are recorded only as "sent out of band").
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from gate.ledger import GENESIS, _entry_hash

SAFE_FILE = re.compile(r"[A-Za-z0-9_-]{1,64}\.ledger\.jsonl")
KEEP = {"op", "outcome", "reason", "method", "status", "approver", "mode", "why", "how", "steps", "step", "removed",
        "secret_out_of_band", "quarantine"}
SHORT = {"request_hash": 12, "receipt": 6, "challenge": 8, "cancel_hash": 6, "user": 8}

TITLES = {
    "run_opened": "Conversation opened", "decision": "The gate decided on a request",
    "challenge": "Approval request", "push_sent": "Push sent to the approver's own device",
    "forwarding": "Receipt burned; the exact request forwarded once", "executed": "The identity server applied it",
    "upstream_failed": "The identity server returned an error; nothing changed", "composite_step": "Step of an approved action",
    "agent_claimed_verification": "The agent claimed it verified the caller (authorizes nothing)",
    "escalation": "Handed to a human", "quarantine": "Run quarantined", "cancel_offered": "The owner can cancel",
    "run_closed": "Conversation closed",
    "tripwire": "One decline froze agent-driven changes to this account for 24 hours",
    "contrast_mode": "The unprotected column: the agent decides, nothing asks the owner",
}

# The unprotected column ("agent decides", the status quo shown for contrast): no owner approval, the temporary
# password goes to the agent, and the agent's own "I verified the caller" is what lets the change through.
CONTRAST_TITLES = {
    "forwarding": "Forwarded on the agent's say-so: nobody asked the owner",
    "agent_claimed_verification": "The agent claimed it verified the caller: in this column, that is all it takes",
}


def _clean(data: dict) -> dict:
    out = {}
    for k, v in (data or {}).items():
        if k in KEEP:
            out[k] = v if not isinstance(v, str) else v[:300]
        elif k in SHORT and isinstance(v, str):
            out[k] = v[:SHORT[k]] + ("…" if len(v) > SHORT[k] else "")
        elif k in ("path", "target") and isinstance(v, str):
            out[k] = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", lambda m: m.group(0)[:8] + "…", v)
    return out


def build(rec: dict, ledger_dir: str) -> dict:
    """Return {ok, problem, chain: {...}, steps: [...]} for one signed share record; never raises."""
    name, head, run_ref = rec.get("ledger_file"), rec.get("ledger_head") or {}, rec.get("run_ref")
    if not name or not SAFE_FILE.fullmatch(name) or not head:
        return {"ok": False, "problem": "this record has no ledger reference (recorded before the flow page existed)"}
    path = os.path.join(ledger_dir, name)
    if not os.path.exists(path):
        return {"ok": False, "problem": "the ledger for this conversation is no longer on the server"}
    contrast = rec.get("mode") == "agent_decides"
    titles = {**TITLES, **CONTRAST_TITLES} if contrast else TITLES
    prev, seq, steps, problem = GENESIS, 0, [], ""
    want = int(head.get("seq", 0))
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if seq >= want:
                    break                          # the record signed the chain up to here; later entries are not its
                e = json.loads(line)
                if e["seq"] != seq + 1 or e["prev"] != prev or \
                        _entry_hash(prev, e["seq"], e["ts"], e["kind"], e["data"]) != e["hash"]:
                    problem = f"the chain breaks at entry {e.get('seq')}"
                    break
                prev, seq = e["hash"], e["seq"]
                run = (e.get("data") or {}).get("run")
                mine = run_ref is None or run is None or hashlib.sha256(str(run).encode()).hexdigest()[:16] == run_ref
                if mine:
                    data = _clean(e.get("data") or {})
                    if contrast:                   # older ledgers marked the agent-bound secret as out of band
                        data.pop("secret_out_of_band", None)
                    steps.append({"seq": e["seq"], "ts": e["ts"], "kind": e["kind"],
                                  "title": titles.get(e["kind"], e["kind"].replace("_", " ")),
                                  "data": data, "hash": e["hash"][:16], "prev": e["prev"][:16]})
    except (OSError, ValueError, KeyError) as ex:
        problem = f"unreadable ledger ({type(ex).__name__})"
    head_ok = not problem and seq == want and prev == head.get("hash")
    if not problem and not head_ok:
        problem = "the ledger does not reach the head this record signed"
    return {"ok": head_ok, "problem": problem,
            "chain": {"entries_checked": seq, "head_seq": want, "head_hash": str(head.get("hash", ""))[:16],
                      "matches_signed_head": head_ok},
            "steps": steps}
