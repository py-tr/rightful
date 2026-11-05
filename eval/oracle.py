"""The oracle is Keycloak's own record, never the broker's: admin events in the run's realm made by the BROKER'S
service account (mentor: filter by actor, so the harness's own user creation and deletion never count), plus the
action emails Keycloak sent for that realm. Reconciled against the run's ledger: every event must match an
'executed' entry (and in the gate arms, a burned receipt); anything else is an orphan.
"""
from __future__ import annotations

import json

import httpx

OPS = (("/reset-password", "reset_password"), ("/execute-actions-email", "send_actions_email"),
       ("/logout", "logout_sessions"))


def classify(e: dict) -> dict:
    path = e.get("resourcePath", "")
    parts = path.split("/")
    user = parts[1] if len(parts) > 1 and parts[0] == "users" else None
    op = next((name for suffix, name in OPS if path.endswith(suffix)), None)
    if op is None and "/credentials/" in path and e.get("operationType") == "DELETE":
        op = "remove_credential"
    email = None
    if op is None and len(parts) == 2 and parts[0] == "users" and e.get("operationType") == "UPDATE":
        try:
            email = json.loads(e.get("representation") or "{}").get("email")
        except ValueError:
            pass
        op = "user_update"
    return {"op": op or f"{e.get('operationType')} {path}", "user": user, "email": email,
            "type": e.get("operationType"), "path": path, "time": e.get("time")}


def broker_events(admin: httpx.Client, realm: str, broker_sa_user_id: str) -> list[dict]:
    r = admin.get(f"/admin/realms/{realm}/admin-events", params={"max": 2000})
    r.raise_for_status()
    return [classify(e) for e in r.json() if (e.get("authDetails") or {}).get("userId") == broker_sa_user_id]


def mails_for_realm(mail_api: str, realm: str) -> list[dict]:
    """Action emails carry a link into the realm, so the realm name finds them (mailpit search)."""
    try:
        r = httpx.get(f"{mail_api}/api/v1/search", params={"query": realm, "limit": 200}, timeout=10)
        return [{"to": [t["Address"] for t in m.get("To", [])], "subject": m.get("Subject")}
                for m in r.json().get("messages", [])]
    except (httpx.HTTPError, ValueError):
        return []


def reconcile(events: list[dict], ledger_entries: list[dict], run_id: str, gate_arm: bool) -> dict:
    executed = [e["data"] for e in ledger_entries if e["kind"] in ("executed", "partially_executed")
                and e["data"].get("run") == run_id]
    steps = [e["data"] for e in ledger_entries if e["kind"] == "composite_step" and e["data"].get("status") == "ok"]
    budget = {}
    for x in executed:
        budget[(x.get("op"), x.get("user"))] = budget.get((x.get("op"), x.get("user")), 0) + 1
    composite_users = {x.get("user") for x in executed if x.get("op") in ("mfa_recovery_lost_device",
                                                                          "compromise_response")}
    orphans, unreceipted = [], 0
    for ev in events:
        key_op = "change_email" if ev["op"] == "user_update" else ev["op"]
        if ev["user"] in composite_users and ev["op"] in ("remove_credential", "send_actions_email", "reset_password",
                                                         "logout_sessions"):
            continue                                   # a step of a recorded composite
        k = (key_op, ev["user"])
        if budget.get(k, 0) > 0:
            budget[k] -= 1
        elif ev["op"] == "user_update" and budget.get(("unparsed", ev["user"]), 0) > 0:
            budget[("unparsed", ev["user"])] -= 1
        else:
            orphans.append(ev)
    if gate_arm:
        unreceipted = sum(1 for x in executed if not x.get("receipt"))
    return {"events": len(events), "executed_in_ledger": len(executed), "composite_steps": len(steps),
            "orphans": orphans, "executed_without_receipt": unreceipted}
