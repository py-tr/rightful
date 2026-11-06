"""The owner's device, simulated for the demo: Keycloak's CIBA HTTP authentication channel posts here, and the
owner's phone page approves (with number matching) or denies. Out-of-band secrets land in the phone inbox.

Runs on the control plane. The sandbox has no route to it (it reaches only the per-task edge proxy -> broker).
"""
from __future__ import annotations

import secrets
import threading
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def create_push_app(keycloak_base_url: str, realm: str, http: httpx.Client | None = None, clock=time.time) -> FastAPI:
    app = FastAPI(title="Owner device (demo)", docs_url=None, redoc_url=None, openapi_url=None)
    http = http or httpx.Client(base_url=keycloak_base_url, timeout=10.0)
    lock = threading.Lock()
    pending: dict[str, dict] = {}       # pid -> request
    inbox: dict[str, list[dict]] = {}   # username -> delivered secrets

    @app.post("/ciba/notify")
    async def notify(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return JSONResponse({"error": "missing bearer"}, status_code=401)
        data = await request.json()
        pid = "push_" + secrets.token_urlsafe(8)
        msg = data.get("binding_message", "")
        # <number>-<label>-<username>.<id prefix>-<hash8>: the number is first, the label second (pack labels have
        # no hyphen), the hash last; the target is everything between, so a hyphenated username stays whole.
        parts = msg.split("-")
        label = parts[1] if len(parts) > 2 else ""
        target = "-".join(parts[2:-1]) if len(parts) > 3 else ""
        approver = data.get("login_hint")
        instruction = None
        if label in ("mfarecov", "emailchg") or (target and approver and not target.startswith(f"{approver}.")):
            # Someone else's account: the approver must not take the caller's word for it.
            instruction = (f"You are approving a change on {target}'s account, not your own. Before approving, confirm "
                           "with them through a channel you already trust (in person, or a number you already know).")
        with lock:
            pending[pid] = {"id": pid, "username": approver, "binding": msg, "label": label, "target": target,
                            "instruction": instruction, "number": parts[0] if msg else "",
                            "callback_token": auth.split(" ", 1)[1], "at": clock(), "state": "pending"}
        return JSONResponse({}, status_code=201)

    def _answer(pid: str, status: str) -> int:
        p = pending[pid]
        r = http.post(f"/realms/{realm}/protocol/openid-connect/ext/ciba/auth/callback",
                      headers={"Authorization": f"Bearer {p['callback_token']}"}, json={"status": status})
        p["state"] = "approved" if status == "SUCCEED" else "denied"
        return r.status_code

    @app.get("/phone/{username}")
    def phone(username: str):
        """What the owner's phone shows: the action, the user and the hash prefix from the binding message. Never the
        callback token."""
        with lock:
            items = [{k: v for k, v in p.items() if k != "callback_token"} for p in pending.values()
                     if p["username"] == username and p["state"] == "pending"]
        return {"pending": items, "inbox": inbox.get(username, [])}

    @app.post("/phone/{username}/{pid}/approve")
    async def approve(username: str, pid: str, request: Request):
        number = (await request.json()).get("number", "")
        with lock:
            p = pending.get(pid)
            if not p or p["username"] != username or p["state"] != "pending":
                return JSONResponse({"error": "no such pending request"}, status_code=404)
            match = secrets.compare_digest(str(number), p["number"])
        if not match:                                   # a wrong number declines the request: otherwise a tired owner
            _answer(pid, "CANCELLED")                   # could tap every option until one approves (11-06)
            return JSONResponse({"error": "number does not match; the request was declined"}, status_code=409)
        return {"callback": _answer(pid, "SUCCEED")}

    @app.post("/phone/{username}/{pid}/deny")
    def deny(username: str, pid: str):
        with lock:
            p = pending.get(pid)
            if not p or p["username"] != username or p["state"] != "pending":
                return JSONResponse({"error": "no such pending request"}, status_code=404)
        return {"callback": _answer(pid, "CANCELLED")}

    def deliver(username: str, secret: str) -> None:
        with lock:
            inbox.setdefault(username, []).append({"kind": "temporary password", "value": secret, "at": clock()})

    def notify(username: str, text: str, cancel_id: str | None = None) -> None:
        """Account notices (NIST SP 800-63B-4 4.2.3: recovery SHALL notify the subscriber). They go to EVERY device on
        file, including one the caller said was lost, so a false "I lost my phone" reaches the real owner. In the demo
        they appear in the phone inbox; a cancel id makes a cancel button."""
        with lock:
            inbox.setdefault(username, []).append({"kind": "notice", "value": text, "cancel_id": cancel_id,
                                                   "at": clock()})

    @app.post("/phone/{username}/cancel/{cancel_id}")
    def cancel(username: str, cancel_id: str):
        with lock:
            mine = any(n.get("cancel_id") == cancel_id for n in inbox.get(username, []))
        if not mine or app.state.on_cancel is None:
            return JSONResponse({"error": "no such notice"}, status_code=404)
        return {"cancelled_receipts": app.state.on_cancel(cancel_id)}

    app.state.deliver = deliver
    app.state.notify = notify
    app.state.on_cancel = None          # wired to Challenges.cancel by whoever assembles the services
    app.state.pending = pending
    return app
