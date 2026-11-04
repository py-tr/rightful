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
        with lock:
            pending[pid] = {"id": pid, "username": data.get("login_hint"), "binding": msg,
                            "number": msg.split("-", 1)[0] if msg else "", "callback_token": auth.split(" ", 1)[1],
                            "at": clock(), "state": "pending"}
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
            if not secrets.compare_digest(str(number), p["number"]):
                return JSONResponse({"error": "number does not match"}, status_code=409)
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

    def notify(username: str, text: str) -> None:
        """Account notices (NIST SP 800-63B-4 4.2.3: recovery SHALL notify the subscriber). The demo shows them in the
        phone inbox; in production they also go to every address on file."""
        with lock:
            inbox.setdefault(username, []).append({"kind": "notice", "value": text, "at": clock()})

    app.state.deliver = deliver
    app.state.notify = notify
    app.state.pending = pending
    return app
