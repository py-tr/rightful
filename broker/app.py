"""The broker's HTTP surface, as seen from the sandbox (through the trusted per-task edge proxy).

- Every request must carry X-Gate-Run, stamped by the edge proxy that the control plane creates per task. The edge
  strips any copy from the sandbox. Without it: 400, nothing forwarded.
- Admin-API requests go through the gate. Allowed ones are forwarded with the broker's own token; responses lose
  Set-Cookie and auth headers and are scanned for the broker's secrets before they reach the sandbox.
- A denied write returns a challenge (id, match number). The agent asks for the push, the owner approves on the
  registered device, and the agent sends the same request again.
- A quarantined run is blocked for the rest of its life, and the control plane is told to destroy its worker.
"""
from __future__ import annotations

import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from gate import Gate

DROP_RESPONSE_HEADERS = {"set-cookie", "authorization", "www-authenticate", "content-length", "content-encoding",
                         "transfer-encoding", "connection", "keep-alive"}


def create_app(gate: Gate, keycloak, challenges, deliver_secret=lambda username, secret: None,
               on_quarantine=lambda run_id, reason: None, console=None,
               notify=lambda username, text, cancel_id=None: None) -> FastAPI:
    from .composites import execute as run_composite
    app = FastAPI(title="Keyless broker", docs_url=None, redoc_url=None, openapi_url=None)
    quarantined: dict[str, str] = {}
    lock = threading.Lock()

    def run_of(request: Request) -> str | None:
        r = request.headers.get("x-gate-run", "")
        return r if r and len(r) <= 64 and r.replace("-", "").replace("_", "").isalnum() else None

    def quarantine(run_id: str, reason: str) -> None:
        with lock:
            if run_id in quarantined:
                return
            quarantined[run_id] = reason
        gate.ledger.append("quarantine", {"run": run_id, "reason": reason})
        on_quarantine(run_id, reason)

    def blocked(run_id: str) -> JSONResponse | None:
        if run_id in quarantined:
            return JSONResponse({"allowed": False, "outcome": "quarantined", "reason": quarantined[run_id],
                                 "quarantined": True}, status_code=403)
        return None

    @app.post("/gate/v1/challenges/{cid}/send")
    def send(cid: str, request: Request):
        run_id = run_of(request)
        if not run_id:
            return JSONResponse({"error": "missing run"}, status_code=400)
        if (b := blocked(run_id)):
            return b
        c = challenges.send(cid, run_id)
        if c is None:
            return JSONResponse({"error": "unknown challenge"}, status_code=404)
        gate.ledger.append("challenge", {"run": run_id, "challenge": c.id, "op": c.operation, "user": c.user_id,
                                         "status": c.status})
        return {"challenge": c.id, "status": c.status, "number": c.number,
                "tell_the_caller": f"A push was sent to the registered device. Approve it and choose {c.number}."
                if c.status == "sent" else None}

    @app.get("/gate/v1/challenges/{cid}")
    def poll(cid: str, request: Request):
        run_id = run_of(request)
        if not run_id:
            return JSONResponse({"error": "missing run"}, status_code=400)
        if (b := blocked(run_id)):
            return b
        c = challenges.poll(cid, run_id)
        if c is None:
            return JSONResponse({"error": "unknown challenge"}, status_code=404)
        if c.status in ("approved", "denied", "expired"):
            gate.ledger.append("challenge", {"run": run_id, "challenge": c.id, "status": c.status})
        return {"challenge": c.id, "status": c.status,
                "next": "send the same request again" if c.status == "approved" else None}

    @app.post("/gate/v1/escalations")
    async def escalation(request: Request):
        run_id = run_of(request)
        if not run_id:
            return JSONResponse({"error": "missing run"}, status_code=400)
        try:
            reason = str((await request.json()).get("reason", ""))[:500]
        except ValueError:
            reason = ""
        gate.ledger.append("escalation", {"run": run_id, "reason": reason})
        return {"escalated": True}

    @app.api_route("/{full:path}", methods=["GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy(full: str, request: Request):
        run_id = run_of(request)
        if not run_id:
            return JSONResponse({"error": "missing run"}, status_code=400)
        if (b := blocked(run_id)):
            return b
        raw = request.scope.get("raw_path", b"").decode("latin-1") or request.url.path
        target = raw + (("?" + request.scope["query_string"].decode("latin-1")) if request.scope.get("query_string") else "")
        body = await request.body()
        if console is not None and console.handles(raw) and not raw.startswith("/admin/realms/"):
            # The console's own UI and sign-in routes: kept alive by the broker's session, never the admin API.
            status, hdrs, data = console.handle(request.method, target, dict(request.headers), body)
            resp = Response(content=data, status_code=status)
            for k, v in hdrs:
                resp.headers.append(k, v)
            return resp
        d = gate.decide(request.method, target, body, run_id)
        if d.quarantine:
            quarantine(run_id, d.quarantine)
        if not d.allow:
            view = d.agent_view()
            if d.challenge:
                c = challenges.create(run_id, d.challenge)
                if c.status == "human_only":
                    view["challenge_required"].update({"challenge": c.id, "status": "human_only", "why": c.why,
                                                       "how": "This ticket cannot be closed by the agent. Escalate it to a human."})
                    gate.ledger.append("challenge", {"run": run_id, "challenge": c.id, "op": c.operation,
                                                     "user": c.user_id, "status": "human_only"})
                else:
                    view["challenge_required"].update({"challenge": c.id, "number": c.number,
                                                       "approver": c.receipt_kind,
                                                       "how": f"POST /gate/v1/challenges/{c.id}/send"})
            return JSONResponse(view, status_code=403)

        if d.op.kind == "composite":
            f = d.forward
            # Snapshot at approval, re-check at execution: if the email on file or the manager changed in between,
            # the approval no longer describes what would happen.
            ch = challenges.find(run_id, d.op.name, f["user"], d.op.request_hash)
            if ch is not None and ch.snapshot and keycloak.user_snapshot(f["user"]) != ch.snapshot:
                gate.ledger.append("composite_aborted", {"run": run_id, "op": d.op.name, "user": f["user"],
                                                         "reason": "email or manager changed after approval"})
                notify(ch.username, f"A recovery on your account was stopped: your account details changed after "
                                    f"it was approved. IT security has been alerted.")
                return JSONResponse({"allowed": False, "outcome": "aborted_changed_since_approval"}, status_code=409)
            result = run_composite(keycloak, gate.ledger, gate.pack["realm"], f["user"], f["steps"], f["receipt"],
                                   run_id, notify, deliver_secret,
                                   lifespan=int(gate.pack.get("action_link_lifespan_seconds", 600)))
            return JSONResponse({"allowed": True, "outcome": "allowed_composite", "action": d.op.name, **result},
                                status_code=200 if result["completed"] else 502)

        old_email = None
        if d.op.kind == "write" and d.op.name == "change_email":
            old_email = keycloak.user_snapshot(d.op.user).get("email")
        up = keycloak.forward(d.forward, with_token=d.op.kind != "static")
        if old_email is not None and 200 <= up.status_code < 300:
            # Recovery guidance: tell the PREVIOUS contact too, so a hijacked change is noticed where it matters.
            notify(keycloak.username(d.op.user), f"The email on your account was changed from {old_email}. If this "
                                                 f"was not you, contact IT security now.")
        content = up.content
        if d.op.kind != "static":
            leaks = [s for s in (keycloak.service_token_if_cached(), d.oob_secret) if s]
            if any(s.encode() in content for s in leaks):
                quarantine(run_id, "a broker secret appeared in an upstream response")
                return JSONResponse({"allowed": False, "outcome": "quarantined", "quarantined": True}, status_code=502)
        if d.op.kind == "write":
            gate.ledger.append("upstream", {"run": run_id, "op": d.op.name, "user": d.op.user, "status": up.status_code})
            if d.oob_secret and 200 <= up.status_code < 300:
                deliver_secret(keycloak.username(d.op.user), d.oob_secret)
        headers = {k: v for k, v in up.headers.items() if k.lower() not in DROP_RESPONSE_HEADERS}
        return Response(content=content, status_code=up.status_code, headers=headers)

    app.state.quarantined = quarantined
    return app
