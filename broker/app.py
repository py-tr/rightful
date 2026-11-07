"""The broker's HTTP surface, as seen from the sandbox (through the trusted per-task edge proxy).

- Every request must carry X-Gate-Run, stamped by the edge proxy that the control plane creates per task. The edge
  strips any copy from the sandbox. Without it: 400, nothing forwarded.
- Admin-API requests go through the gate. Allowed ones are forwarded with the broker's own token; responses lose
  Set-Cookie and auth headers and are scanned for the broker's secrets before they reach the sandbox.
- A denied write returns a challenge (id, match number). The agent asks for the push, the owner approves on the
  registered device, and the agent sends the same request again.
- A quarantined run is blocked for the rest of its life (every further request refused). on_quarantine is a hook for
  the control plane (e.g. to destroy and rebuild the worker); the demo and the evaluation pass a no-op.
"""
from __future__ import annotations

import threading

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from gate import Gate

DROP_RESPONSE_HEADERS = {"set-cookie", "authorization", "www-authenticate", "content-length", "content-encoding",
                         "transfer-encoding", "connection", "keep-alive"}


def create_app(gate: Gate, keycloak, challenges, deliver_secret=lambda username, secret: None,
               on_quarantine=lambda run_id, reason: None, console=None,
               notify=lambda username, text, cancel_id=None: None, run_key_master: bytes | None = None) -> FastAPI:
    """run_key_master: when set (always, in deployment), every request must carry the edge's signature for its run
    (broker/runkey.py); unsigned or mis-signed requests get 401 and nothing else happens."""
    from .composites import execute as run_composite
    from .runkey import SKEW_LOG_SECONDS
    from .runkey import skew as skew_of
    from .runkey import verify as verify_sig
    app = FastAPI(title="Keyless broker", docs_url=None, redoc_url=None, openapi_url=None)
    from gate import LedgerError

    @app.exception_handler(httpx.HTTPStatusError)
    async def upstream_error(request: Request, exc: httpx.HTTPStatusError):
        # A Keycloak error while preparing a decision (e.g. a user id that does not exist in THIS realm, such as
        # another session's company: found by the session-isolation test) stops the action and is answered cleanly.
        code = exc.response.status_code if exc.response is not None else 502
        if code == 404:
            return JSONResponse({"allowed": False, "outcome": "denied_unknown_user",
                                 "reason": "no such user in this company"}, status_code=404)
        return JSONResponse({"allowed": False, "outcome": "upstream_error", "reason": "the identity server failed; "
                             "nothing was changed"}, status_code=502)

    @app.exception_handler(LedgerError)
    async def ledger_down(request: Request, exc: LedgerError):
        # Fail closed AND clean (found by the evaluation's ledger-down arm): the gate already denies every write when
        # the ledger cannot be written, so nothing changes; the sandbox gets a 503, never a 500.
        return JSONResponse({"allowed": False, "outcome": "denied_ledger_down",
                             "reason": "the audit log is unavailable; nothing was changed"}, status_code=503)
    # Rebuilt from the ledger: a quarantined run stays quarantined across a broker restart (review finding #4).
    quarantined: dict[str, str] = {e["data"]["run"]: e["data"].get("reason", "")
                                   for e in gate.ledger.entries() if e["kind"] == "quarantine"}
    lock = threading.Lock()
    # Run lifecycle (mentor's review): with signing on, only runs the control plane opened are accepted, and a closed
    # run speaks for nothing (a lingering edge from a crashed task gets 401). Rebuilt from the ledger.
    open_runs: set[str] = set()
    for e in gate.ledger.entries():
        if e["kind"] == "run_opened":
            open_runs.add(e["data"]["run"])
        elif e["kind"] == "run_closed":
            open_runs.discard(e["data"]["run"])
    skew_logged: dict[str, int] = {}

    def open_run(run_id: str, mode: str = "full") -> None:
        gate.set_mode(run_id, mode)          # an evaluation-only mode raises PermissionError outside a scratch realm
        with lock:
            open_runs.add(run_id)
        gate.ledger.append("run_opened", {"run": run_id, "mode": mode})

    def close_run(run_id: str, why: str = "task ended") -> None:
        with lock:
            open_runs.discard(run_id)
        gate.ledger.append("run_closed", {"run": run_id, "why": why})

    def _target(request: Request) -> str:
        raw = request.scope.get("raw_path", b"").decode("latin-1") or request.url.path
        qs = request.scope.get("query_string") or b""
        return raw + (("?" + qs.decode("latin-1")) if qs else "")

    async def run_of(request: Request) -> str | None:
        r = request.headers.get("x-gate-run", "")
        if not (r and len(r) <= 64 and r.replace("-", "").replace("_", "").isalnum()):
            return None
        if run_key_master is not None:
            ts = request.headers.get("x-gate-ts", "")
            bad = verify_sig(run_key_master, r, ts, request.headers.get("x-gate-sig", ""), request.method,
                             _target(request), await request.body())
            if not bad and r not in open_runs:
                bad = "run is not open (never started, or already ended)"
            sk = skew_of(ts)
            if sk is not None and abs(sk) > SKEW_LOG_SECONDS and skew_logged.get(r) != int(sk // 10):
                skew_logged[r] = int(sk // 10)                 # log drift once per 10 s bucket per run
                gate.ledger.append("clock_skew", {"run": r[:64], "skew_seconds": round(sk, 1), "rejected": bool(bad)})
            if bad:
                try:
                    gate.ledger.append("bad_signature", {"run": r[:64], "reason": bad,
                                                         "client": request.client.host if request.client else ""})
                except Exception:
                    pass
                return None
        return r

    import json as _json

    from gate.grammar import _match
    read_fields = gate.pack.get("read_fields", {})

    def filter_read(path: str, content: bytes) -> bytes:
        """Mentor's review: the sandbox sees only allowlisted fields of a user (never attributes such as the manager,
        federation links, or anything the approver logic depends on). Fail closed: unparseable -> empty."""
        for tpl, fields in read_fields.items():
            if _match(tpl, path, gate.pack["realm"]) is None:
                continue
            try:
                data = _json.loads(content)
            except ValueError:
                return b"{}"
            keep = set(fields)
            if isinstance(data, list):
                data = [{k: v for k, v in x.items() if k in keep} for x in data if isinstance(x, dict)]
            elif isinstance(data, dict):
                data = {k: v for k, v in data.items() if k in keep}
            else:
                data = {}
            return _json.dumps(data).encode()
        return content

    def no_run() -> JSONResponse:
        return JSONResponse({"error": "missing or unsigned run"}, status_code=400 if run_key_master is None else 401)

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
    async def send(cid: str, request: Request):
        run_id = await run_of(request)
        if not run_id:
            return no_run()
        if (b := blocked(run_id)):
            return b
        try:
            c = await run_in_threadpool(challenges.send, cid, run_id)  # blocking Keycloak call: off the event loop
        except httpx.HTTPError as e:
            # The approval service is down (the evaluation's fail-closed arm found a 500 here): nothing can be approved,
            # so nothing will change; the agent gets a clean answer it can escalate on.
            gate.ledger.append("challenge", {"run": run_id, "challenge": cid, "status": "unavailable",
                                             "error": type(e).__name__})
            return JSONResponse({"challenge": cid, "status": "unavailable",
                                 "tell_the_caller": None, "next": "escalate: approvals are unavailable"},
                                status_code=503)
        if c is None:
            return JSONResponse({"error": "unknown challenge"}, status_code=404)
        gate.ledger.append("challenge", {"run": run_id, "challenge": c.id, "op": c.operation, "user": c.user_id,
                                         "status": c.status})
        return {"challenge": c.id, "status": c.status, "number": c.number,
                "tell_the_caller": f"A push was sent to the registered device. Approve it and choose {c.number}."
                if c.status == "sent" else None}

    @app.get("/gate/v1/challenges/{cid}")
    async def poll(cid: str, request: Request):
        run_id = await run_of(request)
        if not run_id:
            return no_run()
        if (b := blocked(run_id)):
            return b
        c = await run_in_threadpool(challenges.poll, cid, run_id)
        if c is None:
            return JSONResponse({"error": "unknown challenge"}, status_code=404)
        if c.status in ("approved", "denied", "expired"):
            gate.ledger.append("challenge", {"run": run_id, "challenge": c.id, "status": c.status})
        return {"challenge": c.id, "status": c.status,
                "next": "send the same request again" if c.status == "approved" else None}

    @app.post("/gate/v1/identity-checks/{user}")
    async def identity_check(user: str, request: Request):
        """A push to the user's registered device whose answer the AGENT sees, bound to no change: how a help desk
        without the gate verifies a caller (the evaluation's gate-off baseline documents it). With the gate it is
        harmless: no write can redeem it (an 'identity_check' approval matches no operation)."""
        import re as _re
        run_id = await run_of(request)
        if not run_id:
            return no_run()
        if (b := blocked(run_id)):
            return b
        if not _re.fullmatch(r"[0-9a-f-]{36}", user):
            return JSONResponse({"error": "user id expected"}, status_code=400)
        import hashlib as _h
        spec = {"operation": "identity_check", "user": user, "label": "verify", "receipt_kind": "owner",
                "request_hash": _h.sha256(f"identity_check|{user}".encode()).hexdigest()}
        try:
            c = await run_in_threadpool(challenges.create, run_id, spec)
        except httpx.HTTPError:
            return JSONResponse({"error": "unknown user"}, status_code=404)
        gate.ledger.append("challenge", {"run": run_id, "challenge": c.id, "op": "identity_check", "user": user,
                                         "status": c.status})
        return {"challenge": c.id, "number": c.number, "status": c.status,
                "how": f"POST /gate/v1/challenges/{c.id}/send, then wait for approval"}

    @app.post("/gate/v1/verifications")
    async def verification(request: Request):
        """The agent records how it verified a caller. Audit only (claimed vs actual); it authorizes nothing, except
        under the evaluation's naive-gate ablation."""
        run_id = await run_of(request)
        if not run_id:
            return no_run()
        if (b := blocked(run_id)):
            return b
        try:
            j = await request.json()
            user, how = str(j.get("user", ""))[:64], str(j.get("how", ""))[:200]
        except ValueError:
            return JSONResponse({"error": "bad request"}, status_code=400)
        gate.agent_claims_verified(run_id, user, how)
        return {"recorded": True}

    @app.post("/gate/v1/escalations")
    async def escalation(request: Request):
        run_id = await run_of(request)
        if not run_id:
            return no_run()
        try:
            reason = str((await request.json()).get("reason", ""))[:500]
        except ValueError:
            reason = ""
        gate.ledger.append("escalation", {"run": run_id, "reason": reason})
        return {"escalated": True}

    @app.api_route("/{full:path}", methods=["GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy(full: str, request: Request):
        run_id = await run_of(request)
        if not run_id:
            return no_run()
        if (b := blocked(run_id)):
            return b
        raw = request.scope.get("raw_path", b"").decode("latin-1") or request.url.path
        target = _target(request)
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
        if not d.allow and d.challenge and not d.quarantine and challenges.declined_before(
                run_id, d.op.name, d.op.user, d.op.request_hash):
            # Hostile signal: the approver already said no to exactly this change, and the agent is trying it again.
            quarantine(run_id, "retried a change the approver had declined")
            return JSONResponse({"allowed": False, "outcome": "quarantined", "quarantined": True,
                                 "reason": "the approver declined this change; retrying it is not allowed"},
                                status_code=403)
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
            # Snapshot at approval (stored IN the receipt), re-check at execution: if the email on file or the manager
            # changed in between, the approval no longer describes what would happen. No stored snapshot -> abort:
            # the check is never skipped (it was, after a restart, before review finding #4).
            snap = f.get("snapshot")
            why = None
            if snap == "skip":          # only from the evaluation's no-approval modes; a stored receipt never says it
                pass
            elif not snap:
                why = "no approval snapshot on the receipt"
            elif challenges.resolver.snapshot(f["user"]) != snap:   # the pack's resolver (default: identity server)
                why = "email or manager changed after approval"
            if why:
                gate.ledger.append("composite_aborted", {"run": run_id, "op": d.op.name, "user": f["user"],
                                                         "reason": why})
                notify(keycloak.username(f["user"]), "A recovery on your account was stopped before anything changed. "
                                                     "IT security has been alerted.")
                return JSONResponse({"allowed": False, "outcome": "aborted_changed_since_approval"
                                     if snap else "aborted_no_snapshot"}, status_code=409)
            result = run_composite(keycloak, gate.ledger, gate.pack["realm"], f["user"], f["steps"], f["receipt"],
                                   run_id, notify, deliver_secret,
                                   lifespan=int(gate.pack.get("action_link_lifespan_seconds", 600)))
            base = {"run": run_id, "op": d.op.name, "user": f["user"], "request_hash": d.op.request_hash,
                    "receipt": f["receipt"]}
            if result["completed"]:
                gate.ledger.append("executed", base)
            elif result["steps_done"]:
                gate.ledger.append("partially_executed", {**base, "steps_done": result["steps_done"],
                                                          "failed_step": result.get("failed_step")})
            else:
                gate.ledger.append("upstream_failed", {**base, "failed_step": result.get("failed_step")})
            return JSONResponse({"allowed": True, "outcome": "allowed_composite", "action": d.op.name, **result},
                                status_code=200 if result["completed"] else 502)

        old_email = None
        if d.op.kind == "write" and d.op.name == "change_email" and gate.mode(run_id) != "allow_all":
            old_email = keycloak.user_snapshot(d.op.user).get("email")
        up = keycloak.forward(d.forward, with_token=d.op.kind != "static")
        if d.op.kind == "write":
            # Only now does the ledger say the change happened, and only if Keycloak accepted it (review finding #3).
            entry = {"run": run_id, "op": d.op.name, "user": d.op.user, "request_hash": d.op.request_hash,
                     "status": up.status_code, "receipt": d.forward.get("receipt"), "mode": gate.mode(run_id)}
            gate.ledger.append("executed" if 200 <= up.status_code < 300 else "upstream_failed", entry)
        if old_email is not None and 200 <= up.status_code < 300:
            # Recovery guidance: tell the PREVIOUS contact too, so a hijacked change is noticed where it matters.
            notify(keycloak.username(d.op.user), f"The email on your account was changed from {old_email}. If this "
                                                 f"was not you, contact IT security now.")
        content = up.content
        if d.op.kind == "read" and 200 <= up.status_code < 300:
            content = filter_read(d.op.path, content)
        if d.op.kind != "static":
            leaks = [s for s in (keycloak.service_token_if_cached(), d.oob_secret) if s]
            if any(s.encode() in content for s in leaks):
                quarantine(run_id, "a broker secret appeared in an upstream response")
                return JSONResponse({"allowed": False, "outcome": "quarantined", "quarantined": True}, status_code=502)
        if d.op.kind == "write":
            if d.oob_secret and 200 <= up.status_code < 300:
                deliver_secret(keycloak.username(d.op.user), d.oob_secret)
        headers = {k: v for k, v in up.headers.items() if k.lower() not in DROP_RESPONSE_HEADERS}
        if d.forward.get("return_secret") and 200 <= up.status_code < 300:
            # Gate-off baseline only (credential-brokered, no authorization): like a help-desk tool without a gate, the
            # temporary password comes back to the agent, which may read it to the caller. Counted in the evaluation.
            return JSONResponse({"temporary_password": d.forward["return_secret"]}, status_code=200)
        return Response(content=content, status_code=up.status_code, headers=headers)

    app.state.quarantined = quarantined
    app.state.open_run, app.state.close_run = open_run, close_run      # called by the control plane's orchestrator
    return app
