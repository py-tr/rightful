"""One broker address and one push address for many concurrent evaluation runs, each with its OWN realm, gate,
receipts, ledger and phone (nothing is shared between runs except Keycloak itself).

- BrokerDispatch routes by the X-Gate-Run header (stamped and signed by that run's edge) to the run's broker app;
  the run's app then verifies the signature itself. Unknown run -> 401.
- PushDispatch routes Keycloak's CIBA notification by the realm named in the callback token's issuer claim
  (Keycloak's HTTP authentication channel is one global URL for all realms).
Both record per-request timing so broker overhead can be reported separately from Keycloak time.
"""
from __future__ import annotations

import base64
import contextvars
import json
import threading
import time


_CURRENT = contextvars.ContextVar("keyless_eval_request", default=None)


class Timing:
    """Per-run: total time in the broker per request, and the Keycloak time inside it (from the run's HTTP client).
    The Keycloak time is accumulated in a per-request container held in a context variable, so concurrent requests
    of different runs never mix, including the endpoints that run in Starlette's thread pool (the context is copied
    there, and the container is shared by reference)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests: list[dict] = []

    @staticmethod
    def upstream_hook():
        def on_request(req):
            req.extensions["t0"] = time.perf_counter()

        def on_response(resp):
            t0, box = resp.request.extensions.get("t0"), _CURRENT.get()
            if t0 is not None and box is not None:
                box["ms"] += (time.perf_counter() - t0) * 1000
        return {"request": [on_request], "response": [on_response]}

    def start(self):
        box = {"ms": 0.0, "t0": time.perf_counter()}
        _CURRENT.set(box)
        return box

    def stop(self, box: dict, method: str, path: str, status: int):
        total = (time.perf_counter() - box["t0"]) * 1000
        up = box["ms"]
        with self.lock:
            self.requests.append({"method": method, "path": path[:120], "status": status, "total_ms": round(total, 1),
                                  "upstream_ms": round(up, 1), "overhead_ms": round(max(total - up, 0.0), 1)})


class BrokerDispatch:
    def __init__(self):
        self.apps: dict[str, tuple] = {}            # run id -> (asgi app, Timing)
        self.lock = threading.Lock()

    def register(self, run_id: str, app, timing: Timing):
        with self.lock:
            self.apps[run_id] = (app, timing)

    def unregister(self, run_id: str):
        with self.lock:
            self.apps.pop(run_id, None)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        hdr = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        with self.lock:
            target = self.apps.get(hdr.get("x-gate-run", ""))
        if target is None:
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"error":"unknown run"}'})
            return
        app, timing = target
        status = {"code": 0}

        async def send_wrap(msg):
            if msg["type"] == "http.response.start":
                status["code"] = msg["status"]
            await send(msg)
        # Starlette runs sync endpoints in a thread pool; timing per request is approximate under concurrency and is
        # reported as such (broker overhead = total minus the Keycloak time measured on the run's own client).
        t0 = timing.start()
        await app(scope, receive, send_wrap)
        timing.stop(t0, scope.get("method", ""), scope.get("path", ""), status["code"])


def realm_from_token(bearer: str) -> str | None:
    try:
        payload = bearer.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        iss = json.loads(base64.urlsafe_b64decode(payload)).get("iss", "")
        return iss.rstrip("/").rsplit("/realms/", 1)[1] if "/realms/" in iss else None
    except (IndexError, ValueError):
        return None


class PushDispatch:
    def __init__(self):
        self.apps: dict[str, object] = {}           # realm -> the run's push app
        self.lock = threading.Lock()

    def register(self, realm: str, app):
        with self.lock:
            self.apps[realm] = app

    def unregister(self, realm: str):
        with self.lock:
            self.apps.pop(realm, None)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        hdr = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        auth = hdr.get("authorization", "")
        realm = realm_from_token(auth.split(" ", 1)[1]) if auth.lower().startswith("bearer ") else None
        with self.lock:
            app = self.apps.get(realm or "")
        if app is None or scope.get("path") != "/ciba/notify":
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        await app(scope, receive, send)
