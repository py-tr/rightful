"""The realm factory (mentor's review): the ONLY process that holds Keycloak's master admin. It mints and deletes the
demo's per-visitor companies and nothing else, behind a two-call API on localhost with a shared token:

  POST   /companies           -> a fresh company from the warm pool: realm name, its own clients' secrets, user ids
  DELETE /companies/{realm}   -> delete it (only realms named demo-*; never the deployment's own realm)

If the demo server (which runs the brokers) is ever compromised, it holds one company's keys at a time, not the key
to all of them. A warm pool of ready companies keeps creation latency off the visitor's first click and caps how fast
companies can be made; a sweeper deletes any demo-* realm older than the maximum lifetime, whatever the demo server
did (browser close does not fire reliably, so time-to-live does the work).

Run: KC_ADMIN_PASSWORD=... FACTORY_TOKEN=... python -m demo.factory
"""
from __future__ import annotations

import os
import re
import secrets
import threading
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from devenv import keycloak_local as kl

REALM_RE = re.compile(r"demo-s[0-9a-f]{12}")
CIBA_EXPIRES_S = 60


class Factory:
    def __init__(self, kc_base: str, pool_size: int = 5, max_companies: int = 12, max_age_s: float = 75 * 60,
                 clock=time.time):
        self.kc, self.pool_size, self.max_companies, self.max_age = kc_base, pool_size, max_companies, max_age_s
        self._clock, self._lock = clock, threading.Lock()
        self.pool: list[dict] = []
        self.handed_out: dict[str, float] = {}       # realm -> when it was created
        self.stop = threading.Event()

    def _admin(self) -> httpx.Client:
        return kl.master_admin(self.kc)

    def _make(self) -> dict:
        realm = "demo-s" + secrets.token_hex(6)
        last = None
        for i in range(3):                           # dev-mode Keycloak can fail a creation under concurrency
            try:
                env = kl.bootstrap(self.kc, realm=realm, smtp=True)
                break
            except httpx.HTTPStatusError as e:
                last = e
                self._delete(realm)
                time.sleep(0.5 * (i + 1))
        else:
            raise RuntimeError(f"could not create a company: {last}")
        a = self._admin()
        rep = a.get(f"/admin/realms/{realm}").json()
        rep.setdefault("attributes", {})["cibaExpiresIn"] = str(CIBA_EXPIRES_S)
        a.put(f"/admin/realms/{realm}", json=rep).raise_for_status()
        cid = a.get(f"/admin/realms/{realm}/clients", params={"clientId": "gate-broker"}).json()[0]["id"]
        sa = a.get(f"/admin/realms/{realm}/clients/{cid}/service-account-user").json()["id"]
        return {"realm": realm, "created": self._clock(), "users": env["users"], "broker": list(env["broker"]),
                "ciba": list(env["ciba"]), "reconciler": list(env["reconciler"]), "broker_sa_user": sa}

    def _delete(self, realm: str) -> bool:
        if not REALM_RE.fullmatch(realm):
            return False                              # never anything but a demo company
        try:
            return self._admin().delete(f"/admin/realms/{realm}").status_code in (204, 404)
        except httpx.HTTPError:
            return False

    def take(self) -> dict | None:
        with self._lock:
            if len(self.handed_out) >= self.max_companies:
                return None
            c = self.pool.pop(0) if self.pool else None
        if c is None:
            c = self._make()                          # the pool ran dry: make one now (slower, still capped)
        with self._lock:
            self.handed_out[c["realm"]] = c["created"]
        return c

    def give_back(self, realm: str) -> bool:
        with self._lock:
            self.handed_out.pop(realm, None)
        return self._delete(realm)

    def refill_and_sweep_once(self) -> None:
        self.refill_once()
        self.sweep_once()

    def refill_once(self) -> None:
        with self._lock:                              # never more than max_companies in use + a full pool, in total
            room = self.max_companies + self.pool_size - len(self.handed_out) - len(self.pool)
            need = min(self.pool_size - len(self.pool), room)
        for _ in range(max(need, 0)):
            try:
                c = self._make()
            except Exception:                         # noqa: BLE001
                break
            with self._lock:
                self.pool.append(c)

    def sweep_once(self) -> None:
        now = self._clock()
        with self._lock:
            expired = [r for r, t in self.handed_out.items() if now - t > self.max_age]
            stale_pool = [c for c in self.pool if now - c["created"] > self.max_age]
            self.pool = [c for c in self.pool if c not in stale_pool]
        for r in expired + [c["realm"] for c in stale_pool]:
            self.give_back(r)
        try:   # safety net: a demo-* realm this factory does not know (e.g. left over from before a restart) is deleted;
               # there is exactly ONE factory per deployment, so an unknown demo company is always an orphan
            known = set(self.handed_out) | {c["realm"] for c in self.pool}
            for rr in self._admin().get("/admin/realms", params={"briefRepresentation": "true"}).json():
                if REALM_RE.fullmatch(rr["realm"]) and rr["realm"] not in known:
                    self._delete(rr["realm"])
        except httpx.HTTPError:
            pass

    def run_background(self, every_s: float = 20.0) -> None:
        def loop():
            while not self.stop.is_set():
                self.refill_and_sweep_once()
                self.stop.wait(every_s)
        threading.Thread(target=loop, daemon=True).start()


def create_factory_app(factory: Factory, token: str) -> FastAPI:
    app = FastAPI(title="Keyless realm factory", docs_url=None, redoc_url=None, openapi_url=None)

    def authorized(request: Request) -> bool:
        return secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {token}")

    @app.post("/companies")
    def create(request: Request):
        if not authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        c = factory.take()
        if c is None:
            return JSONResponse({"error": "busy"}, status_code=503)
        return c

    @app.delete("/companies/{realm}")
    def delete(realm: str, request: Request):
        if not authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not REALM_RE.fullmatch(realm):
            return JSONResponse({"error": "not a demo company"}, status_code=400)
        return {"deleted": factory.give_back(realm)}

    @app.get("/healthz")
    def health():
        return {"pool": len(factory.pool), "companies": len(factory.handed_out)}
    return app


if __name__ == "__main__":
    import uvicorn
    f = Factory(os.environ.get("KC_URL", "http://127.0.0.1:8089"))
    f.run_background()
    uvicorn.run(create_factory_app(f, os.environ["FACTORY_TOKEN"]), host="127.0.0.1", port=8097, log_level="warning")
