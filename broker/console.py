"""The admin console's session, held by the broker (from the Nov 3 broker spike, made least-privilege).

The browser in the sandbox drives the real Keycloak admin console for realm corp, but holds no usable credential:
- the broker performs the console login itself as `helpdesk-console` (manage-users + view-users only); the
  password never reaches the browser;
- Keycloak's cookies live in the broker's jar; every Set-Cookie is stripped except the KEYCLOAK_SESSION marker
  (a session-status marker that cannot authenticate);
- tokens sent to the browser are copies with a destroyed signature (replayed against Keycloak: 401);
- admin-API calls from the console do NOT use those tokens at all: they go through the gate and are forwarded with
  the broker's own service-account token (see app.py). This module only boots and keeps the console UI alive.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading

import httpx


class ConsoleSession:
    def __init__(self, upstream: str, public: str, realm: str, username: str, password: str):
        self.up, self.pub, self.realm = upstream.rstrip("/"), public.rstrip("/"), realm
        self._user, self._pw = username, password
        host = public.split("://", 1)[1]
        self.http = httpx.Client(follow_redirects=False, timeout=30, headers={"Host": host})
        self._jar: dict[str, str] = {}
        self._fake2real: dict[str, str] = {}
        self.real_tokens: set[str] = set()
        self.leaks: list[str] = []
        self._lock = threading.Lock()
        self.routes = (f"/realms/{realm}/", f"/admin/{realm}/console", "/resources/")
        self.token_path = f"/realms/{realm}/protocol/openid-connect/token"
        self.whoami_path = f"/admin/{realm}/console/whoami"

    def handles(self, path: str) -> bool:
        return path.startswith(self.routes)

    def allowed(self, method: str, path: str) -> str | None:
        """The console route is an allowlist (mentor review finding #2, a measured bypass): GET/HEAD on console assets
        and sign-in pages, POST only to the exact token endpoint. Every path passes the gate's strict path check, so
        '..', '%', ';' and '//' never reach Keycloak by this route. Returns a refusal reason, or None if allowed."""
        from gate.grammar import Reject, _check_path
        try:
            _check_path(path, allow_trailing_slash=True)
        except Reject as r:
            return r.reason
        if method in ("GET", "HEAD") and path.startswith(self.routes):
            return None
        if method == "POST" and path == self.token_path:
            return None
        return f"{method} is not allowed on the console route"

    # --- cookies and tokens ---------------------------------------------------------------------------------
    def _send(self, method: str, url: str, headers: dict | None = None, content: bytes | None = None,
              data: dict | None = None) -> httpx.Response:
        h = dict(headers or {})
        with self._lock:
            if self._jar:
                h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._jar.items())
        r = self.http.request(method, url, headers=h, content=content, data=data)
        self.http.cookies.clear()
        with self._lock:
            for sc in r.headers.get_list("set-cookie"):
                nv = sc.split(";", 1)[0]
                if "=" not in nv:
                    continue
                k, v = (x.strip() for x in nv.split("=", 1))
                if "max-age=0" in sc.lower() or v == "":
                    self._jar.pop(k, None)
                else:
                    self._jar[k] = v
        return r

    def _fake(self, tok: str) -> str:
        parts = tok.split(".")
        tail = "brokerfake" + hashlib.sha256(tok.encode()).hexdigest()[:24]
        f = (parts[0] + "." + parts[1] + "." + tail) if len(parts) == 3 else tail
        with self._lock:
            self._fake2real[f] = tok
            self.real_tokens.add(tok)
        return f

    def _swap_in(self, s: str) -> str:
        with self._lock:
            for f, r in self._fake2real.items():
                if f in s:
                    s = s.replace(f, r)
        return s

    def _login(self, html: str) -> httpx.Response | None:
        m = re.search(r'id="kc-form-login"[^>]*action="([^"]+)"', html) or re.search(r'<form[^>]*action="([^"]+)"', html)
        if not m:
            return None
        action = m.group(1).replace("&amp;", "&").replace(self.pub, self.up)
        return self._send("POST", action, data={"username": self._user, "password": self._pw, "credentialId": ""})

    # --- one request from the browser -----------------------------------------------------------------------
    def handle(self, method: str, path_qs: str, headers: dict, body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        path = path_qs.split("?", 1)[0]
        refusal = self.allowed(method, path)
        if refusal:
            return 403, [("Content-Type", "application/json")], json.dumps({"error": refusal}).encode()
        hdrs = {k: v for k, v in headers.items()
                if k.lower() not in ("host", "cookie", "content-length", "accept-encoding", "connection", "x-gate-run")}
        for k in list(hdrs):
            if k.lower() == "authorization":
                hdrs[k] = self._swap_in(hdrs[k])
        if body and path == self.token_path:          # only the token endpoint's refresh field is ever swapped
            try:
                body = self._swap_in(body.decode()).encode()
            except UnicodeDecodeError:
                pass
        r = self._send(method, self.up + path_qs, headers=hdrs, content=body or None)
        if path == f"/realms/{self.realm}/protocol/openid-connect/auth" and r.status_code == 200 \
                and "kc-form-login" in r.text:
            lr = self._login(r.text)
            if lr is not None:
                r = lr
        data = r.content
        if path.endswith("/protocol/openid-connect/token") and "json" in r.headers.get("content-type", ""):
            j = r.json()
            for k in ("access_token", "refresh_token", "id_token"):
                if k in j:
                    j[k] = self._fake(j[k])
            data = json.dumps(j).encode()
        if path == self.whoami_path and r.status_code == 200 and "json" in r.headers.get("content-type", ""):
            # The console user is VIEW-ONLY (its token cannot change anything). The console UI decides which buttons
            # to show from whoami, so the display gets manage-users here; every real write still goes through the
            # gate with the broker's service account. Display only, never authority.
            j = r.json()
            ra = j.setdefault("realm_access", {}).setdefault(self.realm, [])
            for role in ("manage-users", "view-users"):
                if role not in ra:
                    ra.append(role)
            data = json.dumps(j).encode()
        text = data.decode("utf-8", "replace")
        with self._lock:
            if any(t in text for t in self.real_tokens):
                self.leaks.append(path)
                data = b'{"error":"withheld by broker"}'
        out = []
        for k, v in r.headers.multi_items():
            lk = k.lower()
            if lk == "set-cookie":
                if v.split("=", 1)[0].strip().startswith("KEYCLOAK_SESSION"):
                    out.append((k, v))
                continue
            if lk in ("content-length", "transfer-encoding", "content-encoding", "connection"):
                continue
            if lk == "location":
                v = v.replace(self.up, self.pub)
            out.append((k, v))
        return r.status_code, out, data
