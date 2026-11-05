"""The admin console's session, held by the broker (from the Nov 3 broker spike, made least-privilege).

The browser in the sandbox drives the real Keycloak admin console for realm corp, but holds no usable credential:
- the broker performs the console login itself as `helpdesk-console` (VIEW-ONLY: view-users; it can change nothing);
  the password never reaches the browser. Invariant: nothing reachable from the sandbox holds a credential that can
  write;
- the console route is an allowlist and every upstream request is BUILT from checked fields (headers allowlisted,
  the token endpoint limited to the console's own client and its two grants);
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
        self.refused: list[str] = []          # what the console route refused (shown by the probes)
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
            while len(self._fake2real) > self.MAX_TOKENS:      # bounded: the oldest mapping is forgotten first
                old_fake = next(iter(self._fake2real))
                self.real_tokens.discard(self._fake2real.pop(old_fake))
        return f

    MAX_TOKENS = 256

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

    # --- the token endpoint: one client, two grants, a body rebuilt from parsed fields ------------------------
    CONSOLE_CLIENT = "security-admin-console"
    TOKEN_GRANTS = {"authorization_code": {"grant_type", "client_id", "code", "redirect_uri", "code_verifier"},
                    "refresh_token": {"grant_type", "client_id", "refresh_token", "scope"}}
    FORWARD_HEADERS = ("accept", "accept-language", "content-type")

    def token_body(self, body: bytes) -> tuple[bytes | None, str]:
        """Mentor's review: the one allowed POST must not be a password-guessing oracle (the realm's admin-cli accepts
        password grants by default). Only the console's own client and its two grants pass, each with only its own
        fields; the body forwarded is rebuilt from those fields. Returns (body, '') or (None, reason)."""
        from urllib.parse import parse_qsl, urlencode
        try:
            pairs = parse_qsl(body.decode("ascii"), keep_blank_values=True, strict_parsing=True)
        except (UnicodeDecodeError, ValueError):
            return None, "token request body is not a plain form"
        form = dict(pairs)
        if len(form) != len(pairs):
            return None, "repeated field in token request"
        grant = form.get("grant_type", "")
        if grant not in self.TOKEN_GRANTS:
            return None, f"grant {grant[:40]!r} is not allowed on the console route"
        if form.get("client_id") != self.CONSOLE_CLIENT:
            return None, "only the admin console's own client may use the console route"
        extra = set(form) - self.TOKEN_GRANTS[grant]
        if extra:
            return None, f"unexpected field(s) {sorted(extra)[:3]} in token request"
        if grant == "refresh_token":            # only the refresh field is ever swapped back to the real token
            form["refresh_token"] = self._swap_in(form.get("refresh_token", ""))
        return urlencode(form).encode(), ""

    # --- one request from the browser -----------------------------------------------------------------------
    def handle(self, method: str, path_qs: str, headers: dict, body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        def refuse(reason: str):
            with self._lock:
                self.refused.append(f"{method} {path_qs[:100]} -> {reason}")
                del self.refused[:-200]
            return 403, [("Content-Type", "application/json")], json.dumps({"error": reason}).encode()
        path, _, qs = path_qs.partition("?")
        refusal = self.allowed(method, path)
        if refusal:
            return refuse(refusal)
        if any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in qs):     # found by the fuzzer: a raw tab crashed the route
            return refuse("control, space or non-ASCII characters in the query")
        if path == f"/realms/{self.realm}/protocol/openid-connect/auth":
            from urllib.parse import parse_qs
            if parse_qs(qs).get("client_id") != [self.CONSOLE_CLIENT]:
                return refuse("only the admin console's own client may sign in through the console route")
        # The upstream request is BUILT, not forwarded: a header allowlist, the (swapped) bearer, and for the token
        # endpoint a body rebuilt from parsed fields. Nothing else from the sandbox reaches Keycloak.
        hdrs = {k: v for k, v in headers.items() if k.lower() in self.FORWARD_HEADERS}
        auth = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
        if auth:
            hdrs["Authorization"] = self._swap_in(auth)
        if method == "POST":
            body, why = self.token_body(body or b"")
            if body is None:
                return refuse(why)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            if body:
                return refuse("GET with a body")
            body = b""
        try:
            r = self._send(method, self.up + path_qs, headers=hdrs, content=body or None)
        except (httpx.HTTPError, ValueError) as e:      # never a 500 from the console route
            return 502, [("Content-Type", "application/json")], json.dumps(
                {"error": f"upstream request failed: {type(e).__name__}"}).encode()
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
            # DISPLAY ONLY, NEVER AUTHORITY. The console user is view-only (its token cannot change anything). The
            # console UI decides which buttons to show from whoami, so the display gets manage-users here; every real
            # write still goes through the gate with the broker's service account and needs a receipt.
            # The console, like the model, believes it has authority; the gate decides.
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
