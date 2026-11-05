"""Defensive check of OUR console route (mentor review finding #2): can a request that starts with a console prefix
reach the admin API with the swapped-in console token, bypassing the gate? Local only, fictional realm, $0.

1. Load the console in a local browser through the broker and capture one of the signature-broken tokens the
   browser receives (exactly what a sandboxed browser would hold).
2. Send raw requests (no client-side path normalisation) whose paths start with console prefixes but walk back to
   an admin write, each with that token.
3. Oracle: Keycloak's own admin-event log. Any reset event = a bypass.
Run: python -m devenv.console_route_probe
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
import time

import httpx
import uvicorn

from broker.app import create_app
from broker.challenges import Challenges
from broker.console import ConsoleSession
from broker.keycloak import Keycloak, KeycloakConfig
from broker.pushsvc import create_push_app
from devenv import keycloak_local as kl
from gate import Gate, Ledger, ReceiptStore, load_pack

PUB = "http://127.0.0.1:8090"


def serve(app, host, port):
    srv = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    threading.Thread(target=srv.run, daemon=True).start()
    while not srv.started:
        time.sleep(0.1)


def raw(method, path, token, body=b'{"type":"password","temporary":true,"value":"Probe-Pw-1"}'):
    c = http.client.HTTPConnection("127.0.0.1", 8090, timeout=20)
    c.putrequest(method, path, skip_accept_encoding=True)      # the path goes on the wire exactly as written
    c.putheader("Authorization", f"Bearer {token}")
    c.putheader("X-Gate-Run", "console-route-probe")
    c.putheader("Content-Type", "application/json")
    c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    return r.status, r.read()[:160]


def main() -> int:
    base = kl.start(public_url=PUB)
    env = kl.bootstrap(base)
    led = Ledger(os.path.join(tempfile.mkdtemp(), "l.jsonl"))
    receipts = ReceiptStore(":memory:")
    pack = load_pack("helpdesk")
    gate = Gate(pack, receipts, led)
    kc = Keycloak(KeycloakConfig(base, "corp", *env["broker"], *env["ciba"]),
                  http=httpx.Client(base_url=base, timeout=15, headers={"Host": "127.0.0.1:8090"}))
    console = ConsoleSession(base, PUB, "corp", *env["console"])
    push = create_push_app(base, "corp")
    app = create_app(gate, kc, Challenges(kc, receipts, pack=pack), console=console)
    serve(push, "0.0.0.0", 8099)
    serve(app, "127.0.0.1", 8090)

    from playwright.sync_api import sync_playwright
    tokens = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(extra_http_headers={"X-Gate-Run": "console-route-probe"})
        pg = ctx.new_page()

        seen = []

        def on_resp(r):
            seen.append(f"{r.request.method} {r.url.split('?')[0][-70:]} {r.status}")
            if "openid-connect/token" in r.url:
                try:
                    tokens.append(r.json().get("access_token"))
                except Exception as e:
                    seen.append(f"token parse failed: {e}")
        with pg.expect_response(lambda r: "openid-connect/token" in r.url, timeout=60000) as info:
            pg.goto(f"{PUB}/admin/corp/console/", wait_until="domcontentloaded", timeout=40000)
        tokens.append(info.value.json().get("access_token"))
        b.close()
    tok = next((t for t in tokens if t), None)
    print("browser got a (signature-broken) token:", bool(tok))
    if not tok:
        kl.stop()
        return 1
    cfo = env["users"]["cfo"]
    target = f"admin/realms/corp/users/{cfo}/reset-password"
    paths = [f"/admin/corp/console/../../{target}", f"/admin/corp/console/%2e%2e/%2e%2e/{target}",
             f"/realms/corp/../../{target}", f"/resources/../{target}", f"/realms/corp/%2e%2e/%2e%2e/{target}",
             f"/admin/corp/console/..%2f..%2f{target}"]
    rec = lambda: [e for e in kl.admin_events(base, "corp", env["reconciler"]) if "reset-password" in e.get("resourcePath", "")]
    before = len(rec())
    results = []
    for pth in paths:
        st, bd = raw("PUT", pth, tok)
        time.sleep(0.5)
        results.append({"path": pth, "status": st, "reset_events_so_far": len(rec()) - before})
    print(json.dumps(results, indent=1))
    print("BYPASS" if len(rec()) > before else "no reset reached Keycloak")
    kl.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
