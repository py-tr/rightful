"""Drive the real Keycloak console through the broker + gate with Playwright, and report what the gate denied.

Used to grow the read allowlist from evidence (each denied read is reviewed before it is added; nothing is opened
blindly). Also checks the browser holds no usable credential.
Run: python -m devenv.console_probe      (needs Docker and Playwright Chromium; local only, $0)
"""
from __future__ import annotations

import json
import os
import sys
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
OUT = os.path.join(os.path.dirname(__file__), "out")


def serve(app, host, port):
    srv = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    threading.Thread(target=srv.run, daemon=True).start()
    while not srv.started:
        time.sleep(0.1)
    return srv


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    base = kl.start(public_url=PUB)
    env = kl.bootstrap(base)
    receipts = ReceiptStore(":memory:")
    ledger_path = os.path.join(OUT, "probe-ledger.jsonl")
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    gate = Gate(load_pack("helpdesk"), receipts, Ledger(ledger_path))
    kc = Keycloak(KeycloakConfig(base, "corp", *env["broker"], *env["ciba"]),
                  http=httpx.Client(base_url=base, timeout=15, headers={"Host": PUB.split("://")[1]}))
    console = ConsoleSession(base, PUB, "corp", *env["console"])
    push = create_push_app(base, "corp")
    app = create_app(gate, kc, Challenges(kc, receipts), deliver_secret=push.state.deliver, console=console)
    serve(push, "0.0.0.0", 8099)
    serve(app, "127.0.0.1", 8090)

    from playwright.sync_api import sync_playwright
    res = {}
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1366, "height": 860},
                            extra_http_headers={"X-Gate-Run": "browser-probe"})   # what the edge proxy will stamp
        blocked = []
        ctx.route("**/*", lambda rt: rt.continue_() if rt.request.url.startswith(PUB)
                  else (blocked.append(rt.request.url[:90]), rt.abort()))
        pg = ctx.new_page()
        try:
            pg.goto(f"{PUB}/admin/corp/console/#/corp/users", wait_until="domcontentloaded", timeout=40000)
        except Exception as e:
            print("goto:", str(e)[:120])
        time.sleep(12)
        pg.screenshot(path=os.path.join(OUT, "1-users.png"))
        res["users_listed"] = pg.get_by_text("cfo", exact=True).count() > 0
        try:
            pg.get_by_role("link", name="cfo", exact=True).first.click(timeout=10000)
            time.sleep(4)
            pg.get_by_role("tab", name="Credentials").click(timeout=10000)
            time.sleep(3)
            res["credentials_tab"] = True
        except Exception as e:
            res["credentials_tab"] = f"failed: {str(e)[:100]}"
        pg.screenshot(path=os.path.join(OUT, "2-cfo-credentials.png"))
        # The hero: try the reset in the real console without the owner's approval.
        try:
            pg.get_by_role("button", name="Set password").first.click(timeout=10000)
            time.sleep(1.5)
            pw = pg.locator("input[type=password]")
            pw.nth(0).fill("Agent-Typed-Pw-1")
            pw.nth(1).fill("Agent-Typed-Pw-1")
            pg.get_by_role("button", name="Save").click(timeout=5000)
            time.sleep(1)
            pg.get_by_role("button", name="Save password").click(timeout=5000)   # the confirmation dialog
            time.sleep(3)
            res["reset_clicked_in_console"] = True
        except Exception as e:
            res["reset_clicked_in_console"] = f"failed: {str(e)[:120]}"
        pg.screenshot(path=os.path.join(OUT, "3-reset-refused.png"))
        state = json.dumps(ctx.cookies()) + pg.evaluate(
            "() => JSON.stringify({ls: Object.assign({}, localStorage), ss: Object.assign({}, sessionStorage)})") + pg.content()
        b.close()
    res["real_token_in_browser"] = any(t in state for t in console.real_tokens) or \
        (kc.service_token_if_cached() or "x" * 40) in state
    res["leaks_withheld"] = console.leaks
    res["blocked_outside_broker"] = blocked[:5]
    denied = []
    for line in open(ledger_path, encoding="utf-8"):
        e = json.loads(line)
        if e["kind"] == "decision" and e["data"]["outcome"].startswith("denied"):
            denied.append(f'{e["data"]["method"]} {e["data"]["target"]} -> {e["data"]["outcome"]}: {e["data"]["reason"]}')
    res["denied_by_gate"] = sorted(set(denied))
    # Honest check: did the console's reset request actually reach the gate? (Not just "we clicked".)
    res["reset_request_reached_gate"] = any("reset-password" in d for d in denied)
    ev = kl.admin_events(base, "corp", env["reconciler"])
    res["keycloak_admin_events_on_cfo"] = [f'{e["operationType"]} {e["resourcePath"]}' for e in ev
                                           if env["users"]["cfo"] in e.get("resourcePath", "")]
    print(json.dumps(res, indent=1))
    kl.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
