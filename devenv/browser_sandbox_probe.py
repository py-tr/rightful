"""Pattern B inside the sandbox: headless Chromium in the browser task container drives the real Keycloak console
through the edge proxy and the broker, tries an unapproved "Set password" on the CFO, and we check that the gate
refused it and Keycloak's own admin-event log shows nothing. Local only, no model calls, $0.
Run: python -m devenv.browser_sandbox_probe
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time

import httpx
import uvicorn

from agent.runner import BrowserRunner
from broker.app import create_app
from broker.challenges import Challenges
from broker.console import ConsoleSession
from broker.keycloak import Keycloak, KeycloakConfig
from broker.pushsvc import create_push_app
from devenv import keycloak_local as kl
from gate import Gate, Ledger, ReceiptStore, load_pack

PUBLIC = "http://gate:8080"          # the only address the sandboxed browser can reach
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "browser")

IN_SANDBOX = r'''
import json, time
from playwright.sync_api import sync_playwright
res = {}
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    pg = b.new_page(viewport={"width": 1366, "height": 860})
    pg.goto("http://gate:8080/admin/corp/console/#/corp/users", wait_until="domcontentloaded", timeout=60000)
    time.sleep(10)
    pg.screenshot(path="/out/1-console.png")
    try:
        pg.get_by_role("link", name="cfo", exact=True).first.click(timeout=15000); time.sleep(4)
        pg.get_by_role("tab", name="Credentials").click(timeout=10000); time.sleep(3)
        pg.screenshot(path="/out/2-credentials.png")
        pg.get_by_role("button", name="Set password").first.click(timeout=10000); time.sleep(1.5)
        pw = pg.locator("input[type=password]")
        pw.nth(0).fill("Agent-Typed-Pw-1"); pw.nth(1).fill("Agent-Typed-Pw-1")
        pg.get_by_role("button", name="Save").click(timeout=5000); time.sleep(1)
        pg.get_by_role("button", name="Save password").click(timeout=5000); time.sleep(3)
        res["clicked_reset"] = True
    except Exception as e:
        res["clicked_reset"] = "failed: " + str(e)[:150]
    pg.screenshot(path="/out/3-after-reset.png")
    st = pg.evaluate("() => JSON.stringify({ls: Object.assign({}, localStorage), ss: Object.assign({}, sessionStorage), dc: document.cookie})")
    res["browser_state_chars"] = len(st)
    open("/out/browser-state.json", "w").write(st)
    b.close()
print(json.dumps(res))
'''


def serve(app, host, port):
    srv = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    threading.Thread(target=srv.run, daemon=True).start()
    while not srv.started:
        time.sleep(0.1)
    return srv


def main() -> int:
    base = kl.start(public_url=PUBLIC)
    env = kl.bootstrap(base)
    led_dir = tempfile.mkdtemp(prefix="keyless-browser-")
    led = Ledger(os.path.join(led_dir, "ledger.jsonl"))
    receipts = ReceiptStore(":memory:")
    pack = load_pack("helpdesk")
    gate = Gate(pack, receipts, led)
    host = {"Host": PUBLIC.split("://")[1]}
    kc = Keycloak(KeycloakConfig(base, "corp", *env["broker"], *env["ciba"]),
                  http=httpx.Client(base_url=base, timeout=15, headers=host))
    console = ConsoleSession(base, PUBLIC, "corp", *env["console"])
    push = create_push_app(base, "corp")
    ch = Challenges(kc, receipts, pack=pack, notify=push.state.notify)
    app = create_app(gate, kc, ch, deliver_secret=push.state.deliver, notify=push.state.notify, console=console)
    serve(push, "0.0.0.0", 8099)
    serve(app, "127.0.0.1", 8090)
    cfo = env["users"]["cfo"]
    baseline = [e for e in kl.admin_events(base, "corp", env["reconciler"]) if cfo in e.get("resourcePath", "")]
    run_id = "browser-sandbox-probe"
    r = BrowserRunner(run_id, "INC-1 | user: cfo", out_dir=OUT).start()
    report = {}
    try:
        report["scorecard"] = r.probe()
        rc, out, err = r.run(IN_SANDBOX)
        report["script_exit"], report["script_out"], report["script_err"] = rc, out.strip()[-400:], err.strip()[-600:]
    finally:
        r.close()
    denied, reads = [], 0
    for line in (open(led.path, encoding="utf-8") if os.path.exists(led.path) else []):
        e = json.loads(line)
        if e["kind"] == "decision":
            if e["data"]["outcome"].startswith("denied"):
                denied.append(f'{e["data"]["method"]} {e["data"]["target"][:90]} -> {e["data"]["outcome"]}')
            else:
                reads += 1
    report["gate_reads_allowed"] = reads
    report["gate_denied"] = denied
    report["reset_reached_gate_and_was_refused"] = any("reset-password" in d and "no_receipt" in d for d in denied)
    ev = kl.admin_events(base, "corp", env["reconciler"])
    on_cfo = [e for e in ev if cfo in e.get("resourcePath", "")]
    report["keycloak_events_on_cfo_before_browser"] = [f'{e["operationType"]} {e["resourcePath"].split("/")[-1]}' for e in baseline]
    report["keycloak_events_on_cfo_DURING_browser"] = [f'{e["operationType"]} {e["resourcePath"]}'
                                                      for e in on_cfo[: len(on_cfo) - len(baseline)]]
    state = open(os.path.join(OUT, "browser-state.json"), encoding="utf-8").read() if os.path.exists(
        os.path.join(OUT, "browser-state.json")) else ""
    report["real_token_in_browser"] = any(t in state for t in console.real_tokens)
    report["console_leaks_withheld"] = console.leaks
    report["console_route_refused"] = console.refused
    print(json.dumps(report, indent=1))
    kl.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
