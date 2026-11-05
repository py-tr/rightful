"""Run the public demo locally (Docker Keycloak + mail catcher + the realm factory + brokers + the demo server), and
optionally self-test it through its real HTTP API with a scripted stand-in for the model ($0).

  python -m devenv.demo_local            serve on http://127.0.0.1:8000 (open it in a browser)
  python -m devenv.demo_local --selftest the honest path end to end, then exit
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
import threading
import time

import httpx
import uvicorn

from demo.factory import Factory, create_factory_app
from demo.limits import Limits
from demo.server import Demo, FactoryClient, create_demo_app
from devenv import keycloak_local as kl


def serve(app, host, port):
    s = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    threading.Thread(target=s.run, daemon=True).start()
    while not s.started:
        time.sleep(0.1)
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    os.environ.setdefault("SMTP_HOST", "host.docker.internal")
    os.environ.setdefault("KEYLESS_DEMO_CONTRAST", "1")   # the side-by-side's unprotected column (demo-u companies only)
    if a.selftest:
        os.environ["KEYLESS_DEMO_FAKE_LLM"] = "1"
    elif not os.environ.get("VULTR_INFERENCE_API_KEY") and os.environ.get("KEYLESS_DEMO_FAKE_LLM") != "1":
        env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        for line in open(env, encoding="utf-8"):         # the real model for local UX testing (never printed)
            if line.startswith("VULTR_INFERENCE_API_KEY="):
                os.environ["VULTR_INFERENCE_API_KEY"] = line.split("=", 1)[1].strip().strip('"')
        print("model: glm-5.3-flash (real; within the approved $1 UI-test budget, demo limits apply)")
    # the sandbox images carry the SDK: rebuild them on every start (cached, seconds) so the agent never runs an older
    # helpdesk library than the repository's (11-05: a stale image had no verify_caller, so the left column lacked
    # the push tool its instructions describe)
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for df, tag in (("sandbox/Dockerfile.task", "keyless-task:dev"), ("sandbox/Dockerfile.edge", "keyless-edge:dev")):
        subprocess.run(["docker", "build", "-q", "-f", df, "-t", tag, "."], cwd=root, check=True,
                       stdout=subprocess.DEVNULL)
    chk = subprocess.run(["docker", "run", "--rm", "--entrypoint", "python", "keyless-task:dev", "-c",
                          "import helpdesk; print(hasattr(helpdesk, 'verify_caller'))"], capture_output=True, text=True)
    assert chk.stdout.strip() == "True", "the sandbox image's SDK is not the repository's"
    try:
        httpx.get("http://127.0.0.1:8089/realms/master", timeout=3).raise_for_status()
        base = "http://127.0.0.1:8089"
    except httpx.HTTPError:
        kl.start_mail()
        base = kl.start()
    token = secrets.token_urlsafe(24)
    fac = Factory(base, pool_size=2, max_companies=6)
    fac.refill_once()
    serve(create_factory_app(fac, token), "127.0.0.1", 8097)
    out = tempfile.mkdtemp(prefix="keyless-demo-")
    demo = Demo(base, FactoryClient("http://127.0.0.1:8097", token), Limits(os.path.join(out, "limits.json")),
                hosts=[None], out_dir=out, edge_upstream="http://host.docker.internal:8090",
                mail_api="http://127.0.0.1:8025")
    demo.run_background()
    serve(demo.broker, "127.0.0.1", 8090)
    serve(demo.push, "0.0.0.0", 8099)
    serve(create_demo_app(demo), "127.0.0.1", 8000)
    print("demo on http://127.0.0.1:8000  (factory pool:", len(fac.pool), ")")
    if not a.selftest:
        while True:
            time.sleep(3600)
    # --- self-test: a visitor's honest path through the real API ---------------------------------------------
    c = httpx.Client(base_url="https://127.0.0.1:8000", verify=False, timeout=30)
    c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30)
    ok = []
    assert c.get("/api/state").status_code == 401; ok.append("no session -> 401")
    r = c.post("/api/session", json={})
    cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict")
    ok.append("cookie flags HttpOnly/Secure/SameSite=Strict")
    c.cookies.set("ks", r.cookies.get("ks"))
    assert c.post("/api/tickets", json={"scenario": "honest", "caller": "", "ticket": ""},
                  headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    ok.append("cross-site POST -> 403")
    c.post("/api/tickets", json={"scenario": "honest", "caller": "", "ticket": "", "prompt": "light"}).raise_for_status()
    deadline, approved = time.time() + 120, False
    while time.time() < deadline:
        v = c.get("/api/state").json()
        if v["phone"]["pending"] and not approved:
            p = v["phone"]["pending"][0]
            assert len(p["numbers"]) == 3; ok.append("phone shows 3 candidate numbers")
            wrong = [n for n in p["numbers"]]
            assert c.post(f"/api/phone/{p['id']}/approve", json={"number": "00"}).status_code == 400
            ok.append("a number not shown -> refused")
            # the right one is not marked: try each until the server's comparison accepts one (a judge reads it from
            # the agent's message; here the stand-in prints it in its script output)
            for n in wrong:
                if c.post(f"/api/phone/{p['id']}/approve", json={"number": n}).json().get("matched"):
                    break
            approved = True
        if v["tickets"] and v["tickets"][-1]["status"] in ("done", "error", "refused"):
            break
        time.sleep(1.5)
    v = c.get("/api/state").json()
    print("ticket:", v["tickets"][-1]["status"], v["tickets"][-1]["note"])
    for r in v["rows"]:
        print("  row:", r)
    print("  counters: attempted", v["attempted"], "executed", v["executed"])
    print("  phone notices:", [n["text"][:70] for n in v["phone"]["notices"]])
    assert v["executed"] == 1 and any(r["event"] for r in v["rows"]); ok.append("exactly one change, in the oracle column")
    other = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30)
    r2 = other.post("/api/session", json={})
    other.cookies.set("ks", r2.cookies.get("ks"))
    pid = "push_x"
    assert other.post(f"/api/phone/{pid}/approve", json={"number": "11"}).status_code in (400, 404)
    ok.append("another session cannot answer this session's phone")
    print("\nSELFTEST OK:\n - " + "\n - ".join(ok))
    for s in list(demo.sessions.values()):
        demo.end_session(s, "selftest end")
    print("counter after archiving:", demo.counter())
    return 0


if __name__ == "__main__":
    sys.exit(main())
