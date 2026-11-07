"""Run the public demo locally (Docker Keycloak + mail catcher + the realm factory + brokers + the demo server), and
optionally self-test it through its real HTTP API with a scripted stand-in for the model ($0).

  python -m devenv.demo_local            serve on http://127.0.0.1:8000 (open it in a browser)
  python -m devenv.demo_local --selftest the honest path end to end, then exit
"""
from __future__ import annotations

import argparse
import json
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
    # --- self-test: compare mode through the real API (rewritten 11-06; the old one predated compare mode) ---------
    ok = []
    probe = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30)
    assert probe.post("/api/say", json={"text": "hi"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    ok.append("cross-site POST -> 403")

    def visitor():
        """A fresh compare-mode visitor (its own two fictional companies): a decline in one company freezes retries on
        that account (the tripwire), so each phone outcome gets its own visitor."""
        before = set(demo.sessions)
        cl = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30)
        r = cl.post("/api/compare", json={"on": True})
        cookie = r.headers.get("set-cookie", "")
        assert r.json().get("compare") and "HttpOnly" in cookie and "Secure" in cookie
        cl.cookies.set("ks", r.cookies.get("ks"))
        new = next(demo.sessions[k] for k in set(demo.sessions) - before if demo.sessions[k].twin is not None)
        return cl, new

    def converse(choose_right: bool) -> dict:
        c, sess = visitor()
        n0 = len(c.get("/api/events").json()["events"])
        c.post("/api/say", json={"text": "Hi, I'm Jordan, I'm locked out of my account."}).raise_for_status()
        answered, deadline = False, time.time() + 240
        while time.time() < deadline:
            v = c.get("/api/events").json()
            right = [p for p in v["phone"]["pending"] if p.get("company") == "right"]
            if right and not answered:
                p = right[0]
                assert len(p["numbers"]) == 3
                true = sess.stack.push.state.pending[p["id"]]["number"]
                pick = true if choose_right else next(n for n in p["numbers"] if n != true)
                res = c.post(f"/api/phone/{p['id']}/approve", json={"number": pick}).json()
                assert res["ok"] is choose_right, res
                if not choose_right:     # the wrong tap declined it: the right number no longer works
                    assert c.post(f"/api/phone/{p['id']}/approve", json={"number": true}).json().get("ok") is not True
                answered = True
            if answered and not v["busy"] and not v["left"]["busy"]:
                time.sleep(2)
                break
            time.sleep(1.5)
        evs = c.get("/api/events").json()["events"][n0:]
        verdicts = [e["text"] for e in evs if e["who"] == "gate" and e.get("verdict")]
        sources = [e.get("source") for e in evs if e["who"] == "gate" and e.get("verdict")]
        print("  right verdicts:", verdicts, sources)
        tiles = [e for e in evs if e["who"] == "tiles"]

        strip = c.get("/api/events").json().get("strip") or {}
        print("  tiles:", [(t["tried"], t["recorded"]) for t in tiles], "| strip:", {k: strip.get(k) for k in
                                                                                  ("kernel", "gvisor", "model")})
        return {"answered": answered, "verdicts": verdicts, "sources": sources, "tiles": tiles, "strip": strip,
                "rules": [e["rule"] for e in evs if e.get("rule")],
                "sandbox": [e for e in evs if e["who"] == "sandbox"],
                "step_containers": [e.get("container") for e in evs if e["who"] == "step"],
                "restart_offered": any(e["who"] == "explain" and e.get("restart") for e in evs),
                "wrong_number_line": any(e["text"].startswith("Wrong number: request declined") for e in evs)}

    ok.append("compare sessions; cookie HttpOnly/Secure")
    a = converse(choose_right=False)
    assert a["answered"] and any("identity server's own log shows no change" in t for t in a["verdicts"]), a
    ok.append("wrong number: push declined, no second try; verdict cites the identity server's log (no change)")
    assert a["wrong_number_line"] and a["restart_offered"], a
    ok.append("mis-tap explained, with a start-over button")
    assert any(s and "Keycloak admin-event log" in s for s in a["sources"]), a
    ok.append("verdict names its source (Keycloak admin-event log, view-only)")
    assert any('operation "reset_password"' in r and "account owner" in r for r in a["rules"]), a["rules"]
    ok.append("the refusal cites its policy rule: " + next(r for r in a["rules"] if "reset_password" in r)[:90] + "...")
    assert a["tiles"] and a["tiles"][-1]["recorded"] == "nothing" and "reset" in a["tiles"][-1]["tried"], a["tiles"]
    ok.append("tiles: 'Agent tried: reset the password' over 'Identity server recorded: nothing', each with its source")
    assert a["strip"].get("kernel") and "model" in a["strip"] and not a["strip"].get("error"), a["strip"]
    ok.append(f"run strip measured inside the sandbox (kernel {a['strip']['kernel']}, gVisor={a['strip']['gvisor']})")
    assert demo.broker.apps == {}, demo.broker.apps
    ok.append("run routes dropped after the conversation (no leak)")
    b = converse(choose_right=True)
    assert b["answered"] and any("identity server's log shows 1 change" in t for t in b["verdicts"]), b
    ok.append("right number: verdict cites the identity server's log (1 change)")
    assert demo.broker.apps == {}, demo.broker.apps
    ok.append("routes dropped again after the second conversation")
    for x in (a, b):                                   # mentor 11-07: the containment bullets, measured per script
        assert x["sandbox"], "no measured sandbox line"
        sb = x["sandbox"][-1]
        print("  sandbox:", sb["text"])
        assert sb["scripts"] >= 1 and sb["containers"] == sb["scripts"] == sb["gone"] and not sb["unknown"], sb
        assert all(x["step_containers"]) and len(set(x["step_containers"])) == len(x["step_containers"]), x["step_containers"]
    all_ids = a["sandbox"][-1]["ids"] + b["sandbox"][-1]["ids"]
    assert len(set(all_ids)) == len(all_ids), all_ids
    ok.append(f"sandbox lifecycle measured: {len(all_ids)} scripts, {len(set(all_ids))} distinct containers, every one "
              "confirmed gone by Docker afterwards; each step shows its container id")
    pol = httpx.get("http://127.0.0.1:8000/api/policy", timeout=30).json()
    page = httpx.get("http://127.0.0.1:8000/policy", timeout=30)
    assert page.status_code == 200 and len(pol["sha256"]) == 64 and any(
        r["operation"] == "reset_password" and "owner" in r["approver"] for r in pol["rules"]), pol
    recs = [json.loads(x) for x in open(os.path.join(demo.out_dir, "proofs.jsonl"), encoding="utf-8")]
    assert any(r.get("policy_sha256") == pol["sha256"] for r in recs), "no share record carries the policy hash"
    evs = [ln.get("event") for r in recs for ln in r.get("proof", []) if ln.get("event")]
    assert any(e.get("operationType") and "reset-password" in (e.get("resourcePath") or "") for e in evs), evs[:2]
    ok.append("share record carries Keycloak's own event (operationType, resourcePath, time) for the approved change")
    ok.append(f"policy page from the live pack ({len(pol['rules'])} rules, sha256 {pol['sha256'][:12]}...), its hash on share links")
    pv = httpx.Client(base_url="http://127.0.0.1:8000", timeout=120)
    r = pv.post("/api/prove", json={})
    assert r.status_code == 200, r.text[:300]
    j = r.json()
    ins, rep = j["inside"], j["replay"]
    print("  prove:", {k: v for k, v in ins["checks"].items() if not v} or "all checks hold", "| kernel", ins["kernel"],
          "| replay", rep["refused"], "/", rep["attempts"], "| events", rep["admin_events_before"], "->",
          rep["admin_events_after"])
    assert ins["checks"].get("keycloak_unreachable") and ins["checks"].get("no_secrets_in_env"), ins
    assert rep["refused"] == rep["attempts"] == 24 and rep["admin_events_after"] == rep["admin_events_before"], rep
    ok.append(f"containment check: identity server unreachable from the sandbox; {rep['refused']}/{rep['attempts']} "
              "token replays refused; admin-event log unchanged")
    pv.cookies.set("ks", r.cookies.get("ks"))
    again = pv.post("/api/prove", json={})
    assert again.status_code == 429 and "per minute" in again.text, again.text[:200]
    ok.append("containment check limited to one per address per minute")
    d0 = demo.deletions()
    n_cols = sum(1 + (s.twin is not None and s.twin.stack is not None) for s in demo.sessions.values() if s.stack)
    for s in list(demo.sessions.values()):
        demo.end_session(s, "selftest end")
    d1 = demo.deletions()
    print("  deletions:", d0, "->", d1)
    assert d1["deleted"] - d0["deleted"] == n_cols and d1["confirmed_gone"] - d0["confirmed_gone"] == n_cols, (d0, d1)
    ok.append(f"companies deleted at the end of their session: {n_cols} of {n_cols} confirmed gone by the identity server "
              "(404)")
    print("\nSELFTEST OK:\n - " + "\n - ".join(ok))
    return 0

if __name__ == "__main__":
    sys.exit(main())
