"""Mentor's review of the per-session demo: the seams between sessions. Two visitors' fake companies on a real
Keycloak, both with a user called `cfo`. Run with KEYLESS_LIVE=1.
- one session's agent cannot address the other company by path (refused, and no event in the other realm);
- push rate limits and phones are per session (A using up its pushes does not limit B; A's phone never shows B's push).
"""
import os
import secrets
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from broker import runkey

pytestmark = pytest.mark.skipif(os.environ.get("KEYLESS_LIVE") != "1", reason="set KEYLESS_LIVE=1 (needs Docker)")


@pytest.fixture(scope="module")
def two_sessions():
    from demo.stack import SessionStack
    from devenv import keycloak_local as kl
    os.environ.setdefault("SMTP_HOST", "host.docker.internal")
    base = kl.start()
    master = secrets.token_bytes(32)
    out = tempfile.mkdtemp()
    a = SessionStack(base, out, master).create()
    b = SessionStack(base, out, master).create()
    import threading

    import uvicorn

    from eval.dispatch import PushDispatch
    push = PushDispatch()                         # Keycloak's one CIBA channel URL, routed by realm (as in deployment)
    push.register(a.realm, a.push)
    push.register(b.realm, b.push)
    srv = uvicorn.Server(uvicorn.Config(push, host="0.0.0.0", port=8099, log_level="error"))
    threading.Thread(target=srv.run, daemon=True).start()
    while not srv.started:
        time.sleep(0.1)
    yield a, b, master
    srv.should_exit = True
    a.close()
    b.close()


def client(stack, master, run_id):
    stack.app.state.open_run(run_id, "full")
    c = TestClient(stack.app)

    def req(method, path, body=b""):
        ts = str(int(time.time()))
        sig = runkey.sign(runkey.task_key(master, run_id), run_id, ts, method, path, body)
        return c.request(method, path, content=body, headers={"X-Gate-Run": run_id, "X-Gate-Ts": ts, "X-Gate-Sig": sig})
    return req


def test_one_session_cannot_address_the_other_company(two_sessions):
    a, b, master = two_sessions
    req = client(a, master, "run-a1")
    b_cfo = b.users()["cfo"]
    for method, path, body in (
            ("PUT", f"/admin/realms/{b.realm}/users/{b_cfo}/reset-password", b'{"type":"password","temporary":true}'),
            ("GET", f"/admin/realms/{b.realm}/users/{b_cfo}", b""),
            ("PUT", f"/admin/realms/{b.realm}/users/{b_cfo}", b'{"email":"x@evil.example"}'),
            ("POST", f"/gate/v1/actions/mfa-recovery-lost-device/{b_cfo}", b"")):
        r = req(method, path, body)
        assert r.status_code in (403, 404), (method, path, r.status_code, r.text[:200])
        assert "challenge_required" not in r.text or b.realm not in path      # never a push for the other company
    assert b.events() == []                                                     # B's own log: untouched


def test_push_limits_and_phones_are_per_session(two_sessions):
    a, b, master = two_sessions
    rb = client(b, master, "run-b2")
    reset = lambda s: (f"/admin/realms/{s.realm}/users/{s.users()['cfo']}/reset-password",  # noqa: E731
                       b'{"type":"password","temporary":true}')
    statuses = []
    for i in range(4):     # A uses up its pushes (limit 3 per approver); one run each (4 repeats in one run quarantine)
        ra = client(a, master, f"run-a2-{i}")
        p, body = reset(a)
        ch = ra("PUT", p, body).json()["challenge_required"]["challenge"]
        statuses.append(ra("POST", f"/gate/v1/challenges/{ch}/send").json()["status"])
    assert statuses == ["sent", "sent", "sent", "rate_limited"]
    p, body = reset(b)
    ch = rb("PUT", p, body).json()["challenge_required"]["challenge"]
    assert rb("POST", f"/gate/v1/challenges/{ch}/send").json()["status"] == "sent"   # B is not limited by A
    time.sleep(1.5)
    pa = TestClient(a.push).get("/phone/cfo").json()["pending"]
    pb = TestClient(b.push).get("/phone/cfo").json()["pending"]
    assert pb and all(a.realm not in str(x) for x in pb)
    b_binding = pb[0]["binding"]
    assert all(x["binding"] != b_binding for x in pa)                          # A's phone never shows B's push
