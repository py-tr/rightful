"""Review finding #6: the broker trusted any X-Gate-Run from the private network. Now each request must carry the
edge's signature made with that run's own key (derived from a master key only the control plane holds)."""
import importlib
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from broker import runkey
from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from gate import Gate, Ledger, ReceiptStore, load_pack

MASTER = bytes.fromhex("11" * 32)
U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
READ = f"/admin/realms/corp/users/{U}"
RESET = f"/admin/realms/corp/users/{U}/reset-password"


@pytest.fixture
def env(tmp_path):
    seen = []

    def handler(req):
        if req.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "T", "expires_in": 300})
        seen.append((req.method, req.url.path))
        return httpx.Response(200, json={"id": U, "username": "cfo"})
    kc = Keycloak(KeycloakConfig("http://kc", "corp", "b", "s", "c", "s"),
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(handler)))
    receipts = ReceiptStore(":memory:")
    gate = Gate(load_pack("helpdesk"), receipts, Ledger(str(tmp_path / "l.jsonl")))
    app = create_app(gate, kc, Challenges(kc, receipts), run_key_master=MASTER)
    for r in ("run-1", "run-7"):
        app.state.open_run(r)
    client = TestClient(app)
    client.rebuild = lambda: create_app(Gate(load_pack("helpdesk"), receipts, Ledger(str(tmp_path / "l.jsonl"))),
                                        kc, Challenges(kc, receipts), run_key_master=MASTER)
    return client, seen, gate


def signed(run_id, method, target, body=b"", key=None, ts=None):
    ts = ts or str(int(time.time()))
    key = key or runkey.task_key(MASTER, run_id)
    return {"X-Gate-Run": run_id, "X-Gate-Ts": ts, "X-Gate-Sig": runkey.sign(key, run_id, ts, method, target, body)}


def test_signed_request_passes(env):
    c, seen, _ = env
    assert c.get(READ, headers=signed("run-1", "GET", READ)).status_code == 200 and seen


def test_unsigned_run_id_is_refused(env):
    c, seen, gate = env
    r = c.get(READ, headers={"X-Gate-Run": "run-1"})
    assert r.status_code == 401 and seen == []
    assert any(e["kind"] == "bad_signature" for e in gate.ledger.entries())


def test_another_runs_key_cannot_speak_for_this_run(env):
    """A compromised worker holds the keys of its own runs; it still cannot claim run-1 (approved elsewhere)."""
    c, seen, _ = env
    h = signed("run-1", "GET", READ, key=runkey.task_key(MASTER, "run-evil"))
    assert c.get(READ, headers=h).status_code == 401 and seen == []


def test_signature_is_bound_to_the_exact_request(env):
    c, seen, _ = env
    h = signed("run-1", "GET", READ)
    assert c.get(READ + "/credentials", headers=h).status_code == 401           # another path
    body = json.dumps({"type": "password", "temporary": True}).encode()
    h = signed("run-1", "PUT", RESET, body)
    assert c.put(RESET, content=body + b" ", headers=h).status_code == 401      # another body
    assert seen == []


def test_stale_signature_is_refused(env):
    c, seen, _ = env
    old = str(int(time.time()) - 600)
    assert c.get(READ, headers=signed("run-1", "GET", READ, ts=old)).status_code == 401 and seen == []


def test_window_is_120_seconds_and_skew_is_logged(env):
    c, seen, gate = env
    assert c.get(READ, headers=signed("run-1", "GET", READ, ts=str(int(time.time()) - 90))).status_code == 200
    assert c.get(READ, headers=signed("run-1", "GET", READ, ts=str(int(time.time()) - 130))).status_code == 401
    skews = [e["data"] for e in gate.ledger.entries() if e["kind"] == "clock_skew"]
    assert len(skews) == 2 and skews[0]["rejected"] is False and skews[1]["rejected"] is True


def test_a_run_that_was_never_opened_speaks_for_nothing(env):
    c, seen, _ = env
    assert c.get(READ, headers=signed("run-unknown", "GET", READ)).status_code == 401 and seen == []


def test_a_closed_run_speaks_for_nothing_even_after_a_restart(env):
    c, seen, _ = env
    c.app.state.close_run("run-1")
    assert c.get(READ, headers=signed("run-1", "GET", READ)).status_code == 401
    c2 = TestClient(c.rebuild())                                # broker restart: the lifecycle comes from the ledger
    assert c2.get(READ, headers=signed("run-1", "GET", READ)).status_code == 401
    assert c2.get(READ, headers=signed("run-7", "GET", READ)).status_code == 200   # still-open runs stay open
    assert len(seen) == 1


def test_run_ids_are_random():
    ids = {runkey.new_run_id() for _ in range(1000)}
    assert len(ids) == 1000 and all(len(i) == 24 for i in ids)


def test_challenge_routes_are_signed_too(env):
    c, _, _ = env
    assert c.get("/gate/v1/challenges/chl_x", headers={"X-Gate-Run": "run-1"}).status_code == 401
    assert c.get("/gate/v1/challenges/chl_x", headers=signed("run-1", "GET", "/gate/v1/challenges/chl_x")
                 ).status_code == 404                                            # authenticated, just unknown


def test_real_edge_to_real_broker_over_http(env, monkeypatch):
    """Over real sockets: what the edge signs (its request line) is what the broker verifies (raw path + query),
    including percent-encoding and a body. And the sandbox's forged headers are dropped."""
    import socket
    import threading
    from http.server import ThreadingHTTPServer

    import uvicorn
    from urllib.parse import urlsplit
    _, seen, gate = env
    kc_app = env[0].app
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(kc_app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    monkeypatch.setenv("RUN_ID", "run-7")
    monkeypatch.setenv("UPSTREAM", f"http://127.0.0.1:{port}")
    edge = importlib.import_module("sandbox.edge")
    monkeypatch.setattr(edge, "RUN_ID", "run-7")
    monkeypatch.setattr(edge, "RUN_KEY", runkey.task_key(MASTER, "run-7"))
    monkeypatch.setattr(edge, "UP", urlsplit(f"http://127.0.0.1:{port}"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), edge.Edge)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        forged = {"X-Gate-Run": "run-1", "X-Gate-Sig": "f" * 64, "X-Gate-Ts": "1"}
        assert httpx.get(base + READ, headers=forged).status_code == 200
        r = httpx.get(base + "/admin/realms/corp/users?search=jordan%40corp.example&max=5")
        assert r.status_code == 200
        r = httpx.put(base + RESET, content=b'{"type":"password","temporary":true}')
        assert r.status_code == 403 and "challenge_required" in r.json()        # signed fine; the gate decides
        assert not any(e["kind"] == "bad_signature" for e in gate.ledger.entries())
        runs = {e["data"].get("run") for e in gate.ledger.entries() if e["kind"] == "decision"}
        assert runs == {"run-7"}                                                # the forged run id never counted
        monkeypatch.setattr(edge, "RUN_KEY", "")                                # an edge with no key
        assert httpx.get(base + READ).status_code == 401
    finally:
        srv.shutdown()
        server.should_exit = True


def test_edge_under_raw_malformed_http(monkeypatch):
    """Mentor's fuzz order, the edge: length and encoding mismatches, chunked bodies, forged run headers, sent as raw
    bytes. Property: everything that leaves the edge carries ITS run id and a valid signature over exactly what was
    forwarded, whatever the sandbox sent."""
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit
    got = []

    class Up(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _any(self):
            n = int(self.headers.get("Content-Length") or 0)
            got.append((self.command, self.path, dict(self.headers), self.rfile.read(n) if n else b""))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        do_GET = do_PUT = do_POST = do_DELETE = _any

    up = ThreadingHTTPServer(("127.0.0.1", 0), Up)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    monkeypatch.setenv("RUN_ID", "run-e")
    monkeypatch.setenv("UPSTREAM", f"http://127.0.0.1:{up.server_address[1]}")
    edge = importlib.import_module("sandbox.edge")
    key = runkey.task_key(MASTER, "run-e")
    monkeypatch.setattr(edge, "RUN_ID", "run-e")
    monkeypatch.setattr(edge, "RUN_KEY", key)
    monkeypatch.setattr(edge, "UP", urlsplit(f"http://127.0.0.1:{up.server_address[1]}"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), edge.Edge)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    raw = [
        b"PUT /a HTTP/1.1\r\nHost: g\r\nContent-Length: 3\r\nX-Gate-Run: run-1\r\nX-Gate-Sig: ff\r\n\r\nabcdef",
        b"PUT /b HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        b"PUT /c HTTP/1.1\r\nHost: g\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nxyz",
        b"GET /d HTTP/1.1\r\nHost: g\r\nx-gate-run: run-1\r\nX-GATE-TS: 1\r\nX-Gate-Run: run-2\r\n\r\n",
        b"POST /e HTTP/1.1\r\nHost: g\r\nContent-Length: 0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: g\r\nX-Gate-Run: run-1\r\n\r\n",
        b"PUT /f HTTP/1.1\r\nHost: g\r\nContent-Length: abc\r\n\r\n",
        b"GARBAGE\r\n\r\n",
    ]
    try:
        for data in raw:
            s = socket.create_connection(srv.server_address, timeout=3)
            s.sendall(data)
            try:
                s.recv(4096)
                s.settimeout(0.5)
                s.recv(4096)
            except OSError:
                pass
            s.close()
        time.sleep(0.3)
        assert got, "nothing was forwarded at all"
        paths = [p for _, p, _, _ in got]
        assert "/b" not in paths and "/c" not in paths and "/f" not in paths    # bad framing: refused, not forwarded
        for method, path, hdrs, body in got:
            lower = {k.lower(): v for k, v in hdrs.items()}
            assert lower["x-gate-run"] == "run-e", (path, hdrs)                 # never a forged run
            assert runkey.verify(MASTER, "run-e", lower["x-gate-ts"], lower["x-gate-sig"], method, path, body) is None
            assert len([k for k in hdrs if k.lower() == "x-gate-run"]) == 1
    finally:
        srv.shutdown()
        up.shutdown()


def test_edge_and_broker_sign_identically(monkeypatch):
    monkeypatch.setenv("RUN_ID", "run-1")
    monkeypatch.setenv("UPSTREAM", "http://broker:8090")
    edge = importlib.import_module("sandbox.edge")
    key = runkey.task_key(MASTER, "run-1")
    args = ("run-1", "1700000000", "PUT", RESET + "?x=1", b'{"a":1}')
    assert edge.sign(key, *args) == runkey.sign(key, *args)
