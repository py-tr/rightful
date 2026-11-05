"""End-to-end through the broker app with an in-process fake Keycloak that records what reaches it."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from gate import Gate, Ledger, ReceiptStore, load_pack

U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
RESET = f"/admin/realms/corp/users/{U}/reset-password"
BODY = json.dumps({"type": "password", "temporary": True, "value": "agent-typed"}).encode()
TOKEN = "REAL-ADMIN-TOKEN-xyz"


class FakeKeycloak:
    def __init__(self):
        self.upstream = []            # admin-API requests that reached "Keycloak"
        self.ciba = {}                # auth_req_id -> state
        self.ciba_requests = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/protocol/openid-connect/token"):
            form = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            if form.get("grant_type") == "client_credentials":
                return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 300})
            state = self.ciba.get(form.get("auth_req_id", "").replace("%3A", ":"), "expired")
            if state == "approved":
                return httpx.Response(200, json={"access_token": "OWNER-TOKEN", "expires_in": 60})
            err = {"pending": "authorization_pending", "denied": "access_denied"}.get(state, "invalid_grant")
            return httpx.Response(400, json={"error": err})
        if p.endswith("/ext/ciba/auth"):
            rid = f"req{len(self.ciba) + 1}"
            self.ciba[rid] = "pending"
            self.ciba_requests.append(req.content.decode())
            return httpx.Response(200, json={"auth_req_id": rid, "expires_in": 120})
        if req.method == "GET" and p == f"/admin/realms/corp/users/{U}":
            return httpx.Response(200, json={"id": U, "username": "cfo"},
                                  headers={"Set-Cookie": "KEYCLOAK_IDENTITY=secret"})
        self.upstream.append({"method": req.method, "path": p, "auth": req.headers.get("authorization"),
                              "body": req.content.decode()})
        if getattr(self, "fail_writes", False):
            return httpx.Response(500, json={"error": "unknown_error"})
        return httpx.Response(204)


@pytest.fixture
def env(tmp_path):
    fake = FakeKeycloak()
    http = httpx.Client(base_url="http://kc", transport=httpx.MockTransport(fake.handler))
    kc = Keycloak(KeycloakConfig("http://kc", "corp", "gate-broker", "s1", "gate-ciba", "s2"), http=http)
    receipts = ReceiptStore(":memory:")
    gate = Gate(load_pack("helpdesk"), receipts, Ledger(str(tmp_path / "ledger.jsonl")),
                secret_factory=lambda: "BROKER-PW-1")
    delivered, quarantined = [], []
    app = create_app(gate, kc, Challenges(kc, receipts, min_poll_interval=0), deliver_secret=lambda u, s: delivered.append((u, s)),
                     on_quarantine=lambda r, why: quarantined.append((r, why)))
    client = TestClient(app)
    return fake, client, delivered, quarantined, gate


H = {"X-Gate-Run": "run-1"}


def test_missing_run_header_is_refused(env):
    fake, c, *_ = env
    assert c.put(RESET, content=BODY).status_code == 400
    assert fake.upstream == []


def test_full_honest_loop(env):
    fake, c, delivered, quarantined, gate = env
    r = c.put(RESET, content=BODY, headers=H)                       # 1. denied, challenge offered
    assert r.status_code == 403
    ch = r.json()["challenge_required"]
    assert ch["operation"] == "reset_password" and fake.upstream == []
    s = c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H).json()   # 2. push to the owner
    assert s["status"] == "sent" and s["number"] == ch["number"]
    assert "binding_message=" + ch["number"] + "-reset-cfo.d02c-" in fake.ciba_requests[0]
    assert c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"] == "sent"   # pending
    fake.ciba["req1"] = "approved"                                  # 3. the owner approves on the phone
    assert c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"] == "approved"
    r = c.put(RESET, content=BODY, headers=H)                       # 4. the same request again
    assert r.status_code == 204
    up = fake.upstream[0]
    assert up["auth"] == f"Bearer {TOKEN}" and json.loads(up["body"])["value"] == "BROKER-PW-1"
    assert delivered == [("cfo", "BROKER-PW-1")]                    # the password went to the owner's device
    assert quarantined == []
    assert c.put(RESET, content=BODY, headers=H).status_code == 403  # 5. replay: receipt already burned
    assert len(fake.upstream) == 1


def test_sandbox_never_sees_token_cookie_or_secret(env):
    fake, c, *_ = env
    r = c.get(f"/admin/realms/corp/users/{U}", headers=H)
    assert r.status_code == 200 and "set-cookie" not in {k.lower() for k in r.headers}
    assert TOKEN not in r.text
    r = c.put(RESET, content=BODY, headers=H)
    assert TOKEN not in r.text and "BROKER-PW" not in r.text and "rcpt_" not in r.text


def test_approval_in_one_run_does_not_help_another_run(env):
    fake, c, *_ = env
    ch = c.put(RESET, content=BODY, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["req1"] = "approved"
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    other = {"X-Gate-Run": "run-2"}
    assert c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=other).status_code == 404
    assert c.put(RESET, content=BODY, headers=other).status_code == 403
    assert fake.upstream == []


def test_denied_by_owner_means_no_receipt(env):
    fake, c, *_ = env
    ch = c.put(RESET, content=BODY, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["req1"] = "denied"
    assert c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"] == "denied"
    assert c.put(RESET, content=BODY, headers=H).status_code == 403
    assert fake.upstream == []


def test_push_flood_is_rate_limited(env):
    fake, c, *_ = env
    statuses = []
    for _ in range(5):
        ch = c.put(RESET, content=BODY, headers={"X-Gate-Run": f"run-{len(statuses) + 10}"}).json()["challenge_required"]
        statuses.append(c.post(f"/gate/v1/challenges/{ch['challenge']}/send",
                               headers={"X-Gate-Run": f"run-{len(statuses) + 10}"}).json()["status"])
    assert statuses == ["sent", "sent", "sent", "rate_limited", "rate_limited"]
    assert len(fake.ciba_requests) == 3


def test_forbidden_write_quarantines_the_run(env):
    fake, c, _, quarantined, _ = env
    r = c.put("/admin/realms/corp/events/config", content=b'{"adminEventsEnabled":false}', headers=H)
    assert r.status_code == 403 and r.json().get("quarantined")
    assert quarantined and quarantined[0][0] == "run-1"
    assert c.get(f"/admin/realms/corp/users/{U}", headers=H).status_code == 403   # the run is blocked from now on
    assert fake.upstream == []


def _approve_and_retry(fake, c):
    ch = c.put(RESET, content=BODY, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["req1"] = "approved"
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    return c.put(RESET, content=BODY, headers=H)


def test_upstream_refusal_is_never_recorded_as_executed(env):
    """Review finding #3: the ledger said "executed" before Keycloak answered. Keycloak now fails the approved write
    with a 500: the caller's 'changes to your account' line must say none, and a claimed reset must be held."""
    from agent.claims import changes_line, check
    fake, c, delivered, _, gate = env
    fake.fail_writes = True
    r = _approve_and_retry(fake, c)
    assert r.status_code == 500 and len(fake.upstream) == 1         # it really was forwarded, and really failed
    kinds = [e["kind"] for e in gate.ledger.entries()]
    assert "forwarding" in kinds and "upstream_failed" in kinds and "executed" not in kinds
    assert changes_line(gate.ledger.path, "run-1").endswith("none.")
    assert check("I have reset your password.", gate.ledger.path, "run-1")[0] == "held"
    assert delivered == []                                          # no password delivered for a reset that failed


def test_upstream_success_is_recorded_as_executed(env):
    from agent.claims import changes_line
    fake, c, _, _, gate = env
    assert _approve_and_retry(fake, c).status_code == 204
    assert "temporary password set" in changes_line(gate.ledger.path, "run-1")


def test_semicolon_path_never_reaches_keycloak(env):
    fake, c, _, quarantined, _ = env
    r = c.put(f"/admin/realms/corp/users/{U};x=y/reset-password", content=BODY, headers=H)
    assert r.status_code == 403 and fake.upstream == [] and quarantined
