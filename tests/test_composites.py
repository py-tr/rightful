"""Lost-device recovery and compromise response: one approval, broker-executed fixed steps, approver set by policy."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from gate import Gate, Ledger, ReceiptStore, load_pack

CFO = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
NOMGR = "e1a2b3c4-c4a5-4c86-9912-27a5a18fb8cd"
SELFMGR = "f1a2b3c4-c4a5-4c86-9912-27a5a18fb8cd"
OTP = "0b9b2a3e-1111-4c86-9912-27a5a18fb8cd"
LOST = f"/gate/v1/actions/mfa-recovery-lost-device/{CFO}"
H = {"X-Gate-Run": "run-1"}


class FakeKC:
    def __init__(self, fail_on=None):
        self.users = {CFO: {"username": "cfo", "attributes": {"manager": ["ceo"]}},
                      NOMGR: {"username": "contractor", "attributes": {}},
                      SELFMGR: {"username": "boss", "attributes": {"manager": ["boss"]}}}
        self.calls, self.ciba, self.ciba_req, self.fail_on = [], {}, [], fail_on

    def handler(self, req):
        p, m = req.url.path, req.method
        if p.endswith("/openid-connect/token"):
            f = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            if f.get("grant_type") == "client_credentials":
                return httpx.Response(200, json={"access_token": "SA-TOKEN", "expires_in": 300})
            st = self.ciba.get(f.get("auth_req_id"), "x")
            return httpx.Response(200, json={"access_token": "t"}) if st == "approved" else \
                httpx.Response(400, json={"error": "authorization_pending" if st == "pending" else "access_denied"})
        if p.endswith("/ext/ciba/auth"):
            rid = f"r{len(self.ciba) + 1}"
            self.ciba[rid] = "pending"
            self.ciba_req.append(dict(x.split("=", 1) for x in req.content.decode().split("&")))
            return httpx.Response(200, json={"auth_req_id": rid})
        for uid, u in self.users.items():
            if m == "GET" and p == f"/admin/realms/corp/users/{uid}":
                return httpx.Response(200, json={"id": uid, **u})
        if m == "GET" and p.endswith("/credentials"):
            return httpx.Response(200, json=[{"id": OTP, "type": "otp"}, {"id": "pw1", "type": "password"}])
        self.calls.append((m, p, dict(req.url.params), req.content.decode()))
        if self.fail_on and self.fail_on in p:
            return httpx.Response(500)
        return httpx.Response(204)


def build(tmp_path, fail_on=None):
    fake = FakeKC(fail_on)
    kc = Keycloak(KeycloakConfig("http://kc", "corp", "b", "s", "c", "s"),
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(fake.handler)))
    receipts = ReceiptStore(":memory:")
    gate = Gate(load_pack("helpdesk"), receipts, Ledger(str(tmp_path / "l.jsonl")))
    notices, secrets_out = [], []
    ch = Challenges(kc, receipts, pack={"cooling_off_seconds": {"default": 0, "privileged": 0}})
    app = create_app(gate, kc, ch, deliver_secret=lambda u, s: secrets_out.append((u, s)),
                     notify=lambda u, t: notices.append((u, t)))
    return fake, TestClient(app), notices, secrets_out


def approve_flow(fake, c, path):
    ch = c.post(path, headers=H).json()["challenge_required"]
    s = c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H).json()
    fake.ciba[f"r{len(fake.ciba)}"] = "approved"
    st = c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"]
    return ch, s, st


def test_lost_device_goes_to_the_manager_not_the_lost_phone(tmp_path):
    fake, c, notices, _ = build(tmp_path)
    ch, s, st = approve_flow(fake, c, LOST)
    assert ch["approver"] == "manager" and s["status"] == "sent" and st == "approved"
    assert fake.ciba_req[0]["login_hint"] == "ceo"                     # the manager's phone, not the cfo's
    assert "-mfarecov-cfo.d02c-" in fake.ciba_req[0]["binding_message"]   # the manager sees whose account (+ id)
    r = c.post(LOST, headers=H)
    assert r.status_code == 200 and r.json()["completed"]
    methods = [(m, p.rsplit("/", 1)[-1]) for m, p, *_ in fake.calls]
    assert ("DELETE", OTP) in methods                                  # the lost authenticator removed
    email = [x for x in fake.calls if x[1].endswith("execute-actions-email")][0]
    assert json.loads(email[3]) == ["CONFIGURE_TOTP"] and email[2] == {"lifespan": "600"}   # 10 minutes   # no redirect_uri, no client_id
    assert ("POST", "logout") not in methods                           # sessions kept: the mailbox is the way back in
    assert any(u == "cfo" and "recovery" in t.lower() for u, t in notices)   # NIST 800-63B-4 4.2.3
    assert c.post(LOST, headers=H).status_code == 403                  # single use


def test_no_manager_means_human_only_and_no_push(tmp_path):
    fake, c, *_ = build(tmp_path)
    r = c.post(f"/gate/v1/actions/mfa-recovery-lost-device/{NOMGR}", headers=H).json()["challenge_required"]
    assert r["status"] == "human_only" and "Escalate" in r["how"]
    assert c.post(f"/gate/v1/challenges/{r['challenge']}/send", headers=H).json()["status"] == "human_only"
    assert fake.ciba_req == [] and fake.calls == []


def test_manager_equal_to_target_is_human_only(tmp_path):
    fake, c, *_ = build(tmp_path)
    r = c.post(f"/gate/v1/actions/mfa-recovery-lost-device/{SELFMGR}", headers=H).json()["challenge_required"]
    assert r["status"] == "human_only" and fake.ciba_req == []


@pytest.mark.parametrize("suffix,body", [("?redirect_uri=https://evil.example", b""), ("", b'{"email":"x@evil.example"}')])
def test_the_agent_cannot_parameterise_a_composite(tmp_path, suffix, body):
    fake, c, *_ = build(tmp_path)
    r = c.post(LOST + suffix, content=body, headers=H)
    assert r.status_code == 403 and not r.json().get("quarantined") and fake.calls == []   # refused, fed back


def test_owner_approval_does_not_unlock_the_manager_path(tmp_path):
    fake, c, *_ = build(tmp_path)
    # an owner-approved password reset in the same run does not satisfy the lost-device action
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    body = json.dumps({"type": "password", "temporary": True})
    ch = c.put(reset, content=body, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["r1"] = "approved"
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    assert c.post(LOST, headers=H).status_code == 403
    assert not any("credentials/" in p for _, p, *_ in fake.calls)


def test_compromise_response_one_approval_fixed_steps_secret_out_of_band(tmp_path):
    fake, c, notices, secrets_out = build(tmp_path)
    path = f"/gate/v1/actions/compromise-response/{CFO}"
    ch, s, st = approve_flow(fake, c, path)
    assert fake.ciba_req[0]["login_hint"] == "cfo" and st == "approved"   # owner kind: the owner's own device
    r = c.post(path, headers=H)
    assert r.status_code == 200 and r.json()["steps_done"] == ["reset_password_oob", "logout_sessions",
                                                               "send_actions_email:CONFIGURE_TOTP", "notify_owner"]
    assert secrets_out and secrets_out[0][0] == "cfo"
    assert secrets_out[0][1] not in r.text                             # never returned to the sandbox


def test_a_failed_step_stops_and_tells_the_owner(tmp_path):
    fake, c, notices, _ = build(tmp_path, fail_on="execute-actions-email")
    approve_flow(fake, c, LOST)
    r = c.post(LOST, headers=H)
    assert r.status_code == 502 and r.json()["completed"] is False
    assert r.json()["failed_step"] == "send_actions_email:CONFIGURE_TOTP"
    assert any("part-way" in t for _, t in notices)
