"""Consent-fatigue protections: cooling-off with a cancel on every device, the decline tripwire, snapshot re-check,
privileged delays, the approver's instruction, the previous contact notified, and quarantine only on hostile signals."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from broker.pushsvc import create_push_app
from gate import Gate, Ledger, ReceiptStore, load_pack

CFO = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
VIP = "a0a0a0a0-c4a5-4c86-9912-27a5a18fb8cd"
LOST = f"/gate/v1/actions/mfa-recovery-lost-device/{CFO}"
H = {"X-Gate-Run": "run-1"}


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakeKC:
    def __init__(self):
        self.users = {CFO: {"username": "cfo", "email": "cfo@corp.example", "attributes": {"manager": ["ceo"]}},
                      VIP: {"username": "vip", "email": "vip@corp.example",
                            "attributes": {"manager": ["ceo"], "privileged": ["true"]}}}
        self.ciba, self.calls = {}, []

    def handler(self, req):
        p, m = req.url.path, req.method
        if p.endswith("/openid-connect/token"):
            f = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            if f.get("grant_type") == "client_credentials":
                return httpx.Response(200, json={"access_token": "SA", "expires_in": 3600})
            st = self.ciba.get(f.get("auth_req_id"))
            if st == "approved":
                return httpx.Response(200, json={"access_token": "t"})
            return httpx.Response(400, json={"error": "access_denied" if st == "denied" else "authorization_pending"})
        if p.endswith("/ext/ciba/auth"):
            rid = f"r{len(self.ciba) + 1}"
            self.ciba[rid] = "pending"
            return httpx.Response(200, json={"auth_req_id": rid})
        for uid, u in self.users.items():
            if m == "GET" and p == f"/admin/realms/corp/users/{uid}":
                return httpx.Response(200, json={"id": uid, **u})
        if m == "GET" and p.endswith("/credentials"):
            return httpx.Response(200, json=[{"id": "0b9b2a3e-1111-4c86-9912-27a5a18fb8cd", "type": "otp"}])
        self.calls.append((m, p))
        return httpx.Response(204)


def build(tmp_path):
    clock, fake = Clock(), FakeKC()
    kc = Keycloak(KeycloakConfig("http://kc", "corp", "b", "s", "c", "s"), clock=clock,
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(fake.handler)))
    pack = load_pack("helpdesk")
    receipts = ReceiptStore(":memory:", clock=clock)
    push = create_push_app("http://kc", "corp", http=httpx.Client(base_url="http://kc",
                                                                   transport=httpx.MockTransport(fake.handler)))
    ch = Challenges(kc, receipts, pack=pack, notify=push.state.notify, clock=clock)
    push.state.on_cancel = ch.cancel
    gate = Gate(pack, receipts, Ledger(str(tmp_path / "l.jsonl")))
    app = create_app(gate, kc, ch, notify=push.state.notify, deliver_secret=push.state.deliver)
    return clock, fake, TestClient(app), TestClient(push)


def approve(fake, c, path, decision="approved"):
    ch = c.post(path, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba[f"r{len(fake.ciba)}"] = decision
    return c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"]


def test_cooling_off_then_runs(tmp_path):
    clock, fake, c, phone = build(tmp_path)
    assert approve(fake, c, LOST) == "approved"
    r = c.post(LOST, headers=H)
    assert r.status_code == 403 and r.json()["outcome"] == "denied_cooling_off" and not r.json().get("quarantined")
    assert fake.calls == []
    clock.t += 61
    assert c.post(LOST, headers=H).status_code == 200


def test_the_lost_phone_gets_a_cancel_and_cancelling_stops_it(tmp_path):
    clock, fake, c, phone = build(tmp_path)
    approve(fake, c, LOST)
    notices = [n for n in phone.get("/phone/cfo").json()["inbox"] if n.get("cancel_id")]
    assert notices and "cancel" in notices[0]["value"].lower()
    assert phone.post(f"/phone/cfo/cancel/{notices[0]['cancel_id']}").json()["cancelled_receipts"] == 1
    clock.t += 61
    r = c.post(LOST, headers=H)
    assert r.status_code == 403 and fake.calls == []                   # the attack died during the cooling-off
    again = c.post(LOST, headers={"X-Gate-Run": "run-2"}).json()["challenge_required"]
    assert again["status"] == "human_only"                              # and nothing re-asks
    assert phone.post(f"/phone/ceo/cancel/{notices[0]['cancel_id']}").status_code == 404   # only the owner cancels


def test_privileged_users_wait_longer(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    path = f"/gate/v1/actions/mfa-recovery-lost-device/{VIP}"
    approve(fake, c, path)
    clock.t += 61
    assert c.post(path, headers=H).json()["outcome"] == "denied_cooling_off"
    clock.t += 600
    assert c.post(path, headers=H).status_code == 200


def test_decline_tripwire(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    ch = c.put(reset, content=b'{"type":"password","temporary":true}', headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["r1"] = "denied"
    assert c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"] == "denied"
    nxt = c.put(reset, content=b'{"type":"password","temporary":true}',
                headers={"X-Gate-Run": "run-9"}).json()["challenge_required"]
    assert nxt["status"] == "human_only" and "declined" in nxt["why"]
    clock.t += 86401
    later = c.put(reset, content=b'{"type":"password","temporary":true}',
                  headers={"X-Gate-Run": "run-10"}).json()["challenge_required"]
    assert later.get("status") != "human_only"


def test_snapshot_changed_after_approval_aborts(tmp_path):
    clock, fake, c, phone = build(tmp_path)
    approve(fake, c, LOST)
    fake.users[CFO]["email"] = "attacker@evil.example"                  # changed during the cooling-off
    clock.t += 61
    r = c.post(LOST, headers=H)
    assert r.status_code == 409 and r.json()["outcome"] == "aborted_changed_since_approval"
    assert not any("execute-actions-email" in p for _, p in fake.calls)
    assert any("stopped" in n["value"] for n in phone.get("/phone/cfo").json()["inbox"])


def test_manager_push_carries_an_instruction(tmp_path):
    clock, fake, c, phone = build(tmp_path)
    phone.post("/ciba/notify", json={"login_hint": "ceo", "binding_message": "37-mfarecov-cfo.d02c-9f3a1c07"},
               headers={"Authorization": "Bearer X"})
    p = phone.get("/phone/ceo").json()["pending"][0]
    assert p["target"] == "cfo.d02c" and "trust" in p["instruction"]
    phone.post("/ciba/notify", json={"login_hint": "cfo", "binding_message": "12-reset-cfo.d02c-11112222"},
               headers={"Authorization": "Bearer X"})
    own = phone.get("/phone/cfo").json()["pending"][0]
    assert own["instruction"] is None                                    # your own account: no extra warning


def test_email_change_notifies_the_previous_contact(tmp_path):
    clock, fake, c, phone = build(tmp_path)
    path = f"/admin/realms/corp/users/{CFO}"
    body = b'{"email":"jordan.new@corp.example"}'
    ch = c.put(path, content=body, headers=H).json()["challenge_required"]
    assert ch["approver"] == "contact"
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["r1"] = "approved"
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    clock.t += 61
    assert c.put(path, content=body, headers=H).status_code == 204
    assert any("cfo@corp.example" in n["value"] for n in phone.get("/phone/cfo").json()["inbox"])


@pytest.mark.parametrize("method,path,body,hostile", [
    ("PUT", f"/admin/realms/corp/users/{CFO}/reset-password", b'{"type":"password","temporary":true,"x":1}', False),
    ("POST", LOST + "?note=hi", b"", False),
    ("PUT", f"/admin/realms/corp/users/{CFO};x=y/reset-password", b'{"type":"password"}', True),
    ("PUT", "/admin/realms/corp/events/config", b"{}", True),
    ("POST", f"/admin/realms/corp/users/{CFO}/role-mappings/realm", b"[]", True),
    ("PUT", "/admin/realms/corp", b"{}", True),
])
def test_quarantine_only_on_hostile_signals(tmp_path, method, path, body, hostile):
    clock, fake, c, _ = build(tmp_path)
    r = c.request(method, path, content=body, headers=H)
    assert r.status_code == 403 and bool(r.json().get("quarantined")) is hostile and fake.calls == []


def test_retrying_a_declined_change_quarantines(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    body = b'{"type":"password","temporary":true}'
    ch = c.put(reset, content=body, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["r1"] = "denied"
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    r = c.put(reset, content=body, headers=H)                 # the agent tries the declined change again
    assert r.status_code == 403 and r.json()["quarantined"] and "declined" in r.json()["reason"]
    assert fake.calls == []
