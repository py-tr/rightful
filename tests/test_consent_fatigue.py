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


def build(tmp_path, clock=None, fake=None, push=None):
    """Everything durable lives in files (the receipts database and the ledger), as in deployment. Calling build again
    with the same tmp_path, clock and fake is a broker restart. `push` is the phone service, kept across a restart
    (it is a separate device)."""
    clock, fake = clock or Clock(), fake or FakeKC()
    kc = Keycloak(KeycloakConfig("http://kc", "corp", "b", "s", "c", "s"), clock=clock,
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(fake.handler)))
    pack = load_pack("helpdesk")
    receipts = ReceiptStore(str(tmp_path / "receipts.db"), clock=clock)
    if push is None:
        push = create_push_app("http://kc", "corp", http=httpx.Client(base_url="http://kc",
                                                                       transport=httpx.MockTransport(fake.handler)), verify_tokens=False)
    ledger = Ledger(str(tmp_path / "l.jsonl"))
    ch = Challenges(kc, receipts, pack=pack, notify=push.state.notify, clock=clock, ledger=ledger)
    push.state.on_cancel = ch.cancel
    gate = Gate(pack, receipts, ledger)
    app = create_app(gate, kc, ch, notify=push.state.notify, deliver_secret=push.state.deliver)
    build.last = (push, ch, receipts)
    return clock, fake, TestClient(app), TestClient(push)


def restart(tmp_path, clock, fake):
    push, _, old_receipts = build.last
    old_receipts._db.close()
    return build(tmp_path, clock, fake, push)


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
    assert 59 <= r.json()["retry_after_seconds"] <= 60          # the pilot: an honest agent needs to know how long
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


def test_hyphenated_username_is_parsed_whole(tmp_path):
    """A hyphenated username once split into the wrong field: 'mary-ann' showed as 'mary', and her own push got the
    someone-else warning (or another user's push could look like hers)."""
    clock, fake, c, phone = build(tmp_path)
    phone.post("/ciba/notify", json={"login_hint": "mary-ann", "binding_message": "41-reset-mary-ann.a0a0-11112222"},
               headers={"Authorization": "Bearer X"})
    p = phone.get("/phone/mary-ann").json()["pending"][0]
    assert p["target"] == "mary-ann.a0a0" and p["label"] == "reset" and p["number"] == "41"
    assert p["instruction"] is None
    phone.post("/ciba/notify", json={"login_hint": "mary", "binding_message": "42-reset-mary-ann.a0a0-11112222"},
               headers={"Authorization": "Bearer X"})
    q = phone.get("/phone/mary").json()["pending"][0]
    assert q["instruction"] is not None                                  # 'mary' approving mary-ann's account


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
    ("PUT", f"/admin/realms/corp/users/{CFO}/reset-password/", b'{"type":"password","temporary":true}', False),
    ("PUT", f"/admin/realms/corp/users/{CFO}/reset-password", b'{"type":"password",', False),    # broken JSON
    # ('..' is not listed: the HTTP test client resolves dot segments before sending; test_grammar covers it raw.)
    ("PUT", f"/admin/realms/corp/users/%64{CFO[1:]}/reset-password", b"{}", True),
    ("PUT", f"/admin/realms/corp/users/{CFO}/execute-actions-email?lifespan=%zz", b"[]", True),
])
def test_quarantine_only_on_hostile_signals(tmp_path, method, path, body, hostile):
    clock, fake, c, _ = build(tmp_path)
    r = c.request(method, path, content=body, headers=H)
    assert r.status_code == 403 and bool(r.json().get("quarantined")) is hostile and fake.calls == []


# --- review finding #4: nothing safety-relevant resets on a broker restart --------------------------------------

def test_snapshot_check_survives_a_restart(tmp_path):
    """The snapshot lived only on the in-memory challenge; after a restart the re-check was skipped (fail-open).
    Now it is stored in the receipt row, so the restarted broker still catches the changed email."""
    clock, fake, c, phone = build(tmp_path)
    approve(fake, c, LOST)
    fake.users[CFO]["email"] = "attacker@evil.example"
    clock.t += 61
    clock, fake, c, phone = restart(tmp_path, clock, fake)
    r = c.post(LOST, headers=H)
    assert r.status_code == 409 and r.json()["outcome"] == "aborted_changed_since_approval"
    assert not any("execute-actions-email" in p for _, p in fake.calls)


def test_receipt_without_snapshot_aborts_the_composite(tmp_path):
    """Fail closed: a receipt with no stored snapshot (e.g. from an older database) never runs a composite."""
    clock, fake, c, _ = build(tmp_path)
    _, _, receipts = build.last
    from gate.grammar import parse
    op = parse(load_pack("helpdesk"), "POST", LOST, b"")
    receipts.mint("run-1", op.name, op.user, op.request_hash, approver="ceo", channel="ciba:manager", ttl_seconds=60)
    r = c.post(LOST, headers=H)
    assert r.status_code == 409 and r.json()["outcome"] == "aborted_no_snapshot" and fake.calls == []


def test_quarantine_survives_a_restart(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    assert c.put("/admin/realms/corp/events/config", content=b"{}", headers=H).json()["quarantined"]
    clock, fake, c, _ = restart(tmp_path, clock, fake)
    r = c.get(f"/admin/realms/corp/users/{CFO}", headers=H)
    assert r.status_code == 403 and r.json()["outcome"] == "quarantined"


def test_decline_tripwire_survives_a_restart(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    body = b'{"type":"password","temporary":true}'
    ch = c.put(reset, content=body, headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["r1"] = "denied"
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    clock, fake, c, _ = restart(tmp_path, clock, fake)
    nxt = c.put(reset, content=body, headers={"X-Gate-Run": "run-9"}).json()["challenge_required"]
    assert nxt["status"] == "human_only" and "declined" in nxt["why"]


def test_cancel_button_still_works_after_a_restart(tmp_path):
    clock, fake, c, phone = build(tmp_path)
    approve(fake, c, LOST)
    notice = [n for n in phone.get("/phone/cfo").json()["inbox"] if n.get("cancel_id")][0]
    clock, fake, c, phone = restart(tmp_path, clock, fake)
    assert phone.post(f"/phone/cfo/cancel/{notice['cancel_id']}").json()["cancelled_receipts"] == 1
    clock.t += 61
    assert c.post(LOST, headers=H).status_code == 403 and fake.calls == []


def test_push_rate_limit_survives_a_restart(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    statuses = []
    for i in range(5):
        h = {"X-Gate-Run": f"run-{i}"}
        ch = c.put(reset, content=b'{"type":"password","temporary":true}', headers=h).json()["challenge_required"]
        statuses.append(c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=h).json()["status"])
        if i == 1:
            clock, fake, c, _ = restart(tmp_path, clock, fake)
    assert statuses == ["sent", "sent", "sent", "rate_limited", "rate_limited"]


def test_unapproved_attempt_count_survives_a_restart(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    body = b'{"type":"password","temporary":true}'
    for _ in range(3):
        assert not c.put(reset, content=body, headers=H).json().get("quarantined")
    clock, fake, c, _ = restart(tmp_path, clock, fake)
    assert c.put(reset, content=body, headers=H).json().get("quarantined")      # the 4th, counted across the restart


# --- review finding #5: two concurrent polls of one approval mint one receipt ------------------------------------

def test_concurrent_polls_mint_one_receipt(tmp_path):
    import threading
    clock, fake, c, _ = build(tmp_path)
    _, ch_store, receipts = build.last
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    ch = c.put(reset, content=b'{"type":"password","temporary":true}', headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    fake.ciba["r1"] = "approved"
    real_snapshot = ch_store.kc.user_snapshot
    barrier = threading.Barrier(8)

    def slow_snapshot(uid):                  # widen the window: every poll is inside it before any mint
        try:
            barrier.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        return real_snapshot(uid)
    ch_store.kc.user_snapshot = slow_snapshot
    ch_store.min_poll_interval = 0               # let every poll through, so the lock (not the throttle) is tested
    threads = [threading.Thread(target=ch_store.poll, args=(ch["challenge"], "run-1")) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert receipts.count() == 1


def test_poll_has_a_server_side_minimum_interval(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    reset = f"/admin/realms/corp/users/{CFO}/reset-password"
    ch = c.put(reset, content=b'{"type":"password","temporary":true}', headers=H).json()["challenge_required"]
    c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    polls = []
    real = build.last[1].kc.ciba_poll
    build.last[1].kc.ciba_poll = lambda rid: polls.append(rid) or real(rid)
    for _ in range(50):                                   # a tight loop at one instant
        c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    assert len(polls) == 1
    clock.t += 1.0
    c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H)
    assert len(polls) == 2


def test_harmless_malformed_writes_are_strikes_and_survive_a_restart(tmp_path):
    clock, fake, c, _ = build(tmp_path)
    bad = f"/admin/realms/corp/users/{CFO}/reset-password/"           # trailing slash: a mistake, not a trick
    for _ in range(2):
        assert not c.put(bad, content=b"{}", headers=H).json().get("quarantined")
    clock, fake, c, _ = restart(tmp_path, clock, fake)
    assert not c.put(bad, content=b"{}", headers=H).json().get("quarantined")
    assert c.put(bad, content=b"{}", headers=H).json().get("quarantined")      # the 4th strike, across a restart
    assert fake.calls == []


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
