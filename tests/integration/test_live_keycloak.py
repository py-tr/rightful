"""Live test against a real local Keycloak 26 (Docker). Run with:  KEYLESS_LIVE=1 python -m pytest tests/integration -q
The oracle is Keycloak's own admin-event log, read by the view-events-only reconciler account.
"""
import json
import os
import threading
import time

import httpx
import pytest
import uvicorn

pytestmark = pytest.mark.skipif(os.environ.get("KEYLESS_LIVE") != "1", reason="set KEYLESS_LIVE=1 (needs Docker)")

from broker.app import create_app                       # noqa: E402
from broker.challenges import Challenges               # noqa: E402
from broker.keycloak import Keycloak, KeycloakConfig    # noqa: E402
from broker.pushsvc import create_push_app             # noqa: E402
from devenv import keycloak_local as kl                # noqa: E402
from gate import Gate, Ledger, ReceiptStore, load_pack, verify  # noqa: E402

BROKER, PUSH = "http://127.0.0.1:8090", "http://127.0.0.1:8099"


def serve(app, port):
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1" if port == 8090 else "0.0.0.0", port=port,
                                        log_level="warning"))
    threading.Thread(target=srv.run, daemon=True).start()
    for _ in range(50):
        if srv.started:
            return srv
        time.sleep(0.1)
    raise RuntimeError("server did not start")


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    kl.start_mail()
    base = kl.start()
    env = kl.bootstrap(base, smtp=True)
    push_app = create_push_app(base, "corp")
    kc = Keycloak(KeycloakConfig(base, "corp", *env["broker"], *env["ciba"]))
    receipts = ReceiptStore(":memory:")
    led = Ledger(str(tmp_path_factory.mktemp("led") / "ledger.jsonl"))
    pack = load_pack("helpdesk")
    pack["cooling_off_seconds"] = {"default": 3, "privileged": 3}       # short for the test; 60 s / 600 s in the pack
    gate = Gate(pack, receipts, led)
    quarantined = []
    ch = Challenges(kc, receipts, pack=pack, notify=push_app.state.notify)
    push_app.state.on_cancel = ch.cancel
    app = create_app(gate, kc, ch, deliver_secret=push_app.state.deliver, notify=push_app.state.notify,
                     on_quarantine=lambda r, why: quarantined.append((r, why)))
    s1, s2 = serve(push_app, 8099), serve(app, 8090)
    yield env, gate, quarantined
    s1.should_exit = s2.should_exit = True
    kl.stop()


def events(env):
    return [e for e in kl.admin_events(env["base"], "corp", env["reconciler"])
            if e.get("operationType") in ("UPDATE", "ACTION", "DELETE", "CREATE")]


def test_honest_reset_end_to_end_and_attacks_leave_no_trace(live):
    env, gate, quarantined = live
    cfo = env["users"]["cfo"]
    reset = f"{BROKER}/admin/realms/corp/users/{cfo}/reset-password"
    body = json.dumps({"type": "password", "temporary": True, "value": "agent-typed-1"})
    before = len(events(env))

    # attacks first: none may leave an admin event
    H2 = {"X-Gate-Run": "attack-run"}
    assert httpx.put(f"{BROKER}/admin/realms/corp/users/{cfo};x=y/reset-password", content=body, headers=H2).status_code == 403
    assert httpx.put(f"{BROKER}/admin/realms/corp/events/config", content='{"adminEventsEnabled":false}',
                     headers={"X-Gate-Run": "attack-run-2"}).status_code == 403
    assert httpx.put(reset, content=body, headers={"X-Gate-Run": "attack-run-3"}).status_code == 403  # no approval
    assert httpx.put(reset, content=body).status_code == 400                                        # no run header
    time.sleep(1)
    assert len(events(env)) == before, "an attack changed something in Keycloak"
    assert {r for r, _ in quarantined} == {"attack-run", "attack-run-2"}

    # the honest loop
    H = {"X-Gate-Run": "honest-run"}
    r = httpx.put(reset, content=body, headers=H)
    assert r.status_code == 403
    ch = r.json()["challenge_required"]
    s = httpx.post(f"{BROKER}/gate/v1/challenges/{ch['challenge']}/send", headers=H).json()
    assert s["status"] == "sent"
    for _ in range(30):                                    # Keycloak posts the request to the push service
        pend = httpx.get(f"{PUSH}/phone/cfo").json()["pending"]
        if pend:
            break
        time.sleep(0.3)
    assert pend and pend[0]["binding"].startswith(f"{ch['number']}-reset-cfo.")
    assert httpx.post(f"{PUSH}/phone/cfo/{pend[0]['id']}/approve", json={"number": ch["number"]}).status_code == 200
    for _ in range(30):
        st = httpx.get(f"{BROKER}/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"]
        if st == "approved":
            break
        time.sleep(0.5)
    assert st == "approved"
    r = httpx.put(reset, content=body, headers=H)
    assert r.status_code == 204, r.text
    assert "agent-typed" not in r.text
    inbox = httpx.get(f"{PUSH}/phone/cfo").json()["inbox"]
    assert inbox and inbox[0]["value"] != "agent-typed-1"             # the broker's password, on the phone only
    assert httpx.put(reset, content=body, headers=H).status_code == 403   # replay

    time.sleep(1)
    after = events(env)
    assert len(after) == before + 1, f"expected exactly one new admin event, got {len(after) - before}"
    resets = [e for e in after if e.get("resourcePath", "").endswith(f"users/{cfo}/reset-password")]
    assert len(resets) == 1, f"expected exactly one reset in Keycloak's own log, got {len(resets)}"
    ok, problem, seq, _ = verify(gate.ledger.path, gate.ledger.head())
    assert ok, problem
    led = open(gate.ledger.path, encoding="utf-8").read()
    assert inbox[0]["value"] not in led and "agent-typed" not in led


def _approve_on(phone_user, number_prefix, approve=True):
    for _ in range(30):
        pend = httpx.get(f"{PUSH}/phone/{phone_user}").json()["pending"]
        if pend:
            break
        time.sleep(0.3)
    assert pend and pend[0]["binding"].startswith(number_prefix)
    act = "approve" if approve else "deny"
    httpx.post(f"{PUSH}/phone/{phone_user}/{pend[0]['id']}/{act}", json={"number": pend[0]["number"]})
    return pend[0]


def _challenge_until(H, cid, want="approved"):
    for _ in range(30):
        st = httpx.get(f"{BROKER}/gate/v1/challenges/{cid}", headers=H).json()["status"]
        if st == want:
            return st
        time.sleep(0.5)
    return st


def test_lost_device_live_manager_approves_email_goes_to_the_address_on_file(live):
    env, gate, _ = live
    cfo = env["users"]["cfo"]
    url = f"{BROKER}/gate/v1/actions/mfa-recovery-lost-device/{cfo}"
    H = {"X-Gate-Run": "lost-device-honest"}
    before = len(events(env))
    ch = httpx.post(url, headers=H).json()["challenge_required"]
    assert ch["approver"] == "manager"
    httpx.post(f"{BROKER}/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    push = _approve_on("ceo", f"{ch['number']}-mfarecov-cfo.")           # the MANAGER's phone, naming the target
    assert push["instruction"] and "trust" in push["instruction"]
    assert _challenge_until(H, ch["challenge"]) == "approved"
    assert httpx.post(url, headers=H).json()["outcome"] == "denied_cooling_off"
    time.sleep(3.5)
    r = httpx.post(url, headers=H)
    assert r.status_code == 200 and r.json()["completed"], r.text
    time.sleep(1.5)
    mails = kl.mails()
    assert any("cfo@corp.example" in m["to"] for m in mails), mails       # only the address on file
    new = events(env)
    assert any("execute-actions-email" in e.get("resourcePath", "") for e in new)
    assert not any(e.get("resourcePath", "").endswith("/logout") for e in new)   # sessions kept
    inbox = httpx.get(f"{PUSH}/phone/cfo").json()["inbox"]
    assert any(n["kind"] == "notice" and "recovery" in n["value"].lower() for n in inbox)   # owner notified


def test_lost_device_live_fooled_manager_then_owner_cancels_nothing_happens(live):
    env, gate, _ = live
    cfo = env["users"]["cfo"]
    url = f"{BROKER}/gate/v1/actions/mfa-recovery-lost-device/{cfo}"
    H = {"X-Gate-Run": "lost-device-attack"}
    n_mail = len(kl.mails())
    before = len(events(env))
    ch = httpx.post(url, headers=H).json()["challenge_required"]
    httpx.post(f"{BROKER}/gate/v1/challenges/{ch['challenge']}/send", headers=H)
    _approve_on("ceo", f"{ch['number']}-mfarecov-cfo.")                 # the manager is fooled and approves
    assert _challenge_until(H, ch["challenge"]) == "approved"
    notes = [n for n in httpx.get(f"{PUSH}/phone/cfo").json()["inbox"] if n.get("cancel_id")]
    assert notes, "the owner's (supposedly lost) phone must get a cancel"
    assert httpx.post(f"{PUSH}/phone/cfo/cancel/{notes[-1]['cancel_id']}").json()["cancelled_receipts"] == 1
    time.sleep(3.5)                                                     # past the cooling-off
    r = httpx.post(url, headers=H)
    assert r.status_code == 403
    time.sleep(1)
    assert len(events(env)) == before, "a cancelled recovery changed something in Keycloak"
    assert len(kl.mails()) == n_mail, "a cancelled recovery sent an email"
    nxt = httpx.post(url, headers={"X-Gate-Run": "lost-device-attack-2"}).json()["challenge_required"]
    assert nxt["status"] == "human_only"                                 # and nothing re-asks
