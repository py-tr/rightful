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
    base = kl.start()
    env = kl.bootstrap(base)
    push_app = create_push_app(base, "corp")
    kc = Keycloak(KeycloakConfig(base, "corp", *env["broker"], *env["ciba"]))
    receipts = ReceiptStore(":memory:")
    led = Ledger(str(tmp_path_factory.mktemp("led") / "ledger.jsonl"))
    gate = Gate(load_pack("helpdesk"), receipts, led)
    quarantined = []
    app = create_app(gate, kc, Challenges(kc, receipts), deliver_secret=push_app.state.deliver,
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
    assert pend and pend[0]["binding"].startswith(f"{ch['number']}-reset-cfo-")
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
