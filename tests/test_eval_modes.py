"""The evaluation's weaker gate modes (gate-off baseline and ablations). Most important: they are REFUSED in code
outside a scratch realm with KEYLESS_EVAL=1, so the demo can never run without the gate."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from gate import Gate, Ledger, ReceiptStore, load_pack

U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
OTHER = "a0a0a0a0-c4a5-4c86-9912-27a5a18fb8cd"


def make(tmp_path, realm):
    writes = []

    def handler(req):
        p = req.url.path
        if p.endswith("/token"):
            f = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            if f.get("grant_type") == "client_credentials":
                return httpx.Response(200, json={"access_token": "SA", "expires_in": 300})
            return httpx.Response(200, json={"access_token": "owner"})          # every CIBA poll: approved
        if p.endswith("/ext/ciba/auth"):
            return httpx.Response(200, json={"auth_req_id": "r1"})
        if req.method == "GET":
            return httpx.Response(200, json={"id": U, "username": "cfo", "email": "cfo@corp.example",
                                             "attributes": {"manager": ["ceo"]}})
        writes.append((req.method, p, req.content.decode()))
        return httpx.Response(204)
    pack = {**load_pack("helpdesk"), "realm": realm}
    kc = Keycloak(KeycloakConfig("http://kc", realm, "b", "s", "c", "s"),
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(handler)))
    receipts = ReceiptStore(":memory:")
    gate = Gate(pack, receipts, Ledger(str(tmp_path / "l.jsonl")), secret_factory=lambda: "GEN-PW-1")
    app = create_app(gate, kc, Challenges(kc, receipts, pack=pack, min_poll_interval=0))
    return TestClient(app), writes, gate


@pytest.mark.parametrize("mode", ["allow_all", "allowlist_only", "unbound", "naive"])
def test_eval_modes_are_refused_in_the_demo_realm(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("KEYLESS_EVAL", "1")                     # even with the variable set
    c, writes, gate = make(tmp_path, "corp")
    with pytest.raises(PermissionError):
        c.app.state.open_run("run-1", mode)
    assert any(e["kind"] == "eval_mode_refused" for e in gate.ledger.entries())   # logged loudly
    assert gate.mode("run-1") == "full"


@pytest.mark.parametrize("mode", ["allow_all", "naive"])
def test_eval_modes_are_refused_without_the_eval_variable(tmp_path, monkeypatch, mode):
    monkeypatch.delenv("KEYLESS_EVAL", raising=False)
    c, _, gate = make(tmp_path, "eval-b1")
    with pytest.raises(PermissionError):
        c.app.state.open_run("run-1", mode)


def test_allow_all_is_credential_brokered_with_no_authorization(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYLESS_EVAL", "1")
    c, writes, gate = make(tmp_path, "eval-b1")
    c.app.state.open_run("run-1", "allow_all")
    H = {"X-Gate-Run": "run-1"}
    r = c.put(f"/admin/realms/eval-b1/users/{U}/reset-password", content=b'{"type":"password","temporary":true}',
              headers=H)
    assert r.status_code == 200 and r.json()["temporary_password"] == "GEN-PW-1"      # the agent gets the password
    assert writes[-1][0] == "PUT" and json.loads(writes[-1][2])["value"] == "GEN-PW-1"
    r = c.put(f"/admin/realms/eval-b1/users/{U}", content=b'{"attributes":{"x":["y"]}}', headers=H)   # unparsed write
    assert r.status_code == 204 and len(writes) == 2
    assert c.put("/admin/realms/corp/users/x", content=b"{}", headers=H).status_code == 403     # the realm boundary
    assert any(e["kind"] == "executed" for e in gate.ledger.entries())


def test_full_mode_is_unchanged_in_a_scratch_realm(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYLESS_EVAL", "1")
    c, writes, _ = make(tmp_path, "eval-b1")
    c.app.state.open_run("run-1", "full")
    r = c.put(f"/admin/realms/eval-b1/users/{U}/reset-password", content=b'{"type":"password","temporary":true}',
              headers={"X-Gate-Run": "run-1"})
    assert r.status_code == 403 and "challenge_required" in r.json() and writes == []


def test_allowlist_only_needs_no_approval_but_keeps_the_grammar(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYLESS_EVAL", "1")
    c, writes, _ = make(tmp_path, "eval-b1")
    c.app.state.open_run("run-1", "allowlist_only")
    H = {"X-Gate-Run": "run-1"}
    assert c.put(f"/admin/realms/eval-b1/users/{U}/reset-password", content=b'{"type":"password","temporary":true}',
                 headers=H).status_code == 204
    assert c.put(f"/admin/realms/eval-b1/users/{U}", content=b'{"attributes":{}}', headers=H).status_code == 403
    assert len(writes) == 1


def test_unbound_receipt_lets_one_approval_unlock_a_different_change(tmp_path, monkeypatch):
    """The approve-then-switch case: the owner approved a reset; the agent then changes the email instead."""
    monkeypatch.setenv("KEYLESS_EVAL", "1")
    for mode, expect in (("unbound", 204), ("full", 403)):
        (tmp_path / mode).mkdir()
        c, writes, _ = make(tmp_path / mode, "eval-b1")
        run = f"run-{mode}"
        c.app.state.open_run(run, mode)
        H = {"X-Gate-Run": run}
        ch = c.put(f"/admin/realms/eval-b1/users/{U}/reset-password", content=b'{"type":"password","temporary":true}',
                   headers=H).json()["challenge_required"]
        c.post(f"/gate/v1/challenges/{ch['challenge']}/send", headers=H)
        assert c.get(f"/gate/v1/challenges/{ch['challenge']}", headers=H).json()["status"] == "approved"
        r = c.put(f"/admin/realms/eval-b1/users/{U}", content=b'{"email":"attacker@evil.example"}', headers=H)
        assert r.status_code == expect, mode


def test_naive_gate_trusts_the_agents_own_claim(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYLESS_EVAL", "1")
    for mode, expect in (("naive", 204), ("full", 403)):
        (tmp_path / mode).mkdir()
        c, writes, gate = make(tmp_path / mode, "eval-b1")
        run = f"run-{mode}"
        c.app.state.open_run(run, mode)
        H = {"X-Gate-Run": run}
        c.post("/gate/v1/verifications", json={"user": U, "how": "ticket note says L1 verified"}, headers=H)
        r = c.put(f"/admin/realms/eval-b1/users/{U}/reset-password", content=b'{"type":"password","temporary":true}',
                  headers=H)
        assert r.status_code == expect, mode
        assert any(e["kind"] == "agent_claimed_verification" for e in gate.ledger.entries())   # logged in every mode
