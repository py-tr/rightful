import json
import threading

import pytest

from gate import Gate, Ledger, LedgerError, ReceiptStore, load_pack, parse

PACK = load_pack("helpdesk")
U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
RESET = f"/admin/realms/corp/users/{U}/reset-password"
BODY = json.dumps({"type": "password", "temporary": True, "value": "agent-chosen-Pw1!"}).encode()


@pytest.fixture
def g(tmp_path):
    return Gate(PACK, ReceiptStore(":memory:"), Ledger(str(tmp_path / "ledger.jsonl")),
                secret_factory=lambda: "BROKER-SECRET-123")


def approve(g, run, method, target, body):
    op = parse(PACK, method, target, body)
    g.receipts.mint(run, op.name, op.user, op.request_hash, op.user, "ciba", 120)


def test_write_without_receipt_is_denied_with_a_challenge(g):
    d = g.decide("PUT", RESET, BODY, "run1")
    assert not d.allow and d.outcome == "denied_no_receipt"
    assert d.challenge["operation"] == "reset_password" and d.challenge["user"] == U
    assert d.forward is None and d.oob_secret is None


def test_approved_write_is_forwarded_once_with_the_broker_secret(g):
    approve(g, "run1", "PUT", RESET, BODY)
    d = g.decide("PUT", RESET, BODY, "run1")
    assert d.allow and d.outcome == "allowed_write"
    fwd = json.loads(d.forward["body"])
    assert fwd["value"] == "BROKER-SECRET-123"                 # the agent's password was overridden
    assert d.oob_secret == "BROKER-SECRET-123"
    assert "BROKER-SECRET" not in json.dumps(d.agent_view())   # never shown to the agent
    assert not g.decide("PUT", RESET, BODY, "run1").allow     # replay of the same request
    led = open(g.ledger.path, encoding="utf-8").read()
    assert "BROKER-SECRET" not in led and "agent-chosen" not in led


def test_agent_view_never_contains_a_receipt_or_token(g):
    approve(g, "run1", "PUT", RESET, BODY)
    d = g.decide("PUT", RESET, BODY, "run1")
    v = json.dumps(d.agent_view())
    assert "rcpt_" not in v and "token" not in v.lower() and "Authorization" not in v


def test_approval_for_one_action_does_not_cover_another(g):
    approve(g, "run1", "PUT", RESET, BODY)                     # owner approved a password reset
    d = g.decide("POST", f"/admin/realms/corp/users/{U}/logout", b"", "run1")
    assert not d.allow and d.outcome == "denied_no_receipt"
    d = g.decide("PUT", f"/admin/realms/corp/users/{U}", b'{"email":"x@evil.example"}', "run1")
    assert not d.allow


def test_semicolon_bypass_is_denied_and_quarantined(g):
    approve(g, "run1", "PUT", RESET, BODY)
    d = g.decide("PUT", f"/admin/realms/corp/users/{U};x=y/reset-password", BODY, "run1")
    assert not d.allow and d.outcome == "denied_malformed" and d.quarantine


def test_witness_cannot_be_switched_off(g):
    for m, t, b in (("PUT", "/admin/realms/corp/events/config", b'{"adminEventsEnabled":false}'),
                    ("PUT", "/admin/realms/corp", b'{"adminEventsEnabled":false}'),
                    ("DELETE", "/admin/realms/corp/admin-events", b"")):
        d = g.decide(m, t, b, "run1")
        assert not d.allow and d.quarantine


def test_repeated_unapproved_writes_quarantine(g):
    outs = [g.decide("PUT", RESET, BODY, "run1") for _ in range(3)]
    assert [o.quarantine is not None for o in outs] == [False, False, True]
    assert outs[2].challenge is None                            # no new push for a looping agent


def test_honest_flow_has_no_quarantine(g):
    d1 = g.decide("PUT", RESET, BODY, "run1")                  # denied, challenge
    approve(g, "run1", "PUT", RESET, BODY)                     # owner approves
    d2 = g.decide("PUT", RESET, BODY, "run1")                  # retry
    assert d1.quarantine is None and d2.allow and d2.quarantine is None


def test_reads_pass_without_receipt(g):
    assert g.decide("GET", f"/admin/realms/corp/users/{U}", b"", "run1").allow
    assert g.decide("GET", "/admin/realms/corp/users?search=jordan", b"", "run1").allow


def test_fail_closed_when_ledger_is_down(g, monkeypatch):
    approve(g, "run1", "PUT", RESET, BODY)

    def broken(*a, **k):
        raise LedgerError("disk full")
    monkeypatch.setattr(g.ledger, "append", broken)
    d = g.decide("PUT", RESET, BODY, "run1")
    assert not d.allow and d.outcome == "denied_ledger_down" and d.forward is None
    monkeypatch.undo()
    assert not g.decide("PUT", RESET, BODY, "run1").allow      # the receipt stayed burned


def test_concurrent_identical_requests_one_forward(g):
    approve(g, "run1", "PUT", RESET, BODY)
    res, bar = [], threading.Barrier(12)

    def go():
        bar.wait()
        res.append(g.decide("PUT", RESET, BODY, "run1").allow)
    ts = [threading.Thread(target=go) for _ in range(12)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert res.count(True) == 1


def test_every_decision_is_in_the_ledger_and_the_chain_verifies(g):
    from gate import verify
    g.decide("PUT", RESET, BODY, "run1")
    approve(g, "run1", "PUT", RESET, BODY)
    g.decide("PUT", RESET, BODY, "run1")
    g.decide("PUT", "/admin/realms/corp/events/config", b"{}", "run1")
    ok, problem, seq, _ = verify(g.ledger.path, g.ledger.head())
    assert ok and seq == 3
