import json
import threading

import pytest

from gate import Ledger, LedgerError, ReceiptStore, verify


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def store(clock=None):
    return ReceiptStore(":memory:", clock=clock or Clock())


def test_receipt_single_use():
    s = store()
    s.mint("run1", "reset_password", "u1", "h1", "u1", "ciba", 120)
    assert s.redeem("run1", "reset_password", "u1", "h1").ok
    r = s.redeem("run1", "reset_password", "u1", "h1")
    assert not r.ok and r.reason == "used"


@pytest.mark.parametrize("run,op,user,h", [
    ("run2", "reset_password", "u1", "h1"),     # another run (cross-run reuse)
    ("run1", "remove_credential", "u1", "h1"),  # another operation
    ("run1", "reset_password", "u2", "h1"),     # another user (cross-account)
    ("run1", "reset_password", "u1", "h2"),     # another exact request (body mutation)
])
def test_receipt_bound_to_run_op_user_request(run, op, user, h):
    s = store()
    s.mint("run1", "reset_password", "u1", "h1", "u1", "ciba", 120)
    r = s.redeem(run, op, user, h)
    assert not r.ok and r.reason == "no_receipt"
    assert s.redeem("run1", "reset_password", "u1", "h1").ok   # the real one is still intact


def test_receipt_expiry_boundary():
    c = Clock()
    s = store(c)
    s.mint("run1", "op", "u1", "h1", "u1", "ciba", 60)
    c.t += 60.0                                   # exactly at expiry: expired
    r = s.redeem("run1", "op", "u1", "h1")
    assert not r.ok and r.reason == "expired"
    s.mint("run1", "op", "u1", "h2", "u1", "ciba", 60)
    c.t += 59.0
    assert s.redeem("run1", "op", "u1", "h2").ok   # one second before: fine


def test_mint_requires_everything():
    s = store()
    with pytest.raises(ValueError):
        s.mint("run1", "op", "u1", "", "u1", "ciba", 60)
    with pytest.raises(ValueError):
        s.mint("run1", "op", "u1", "h", "u1", "ciba", 0)


def test_concurrent_double_redemption_exactly_one_wins():
    s = ReceiptStore(":memory:")
    s.mint("run1", "op", "u1", "h1", "u1", "ciba", 120)
    results, barrier = [], threading.Barrier(16)

    def go():
        barrier.wait()
        results.append(s.redeem("run1", "op", "u1", "h1").ok)

    ts = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count(True) == 1 and results.count(False) == 15


def test_ledger_chain_and_tamper(tmp_path):
    p = tmp_path / "ledger.jsonl"
    led = Ledger(str(p))
    for i in range(5):
        led.append("decision", {"i": i})
    head = led.head()
    assert verify(str(p), head)[0]
    lines = p.read_text(encoding="utf-8").splitlines()

    edited = json.loads(lines[2]); edited["data"]["i"] = 99
    p.write_text("\n".join(lines[:2] + [json.dumps(edited)] + lines[3:]) + "\n", encoding="utf-8")
    assert not verify(str(p))[0]                                   # modified entry

    p.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")
    assert not verify(str(p))[0]                                   # deleted entry

    p.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    ok_file_only = verify(str(p))[0]
    assert ok_file_only and not verify(str(p), head)[0]            # truncation: only the anchor catches it


def test_ledger_refuses_to_open_a_broken_file(tmp_path):
    p = tmp_path / "ledger.jsonl"
    led = Ledger(str(p))
    led.append("decision", {"i": 1})
    led.append("decision", {"i": 2})
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text(lines[1] + "\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        Ledger(str(p))
