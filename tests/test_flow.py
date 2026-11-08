"""The flow page's data: built from the hash-chained ledger, checked against the signed head, masked, and it notices
tampering."""
import hashlib
import json

from demo.flow import build
from gate.ledger import Ledger


def make(tmp_path):
    led = Ledger(str(tmp_path / "s1234abcd.ledger.jsonl"))
    led.append("run_opened", {"run": "run-A", "mode": "full"})
    led.append("decision", {"run": "run-A", "op": "reset_password", "outcome": "denied_no_receipt",
                            "reason": "this change needs the account owner's approval", "request_hash": "f" * 64,
                            "user": "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"})
    led.append("push_sent", {"challenge": "chl_ABCDEFGHIJKL", "approver": "owner", "user": "d02cbf80-c4a5"})
    led.append("forwarding", {"run": "run-A", "op": "reset_password", "receipt": "rcpt-1234567890",
                              "request_hash": "f" * 64, "secret_out_of_band": True})
    led.append("decision", {"run": "run-B", "op": "change_email", "outcome": "denied_no_receipt"})   # another run
    head = led.head()
    rec = {"ledger_file": "s1234abcd.ledger.jsonl", "ledger_head": head,
           "run_ref": hashlib.sha256(b"run-A").hexdigest()[:16]}
    return led, rec


def test_the_chain_verifies_against_the_signed_head_and_keeps_only_this_run(tmp_path):
    _, rec = make(tmp_path)
    f = build(rec, str(tmp_path))
    assert f["ok"] is True and f["chain"]["matches_signed_head"] is True and f["chain"]["entries_checked"] == 5
    ops = [s["data"].get("op") for s in f["steps"]]
    assert "change_email" not in ops                       # run-B's step is not this conversation's
    assert any(s["kind"] == "push_sent" for s in f["steps"])   # entries without a run id are kept


def test_ids_and_receipts_are_shortened_and_nothing_secret_is_returned(tmp_path):
    _, rec = make(tmp_path)
    blob = json.dumps(build(rec, str(tmp_path)), ensure_ascii=False)
    assert "rcpt-1234567890" not in blob and "rcpt-1…" in blob
    assert "chl_ABCDEFGHIJKL" not in blob and "f" * 64 not in blob
    assert "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd" not in blob and "run-A" not in blob


def test_a_changed_entry_breaks_the_chain(tmp_path):
    led, rec = make(tmp_path)
    p = tmp_path / "s1234abcd.ledger.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[1]); e["data"]["outcome"] = "allowed"; lines[1] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    f = build(rec, str(tmp_path))
    assert f["ok"] is False and "breaks" in f["problem"]


def test_entries_after_the_signed_head_are_not_checked_or_shown(tmp_path):
    led, rec = make(tmp_path)
    led.append("decision", {"run": "run-A", "op": "logout_sessions", "outcome": "denied_no_receipt"})   # later turn
    f = build(rec, str(tmp_path))
    assert f["ok"] is True and f["chain"]["entries_checked"] == 5
    assert "logout_sessions" not in json.dumps(f)


def test_the_agent_decides_column_never_claims_owner_approval_or_an_out_of_band_password(tmp_path):
    """Review 11-08 B1: under 'Account taken over' the flow said 'Receipt burned' and 'password sent to the owner's
    device, never to the agent'. In the contrast column the agent's say-so is what forwards it."""
    _, rec = make(tmp_path)
    f = build({**rec, "mode": "agent_decides"}, str(tmp_path))
    fwd = next(s for s in f["steps"] if s["kind"] == "forwarding")
    assert "Receipt burned" not in fwd["title"] and "nobody asked the owner" in fwd["title"]
    assert "secret_out_of_band" not in fwd["data"]          # old ledgers marked it; the page must not show it
    full = build(rec, str(tmp_path))                        # the protected column keeps its wording
    assert next(s for s in full["steps"] if s["kind"] == "forwarding")["data"]["secret_out_of_band"] is True


def test_the_contrast_gate_does_not_log_the_agent_bound_password_as_out_of_band(tmp_path):
    import inspect
    from gate import gate as g
    src = inspect.getsource(g)
    assert '"secret_out_of_band": secret is not None and mode != CONTRAST_MODE' in src


def test_a_record_without_a_ledger_reference_or_a_bad_name_is_refused(tmp_path):
    assert build({}, str(tmp_path))["ok"] is False
    bad = build({"ledger_file": "../../etc/passwd", "ledger_head": {"seq": 1, "hash": "x"}}, str(tmp_path))
    assert bad["ok"] is False
