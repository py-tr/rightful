"""Signed run receipts (brainstorm P1, 11-08): a shared run can be checked offline; one changed byte makes it INVALID."""
import json

from gate.receipt_sign import Signer, canonical, verify
from gate.verify_receipt import main as verify_cli

REC = {"token": "abc12345", "t": 1794109356.944728, "summary": "Nothing changed: the identity server's own log shows "
       "no change to Jordan's account.", "proof": [{"ref": "9728", "made": False, "log": "none"}], "pair": "p1",
       "mode": "rightful", "policy_sha256": "d2c42c0b", "verdict": "ok", "chat": [{"who": "you", "text": "hi ünïcode"}]}


def signed(tmp_path, rec=REC):
    s = Signer(str(tmp_path / "k.pem"))
    r = json.loads(json.dumps(rec))
    r["signature"] = s.sign(r)
    return s, json.loads(json.dumps(r))             # as a reader loads it back from the file


def test_a_signed_record_verifies(tmp_path):
    s, r = signed(tmp_path)
    assert verify(r) == (True, f"valid (key {s.key_id})")
    assert verify(r, s.public_b64)[0] is True


def test_one_changed_value_makes_it_invalid(tmp_path):
    _, r = signed(tmp_path)
    r["proof"][0]["made"] = True                    # "the change happened" after all
    ok, why = verify(r)
    assert not ok and "changed after it was signed" in why


def test_a_record_signed_by_another_key_fails_against_the_site_key(tmp_path):
    _, r = signed(tmp_path)
    other = Signer(str(tmp_path / "other.pem"))
    assert verify(r, other.public_b64) == (False, "signed by a different key than the site publishes")


def test_the_key_survives_a_restart(tmp_path):
    a = Signer(str(tmp_path / "k.pem"))
    b = Signer(str(tmp_path / "k.pem"))
    assert a.public_b64 == b.public_b64 and a.key_id == b.key_id


def test_the_paired_column_attached_at_serve_time_is_not_part_of_the_signature(tmp_path):
    _, r = signed(tmp_path)
    _, pair = signed(tmp_path, {**REC, "token": "def67890"})
    r["other"] = pair
    assert canonical(r) == canonical({k: v for k, v in r.items() if k != "other"})
    assert verify(r)[0] and verify(r["other"])[0]


def test_a_lone_surrogate_from_a_visitor_cannot_break_signing(tmp_path):
    """Review 11-08 m3: the canonical form is ASCII-escaped, so odd input signs and verifies instead of raising."""
    s, r = signed(tmp_path, {**REC, "chat": [{"who": "you", "text": "\ud800 broken"}]})
    assert verify(r, s.public_b64)[0] is True


def test_the_command_line_says_valid_or_invalid(tmp_path, capsys):
    s, r = signed(tmp_path)
    p = tmp_path / "run.json"
    p.write_text(json.dumps(r), encoding="utf-8")
    assert verify_cli([str(p), "--key", s.public_b64]) == 0
    assert "VALID" in capsys.readouterr().out
    r["verdict"] = "edited"
    p.write_text(json.dumps(r), encoding="utf-8")
    assert verify_cli([str(p)]) == 1
    assert "INVALID" in capsys.readouterr().out
