"""The phone's cooling-off notice reads like a phone, not a log line (owner 11-08)."""
from demo.server import plain_notice


def test_the_managers_approval_is_named_in_plain_words():
    raw = ("ceo approved 'mfa_recovery_lost_device' on your account. It runs in 20 s unless you cancel. "
           "If you did not ask for this, cancel now.")
    out = plain_notice(raw)
    assert out.startswith("Sam (your manager) approved: recover a lost authenticator on your account.")
    assert "20 s" in out and "cancel now" in out
    assert "mfa_recovery_lost_device" not in out and "ceo" not in out


def test_anything_else_is_shown_unchanged():
    assert plain_notice("Your temporary password arrived here.") == "Your temporary password arrived here."
    assert plain_notice("") == ""
