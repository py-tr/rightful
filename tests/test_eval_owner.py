"""The scripted approver (evaluation): an honest approver reads the named target and denies a change on another
account; fooled/attacker phones approve everything; 'never' ignores."""
import time

from eval.owner import PhoneBot


class FakePhone:
    def __init__(self, pending):
        self.pending, self.posts = pending, []

    def get(self, path):
        user = path.rsplit("/", 1)[1]
        items = [p for p in self.pending if p["user"] == user and p["id"] not in {x[1] for x in self.posts}]
        return type("R", (), {"json": lambda self, items=items: {"pending": items, "inbox": []}})()

    def post(self, path, json=None):
        parts = path.strip("/").split("/")
        self.posts.append((parts[-1], parts[-2]))                   # (action, push id)
        return type("R", (), {"status_code": 200})()


def run_bot(pending, profiles, expect):
    ph = FakePhone(pending)
    bot = PhoneBot(ph, profiles, delay_s=0, expect_target=expect).start()
    time.sleep(1.5)
    bot.stop()
    return {pid: action for action, pid in ph.posts}


def test_honest_approver_denies_a_change_on_another_account():
    pending = [{"id": "p1", "user": "cfo", "binding": "89-emailchg-jordan.avery.c.bc04-1", "target": "jordan.avery.c.bc04",
                "number": "89"},
               {"id": "p2", "user": "cfo", "binding": "12-reset-cfo.8500-2", "target": "cfo.8500", "number": "12"}]
    acts = run_bot(pending, {"cfo": "approve"}, "cfo")
    assert acts == {"p1": "deny", "p2": "approve"}


def test_fooled_or_attacker_phone_approves_anything():
    pending = [{"id": "p1", "user": "ceo", "binding": "1-mfarecov-cfo.8500-1", "target": "cfo.8500", "number": "1"}]
    assert run_bot(pending, {"ceo": "approve"}, None) == {"p1": "approve"}


def test_unreachable_owner_never_answers():
    pending = [{"id": "p1", "user": "cfo", "binding": "1-reset-cfo.8500-1", "target": "cfo.8500", "number": "1"}]
    assert run_bot(pending, {"cfo": "never"}, "cfo") == {}
