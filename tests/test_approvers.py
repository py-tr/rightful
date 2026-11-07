"""The default approver resolver must answer exactly as broker/challenges.py did before the move (the help-desk results
were measured on that code): same approver, same human_only, same reason, same privileged flag, same snapshot."""
from broker.approvers import IdentityServerResolver


class StubKC:
    def __init__(self, users):
        self.users = users

    def username(self, uid):
        return self.users[uid]["username"]

    def manager_of(self, uid):
        return self.users[uid].get("manager")

    def attribute(self, uid, name):
        return self.users[uid].get(name)

    def user_snapshot(self, uid):
        return {"email": self.users[uid].get("email"), "manager": self.users[uid].get("manager")}


def old_logic(kc, uid, kind):
    """The pre-move body of Challenges.create, copied verbatim."""
    username = kc.username(uid)
    approver, human_only, why = username, False, ""
    if kind in ("manager", "contact"):
        mgr = kc.manager_of(uid)
        approver = mgr or ""
        if not mgr or mgr == username:
            human_only, why = True, "no independent manager on record"
    return username, approver, human_only, why


USERS = {"u1": {"username": "cfo", "manager": "ceo", "email": "cfo@corp.example"},
         "u2": {"username": "ceo", "manager": None, "email": "ceo@corp.example"},
         "u3": {"username": "self", "manager": "self", "email": "s@corp.example"},
         "u4": {"username": "vip", "manager": "ceo", "privileged": "true", "email": "vip@corp.example"}}


def test_default_resolver_matches_the_old_code_in_every_case():
    kc = StubKC(USERS)
    r = IdentityServerResolver(kc, {})
    for uid in USERS:
        for kind in ("owner", "manager", "contact", "something_else"):
            subject = r.subject_name(uid)
            assert (subject, *r.approver_for(uid, kind, subject)) == old_logic(kc, uid, kind), (uid, kind)


def test_default_resolver_privileged_and_snapshot_unchanged():
    kc = StubKC(USERS)
    r = IdentityServerResolver(kc, {})
    assert r.privileged("u4") and not r.privileged("u1")
    assert IdentityServerResolver(kc, {"privileged_attribute": "missing"}).privileged("u4") is False
    assert r.snapshot("u1") == kc.user_snapshot("u1")
