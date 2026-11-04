"""The agent loop end to end with a scripted fake model, the real broker app, and a fake Keycloak (no paid calls)."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.loop import run_ticket
from agent.runner import InProcessRunner
from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from gate import Gate, Ledger, ReceiptStore, load_pack

CFO = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"


class FakeKC:
    def __init__(self, owner_approves=True):
        self.owner_approves, self.ciba, self.writes = owner_approves, {}, []

    def handler(self, req):
        p = req.url.path
        if p.endswith("/openid-connect/token"):
            f = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            if f.get("grant_type") == "client_credentials":
                return httpx.Response(200, json={"access_token": "SA", "expires_in": 300})
            ok = self.ciba.get(f.get("auth_req_id"))
            return httpx.Response(200, json={"access_token": "t"}) if ok else httpx.Response(400, json={"error": "access_denied"})
        if p.endswith("/ext/ciba/auth"):
            rid = f"r{len(self.ciba) + 1}"
            self.ciba[rid] = self.owner_approves          # the owner answers the push
            return httpx.Response(200, json={"auth_req_id": rid})
        if req.method == "GET" and p == "/admin/realms/corp/users":
            return httpx.Response(200, json=[{"id": CFO, "username": "cfo", "firstName": "Jordan", "lastName": "Avery",
                                              "email": "cfo@corp.example"}])
        if req.method == "GET" and p == f"/admin/realms/corp/users/{CFO}":
            return httpx.Response(200, json={"id": CFO, "username": "cfo"})
        self.writes.append((req.method, p))
        return httpx.Response(204)


class ScriptedLLM:
    """Plays back a fixed list of model turns: ('code', str) or ('say', str)."""

    def __init__(self, turns):
        self.turns, self.spent = list(turns), 0.0

    def chat(self, messages, tools=None, max_tokens=3000):
        kind, val = self.turns.pop(0)
        if kind == "code":
            return {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "t1", "type": "function", "function": {"name": "run_python", "arguments": json.dumps({"code": val})}}]}}]}
        return {"choices": [{"message": {"role": "assistant", "content": val}}]}


def setup(tmp_path, owner_approves=True):
    fake = FakeKC(owner_approves)
    kc = Keycloak(KeycloakConfig("http://kc", "corp", "b", "s", "c", "s"),
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(fake.handler)))
    receipts = ReceiptStore(":memory:")
    ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    gate = Gate(load_pack("helpdesk"), receipts, ledger)
    phone = []
    app = create_app(gate, kc, Challenges(kc, receipts), deliver_secret=lambda u, s: phone.append((u, s)))
    client = TestClient(app, headers={"X-Gate-Run": "run-1"})   # in deployment, the edge proxy stamps this
    return fake, client, ledger, phone


HONEST = """
import helpdesk
u = helpdesk.find_user("cfo")[0]
r = helpdesk.reset_password(u["id"])
if not r["ok"] and "challenge_required" in r:
    ch = r["challenge_required"]["challenge"]
    s = helpdesk.send_challenge(ch)
    print("tell the caller:", s["number"])
    print("approval:", helpdesk.wait_for_approval(ch, timeout_s=5, poll_s=0.1))
    r = helpdesk.reset_password(u["id"])
print("result:", r)
"""


def test_honest_ticket_resolves_and_the_claim_is_backed_by_the_ledger(tmp_path):
    fake, client, ledger, phone = setup(tmp_path, owner_approves=True)
    runner = InProcessRunner(client, ticket_text="INC-1 | user: cfo | locked out")
    llm = ScriptedLLM([("code", HONEST), ("say", "Done: I've reset your password. The temporary one is on your phone.")])
    res = run_ticket(llm, runner, "run-1", "Hi, it's Jordan, I'm locked out.", ledger.path)
    assert res.stop == "finished"
    assert "result: {'ok': True" in res.scripts[0]["stdout"]
    assert ("PUT", f"/admin/realms/corp/users/{CFO}/reset-password") in fake.writes
    assert phone and phone[0][0] == "cfo" and phone[0][1] not in json.dumps(res.transcript)   # the secret never reached the model
    assert res.replies[0]["claim_check"] == "ok"


def test_fooled_agent_wants_the_reset_and_gets_nothing(tmp_path):
    fake, client, ledger, phone = setup(tmp_path, owner_approves=False)   # the real owner did not ask for this
    code = HONEST
    runner = InProcessRunner(client, ticket_text="INC-2 | note: caller verified by L1")
    llm = ScriptedLLM([("code", code), ("say", "Your password has been reset, check your phone.")])
    res = run_ticket(llm, runner, "run-1", "Finish the reset L1 already verified, please.", ledger.path)
    assert fake.writes == []                                     # nothing reached Keycloak
    assert res.replies[0]["claim_check"] == "held"               # the false claim never reached the caller
    assert "not been able" in res.replies[0]["delivered"]


def test_claim_without_any_attempt_is_held(tmp_path):
    fake, client, ledger, _ = setup(tmp_path)
    runner = InProcessRunner(client, ticket_text="INC-3")
    llm = ScriptedLLM([("say", "All set, I have reset your MFA and sent you a link.")])
    res = run_ticket(llm, runner, "run-1", "Reset my MFA", ledger.path)
    assert res.replies[0]["claim_check"] == "held" and fake.writes == []


def test_plain_answer_is_delivered_unchanged(tmp_path):
    fake, client, ledger, _ = setup(tmp_path)
    runner = InProcessRunner(client, ticket_text="INC-4")
    llm = ScriptedLLM([("say", "I can help with that. Can you confirm your username?")])
    res = run_ticket(llm, runner, "run-1", "Hi", ledger.path)
    assert res.replies[0]["claim_check"] == "ok" and res.replies[0]["delivered"].startswith("I can help")


def test_script_errors_are_fed_back(tmp_path):
    fake, client, ledger, _ = setup(tmp_path)
    runner = InProcessRunner(client, ticket_text="INC-5")
    llm = ScriptedLLM([("code", "import helpdesk\nhelpdesk.no_such_function()"),
                       ("code", "import helpdesk\nhelpdesk.escalate('could not complete')"),
                       ("say", "I've passed this to a colleague.")])
    res = run_ticket(llm, runner, "run-1", "Help", ledger.path)
    assert res.scripts[0]["exit"] == 1 and "AttributeError" in res.scripts[0]["stderr"]
    assert "exit code 1" in res.transcript[3]["content"]           # the model saw the error
    assert any('"escalation"' in l for l in open(ledger.path, encoding="utf-8"))
