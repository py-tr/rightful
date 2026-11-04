import httpx
from fastapi.testclient import TestClient

from broker.pushsvc import create_push_app


def make():
    calls = []

    def handler(req: httpx.Request):
        calls.append({"path": req.url.path, "auth": req.headers.get("authorization"), "body": req.content.decode()})
        return httpx.Response(204)
    app = create_push_app("http://kc", "corp", http=httpx.Client(base_url="http://kc",
                                                                  transport=httpx.MockTransport(handler)))
    return app, TestClient(app), calls


def notify(c, user="cfo", msg="48-reset-cfo-9f3a1c07"):
    return c.post("/ciba/notify", json={"login_hint": user, "binding_message": msg},
                  headers={"Authorization": "Bearer CALLBACK-TOKEN"})


def test_approve_needs_the_matching_number():
    app, c, calls = make()
    assert notify(c).status_code == 201
    p = c.get("/phone/cfo").json()["pending"][0]
    assert "callback_token" not in p and p["number"] == "48"
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "12"}).status_code == 409
    assert calls == []
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "48"}).status_code == 200
    assert calls[0]["auth"] == "Bearer CALLBACK-TOKEN" and '"SUCCEED"' in calls[0]["body"]
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "48"}).status_code == 404   # once only


def test_another_users_phone_cannot_answer():
    app, c, calls = make()
    notify(c)
    pid = c.get("/phone/cfo").json()["pending"][0]["id"]
    assert c.post(f"/phone/jordan.avery.c/{pid}/approve", json={"number": "48"}).status_code == 404
    assert c.get("/phone/jordan.avery.c").json()["pending"] == []
    assert calls == []


def test_deny_and_inbox():
    app, c, calls = make()
    notify(c)
    pid = c.get("/phone/cfo").json()["pending"][0]["id"]
    assert c.post(f"/phone/cfo/{pid}/deny").status_code == 200 and '"CANCELLED"' in calls[0]["body"]
    app.state.deliver("cfo", "TMP-PW-1")
    assert c.get("/phone/cfo").json()["inbox"][0]["value"] == "TMP-PW-1"
    assert c.get("/phone/ceo").json()["inbox"] == []


def test_notify_without_bearer_is_refused():
    app, c, calls = make()
    assert c.post("/ciba/notify", json={"login_hint": "cfo", "binding_message": "1-a-b-c"}).status_code == 401
