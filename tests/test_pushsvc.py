import httpx
from fastapi.testclient import TestClient

from broker.pushsvc import create_push_app


def make():
    calls = []

    def handler(req: httpx.Request):
        calls.append({"path": req.url.path, "auth": req.headers.get("authorization"), "body": req.content.decode()})
        return httpx.Response(204)
    app = create_push_app("http://kc", "corp", http=httpx.Client(base_url="http://kc",
                                                                  transport=httpx.MockTransport(handler)), verify_tokens=False)
    return app, TestClient(app), calls


def notify(c, user="cfo", msg="48-reset-cfo-9f3a1c07"):
    return c.post("/ciba/notify", json={"login_hint": user, "binding_message": msg},
                  headers={"Authorization": "Bearer CALLBACK-TOKEN"})


def test_approve_needs_the_matching_number():
    app, c, calls = make()
    assert notify(c).status_code == 201
    p = c.get("/phone/cfo").json()["pending"][0]
    assert "callback_token" not in p and p["number"] == "48"
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "48"}).status_code == 200
    assert calls[0]["auth"] == "Bearer CALLBACK-TOKEN" and '"SUCCEED"' in calls[0]["body"]
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "48"}).status_code == 404   # once only


def test_a_wrong_number_declines_the_request_so_tapping_every_option_never_approves():
    app, c, calls = make()
    notify(c)
    p = c.get("/phone/cfo").json()["pending"][0]
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "12"}).status_code == 409
    assert len(calls) == 1 and '"CANCELLED"' in calls[0]["body"]          # Keycloak is told: declined
    assert c.post(f"/phone/cfo/{p['id']}/approve", json={"number": "48"}).status_code == 404   # no second try
    assert all('"SUCCEED"' not in x["body"] for x in calls)


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


def _realm_keys():
    import json as _json
    import time as _time

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = _json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(good.public_key()))
    jwk.update({"kid": "realm-key", "use": "sig", "alg": "RS256"})

    def tok(key, exp_in=60):
        return jwt.encode({"exp": int(_time.time()) + exp_in, "iss": "http://kc/realms/corp"}, key,
                          algorithm="RS256", headers={"kid": "realm-key"})
    return jwk, tok, good, other


def test_notify_accepts_only_tokens_signed_by_this_realm():
    jwk, tok, good, other = _realm_keys()

    def handler(req: httpx.Request):
        if req.url.path.endswith("/protocol/openid-connect/certs"):
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(204)
    app = create_push_app("http://kc", "corp", http=httpx.Client(base_url="http://kc",
                                                                  transport=httpx.MockTransport(handler)))
    c = TestClient(app)
    body = {"login_hint": "cfo", "binding_message": "48-reset-cfo-9f3a1c07"}
    assert c.post("/ciba/notify", json=body, headers={"Authorization": "Bearer anything"}).status_code == 401
    assert c.post("/ciba/notify", json=body, headers={"Authorization": f"Bearer {tok(other)}"}).status_code == 401
    assert c.post("/ciba/notify", json=body, headers={"Authorization": f"Bearer {tok(good, -5)}"}).status_code == 401
    assert c.get("/phone/cfo").json()["pending"] == []                      # nothing forged reached the phone
    assert c.post("/ciba/notify", json=body, headers={"Authorization": f"Bearer {tok(good)}"}).status_code == 201
    assert len(c.get("/phone/cfo").json()["pending"]) == 1
