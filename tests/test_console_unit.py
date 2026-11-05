"""The console route builds every upstream request (mentor's review after the measured bypass): a header allowlist,
the token endpoint limited to the console's own client and its two grants, a body rebuilt from parsed fields."""
from urllib.parse import parse_qsl

import httpx
import pytest

from broker.console import ConsoleSession

TOKEN = "/realms/corp/protocol/openid-connect/token"
AUTH = "/realms/corp/protocol/openid-connect/auth"


@pytest.fixture
def cs():
    seen = []

    def handler(req):
        seen.append(req)
        if req.url.path == TOKEN:
            return httpx.Response(200, json={"access_token": "a.b.REALSIG", "refresh_token": "r.s.REALSIG2"})
        return httpx.Response(200, text="ok", headers={"Content-Type": "text/plain"})
    s = ConsoleSession("http://kc:8080", "http://gate:8080", "corp", "helpdesk-console", "pw")
    s.http = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return s, seen


def form(req):
    return dict(parse_qsl(req.content.decode()))


@pytest.mark.parametrize("body,why", [
    (b"grant_type=password&client_id=admin-cli&username=cfo&password=Winter2026", "password grant"),
    (b"grant_type=password&client_id=security-admin-console&username=cfo&password=x", "password grant, console id"),
    (b"grant_type=client_credentials&client_id=gate-broker&client_secret=guess", "client credentials"),
    (b"grant_type=refresh_token&client_id=admin-cli&refresh_token=x", "another client"),
    (b"grant_type=urn:openid:params:grant-type:ciba&client_id=gate-ciba&auth_req_id=x", "CIBA"),
    (b"grant_type=refresh_token&client_id=security-admin-console&refresh_token=x&password=y", "smuggled field"),
    (b"grant_type=refresh_token&grant_type=password&client_id=security-admin-console", "repeated field"),
    (b"\xff\xfe", "not a form"),
])
def test_token_endpoint_is_not_a_password_oracle(cs, body, why):
    s, seen = cs
    status, _, data = s.handle("POST", TOKEN, {"Content-Type": "application/x-www-form-urlencoded"}, body)
    assert status == 403 and seen == [], why


def test_console_refresh_passes_with_the_real_token_swapped_in(cs):
    s, seen = cs
    status, _, data = s.handle("POST", TOKEN, {}, b"grant_type=authorization_code&client_id=security-admin-console"
                                                  b"&code=c1&redirect_uri=http%3A%2F%2Fgate%3A8080%2Fadmin&code_verifier=v")
    assert status == 200 and b"REALSIG" not in data                            # the browser gets fakes only
    fake_refresh = __import__("json").loads(data)["refresh_token"]
    status, _, _ = s.handle("POST", TOKEN, {}, f"grant_type=refresh_token&client_id=security-admin-console"
                                               f"&refresh_token={fake_refresh}".encode())
    assert status == 200 and form(seen[-1])["refresh_token"] == "r.s.REALSIG2"  # swapped back only here


def test_only_allowlisted_headers_reach_keycloak(cs):
    s, seen = cs
    s.handle("GET", "/resources/x/admin/app.js", {"Accept": "*/*", "X-HTTP-Method-Override": "PUT",
                                                  "X-Forwarded-Host": "evil", "Cookie": "KEYCLOAK_IDENTITY=x",
                                                  "Origin": "http://evil"}, b"")
    sent = {k.lower() for k in seen[-1].headers}
    assert "x-http-method-override" not in sent and "x-forwarded-host" not in sent and "origin" not in sent
    assert seen[-1].headers.get("cookie") in (None, "")                        # only the broker's own jar


def test_sign_in_only_for_the_console_client(cs):
    s, seen = cs
    assert s.handle("GET", AUTH + "?client_id=admin-cli&response_type=code&redirect_uri=x", {}, b"")[0] == 403
    assert seen == []
    assert s.handle("GET", AUTH + "?client_id=security-admin-console&response_type=code", {}, b"")[0] == 200


def test_get_with_a_body_is_refused(cs):
    s, seen = cs
    assert s.handle("GET", "/resources/x/app.js", {}, b"payload")[0] == 403 and seen == []


def test_token_map_is_bounded(cs):
    s, _ = cs
    for i in range(s.MAX_TOKENS + 50):
        s._fake(f"h.p.sig{i}")
    assert len(s._fake2real) == s.MAX_TOKENS and len(s.real_tokens) == s.MAX_TOKENS
