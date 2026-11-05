import json

import pytest

from gate import Reject, load_pack, parse

PACK = load_pack("helpdesk")
U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
C = "0b9b2a3e-1111-4c86-9912-27a5a18fb8cd"
RESET = f"/admin/realms/corp/users/{U}/reset-password"
BODY = json.dumps({"type": "password", "temporary": True, "value": "agent-chosen"}).encode()


def kind(method, target, body=b""):
    try:
        return parse(PACK, method, target, body).name
    except Reject as r:
        return f"REJECT:{r.kind}"


def test_legit_operations_parse():
    assert kind("PUT", RESET, BODY) == "reset_password"
    assert kind("PUT", f"/admin/realms/corp/users/{U}/execute-actions-email?lifespan=900", b'["UPDATE_PASSWORD"]') \
        == "send_actions_email"
    assert kind("DELETE", f"/admin/realms/corp/users/{U}/credentials/{C}") == "remove_credential"
    assert kind("POST", f"/admin/realms/corp/users/{U}/logout") == "logout_sessions"
    assert kind("PUT", f"/admin/realms/corp/users/{U}", b'{"email":"jordan.avery@corp.example"}') == "change_email"
    assert kind("GET", f"/admin/realms/corp/users?search=jordan&max=20") == "read"
    # The static route is closed (mentor's review: same shape as the old console route). Console assets go only
    # through the console route's allowlist; without a console, nothing outside the admin API is reachable.
    assert kind("GET", "/resources/abc123/admin/keycloak.v2/app.js") == "REJECT:not_allowlisted"
    assert kind("GET", "/admin/realms/corp/users?q=manager:ceo") == "REJECT:not_allowlisted"     # no attribute search
    assert kind("GET", "/admin/realms/corp/users?first=0&max=11&q=") == "read"     # what the real console sends


@pytest.mark.parametrize("target", [
    f"/admin/realms/corp/users/{U};x=y/reset-password",          # matrix parameter (real Keycloak 26 bypass)
    f"/admin/realms/corp/users/{U}/reset-password;jsessionid=1",
    f"/admin/realms/corp/users/%64{U[1:]}/reset-password",         # percent-encoding
    f"/admin/realms/corp/users/{U}/../{U}/reset-password",          # dot segment
    f"/admin/realms/corp/users//{U}/reset-password",                # empty segment
    f"/admin/realms/corp/users/{U}/reset-password/",                # trailing slash
    f"/admin/realms/corp/users/{U.upper()}/reset-password",         # case of the id
    f"/admin/realms/CORP/users/{U}/reset-password",                 # case of the realm
    f"/admin/realms/master/users/{U}/reset-password",               # another realm
    f"/admin/realms/corp/users/{U}/Reset-Password",                 # case of the action
    f"/admin/realms/corp/users/{U}/reset-password#frag",
    f"/admin/realms/corp/users/{U}\\reset-password",
    f"/admin/realms/corp/users/{U}/reset-password?redirect_uri=x",  # unexpected query
])
def test_path_tricks_rejected(target):
    assert kind("PUT", target, BODY).startswith("REJECT")


@pytest.mark.parametrize("body", [
    b'{"type":"password","temporary":true,"value":"x","credentialData":"{}"}',   # extra field
    b'{"type":"password","temporary":false,"value":"x"}',                        # permanent password
    b'{"type":"otp","temporary":true}',                                           # other credential type
    b'{"type":"password","type":"otp","temporary":true}',                         # duplicate key
    b'[{"type":"password"}]',                                                      # not an object
    b'{"type":"password","temporary":true,"value":NaN}',                           # NaN
    b'\xff\xfe',                                                                   # not UTF-8
])
def test_body_tricks_rejected_on_reset(body):
    assert kind("PUT", RESET, body).startswith("REJECT")


def test_update_user_accepts_only_email():
    t = f"/admin/realms/corp/users/{U}"
    for body in (b'{"email":"a@corp.example","credentials":[{"type":"password","value":"x"}]}',
                 b'{"email":"a@corp.example","requiredActions":[]}',
                 b'{"email":"a@corp.example","realmRoles":["admin"]}',
                 b'{"enabled":false}', b'{}'):
        assert kind("PUT", t, body).startswith("REJECT"), body


def test_actions_email_rejects_redirect_and_client_and_unknown_actions():
    t = f"/admin/realms/corp/users/{U}/execute-actions-email"
    assert kind("PUT", t + "?redirect_uri=https://evil.example", b'["UPDATE_PASSWORD"]').startswith("REJECT")
    assert kind("PUT", t + "?client_id=admin-cli", b'["UPDATE_PASSWORD"]').startswith("REJECT")
    assert kind("PUT", t + "?lifespan=900&lifespan=99999", b'["UPDATE_PASSWORD"]').startswith("REJECT")
    assert kind("PUT", t, b'["UPDATE_PASSWORD","DELETE_ACCOUNT"]').startswith("REJECT")
    assert kind("PUT", t, b'["UPDATE_PASSWORD","UPDATE_PASSWORD"]').startswith("REJECT")
    assert kind("PUT", t, b'[]').startswith("REJECT")


@pytest.mark.parametrize("method,target,body", [
    ("PUT", "/admin/realms/corp/events/config", b'{"adminEventsEnabled":false}'),   # witness off
    ("PUT", "/admin/realms/corp", b'{"adminEventsEnabled":false}'),
    ("DELETE", "/admin/realms/corp/admin-events", b""),
    ("POST", f"/admin/realms/corp/users/{U}/role-mappings/realm", b'[{"name":"admin"}]'),
    ("POST", "/admin/realms/corp/clients", b'{"clientId":"evil"}'),
    ("DELETE", f"/admin/realms/corp/users/{U}", b""),
    ("GET", "/admin/realms/corp/clients/abc/client-secret", b""),
    ("GET", "/admin/realms/corp/admin-events", b""),
    ("PATCH", RESET, BODY),
    ("GET", "/resources/../admin/realms/corp/users", b""),
])
def test_everything_else_is_denied(method, target, body):
    assert kind(method, target, body).startswith("REJECT")


def test_override_field_is_blanked_in_hash():
    a = parse(PACK, "PUT", RESET, BODY)
    b = parse(PACK, "PUT", RESET, json.dumps({"type": "password", "temporary": True, "value": "other"}).encode())
    c = parse(PACK, "PUT", RESET, json.dumps({"type": "password", "temporary": True}).encode())
    assert a.request_hash == b.request_hash == c.request_hash   # the password the agent typed is not part of it
    assert b"agent-chosen" not in a.canonical_body


def test_hash_binds_target_and_body():
    other = "e1a2b3c4-c4a5-4c86-9912-27a5a18fb8cd"
    h1 = parse(PACK, "PUT", RESET, BODY).request_hash
    h2 = parse(PACK, "PUT", RESET.replace(U, other), BODY).request_hash
    e1 = parse(PACK, "PUT", f"/admin/realms/corp/users/{U}", b'{"email":"a@corp.example"}').request_hash
    e2 = parse(PACK, "PUT", f"/admin/realms/corp/users/{U}", b'{"email":"b@corp.example"}').request_hash
    assert h1 != h2 and e1 != e2


def test_read_search_values_may_be_url_encoded_but_only_once():
    ok = parse(PACK, "GET", "/admin/realms/corp/users?search=Jordan%20Avery&max=10", b"")
    assert ok.name == "read" and ("search", "Jordan Avery") in ok.query
    assert parse(PACK, "GET", "/admin/realms/corp/users?search=Jordan+Avery", b"").query[0] == ("search", "Jordan Avery")
    for bad in ("search=%2541", "search=%0d%0a", "search=%zz", "sea%72ch=x"):
        assert kind("GET", f"/admin/realms/corp/users?{bad}").startswith("REJECT"), bad
    # writes stay strict: no encoding at all
    assert kind("PUT", f"/admin/realms/corp/users/{U}/execute-actions-email?lifespan=9%300",
                b'["UPDATE_PASSWORD"]').startswith("REJECT")
