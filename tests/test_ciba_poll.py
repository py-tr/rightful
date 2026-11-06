"""The CIBA poll's answers: a transient identity-server failure is 'pending' (ask again), never a final 'expired'
(found 11-06: one 5xx used to turn an honest approval into "the owner did not answer")."""
import httpx
import pytest

from broker.keycloak import Keycloak, KeycloakConfig


def kc_answering(status: int, body=None, ctype="application/json", raw: bytes | None = None):
    def handler(req: httpx.Request):
        if raw is not None:
            return httpx.Response(status, content=raw, headers={"content-type": ctype})
        return httpx.Response(status, json=body or {})
    return Keycloak(KeycloakConfig("http://kc", "corp", "b", "s", "c", "s"),
                    http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(handler)))


@pytest.mark.parametrize("status,body,want", [
    (200, {"access_token": "x"}, "approved"),
    (400, {"error": "authorization_pending"}, "pending"),
    (400, {"error": "slow_down"}, "pending"),
    (400, {"error": "access_denied"}, "denied"),
    (400, {"error": "expired_token"}, "expired"),
    (400, {"error": "invalid_grant"}, "expired"),
    (500, {"error": "unknown_error"}, "pending"),
    (503, None, "pending"),
])
def test_poll_mapping(status, body, want):
    assert kc_answering(status, body).ciba_poll("req-1") == want


def test_unparseable_json_is_pending_not_expired():
    assert kc_answering(400, raw=b"{not json", ctype="application/json").ciba_poll("req-1") == "pending"
