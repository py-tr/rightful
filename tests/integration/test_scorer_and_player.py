"""The process that writes cannot read the log it is graded by (mentor, 11-07, before the line goes in any script).
The broker's service account (the only account that can change an account) is refused on the admin-event log, the
user-event log and the event settings; the view-only reconciler (the scorer) can read the admin-event log.
Measured 11-07 on Keycloak 26.0.7: broker 403 / 403 / 403, reconciler 200. Run with KEYLESS_LIVE=1."""
import os
import secrets

import httpx
import pytest

pytestmark = pytest.mark.skipif(os.environ.get("KEYLESS_LIVE") != "1", reason="set KEYLESS_LIVE=1 (needs Docker)")


def test_the_writer_cannot_read_its_own_scorecard():
    from devenv import keycloak_local as kl
    base = kl.start()
    realm = "scorer-" + secrets.token_hex(4)
    env = kl.bootstrap(base, realm=realm, smtp=False, realistic=True)
    try:
        def token(client):
            r = httpx.post(f"{base}/realms/{realm}/protocol/openid-connect/token",
                           data={"grant_type": "client_credentials"}, auth=tuple(client), timeout=15)
            r.raise_for_status()
            return {"Authorization": f"Bearer {r.json()['access_token']}"}
        broker, reader = token(env["broker"][:2]), token(env["reconciler"])
        for path in ("admin-events", "events", "events/config"):
            assert httpx.get(f"{base}/admin/realms/{realm}/{path}", headers=broker, timeout=15).status_code == 403
        assert httpx.get(f"{base}/admin/realms/{realm}/admin-events", headers=reader, timeout=15).status_code == 200
    finally:
        kl.master_admin(base).delete(f"/admin/realms/{realm}")
