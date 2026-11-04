"""Local Keycloak for development and the integration test (fictional realm "corp", local-only admin password).

Creates:
- realm corp with admin events (with representation) and CIBA (poll mode, login_hint);
- users cfo (Jordan Avery), jordan.avery.c (a lookalike contractor), ceo;
- client gate-broker: a service account with realm-management manage-users + view-users ONLY;
- client gate-ciba: confidential, CIBA grant;
- client gate-reconciler: a service account with view-events ONLY (reads the witness; cannot change anything).
Keycloak's CIBA authentication channel points at the push service on the host.
"""
from __future__ import annotations

import subprocess
import sys
import time

import httpx

IMAGE = "quay.io/keycloak/keycloak:26.0.7"
NAME = "keyless-kc"


def start(port: int = 8089, push_url: str = "http://host.docker.internal:8099/ciba/notify",
          public_url: str | None = None) -> str:
    """public_url: the address the sandbox browser uses (the broker). Keycloak then builds its links with it."""
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    extra = [f"--hostname={public_url}"] if public_url else []
    subprocess.run(["docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{port}:8080",
                    "--add-host", "host.docker.internal:host-gateway",
                    "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
                    IMAGE, "start-dev",
                    f"--spi-ciba-auth-channel-ciba-http-auth-channel-http-authentication-channel-uri={push_url}",
                    *extra],
                   check=True, capture_output=True)
    base = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            if httpx.get(f"{base}/realms/master", timeout=2).status_code == 200:
                return base
        except httpx.HTTPError:
            pass
        time.sleep(2)
    sys.exit("Keycloak did not start")


def stop() -> None:
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)


def master_admin(base: str) -> httpx.Client:
    t = httpx.post(f"{base}/realms/master/protocol/openid-connect/token",
                   data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    t.raise_for_status()
    return httpx.Client(base_url=base, headers={"Authorization": f"Bearer {t.json()['access_token']}"}, timeout=15)


def bootstrap(base: str, realm: str = "corp") -> dict:
    a = master_admin(base)
    a.post("/admin/realms", json={
        "realm": realm, "enabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True,
        "eventsEnabled": True,
        "attributes": {"cibaBackchannelTokenDeliveryMode": "poll", "cibaExpiresIn": "180", "cibaInterval": "1",
                       "cibaAuthRequestedUserHint": "login_hint"}}).raise_for_status()
    users = {}
    for username, first, last in (("cfo", "Jordan", "Avery"), ("jordan.avery.c", "Jordan", "Avery-Cole"),
                                  ("ceo", "Sam", "Lee")):
        a.post(f"/admin/realms/{realm}/users", json={
            "username": username, "enabled": True, "firstName": first, "lastName": last, "emailVerified": True,
            "email": f"{username}@corp.example"}).raise_for_status()
        users[username] = a.get(f"/admin/realms/{realm}/users", params={"username": username, "exact": "true"}).json()[0]["id"]

    def client(client_id: str, attrs: dict, service_account: bool) -> tuple[str, str]:
        a.post(f"/admin/realms/{realm}/clients", json={
            "clientId": client_id, "publicClient": False, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "serviceAccountsEnabled": service_account,
            "attributes": attrs}).raise_for_status()
        cid = a.get(f"/admin/realms/{realm}/clients", params={"clientId": client_id}).json()[0]["id"]
        return cid, a.get(f"/admin/realms/{realm}/clients/{cid}/client-secret").json()["value"]

    rm = a.get(f"/admin/realms/{realm}/clients", params={"clientId": "realm-management"}).json()[0]["id"]
    roles = {r["name"]: r for r in a.get(f"/admin/realms/{realm}/clients/{rm}/roles").json()}

    def grant(cid: str, names: list[str]) -> None:
        sa = a.get(f"/admin/realms/{realm}/clients/{cid}/service-account-user").json()["id"]
        a.post(f"/admin/realms/{realm}/users/{sa}/role-mappings/clients/{rm}",
               json=[roles[n] for n in names]).raise_for_status()

    b_id, b_secret = client("gate-broker", {}, True)
    grant(b_id, ["manage-users", "view-users"])
    _, c_secret = client("gate-ciba", {"oidc.ciba.grant.enabled": "true",
                                       "ciba.backchannel.token.delivery.mode": "poll"}, False)
    r_id, r_secret = client("gate-reconciler", {}, True)
    grant(r_id, ["view-events"])

    # The console user the BROKER logs in as (the password stays in the broker; the browser never sees it).
    import secrets as _s
    console_pw = _s.token_urlsafe(18)
    a.post(f"/admin/realms/{realm}/users", json={
        "username": "helpdesk-console", "enabled": True, "firstName": "Help", "lastName": "Desk",
        "email": "helpdesk-console@corp.example", "emailVerified": True,
        "credentials": [{"type": "password", "value": console_pw, "temporary": False}]}).raise_for_status()
    hc = a.get(f"/admin/realms/{realm}/users", params={"username": "helpdesk-console", "exact": "true"}).json()[0]["id"]
    a.post(f"/admin/realms/{realm}/users/{hc}/role-mappings/clients/{rm}",
           json=[roles["manage-users"], roles["view-users"]]).raise_for_status()
    return {"base": base, "realm": realm, "users": users,
            "broker": ("gate-broker", b_secret), "ciba": ("gate-ciba", c_secret),
            "reconciler": ("gate-reconciler", r_secret), "console": ("helpdesk-console", console_pw)}


def admin_events(base: str, realm: str, reconciler: tuple[str, str]) -> list[dict]:
    """Read the witness with the read-only reconciler account."""
    t = httpx.post(f"{base}/realms/{realm}/protocol/openid-connect/token", data={"grant_type": "client_credentials"},
                   auth=reconciler)
    t.raise_for_status()
    r = httpx.get(f"{base}/admin/realms/{realm}/admin-events", params={"max": 500},
                  headers={"Authorization": f"Bearer {t.json()['access_token']}"})
    r.raise_for_status()
    return r.json()
