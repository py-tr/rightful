"""The broker's own connection to Keycloak. The sandbox never sees anything from this module.

The broker authenticates as a service account that holds only realm-management manage-users + view-users
(measured on Keycloak 26: it cannot touch the event log, grant roles, create clients or read secrets).
Approvals use Keycloak's native CIBA flow with the broker as the CIBA client, so the token stays here.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx


@dataclass
class KeycloakConfig:
    base_url: str                 # e.g. http://127.0.0.1:8089
    realm: str                    # e.g. corp
    broker_client_id: str         # service account with manage-users + view-users only
    broker_client_secret: str
    ciba_client_id: str           # confidential client with the CIBA grant enabled (poll mode)
    ciba_client_secret: str


class Keycloak:
    def __init__(self, cfg: KeycloakConfig, http: httpx.Client | None = None, clock=time.time):
        self.cfg, self._clock = cfg, clock
        self.http = http or httpx.Client(base_url=cfg.base_url, timeout=15.0)
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_exp = 0.0

    # --- the broker's admin session ---------------------------------------------------------------------------
    def service_token(self) -> str:
        with self._lock:
            if self._token and self._clock() < self._token_exp - 30:
                return self._token
            r = self.http.post(f"/realms/{self.cfg.realm}/protocol/openid-connect/token",
                               data={"grant_type": "client_credentials"},
                               auth=(self.cfg.broker_client_id, self.cfg.broker_client_secret))
            r.raise_for_status()
            j = r.json()
            self._token, self._token_exp = j["access_token"], self._clock() + float(j.get("expires_in", 60))
            return self._token

    def service_token_if_cached(self) -> str | None:
        return self._token

    def forward(self, fwd: dict, with_token: bool = True) -> httpx.Response:
        """Send exactly what the gate decided, with the broker's own token. Nothing else from the sandbox."""
        headers = dict(fwd["headers"])
        if with_token:
            headers["Authorization"] = f"Bearer {self.service_token()}"
        return self.http.request(fwd["method"], fwd["path"], params=fwd["query"] or None,
                                 content=fwd["body"] or None, headers=headers)

    def _user(self, user_id: str) -> dict:
        r = self.http.get(f"/admin/realms/{self.cfg.realm}/users/{user_id}",
                          headers={"Authorization": f"Bearer {self.service_token()}"})
        r.raise_for_status()
        return r.json()

    def username(self, user_id: str) -> str:
        return self._user(user_id)["username"]

    def attribute(self, user_id: str, name: str) -> str | None:
        vals = (self._user(user_id).get("attributes") or {}).get(name) or []
        return str(vals[0]).lower() if vals else None

    def user_snapshot(self, user_id: str) -> dict:
        """What must not change between approval and execution."""
        u = self._user(user_id)
        return {"email": u.get("email"), "manager": ((u.get("attributes") or {}).get("manager") or [None])[0]}

    def manager_of(self, user_id: str) -> str | None:
        """The manager's username from the user attribute 'manager' (set by HR; the broker can read, not edit it)."""
        vals = (self._user(user_id).get("attributes") or {}).get("manager") or []
        return vals[0] if vals else None

    # --- CIBA: the owner's approval on the registered device -----------------------------------------------
    def ciba_start(self, username: str, binding_message: str) -> str:
        r = self.http.post(f"/realms/{self.cfg.realm}/protocol/openid-connect/ext/ciba/auth",
                           data={"login_hint": username, "scope": "openid", "binding_message": binding_message},
                           auth=(self.cfg.ciba_client_id, self.cfg.ciba_client_secret))
        r.raise_for_status()
        return r.json()["auth_req_id"]

    def ciba_poll(self, auth_req_id: str) -> str:
        """'approved' | 'pending' | 'denied' | 'expired'. The resulting token is discarded: approval is all we need."""
        r = self.http.post(f"/realms/{self.cfg.realm}/protocol/openid-connect/token",
                           data={"grant_type": "urn:openid:params:grant-type:ciba", "auth_req_id": auth_req_id},
                           auth=(self.cfg.ciba_client_id, self.cfg.ciba_client_secret))
        if r.status_code == 200:
            return "approved"
        if r.status_code >= 500:                       # the identity server hiccuped: ask again, never turn an honest
            return "pending"                           # approval into "no answer" (11-06)
        try:
            err = (r.json() if r.headers.get("content-type", "").startswith("application/json") else {}).get("error")
        except ValueError:
            return "pending"                           # unparseable answer: same
        if err in ("authorization_pending", "slow_down"):
            return "pending"
        if err == "access_denied":
            return "denied"
        return "expired"                               # expired_token, invalid_grant: final
