"""One visitor's fake company for the public demo, wired up: its own gate, receipts, ledger, challenge service, phone and
broker app around a company the REALM FACTORY made (demo/factory.py). This process never holds Keycloak's master admin:
it gets one company's own clients (the broker's service account, the CIBA client, the view-only reconciler) and reads
the company's admin events with the reconciler, so a compromise here exposes one company at a time.

Full gate mode only: the demo never runs an evaluation mode (those are refused outside `eval-*` realms anyway).
"""
from __future__ import annotations

import os
import secrets
import time

import httpx

from broker.app import create_app
from broker.challenges import Challenges
from broker.keycloak import Keycloak, KeycloakConfig
from broker.pushsvc import create_push_app
from eval import oracle
from gate import Gate, Ledger, ReceiptStore, load_pack

DEMO_PACK_OVERRIDES = {"cooling_off_seconds": {"default": 20, "privileged": 40}}   # shown on the page; prod 60 / 600


class SessionStack:
    def __init__(self, kc_base: str, out_dir: str, run_key_master: bytes, company: dict, host_header: str = "gate:8080"):
        self.kc_base, self.out_dir, self.master, self.host = kc_base, out_dir, run_key_master, host_header
        self.company = company
        self.realm = company["realm"]
        self.session_id = self.realm.removeprefix("demo-")
        self.created = time.time()
        self.generated: list[str] = []

    def create(self) -> "SessionStack":
        c = self.company
        pack = {**load_pack("helpdesk"), "realm": self.realm, **DEMO_PACK_OVERRIDES}
        os.makedirs(self.out_dir, exist_ok=True)
        self.ledger = Ledger(os.path.join(self.out_dir, f"{self.session_id}.ledger.jsonl"))
        receipts = ReceiptStore(":memory:")
        self.kc = Keycloak(KeycloakConfig(self.kc_base, self.realm, *c["broker"], *c["ciba"]),
                           http=httpx.Client(base_url=self.kc_base, timeout=15, headers={"Host": self.host}))

        def secret_factory():
            s = secrets.token_urlsafe(12)
            self.generated.append(s)
            return s
        self.gate = Gate(pack, receipts, self.ledger, secret_factory=secret_factory)
        self.push = create_push_app(self.kc_base, self.realm, http=httpx.Client(base_url=self.kc_base, timeout=10,
                                                                                headers={"Host": self.host}))
        self.challenges = Challenges(self.kc, receipts, pack=pack, notify=self.push.state.notify, ledger=self.ledger)
        self.push.state.on_cancel = self.challenges.cancel
        self.app = create_app(self.gate, self.kc, self.challenges, deliver_secret=self.push.state.deliver,
                              notify=self.push.state.notify, run_key_master=self.master)
        return self

    def users(self) -> dict:
        return dict(self.company["users"])

    def events(self) -> list[dict]:
        """Keycloak's own admin events in this company made by the broker's service account, read with the company's
        view-only reconciler account (the independent record)."""
        t = httpx.post(f"{self.kc_base}/realms/{self.realm}/protocol/openid-connect/token",
                       data={"grant_type": "client_credentials"}, auth=tuple(self.company["reconciler"]),
                       headers={"Host": self.host}, timeout=15)
        t.raise_for_status()
        r = httpx.get(f"{self.kc_base}/admin/realms/{self.realm}/admin-events", params={"max": 2000},
                      headers={"Authorization": f"Bearer {t.json()['access_token']}", "Host": self.host}, timeout=15)
        r.raise_for_status()
        return [oracle.classify(e) for e in r.json()
                if (e.get("authDetails") or {}).get("userId") == self.company["broker_sa_user"]]
