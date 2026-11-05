"""One visitor's fake company for the public demo: a FRESH Keycloak realm with mock users (cfo Jordan Avery, the
lookalike contractor jordan.avery.c, ceo Sam Lee as cfo's manager), its own gate, receipts, ledger, challenge service,
phone and broker app. Created at session start, deleted when the session ends. Nothing is shared between visitors
except Keycloak itself, and no visitor ever touches the deployment's own realm.

The same per-run isolation the evaluation uses (eval/harness.py), in FULL gate mode only: the demo never runs an
evaluation mode (those are refused outside `eval-*` realms anyway).
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
from devenv import keycloak_local as kl
from gate import Gate, Ledger, ReceiptStore, load_pack

DEMO_PACK_OVERRIDES = {"cooling_off_seconds": {"default": 20, "privileged": 40}}   # shown on the page; prod 60 / 600
CIBA_EXPIRES_S = 60


class SessionStack:
    def __init__(self, kc_base: str, out_dir: str, run_key_master: bytes, host_header: str = "gate:8080"):
        self.kc_base, self.out_dir, self.master, self.host = kc_base, out_dir, run_key_master, host_header
        self.session_id = "s" + secrets.token_hex(6)
        self.realm = f"demo-{self.session_id}"
        self.created = time.time()
        self.generated: list[str] = []
        self.app = self.push = self.gate = self.env = None

    def _bootstrap(self, attempts: int = 3) -> dict:
        """Keycloak in dev mode can fail a realm creation under concurrency (measured in the evaluation: 'Not found in
        database', 0.7% of runs). Retry with a clean slate."""
        last = None
        for i in range(attempts):
            try:
                return kl.bootstrap(self.kc_base, realm=self.realm, smtp=True)
            except httpx.HTTPStatusError as e:
                last = e
                try:
                    kl.master_admin(self.kc_base).delete(f"/admin/realms/{self.realm}")
                except Exception:                       # noqa: BLE001
                    pass
                time.sleep(0.5 * (i + 1))
        raise RuntimeError(f"could not create the session's realm: {last}")

    def create(self) -> "SessionStack":
        self.env = self._bootstrap()
        admin = kl.master_admin(self.kc_base)
        rep = admin.get(f"/admin/realms/{self.realm}").json()
        rep.setdefault("attributes", {})["cibaExpiresIn"] = str(CIBA_EXPIRES_S)
        admin.put(f"/admin/realms/{self.realm}", json=rep).raise_for_status()
        cid = admin.get(f"/admin/realms/{self.realm}/clients", params={"clientId": "gate-broker"}).json()[0]["id"]
        self.broker_sa = admin.get(f"/admin/realms/{self.realm}/clients/{cid}/service-account-user").json()["id"]
        pack = {**load_pack("helpdesk"), "realm": self.realm, **DEMO_PACK_OVERRIDES}
        os.makedirs(self.out_dir, exist_ok=True)
        self.ledger = Ledger(os.path.join(self.out_dir, f"{self.session_id}.ledger.jsonl"))
        receipts = ReceiptStore(":memory:")
        self.kc = Keycloak(KeycloakConfig(self.kc_base, self.realm, *self.env["broker"], *self.env["ciba"]),
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
        return dict(self.env["users"])

    def events(self) -> list[dict]:
        """Keycloak's own admin events in this realm made by the broker's service account (the independent record)."""
        from eval import oracle
        return oracle.broker_events(kl.master_admin(self.kc_base), self.realm, self.broker_sa)

    def close(self) -> bool:
        try:
            r = kl.master_admin(self.kc_base).delete(f"/admin/realms/{self.realm}")
            return r.status_code in (204, 404)
        except Exception:                               # noqa: BLE001
            return False
