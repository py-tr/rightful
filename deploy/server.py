"""Production entry point on the control-plane VM: the broker (VPC-only) and the owner-device service (public through
Caddy for the demo phone pane). Configuration comes from the environment and /opt/keyless/secrets.json (root-only)."""
from __future__ import annotations

import json
import os
import threading
import time

import httpx
import uvicorn

from broker.app import create_app
from broker.challenges import Challenges
from broker.console import ConsoleSession
from broker.keycloak import Keycloak, KeycloakConfig
from broker.pushsvc import create_push_app
from gate import Gate, Ledger, ReceiptStore, load_pack

SECRETS = os.environ.get("KEYLESS_SECRETS", "/opt/keyless/secrets.json")
KC = os.environ.get("KC_URL", "http://127.0.0.1:8089")
PUBLIC_FOR_SANDBOX = os.environ.get("SANDBOX_PUBLIC", "http://gate:8080")   # what the sandboxed browser calls
BROKER_BIND = os.environ.get("BROKER_BIND", "127.0.0.1")                    # the VPC address in deployment
LEDGER = os.environ.get("LEDGER_PATH", "/var/lib/keyless/ledger.jsonl")


def build():
    s = json.load(open(SECRETS, encoding="utf-8"))
    pack = load_pack("helpdesk")
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    receipts = ReceiptStore(os.environ.get("RECEIPTS_DB", "/var/lib/keyless/receipts.db"))
    gate = Gate(pack, receipts, Ledger(LEDGER))
    host = {"Host": PUBLIC_FOR_SANDBOX.split("://")[1]}
    kc = Keycloak(KeycloakConfig(KC, "corp", *s["broker"], *s["ciba"]),
                  http=httpx.Client(base_url=KC, timeout=15, headers=host))
    console = ConsoleSession(KC, PUBLIC_FOR_SANDBOX, "corp", *s["console"])
    push = create_push_app(KC, "corp", http=httpx.Client(base_url=KC, timeout=10, headers=host))
    ch = Challenges(kc, receipts, pack=pack, notify=push.state.notify)
    push.state.on_cancel = ch.cancel
    broker = create_app(gate, kc, ch, deliver_secret=push.state.deliver, notify=push.state.notify, console=console)

    @push.get("/healthz")
    def health():
        return {"ok": True, "ledger_entries": gate.ledger.head()["seq"]}

    return broker, push


def main():
    broker, push = build()
    servers = [uvicorn.Server(uvicorn.Config(broker, host=BROKER_BIND, port=8090, log_level="warning")),
               uvicorn.Server(uvicorn.Config(push, host="0.0.0.0", port=8099, log_level="warning"))]
    for s in servers:
        threading.Thread(target=s.run, daemon=True).start()
    while all(not s.should_exit for s in servers):
        time.sleep(5)


if __name__ == "__main__":
    main()
