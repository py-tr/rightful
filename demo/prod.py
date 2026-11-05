"""Production entry point of the public demo on the control-plane VM (systemd unit keyless-demo).

  - the demo web app on 127.0.0.1:8000, public only through Caddy (TLS);
  - the per-company broker dispatch on the VPC address :8090 (the sandboxes' edge on the worker calls it);
  - the device service dispatch on :8099 (Keycloak's CIBA channel; never routed publicly);
  - visitors' scripts run on the worker VM under gVisor (DEMO_DOCKER_HOSTS), never on this machine, which holds the
    model key, the HMAC master and the realm factory's token;
  - companies come from the realm factory (keyless-factory, 127.0.0.1:8097), the only holder of Keycloak's master admin;
  - counters, limits and permalinks persist in DEMO_DIR across restarts.

Environment: VPC_IP, DEMO_DOCKER_HOSTS (comma-separated ssh://root@10.40.0.x), FACTORY_TOKEN, VULTR_INFERENCE_API_KEY,
KEYLESS_DEMO_CONTRAST=1, optional DEMO_DIR (default /var/lib/keyless/demo), KC_URL, MAIL_API.
"""
from __future__ import annotations

import os
import threading
import time

import uvicorn

from demo.limits import Limits
from demo.server import Demo, FactoryClient, create_demo_app


def main() -> None:
    if os.environ.get("KEYLESS_EVAL"):
        raise SystemExit("REFUSED: the public demo never runs with KEYLESS_EVAL set")
    vpc = os.environ["VPC_IP"]
    hosts = [h.strip() for h in os.environ["DEMO_DOCKER_HOSTS"].split(",") if h.strip()]
    if not hosts or not all(h.startswith("ssh://") for h in hosts):
        raise SystemExit("REFUSED: visitors' scripts must run on a worker (ssh://...), never on the control plane")
    out = os.environ.get("DEMO_DIR", "/var/lib/keyless/demo")
    os.makedirs(out, exist_ok=True)
    demo = Demo(os.environ.get("KC_URL", "http://127.0.0.1:8089"),
                FactoryClient("http://127.0.0.1:8097", os.environ["FACTORY_TOKEN"]),
                Limits(os.path.join(out, "limits.json"),
                       total_usd=float(os.environ.get("DEMO_TOTAL_USD", "15"))),   # owner-approved total, 11-05
                hosts=hosts, out_dir=out,
                edge_upstream=f"http://{vpc}:8090", mail_api=os.environ.get("MAIL_API", "http://127.0.0.1:8025"),
                model=os.environ.get("DEMO_MODEL", "glm-5.3-flash"))
    demo.run_background()
    servers = [uvicorn.Server(uvicorn.Config(demo.broker, host=vpc, port=8090, log_level="warning")),
               uvicorn.Server(uvicorn.Config(demo.push, host="0.0.0.0", port=8099, log_level="warning")),
               uvicorn.Server(uvicorn.Config(create_demo_app(demo), host="127.0.0.1", port=8000, log_level="warning",
                                             proxy_headers=False))]
    for s in servers:
        threading.Thread(target=s.run, daemon=True).start()
    while all(not s.should_exit for s in servers):
        time.sleep(5)


if __name__ == "__main__":
    main()
