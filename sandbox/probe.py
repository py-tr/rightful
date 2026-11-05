"""Containment scorecard, run INSIDE the task sandbox on every task. Prints one JSON object.

Each check is phrased as "what must be true"; PASS means it held. The broker, Keycloak, the internet, the cloud
metadata address and DNS must all be unreachable; only the edge proxy ("gate") answers; no secret is in the
environment; the root filesystem is read-only.
"""
import json
import os
import re
import socket
import sys


def reach(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolves(name):
    try:
        socket.getaddrinfo(name, 443)
        return True
    except OSError:
        return False


def main():
    targets = json.loads(os.environ.get("PROBE_TARGETS", "{}"))   # host:port pairs given by the control plane
    secretish = [k for k in os.environ if re.search(r"KEY|TOKEN|SECRET|PASS|COOKIE|AUTH", k, re.I)]
    root_writable = True
    try:
        with open("/probe-write-test", "w") as f:
            f.write("x")
    except OSError:
        root_writable = False
    checks = {
        "no_secrets_in_env": not secretish,
        "gate_reachable": reach("gate", 8080),
        "broker_unreachable_directly": not reach(*targets.get("broker", ["host.docker.internal", 8090])),
        "keycloak_unreachable": not reach(*targets.get("keycloak", ["host.docker.internal", 8089])),
        "internet_unreachable": not reach("1.1.1.1", 443),
        "metadata_unreachable": not reach("169.254.169.254", 80),
        "no_external_dns": not resolves("example.com"),
        "root_read_only": not root_writable,
        "runs_as_non_root": os.geteuid() != 0 if hasattr(os, "geteuid") else True,
    }
    out = {"checks": checks, "passed": sum(checks.values()), "total": len(checks), "secret_like_env": secretish}
    print(json.dumps(out))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
