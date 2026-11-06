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


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def measured():
    """What the sandbox itself sees (11-06: the runner used to report only the runtime it was CONFIGURED with). Under
    gVisor the kernel is gVisor's own emulated one, whatever the host runs: measured on the live worker 11-06,
    uname -r = '4.19.0-gvisor' while the host is 6.8.0. Limits come from the container's own cgroup files."""
    version = _read("/proc/version") or ""
    release = os.uname().release if hasattr(os, "uname") else ""
    mem = _read("/sys/fs/cgroup/memory.max") or _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    pids = _read("/sys/fs/cgroup/pids.max") or _read("/sys/fs/cgroup/pids/pids.max")
    cpu = _read("/sys/fs/cgroup/cpu.max")
    mem_mb = int(mem) // (1024 * 1024) if mem and mem.isdigit() else None
    return {"kernel_release": release, "proc_version": version[:160],
            "gvisor": "gvisor" in release.lower() or "gvisor" in version.lower(),
            "memory_limit_mb": mem_mb, "pids_limit": pids, "cpu_max": cpu}


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
    out = {"checks": checks, "passed": sum(checks.values()), "total": len(checks), "secret_like_env": secretish,
           "measured": measured()}
    print(json.dumps(out))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
