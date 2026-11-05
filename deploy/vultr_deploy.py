"""Deploy Keyless on Vultr from a workstation (approved budget cap: $50 through judging).

  python -m deploy.vultr_deploy up              create VPC, firewall groups, SSH key, control plane + worker; provision
  python -m deploy.vultr_deploy status          what exists, hourly cost, public URL, health
  python -m deploy.vultr_deploy recycle-worker  destroy the worker VM and build a fresh one (the quarantine moment)
  python -m deploy.vultr_deploy down            delete everything this script created (from the state file)

Everything created is recorded in deploy/.state/state.json (gitignored) together with the temporary SSH key.
Prints the step it is on, and on failure the step that failed; it never prints API keys or generated secrets.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tarfile
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(ROOT, "deploy", ".state")
STATE = os.path.join(STATE_DIR, "state.json")
API = "https://api.vultr.com/v2"
REGION, PLAN, OS_ID = os.environ.get("KEYLESS_REGION", "fra"), "vc2-2c-4gb", 2284
HOURLY = {"vc2-2c-4gb": 0.027}


def key() -> str:
    for line in open(os.path.join(ROOT, ".env"), encoding="utf-8"):
        if line.startswith("VULTR_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"')
    sys.exit("VULTR_API_KEY missing in .env")


def call(method: str, path: str, body: dict | None = None) -> dict:
    r = httpx.request(method, API + path, json=body, headers={"Authorization": f"Bearer {key()}"}, timeout=60)
    if r.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
    return r.json() if r.content else {}


def load() -> dict:
    return json.load(open(STATE, encoding="utf-8")) if os.path.exists(STATE) else {}


def save(s: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    json.dump(s, open(STATE, "w", encoding="utf-8"), indent=1)


def ssh_base(ip: str) -> list[str]:
    kh = os.path.join(STATE_DIR, "known_hosts")
    return ["ssh", "-i", os.path.join(STATE_DIR, "id_ed25519"), "-o", "StrictHostKeyChecking=no",
            "-o", f"UserKnownHostsFile={kh}", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30", f"root@{ip}"]


def ssh(ip: str, cmd: str, input_text: str | None = None, timeout: int = 2400) -> subprocess.CompletedProcess:
    # Bytes, not text: on Windows, text-mode stdin turns every \n into \r\n and bash then fails ("pipefail\r").
    data = input_text.replace("\r", "").encode("utf-8") if input_text is not None else None
    p = subprocess.run(ssh_base(ip) + [cmd], input=data, capture_output=True, timeout=timeout)
    p.stdout = p.stdout.decode("utf-8", "replace")
    p.stderr = p.stderr.decode("utf-8", "replace")
    return p


def scp(ip: str, local: str, remote: str) -> None:
    kh = os.path.join(STATE_DIR, "known_hosts")
    subprocess.run(["scp", "-q", "-i", os.path.join(STATE_DIR, "id_ed25519"), "-o", "StrictHostKeyChecking=no",
                    "-o", f"UserKnownHostsFile={kh}", local, f"root@{ip}:{remote}"], check=True, timeout=600)


def tarball() -> str:
    """Only tracked files (git archive), so no .env, no local outputs, no state."""
    out = os.path.join(STATE_DIR, "keyless.tgz")
    subprocess.run(["git", "-C", ROOT, "archive", "--format=tar.gz", "-o", out, "HEAD"], check=True)
    with tarfile.open(out) as t:
        names = t.getnames()
    assert not any(n.endswith(".env") or ".state" in n for n in names), "tarball would contain secrets"
    return out


def wait_instance(iid: str) -> dict:
    for _ in range(120):
        inst = call("GET", f"/instances/{iid}")["instance"]
        if inst["status"] == "active" and inst["main_ip"] not in ("", "0.0.0.0"):
            return inst
        time.sleep(5)
    raise RuntimeError(f"instance {iid} not active")


def vpc_ip(iid: str) -> str:
    for _ in range(60):
        v = call("GET", f"/instances/{iid}/vpcs").get("vpcs", [])
        if v and v[0].get("ip_address"):
            return v[0]["ip_address"]
        time.sleep(5)
    raise RuntimeError("no VPC address")


def wait_ssh(ip: str) -> None:
    for _ in range(60):
        if subprocess.run(ssh_base(ip) + ["true"], capture_output=True, timeout=30).returncode == 0:
            return
        time.sleep(5)
    raise RuntimeError(f"ssh to {ip} never came up")


def create_worker(s: dict) -> None:
    w = call("POST", "/instances", {"region": REGION, "plan": PLAN, "os_id": OS_ID, "label": "keyless-worker",
                                    "hostname": "keyless-worker", "sshkey_id": [s["ssh_key"]], "backups": "disabled",
                                    "attach_vpc": [s["vpc"]], "firewall_group_id": s["fw_worker"],
                                    "tags": ["keyless"]})["instance"]
    s["worker"] = w["id"]
    save(s)
    inst = wait_instance(w["id"])
    s["worker_ip"], s["worker_vpc_ip"] = inst["main_ip"], vpc_ip(w["id"])
    save(s)
    wait_ssh(s["worker_ip"])
    scp(s["worker_ip"], s["tgz"], "/root/keyless.tgz")
    r = ssh(s["worker_ip"], f"BROKER_VPC_IP={s['control_vpc_ip']} bash -s",
            input_text=open(os.path.join(ROOT, "deploy", "worker.sh"), encoding="utf-8").read().replace("\r", ""))
    print(r.stdout[-1500:], r.stderr[-800:])
    if "WORKER OK" not in r.stdout:
        raise RuntimeError("worker setup failed")
    # The control plane drives the worker's Docker over SSH on the VPC.
    pub = ssh(s["control_ip"], "test -f /root/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 -q; "
                               "cat /root/.ssh/id_ed25519.pub").stdout.strip()
    ssh(s["worker_ip"], "mkdir -p /root/.ssh && cat >> /root/.ssh/authorized_keys", input_text=pub + "\n")
    chk = ssh(s["control_ip"], f"DOCKER_HOST=ssh://root@{s['worker_vpc_ip']} ssh -o StrictHostKeyChecking=accept-new "
                               f"root@{s['worker_vpc_ip']} true && DOCKER_HOST=ssh://root@{s['worker_vpc_ip']} "
                               "docker info --format '{{.Runtimes}}'")
    print("control -> worker docker runtimes:", chk.stdout.strip()[:200], chk.stderr.strip()[:200])


def provision_control(s: dict) -> None:
    s["tgz"] = tarball()
    scp(s["control_ip"], s["tgz"], "/root/keyless.tgz")
    pw = secrets.token_urlsafe(18)
    # The admin password travels inside the script on stdin, never on a command line (where `ps` would show it).
    script = open(os.path.join(ROOT, "deploy", "control.sh"), encoding="utf-8").read().replace("\r", "")
    if "set -euo pipefail\n" not in script:
        raise RuntimeError("control.sh lost its 'set -euo pipefail' line; cannot inject the admin password")
    script = script.replace("set -euo pipefail\n", f"set -euo pipefail\nKC_ADMIN_PW='{pw}'\n", 1)
    r = ssh(s["control_ip"], f"VPC_IP={s['control_vpc_ip']} PUBLIC_HOST={s['public_host']} bash -s", input_text=script)
    print(r.stdout[-2000:], r.stderr[-800:])
    if "CONTROL OK" not in r.stdout:
        raise RuntimeError("control setup failed")
    s["control_ok"] = True
    save(s)


def provision() -> None:
    """Continue a deployment from the state file (after a fixed failure), without creating duplicates."""
    s = load()
    if not s.get("control"):
        sys.exit("no control plane in the state file; use up")
    if not s.get("control_ok"):
        print("provisioning the control plane...", flush=True)
        provision_control(s)
    if not s.get("worker"):
        print("creating the worker...", flush=True)
        s["tgz"] = tarball()
        create_worker(s)
    print(f"\nUP. Public URL: https://{s['public_host']}/healthz  (state: {STATE})")


def up() -> None:
    s = load()
    if s.get("control") or s.get("worker"):
        sys.exit("already deployed (state file exists); use status / down")
    step = "start"
    try:
        step = "ssh key"
        os.makedirs(STATE_DIR, exist_ok=True)
        kp = os.path.join(STATE_DIR, "id_ed25519")
        if not os.path.exists(kp):
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", kp, "-q"], check=True)
        s["ssh_key"] = call("POST", "/ssh-keys", {"name": "keyless-deploy",
                                                  "ssh_key": open(kp + ".pub").read().strip()})["ssh_key"]["id"]
        save(s)
        step = "vpc"
        s["vpc"] = call("POST", "/vpcs", {"region": REGION, "description": "keyless",
                                          "v4_subnet": "10.40.0.0", "v4_subnet_mask": 24})["vpc"]["id"]
        save(s)
        step = "firewall groups"
        me = httpx.get("https://api.ipify.org", timeout=20).text.strip()
        s["fw_control"] = call("POST", "/firewalls", {"description": "keyless-control"})["firewall_group"]["id"]
        s["fw_worker"] = call("POST", "/firewalls", {"description": "keyless-worker"})["firewall_group"]["id"]
        save(s)
        for fw, rules in ((s["fw_control"], [("22", me, 32), ("80", "0.0.0.0", 0), ("443", "0.0.0.0", 0)]),
                          (s["fw_worker"], [("22", me, 32)])):
            for port, subnet, size in rules:
                call("POST", f"/firewalls/{fw}/rules", {"ip_type": "v4", "protocol": "tcp", "subnet": subnet,
                                                        "subnet_size": size, "port": port})
        step = "tarball"
        s["tgz"] = tarball()
        step = "control plane"
        c = call("POST", "/instances", {"region": REGION, "plan": PLAN, "os_id": OS_ID, "label": "keyless-control",
                                        "hostname": "keyless-control", "sshkey_id": [s["ssh_key"]],
                                        "backups": "disabled", "attach_vpc": [s["vpc"]],
                                        "firewall_group_id": s["fw_control"], "tags": ["keyless"]})["instance"]
        s["control"] = c["id"]
        save(s)
        inst = wait_instance(c["id"])
        s["control_ip"], s["control_vpc_ip"] = inst["main_ip"], vpc_ip(c["id"])
        s["public_host"] = s["control_ip"].replace(".", "-") + ".sslip.io"
        save(s)
        wait_ssh(s["control_ip"])
        provision_control(s)
        step = "worker"
        create_worker(s)
        print(f"\nUP. Public URL: https://{s['public_host']}/healthz  (state: {STATE})")
    except Exception as e:
        print(f"\nFAILED at step '{step}': {e}\nResources created so far are in {STATE}; run 'down' to remove them.")
        raise SystemExit(1)


def status() -> None:
    s = load()
    if not s:
        print("nothing deployed")
        return
    for k in ("control", "worker"):
        if s.get(k):
            try:
                i = call("GET", f"/instances/{s[k]}")["instance"]
                print(f"{k}: {i['status']} {i['main_ip']} vpc {s.get(k + '_vpc_ip')} plan {i['plan']} created {i['date_created']}")
            except RuntimeError as e:
                print(f"{k}: {e}")
    n = sum(1 for k in ("control", "worker") if s.get(k))
    print(f"hourly cost now ~${n * HOURLY[PLAN]:.3f}/h")
    if s.get("public_host"):
        try:
            print("health:", httpx.get(f"https://{s['public_host']}/healthz", timeout=15).text)
        except httpx.HTTPError as e:
            print("health: unreachable", type(e).__name__)
    a = call("GET", "/account")["account"]
    print(f"account pending charges ${a['pending_charges']}")


def recycle_worker() -> None:
    s = load()
    t0 = time.time()
    if s.get("worker"):
        call("DELETE", f"/instances/{s['worker']}")
        print(f"worker {s['worker']} destroyed")
        s.pop("worker", None)
        save(s)
    create_worker(s)
    print(f"fresh worker ready in {time.time() - t0:.0f} s")


def down() -> None:
    s = load()
    for k in ("worker", "control"):
        if s.get(k):
            try:
                call("DELETE", f"/instances/{s[k]}")
                print(f"deleted {k}")
            except RuntimeError as e:
                print(f"{k}: {e}")
            s.pop(k, None)
            save(s)
    time.sleep(20)                                   # instances must be gone before VPC and firewalls can be removed
    for k, path in (("fw_control", "/firewalls/"), ("fw_worker", "/firewalls/"), ("vpc", "/vpcs/"),
                    ("ssh_key", "/ssh-keys/")):
        if s.get(k):
            for attempt in range(6):
                try:
                    call("DELETE", path + s[k])
                    print(f"deleted {k}")
                    break
                except RuntimeError as e:
                    if attempt == 5:
                        print(f"{k}: {e}")
                    time.sleep(10)
            s.pop(k, None)
            save(s)
    if not any(s.get(k) for k in ("control", "worker", "vpc", "fw_control", "fw_worker", "ssh_key")):
        os.remove(STATE)
        print("all removed")


if __name__ == "__main__":
    {"up": up, "provision": provision, "status": status, "recycle-worker": recycle_worker, "down": down}[sys.argv[1]]()
