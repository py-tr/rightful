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
CONTROL_PLAN = os.environ.get("KEYLESS_CONTROL_PLAN", PLAN)       # the evaluation night uses vc2-4c-8gb
HOURLY = {"vc2-2c-4gb": 0.030, "vc2-4c-8gb": 0.060}             # $20 / $40 a month (Vultr API, 2026-11-05)


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
    # core.autocrlf=false: the repository's own LF bytes. With Windows' autocrlf=true, git archive wrote CRLF, so the
    # hashes the evaluation records on the server never matched the pre-registered ones (found before the main run).
    subprocess.run(["git", "-C", ROOT, "-c", "core.autocrlf=false", "archive", "--format=tar.gz", "-o", out, "HEAD"],
                   check=True)
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
        c = call("POST", "/instances", {"region": REGION, "plan": CONTROL_PLAN, "os_id": OS_ID, "label": "keyless-control",
                                        "hostname": "keyless-control", "sshkey_id": [s["ssh_key"]],
                                        "backups": "disabled", "attach_vpc": [s["vpc"]],
                                        "firewall_group_id": s["fw_control"], "tags": ["keyless"]})["instance"]
        s["control"], s["control_plan"] = c["id"], CONTROL_PLAN
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
    for w in s.get("fleet", []):
        try:
            i = call("GET", f"/instances/{w['id']}")["instance"]
            print(f"fleet {w['label']}: {i['status']} vpc {w.get('vpc_ip')} ok={w.get('ok')}")
        except RuntimeError as e:
            print(f"fleet {w['label']}: {e}")
    cost = (HOURLY.get(s.get("control_plan", PLAN), 0.06) if s.get("control") else 0) \
        + (HOURLY[PLAN] if s.get("worker") else 0) + HOURLY[PLAN] * len(s.get("fleet", []))
    print(f"hourly cost now ~${cost:.3f}/h")
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


# --- the evaluation night: temporary workers ("throwaway instances"), the harness on the control plane -------------
_STATE_LOCK = __import__("threading").Lock()


def _track(rec: dict) -> None:
    """Every created instance goes into the state file AT ONCE, so `down` can always delete it (found: an account
    limit error aborted the batch and left 3 created workers untracked and billing)."""
    with _STATE_LOCK:
        s = load()
        fl = [w for w in s.get("fleet", []) if w["id"] != rec["id"]]
        s["fleet"] = fl + [rec]
        save(s)


def _fleet_one(s: dict, label: str, existing_id: str | None = None) -> dict:
    try:
        if existing_id:
            rec = {"id": existing_id, "label": label, "created": time.time()}
        else:
            w = call("POST", "/instances", {"region": REGION, "plan": PLAN, "os_id": OS_ID, "label": label,
                                            "hostname": label, "sshkey_id": [s["ssh_key"]], "backups": "disabled",
                                            "attach_vpc": [s["vpc"]], "firewall_group_id": s["fw_worker"],
                                            "tags": ["keyless", "keyless-fleet"]})["instance"]
            rec = {"id": w["id"], "label": label, "created": time.time()}
        _track(rec)
    except RuntimeError as e:
        return {"label": label, "ok": False, "error": str(e)[:300]}
    try:
        return _provision_fleet_worker(s, rec)
    except Exception as e:                            # noqa: BLE001  tracked already, so `down` still removes it
        rec.update({"ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
        _track(rec)
        return rec


def _provision_fleet_worker(s: dict, rec: dict) -> dict:
    inst = wait_instance(rec["id"])
    rec["ip"], rec["vpc_ip"] = inst["main_ip"], vpc_ip(rec["id"])
    wait_ssh(rec["ip"])
    scp(rec["ip"], s["tgz"], "/root/keyless.tgz")
    r = ssh(rec["ip"], f"BROKER_VPC_IP={s['control_vpc_ip']} bash -s",
            input_text=open(os.path.join(ROOT, "deploy", "worker.sh"), encoding="utf-8").read())
    if "WORKER OK" not in r.stdout:
        rec["ok"] = False
        rec["error"] = (r.stdout[-400:] + r.stderr[-400:])
        return rec
    pub = ssh(s["control_ip"], "cat /root/.ssh/id_ed25519.pub").stdout.strip()
    ssh(rec["ip"], "mkdir -p /root/.ssh && cat >> /root/.ssh/authorized_keys", input_text=pub + "\n")
    # a new worker can get a deleted one's VPC address: forget the old host key first (11-05: all 3 checks failed)
    chk = ssh(s["control_ip"], f"ssh-keygen -R {rec['vpc_ip']} >/dev/null 2>&1; "
                               f"ssh -o StrictHostKeyChecking=accept-new root@{rec['vpc_ip']} true && "
                               f"DOCKER_HOST=ssh://root@{rec['vpc_ip']} docker info --format '{{{{.Runtimes}}}}'")
    rec["ok"] = "runsc" in chk.stdout
    rec["provisioned_s"] = round(time.time() - rec["created"])
    _track(rec)
    return rec


def fleet(n: int) -> None:
    """Create n temporary workers in parallel (measured: time to ready), wired to the control plane."""
    from concurrent.futures import ThreadPoolExecutor
    s = load()
    if not s.get("control_ok"):
        sys.exit("no provisioned control plane")
    s["tgz"] = tarball()
    have = len(s.get("fleet", []))
    labels = [f"keyless-eval-w{have + k + 1}" for k in range(n)]
    t0 = time.time()
    # adopt instances of an earlier, interrupted fleet call that are not in the state file yet
    tracked = {w["id"] for w in s.get("fleet", [])}
    orphans = [i for i in call("GET", "/instances")["instances"]
               if i["label"].startswith("keyless-eval-w") and i["id"] not in tracked]
    jobs = [(i["label"], i["id"]) for i in orphans] + [(lb, None) for lb in labels[: max(n - len(orphans), 0)]]
    with ThreadPoolExecutor(max_workers=max(len(jobs), 1)) as pool:
        recs = list(pool.map(lambda j: _fleet_one(s, j[0], j[1]), jobs))
    for r in recs:
        print(f"{r['label']}: ok={r.get('ok')} vpc {r.get('vpc_ip')} ready in {r.get('provisioned_s')} s"
              + (f" ERROR {r['error'][-200:]}" if r.get("error") else ""))
    print(f"fleet of {n} in {time.time() - t0:.0f} s")


def fleet_down() -> None:
    s = load()
    for w in s.get("fleet", []):
        try:
            call("DELETE", f"/instances/{w['id']}")
            print(f"deleted {w['label']} (lived {(time.time() - w['created']) / 3600:.2f} h)")
        except RuntimeError as e:
            print(f"{w['label']}: {e}")
    s["fleet"] = []
    save(s)


def eval_setup() -> None:
    """On the control plane: the demo service off for the night (the harness takes its ports), the model key and the
    Keycloak admin password into a root-only env file (via stdin, never a command line), the case files uploaded,
    SSH connection sharing to the workers."""
    s = load()
    ip = s["control_ip"]
    key_line = next(l.strip() for l in open(os.path.join(ROOT, ".env"), encoding="utf-8")
                    if l.startswith("VULTR_INFERENCE_API_KEY="))
    ssh(ip, "systemctl stop keyless; mkdir -p /opt/keyless/cases /var/lib/keyless/eval; umask 077; "
            "{ cat; echo KC_ADMIN_PASSWORD=$(cat /opt/keyless/kc-admin); echo SMTP_HOST=keyless-mail; } "
            "> /opt/keyless/eval.env; chmod 600 /opt/keyless/eval.env", input_text=key_line + "\n")
    from eval.cases import FILES, DEFAULT_DIR
    src = os.environ.get("KEYLESS_CASES_DIR", DEFAULT_DIR)
    for f in FILES.values():
        scp(ip, os.path.join(src, f), f"/opt/keyless/cases/{f}")
    ssh(ip, "chmod 700 /opt/keyless/cases; chmod 600 /opt/keyless/cases/*; mkdir -p /root/.ssh; "
            "printf 'Host 10.40.0.*\\n  ControlMaster auto\\n  ControlPath /root/.ssh/cm-%%r@%%h:%%p\\n  "
            "ControlPersist 30m\\n' > /root/.ssh/config; chmod 600 /root/.ssh/config")
    print("eval setup done (demo service stopped; env file root-only; cases uploaded)")


def eval_start(cmd: str, cap: str, per_host: str = "3") -> None:
    s = load()
    hosts = ",".join(f"ssh://root@{w['vpc_ip']}" for w in s.get("fleet", []) if w.get("ok"))
    if s.get("worker_vpc_ip"):
        hosts = (hosts + "," if hosts else "") + f"ssh://root@{s['worker_vpc_ip']}"
    v = s["control_vpc_ip"]
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    r = ssh(s["control_ip"],
            f"cd /opt/keyless && set -a && . /opt/keyless/eval.env && set +a && export KEYLESS_EVAL=1 "
            f"KEYLESS_COMMIT={commit} KEYLESS_CASES_DIR=/opt/keyless/cases && "
            # only the harness goes to the background, in its own subshell; otherwise the whole && chain holds the
            # SSH channel until the harness exits
            f"(setsid nohup .venv/bin/python -u -m eval.harness {cmd} "
            f"--cap {cap} --hosts {hosts} --per-host {per_host} --bind {v} --edge-upstream http://{v}:8090 "
            f"--out /var/lib/keyless/eval/gateon < /dev/null > /var/lib/keyless/eval/harness-{cmd}.log 2>&1 &); "
            f"echo started", timeout=60)
    print(r.stdout.strip(), r.stderr.strip()[-300:], "| hosts:", hosts)


DEMO_UNITS = r"""
cat > /etc/systemd/system/keyless-factory.service <<'EOF'
[Unit]
Description=Keyless realm factory (the only holder of Keycloak's master admin)
After=docker.service
[Service]
WorkingDirectory=/opt/keyless
EnvironmentFile=/opt/keyless/factory.env
ExecStart=/opt/keyless/.venv/bin/python -m demo.factory
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/keyless-demo.service <<'EOF'
[Unit]
Description=Keyless public demo (web app, per-company brokers, device service)
After=keyless-factory.service
[Service]
WorkingDirectory=/opt/keyless
EnvironmentFile=/opt/keyless/demo.env
ExecStart=/opt/keyless/.venv/bin/python -m demo.prod
Restart=always
[Install]
WantedBy=multi-user.target
EOF
"""


def demo_deploy() -> None:
    """The public demo, AFTER the evaluation (it takes the harness's ports): fresh code on the control plane and the
    worker (sandbox images rebuilt from the same code), the factory and the demo as two services with separate
    root-only env files (the demo never gets Keycloak's admin password), Caddy in front, the old single-realm service
    off. Visitors' scripts run on the worker under gVisor."""
    s = load()
    ip, wip, vpc, wvpc = s["control_ip"], s["worker_ip"], s["control_vpc_ip"], s["worker_vpc_ip"]
    tgz = tarball()
    for host in (ip, wip):
        scp(host, tgz, "/root/keyless.tgz")
    r = ssh(wip, "mkdir -p /opt/keyless && tar -xzf /root/keyless.tgz -C /opt/keyless && cd /opt/keyless && "
                 "docker build -q -f sandbox/Dockerfile.task -t keyless-task:dev . >/dev/null && "
                 "docker build -q -f sandbox/Dockerfile.edge -t keyless-edge:dev . >/dev/null && "
                 "docker run --rm --entrypoint python keyless-task:dev -c "
                 "'import helpdesk; print(\"sdk_ok\", hasattr(helpdesk, \"verify_caller\"))'")
    print("worker:", r.stdout.strip()[-200:], r.stderr.strip()[-200:])
    key_line = next(l.strip() for l in open(os.path.join(ROOT, ".env"), encoding="utf-8")
                    if l.startswith("VULTR_INFERENCE_API_KEY="))
    ssh(ip, "tar -xzf /root/keyless.tgz -C /opt/keyless && /opt/keyless/.venv/bin/pip install -q segno==1.6.1 && "
            "mkdir -p /var/lib/keyless/demo && umask 077 && "
            "TOKEN=$(openssl rand -hex 24) && "
            "{ echo KC_ADMIN_PASSWORD=$(cat /opt/keyless/kc-admin); echo FACTORY_TOKEN=$TOKEN; "
            "  echo KC_URL=http://127.0.0.1:8089; echo SMTP_HOST=keyless-mail; } > /opt/keyless/factory.env && "
            f"{{ cat; echo FACTORY_TOKEN=$TOKEN; echo VPC_IP={vpc}; echo DEMO_DOCKER_HOSTS=ssh://root@{wvpc}; "
            "  echo KEYLESS_DEMO_CONTRAST=1; echo DEMO_DIR=/var/lib/keyless/demo; echo DEMO_MODEL=qwen3.8-27b; "
            "  echo DEMO_TOTAL_USD=15; } > /opt/keyless/demo.env && "
            "chmod 600 /opt/keyless/factory.env /opt/keyless/demo.env", input_text=key_line + "\n")
    host = s.get("public_host") or f"{ip.replace('.', '-')}.sslip.io"
    caddy = (f"{host} {{\n  request_body {{\n    max_size 64KB\n  }}\n  reverse_proxy 127.0.0.1:8000\n}}\n")
    r = ssh(ip, DEMO_UNITS + "systemctl stop keyless 2>/dev/null; systemctl disable keyless 2>/dev/null; "
                f"cat > /etc/caddy/Caddyfile <<'EOF'\n{caddy}EOF\n"
                "systemctl daemon-reload && systemctl enable --now keyless-factory keyless-demo >/dev/null && "
                "systemctl reload caddy || systemctl restart caddy; "
                "for i in $(seq 1 60); do curl -sf http://127.0.0.1:8000/healthz >/dev/null && break; sleep 2; done; "
                "curl -s http://127.0.0.1:8000/healthz; echo; systemctl is-active keyless-factory keyless-demo")
    print(r.stdout.strip()[-600:], r.stderr.strip()[-300:])
    print(f"public URL: https://{host}/")


def fleet_sync() -> None:
    """Current code to the control plane and every worker (sandbox images rebuilt and their SDK checked), WITHOUT
    starting any service: for a measurement after the main evaluation."""
    s = load()
    tgz = tarball()
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    scp(s["control_ip"], tgz, "/root/keyless.tgz")
    ssh(s["control_ip"], "tar -xzf /root/keyless.tgz -C /opt/keyless")
    workers = [w["ip"] for w in s.get("fleet", []) if w.get("ok") and w.get("ip")] + [s["worker_ip"]]
    for ip in workers:
        scp(ip, tgz, "/root/keyless.tgz")
        r = ssh(ip, "mkdir -p /opt/keyless && tar -xzf /root/keyless.tgz -C /opt/keyless && cd /opt/keyless && "
                    "docker build -q -f sandbox/Dockerfile.task -t keyless-task:dev . >/dev/null && "
                    "docker build -q -f sandbox/Dockerfile.edge -t keyless-edge:dev . >/dev/null && "
                    "docker run --rm --entrypoint python keyless-task:dev -c "
                    "'import helpdesk; print(\"sdk_ok\", hasattr(helpdesk, \"record_verification\"), "
                    "hasattr(helpdesk, \"verify_caller\"))'")
        print(ip, r.stdout.strip()[-60:], r.stderr.strip()[-160:])
    print("synced commit", commit)


def secondary_start(kind: str, cap: str, per_host: str = "3") -> None:
    """A labelled secondary (eval/secondary.py) on the fleet, after fleet-sync; output under eval/secondary-<kind>."""
    s = load()
    hosts = ",".join(f"ssh://root@{w['vpc_ip']}" for w in s.get("fleet", []) if w.get("ok"))
    hosts = (hosts + "," if hosts else "") + f"ssh://root@{s['worker_vpc_ip']}"
    v = s["control_vpc_ip"]
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    ids = ""
    if kind == "tokens":
        scp(s["control_ip"], os.path.join(ROOT, "eval", "out", "secondary-tokens-ids.json"), "/opt/keyless/tokens-ids.json")
        ids = "--ids /opt/keyless/tokens-ids.json"
    r = ssh(s["control_ip"],
            f"cd /opt/keyless && set -a && . /opt/keyless/eval.env && set +a && export KEYLESS_EVAL=1 "
            f"KEYLESS_COMMIT={commit} KEYLESS_CASES_DIR=/opt/keyless/cases && "
            f"(setsid nohup .venv/bin/python -u -m eval.secondary {kind} {ids} --cap {cap} --hosts {hosts} "
            f"--per-host {per_host} --bind {v} --edge-upstream http://{v}:8090 --out /var/lib/keyless/eval/secondary-{kind} "
            f"< /dev/null > /var/lib/keyless/eval/secondary-{kind}.log 2>&1 &); echo started", timeout=120)
    print(r.stdout.strip(), r.stderr.strip()[-300:], "| hosts:", hosts)


def demo_eval_start(cap: str, per_host: str = "3") -> None:
    """The demo-setup measurement (eval/PREREG-demosetup.md), AFTER the main evaluation and its re-runs: a separate
    module and output directory; the main evaluation's files are not touched."""
    s = load()
    hosts = ",".join(f"ssh://root@{w['vpc_ip']}" for w in s.get("fleet", []) if w.get("ok"))
    if s.get("worker_vpc_ip"):
        hosts = (hosts + "," if hosts else "") + f"ssh://root@{s['worker_vpc_ip']}"
    v = s["control_vpc_ip"]
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    r = ssh(s["control_ip"],
            f"cd /opt/keyless && set -a && . /opt/keyless/eval.env && set +a && export KEYLESS_COMMIT={commit} && "
            f"(setsid nohup .venv/bin/python -u -m eval.demo_setup run "
            f"--cap {cap} --hosts {hosts} --per-host {per_host} --bind {v} --edge-upstream http://{v}:8090 "
            f"--out /var/lib/keyless/eval/demosetup < /dev/null > /var/lib/keyless/eval/demosetup.log 2>&1 &); "
            f"echo started", timeout=60)
    print(r.stdout.strip(), r.stderr.strip()[-300:], "| hosts:", hosts)


def eval_log(cmd: str = "run") -> None:
    s = load()
    print(ssh(s["control_ip"], f"tail -n 30 /var/lib/keyless/eval/harness-{cmd}.log; "
                               "ls /var/lib/keyless/eval/ | head; "
                               "ls /var/lib/keyless/eval/gateon* 2>/dev/null | grep -c 'r.*[0-9a-f].json$'").stdout)


def eval_fetch() -> None:
    s = load()
    out = os.path.join(ROOT, "eval", "out")
    os.makedirs(out, exist_ok=True)
    ssh(s["control_ip"], "cd /var/lib/keyless/eval && tar -czf /root/eval-out.tgz gateon*")
    kh = os.path.join(STATE_DIR, "known_hosts")
    subprocess.run(["scp", "-q", "-i", os.path.join(STATE_DIR, "id_ed25519"), "-o", "StrictHostKeyChecking=no",
                    "-o", f"UserKnownHostsFile={kh}", f"root@{s['control_ip']}:/root/eval-out.tgz",
                    os.path.join(out, "eval-out.tgz")], check=True, timeout=1800)
    with tarfile.open(os.path.join(out, "eval-out.tgz")) as t:
        t.extractall(out)
    print("fetched to", out)


def down() -> None:
    s = load()
    if s.get("fleet"):
        fleet_down()
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
    cmds = {"up": up, "provision": provision, "status": status, "recycle-worker": recycle_worker, "down": down,
            "fleet-down": fleet_down, "eval-setup": eval_setup, "eval-fetch": eval_fetch, "demo-deploy": demo_deploy, "fleet-sync": fleet_sync}
    if sys.argv[1] == "fleet":
        fleet(int(sys.argv[2]))
    elif sys.argv[1] == "eval-start":
        eval_start(sys.argv[2], sys.argv[3], *(sys.argv[4:5]))
    elif sys.argv[1] == "secondary-start":
        secondary_start(sys.argv[2], sys.argv[3], *(sys.argv[4:5]))
    elif sys.argv[1] == "demo-eval-start":
        demo_eval_start(sys.argv[2], *(sys.argv[3:4]))
    elif sys.argv[1] == "eval-log":
        eval_log(*(sys.argv[2:3]))
    else:
        cmds[sys.argv[1]]()
