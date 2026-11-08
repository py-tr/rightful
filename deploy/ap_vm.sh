#!/usr/bin/env bash
# The temporary VM for the payments replication (eval/PREREG-ap3.md). Ubuntu 24.04, run as root with KC_ADMIN_PW set.
# ERPNext v16 (frappe_docker's pwd.yml, bound to 127.0.0.1), Keycloak 26.0.7 and the harness on one machine; the task
# sandboxes run under gVisor (runsc). Nothing listens publicly except SSH; the containers reach the harness (broker
# 8090, CIBA receiver 8099) on the Docker bridge only. Destroyed after the run and the filming.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "=== STEP packages + gvisor"
apt-get -o DPkg::Lock::Timeout=900 update -qq && apt-get -o DPkg::Lock::Timeout=900 install -y -qq docker.io docker-compose-v2 python3-venv curl ca-certificates gnupg ufw >/dev/null
systemctl enable --now docker >/dev/null
curl -fsSL https://gvisor.dev/archive.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
apt-get -o DPkg::Lock::Timeout=900 update -qq && apt-get -o DPkg::Lock::Timeout=900 install -y -qq runsc >/dev/null
grep -q runsc /etc/docker/daemon.json 2>/dev/null || { runsc install >/dev/null && systemctl restart docker; }   # re-runnable
runsc --version | head -1
echo "=== STEP firewall"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
ufw allow in on docker0 to 172.17.0.1 port 8090 proto tcp comment 'edge proxies -> broker' >/dev/null
ufw allow in on docker0 to 172.17.0.1 port 8099 proto tcp comment 'Keycloak CIBA channel' >/dev/null
ufw allow in on docker0 to 172.17.0.1 port 1025 proto tcp comment 'Keycloak -> mail catcher SMTP' >/dev/null
ufw --force enable >/dev/null
echo "=== STEP app + sandbox images"
mkdir -p /opt/keyless /var/lib/keyless/eval /var/lib/keyless/tasks
tar -xzf /root/keyless.tgz -C /opt/keyless && cd /opt/keyless
python3 -m venv .venv
.venv/bin/pip install -q fastapi==0.119.0 uvicorn==0.37.0 httpx==0.27.2 'pyjwt[crypto]==2.15.1' requests==2.32.3
docker build -q -f sandbox/Dockerfile.task -t keyless-task:dev . >/dev/null
docker build -q -f sandbox/Dockerfile.edge -t keyless-edge:dev . >/dev/null
# the harness drives Docker the way it drives a worker (ssh://), so the sandboxes get runsc exactly as on Vultr workers
[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
grep -qf /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys || cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys
ssh -n -o StrictHostKeyChecking=accept-new -o BatchMode=yes root@127.0.0.1 true   # -n: never eat this script's stdin (bash -s)
DOCKER_HOST=ssh://root@127.0.0.1 docker info --format '{{json .Runtimes}}' < /dev/null > /tmp/runtimes.json 2>/dev/null || true
if grep -q '"runsc"' /tmp/runtimes.json; then echo "runsc available over ssh"; else echo "runsc NOT available over ssh"; exit 1; fi
echo "=== STEP keycloak + mail (localhost only)"
docker rm -f keyless-kc keyless-mail >/dev/null 2>&1 || true
# SMTP 1025 too: Keycloak's realms send account emails to host.docker.internal:1025 (devenv/keycloak_local.py), which
# resolves to the docker bridge gateway, so publish it there (still not on a public address). Without it every
# account email failed (8 Nov, PREREG-vultr-reruns deviation log).
GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
docker run -d --name keyless-mail --restart unless-stopped -p 127.0.0.1:8025:8025 -p "$GW:1025:1025" \
  axllent/mailpit:v1.20 >/dev/null
docker run -d --name keyless-kc --restart unless-stopped -p 127.0.0.1:8089:8080 \
  --add-host host.docker.internal:host-gateway \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
  quay.io/keycloak/keycloak:26.0.7 start-dev \
  --spi-ciba-auth-channel-ciba-http-auth-channel-http-authentication-channel-uri=http://host.docker.internal:8099/ciba/notify >/dev/null
for i in $(seq 1 90); do curl -sf http://127.0.0.1:8089/realms/master >/dev/null && break; sleep 2; done
curl -sf http://127.0.0.1:8089/realms/master >/dev/null && echo "keycloak up"
echo "=== STEP erpnext"
mkdir -p /opt/erp && cp /root/pwd.yml /opt/erp/pwd.yml && cd /opt/erp
docker compose -p erp -f pwd.yml up -d < /dev/null >/dev/null 2>&1
# "pong" comes back before ERPNext itself is installed (found on this VM): wait for the site creation to finish
timeout 2400 docker wait erp-create-site-1 < /dev/null >/dev/null || true
docker logs --tail 3 erp-create-site-1 2>&1 | tail -1 | cut -c1-200
sleep 120   # measured on this VM: API keys were refused at random (401) for the first minutes after the install
for i in $(seq 1 180); do
  curl -sf -H 'Host: frontend' http://127.0.0.1:8095/api/method/ping 2>/dev/null | grep -q pong && break; sleep 5
done
curl -sf -H 'Host: frontend' http://127.0.0.1:8095/api/method/ping | grep -q pong && echo "erpnext up"
echo "=== STEP stop rules on this ERPNext (users, permissions, witness)"
cd /opt/keyless && .venv/bin/python -m devenv.erp_witness_check http://127.0.0.1:8095 < /dev/null | tail -40
echo "=== AP VM OK"
