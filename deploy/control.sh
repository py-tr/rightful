#!/usr/bin/env bash
# Control-plane VM setup (Ubuntu 24.04). Run as root with: VPC_IP, PUBLIC_HOST (e.g. 1-2-3-4.sslip.io), KC_ADMIN_PW.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "=== STEP packages"
apt-get update -qq && apt-get install -y -qq docker.io python3-venv caddy curl >/dev/null
systemctl enable --now docker >/dev/null
echo "=== STEP app"
mkdir -p /opt/keyless /var/lib/keyless
tar -xzf /root/keyless.tgz -C /opt/keyless
python3 -m venv /opt/keyless/.venv
/opt/keyless/.venv/bin/pip install -q fastapi==0.119.0 uvicorn==0.37.0 httpx==0.27.2
echo "=== STEP keycloak + mail (localhost only)"
docker rm -f keyless-kc keyless-mail >/dev/null 2>&1 || true
docker network create keyless-net >/dev/null 2>&1 || true
docker run -d --name keyless-mail --network keyless-net --restart unless-stopped -p 127.0.0.1:8025:8025 axllent/mailpit:v1.20 >/dev/null
docker run -d --name keyless-kc --network keyless-net --restart unless-stopped -p 127.0.0.1:8089:8080 \
  --add-host host.docker.internal:host-gateway \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
  quay.io/keycloak/keycloak:26.0.7 start-dev --hostname=http://gate:8080 \
  --spi-ciba-auth-channel-ciba-http-auth-channel-http-authentication-channel-uri=http://host.docker.internal:8099/ciba/notify >/dev/null
for i in $(seq 1 90); do curl -sf http://127.0.0.1:8089/realms/master >/dev/null && break; sleep 2; done
( umask 077; printf '%s' "$KC_ADMIN_PW" > /opt/keyless/kc-admin )   # root-only: the evaluation harness creates realms
echo "=== STEP realm bootstrap"
cd /opt/keyless && KC_ADMIN_PASSWORD="$KC_ADMIN_PW" SMTP_HOST=keyless-mail .venv/bin/python -m deploy.bootstrap_realm /opt/keyless/secrets.json
chmod 600 /opt/keyless/secrets.json
echo "=== STEP service"
cat > /etc/systemd/system/keyless.service <<EOF
[Unit]
Description=Keyless broker and owner-device service
After=docker.service
[Service]
WorkingDirectory=/opt/keyless
Environment=BROKER_BIND=$VPC_IP KC_URL=http://127.0.0.1:8089
ExecStart=/opt/keyless/.venv/bin/python -m deploy.server
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now keyless >/dev/null
echo "=== STEP host firewall (Vultr's Ubuntu image has ufw on, SSH only)"
ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null
ufw allow from 10.40.0.0/24 to any port 8090 proto tcp >/dev/null      # the broker: the private VPC only
echo "=== STEP public front door (TLS via Caddy)"
# Only the health check is public until the demo UI with per-session roles exists (mentor review finding #1: the
# device API was public and unauthenticated). The CIBA callback (/ciba/notify) is never routed publicly.
cat > /etc/caddy/Caddyfile <<EOF
$PUBLIC_HOST {
  handle /healthz {
    reverse_proxy 127.0.0.1:8099
  }
  handle {
    respond "not public yet" 404
  }
}
EOF
systemctl restart caddy
echo "=== STEP host firewall: the broker port only on the VPC address, the device service only via Caddy"
# These iptables rules are NOT persisted across a reboot. That is acceptable here because the Vultr firewall group
# in front of this VM already allows only SSH (operator IP), 80 and 443; 8099 is unreachable from outside either way.
# They are a second layer against other hosts inside the VPC.
iptables -I INPUT 1 -p tcp --dport 8099 -j DROP
iptables -I INPUT 1 -p tcp --dport 8099 -s 172.16.0.0/12 -j ACCEPT      # Keycloak's container (CIBA channel)
iptables -I INPUT 1 -p tcp --dport 8099 -s 127.0.0.1 -j ACCEPT          # Caddy
for i in $(seq 1 30); do curl -sf http://127.0.0.1:8099/healthz >/dev/null && break; sleep 2; done
curl -sf http://127.0.0.1:8099/healthz && echo && echo "=== CONTROL OK"
