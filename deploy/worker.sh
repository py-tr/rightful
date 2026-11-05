#!/usr/bin/env bash
# Worker VM setup (Ubuntu 24.04): Docker + gVisor; builds the sandbox images; locks egress so containers can reach
# ONLY the broker's VPC address (and never the cloud metadata service). Run as root with: BROKER_VPC_IP.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "=== STEP docker + gvisor"
apt-get update -qq && apt-get install -y -qq docker.io curl ca-certificates gnupg iptables-persistent >/dev/null
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
apt-get update -qq && apt-get install -y -qq runsc >/dev/null && runsc install >/dev/null && systemctl restart docker
runsc --version | head -1
echo "=== STEP images"
mkdir -p /opt/keyless && tar -xzf /root/keyless.tgz -C /opt/keyless && cd /opt/keyless
docker build -q -f sandbox/Dockerfile.task -t keyless-task:dev . >/dev/null
docker build -q -f sandbox/Dockerfile.edge -t keyless-edge:dev . >/dev/null
docker build -q -f sandbox/Dockerfile.browser -t keyless-browser:dev . >/dev/null
docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep keyless
echo "=== STEP egress lock (DOCKER-USER)"
iptables -F DOCKER-USER
iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A DOCKER-USER -d 169.254.169.254 -j DROP
iptables -A DOCKER-USER -p tcp -d "$BROKER_VPC_IP" --dport 8090 -j RETURN
iptables -A DOCKER-USER -i br-+ -o br-+ -j RETURN    # sandbox <-> edge on the same task network; Docker's own isolation rules still apply
iptables -A DOCKER-USER -i docker0 -j DROP
iptables -A DOCKER-USER -i br-+ -j DROP
netfilter-persistent save >/dev/null 2>&1 || true
echo "=== WORKER OK"
