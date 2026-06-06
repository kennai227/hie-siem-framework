#!/usr/bin/env bash
# ============================================================
# HIE SIEM — Wazuh Agent Deployment Script
# Supports: Ubuntu 20.04/22.04, RHEL/CentOS 8+, Debian 11+
# Usage: ./deploy-agents.sh <WAZUH_MANAGER_IP> <AGENT_GROUP>
# ============================================================
set -euo pipefail

MANAGER_IP="${1:?Usage: $0 <manager_ip> <agent_group>}"
AGENT_GROUP="${2:-hie-default}"
WAZUH_VERSION="4.7.3"

echo "[HIE-SIEM] Deploying Wazuh agent v${WAZUH_VERSION}"
echo "  Manager : ${MANAGER_IP}"
echo "  Group   : ${AGENT_GROUP}"

detect_os() {
  if   [[ -f /etc/debian_version ]]; then echo "debian"
  elif [[ -f /etc/redhat-release ]]; then echo "rhel"
  else echo "unknown"; fi
}

OS=$(detect_os)

install_debian() {
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor \
    -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="${MANAGER_IP}" WAZUH_AGENT_GROUP="${AGENT_GROUP}" \
    apt-get install -y wazuh-agent="${WAZUH_VERSION}-*"
}

install_rhel() {
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo << REPO
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
  WAZUH_MANAGER="${MANAGER_IP}" WAZUH_AGENT_GROUP="${AGENT_GROUP}" \
    yum install -y wazuh-agent-"${WAZUH_VERSION}"
}

case "$OS" in
  debian) install_debian ;;
  rhel)   install_rhel   ;;
  *)      echo "[ERROR] Unsupported OS"; exit 1 ;;
esac

systemctl daemon-reload
systemctl enable  wazuh-agent
systemctl restart wazuh-agent
systemctl status  wazuh-agent --no-pager

echo "[HIE-SIEM] Agent deployed successfully — registering with manager ${MANAGER_IP}"
