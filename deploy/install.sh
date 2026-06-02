#!/bin/bash
# Install Linux Security Agent on Ubuntu/Debian or RHEL/CentOS
set -e

BINARY_URL="${1:-}"
API_ENDPOINT="${2:-}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/linux-agent"

echo "[install] Linux Security Agent installer"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

# Install binary
if [[ -f "./linux-agent" ]]; then
  cp ./linux-agent "$INSTALL_DIR/linux-agent"
elif [[ -n "$BINARY_URL" ]]; then
  curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/linux-agent"
else
  echo "ERROR: Provide binary path or URL as first argument"
  exit 1
fi
chmod +x "$INSTALL_DIR/linux-agent"
echo "[install] Binary installed to $INSTALL_DIR/linux-agent"

# Config file
mkdir -p "$CONFIG_DIR"
if [[ -n "$API_ENDPOINT" ]]; then
  echo "AGENT_API_ENDPOINT=$API_ENDPOINT" > "$CONFIG_DIR/config"
else
  if [[ ! -f "$CONFIG_DIR/config" ]]; then
    read -rp "Enter API Gateway endpoint URL: " ep
    echo "AGENT_API_ENDPOINT=$ep" > "$CONFIG_DIR/config"
  fi
fi
chmod 600 "$CONFIG_DIR/config"
echo "[install] Config written to $CONFIG_DIR/config"

# Systemd units
cp "$(dirname "$0")/linux-agent.service" /etc/systemd/system/
cp "$(dirname "$0")/linux-agent.timer"   /etc/systemd/system/

systemctl daemon-reload
systemctl enable linux-agent.timer
systemctl start linux-agent.timer

echo "[install] Done. Agent will run every 6 hours."
echo "[install] Run now: systemctl start linux-agent.service"
