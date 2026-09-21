#!/usr/bin/env bash
# NetAI uninstaller — stops and removes the service and its files.
set -euo pipefail
APP_DIR="${NETAI_DIR:-/opt/netai}"
SERVICE_USER="netai"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

echo "This will stop and DELETE the NetAI service, its code and its database."
read -r -p "Type DELETE to continue: " ans
[ "$ans" = "DELETE" ] || { echo "aborted."; exit 0; }

systemctl disable --now netai.service 2>/dev/null || true
rm -f /etc/systemd/system/netai.service
systemctl daemon-reload 2>/dev/null || true
rm -f /etc/sudoers.d/netai-update
rm -rf "$APP_DIR"
id "$SERVICE_USER" &>/dev/null && userdel "$SERVICE_USER" || true
if command -v ufw >/dev/null 2>&1; then ufw delete allow 8000/tcp >/dev/null 2>&1 || true; fi
echo "NetAI removed."
