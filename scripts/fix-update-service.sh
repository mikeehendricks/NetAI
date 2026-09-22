#!/usr/bin/env bash
# NetAI updater repair — run ONCE as root if the /admin "Install update"
# button fails to start updates (empty update log / "no output yet").
#
#   sudo bash /opt/netai/scripts/fix-update-service.sh
#
# Idempotent: safe to run any time. It re-installs the exact systemd unit and
# polkit rule that install.sh writes, fixes the updater script's exec bit, and
# clears any stuck unit state - so the Site-update tab works again.
set -euo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
BRANCH="${NETAI_BRANCH:-main}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root:  sudo bash $0" >&2
  exit 1
fi
if [ ! -d "$APP_DIR" ]; then
  echo "ERROR: $APP_DIR not found (set NETAI_DIR if the app lives elsewhere)" >&2
  exit 1
fi

SERVICE_USER="$(stat -c '%U' "$APP_DIR")"
echo "NetAI updater repair for $APP_DIR (service user: $SERVICE_USER)"

# 1. updater script: root-owned and executable (systemd executes it directly)
chown root:root "$APP_DIR/scripts/update.sh"
chmod 755 "$APP_DIR/scripts/update.sh"

# 2. the root one-shot update unit (exactly what install.sh installs)
cat > /etc/systemd/system/netai-update.service <<EOF
[Unit]
Description=NetAI self-update (git pull, dependencies, service restart)
After=network-online.target netai.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=NETAI_DIR=$APP_DIR
Environment=NETAI_BRANCH=$BRANCH
EnvironmentFile=-$APP_DIR/.env
ExecStart=$APP_DIR/scripts/update.sh
StandardOutput=append:$APP_DIR/instance/update.log
StandardError=append:$APP_DIR/instance/update.log
TimeoutStartSec=900
TimeoutStopSec=30
KillMode=control-group
EOF

# 3. polkit rule: the service account may manage ONLY these two units
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/45-netai-update.rules <<EOF
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.user == "$SERVICE_USER") {
        var unit = action.lookup("unit");
        if (unit == "netai-update.service" || unit == "netai.service") {
            return polkit.Result.YES;
        }
    }
});
EOF
chmod 644 /etc/polkit-1/rules.d/45-netai-update.rules
rm -f /etc/sudoers.d/netai-update   # legacy sudoers rule replaced by the above

# 4. reload + clear any stuck state, then prove the unit is startable
systemctl daemon-reload
systemctl reset-failed netai-update 2>/dev/null || true
systemctl cat netai-update.service >/dev/null && echo "OK: netai-update.service installed and readable"
echo "Done. Use the /admin Update tab as usual - it now also self-heals:"
echo "if the unit ever fails again, the update falls back to direct execution"
echo "and says so in the update log."
