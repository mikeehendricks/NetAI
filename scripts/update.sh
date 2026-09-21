#!/usr/bin/env bash
# NetAI self-update script — pulls latest code from GitHub, refreshes deps,
# and restarts the service. Invoked from /admin (via sudoers rule) or manually.
set -euo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
cd "$APP_DIR"

log() { echo -e "[netai-update] $*"; }

if [ ! -d .git ]; then
  log "ERROR: $APP_DIR is not a git checkout; cannot self-update."
  exit 1
fi

log "current commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "fetching latest code..."
git fetch origin "${NETAI_BRANCH:-main}" --quiet
git reset --hard "origin/${NETAI_BRANCH:-main}" --quiet
log "now at: $(git rev-parse --short HEAD)"

if [ -d .venv ]; then
  PY=".venv/bin/python3"
else
  PY="python3"
fi

log "installing dependencies..."
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet -r requirements.txt
log "dependencies OK"

# restart service if systemd manages it; otherwise remind the operator
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q "^netai.service"; then
  log "restarting netai service..."
  systemctl restart netai
  sleep 1
  if systemctl is-active --quiet netai; then
    log "service restarted and active."
  else
    log "WARNING: service not active after restart — check: journalctl -u netai -n 50"
    exit 1
  fi
else
  log "systemd unit not found — if you run the app manually, restart it now to load the new code."
fi
log "update complete."
