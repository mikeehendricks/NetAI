#!/usr/bin/env bash
# NetAI self-update script — pulls latest code from GitHub, refreshes deps,
# and restarts the service. Invoked from /admin (via sudoers rule) or manually.
set -euo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
BRANCH="${NETAI_BRANCH:-main}"
cd "$APP_DIR"

log() { echo -e "[netai-update] $*"; }

# The repo belongs to the service user; when this script runs as root, drop to
# the owner for git/pip so we never trip git's safe.directory protection and
# never leave root-owned files inside the venv.
OWNER="$(stat -c '%U' "$APP_DIR" 2>/dev/null || echo root)"
as_owner() {
  if [ "$(id -u)" -eq 0 ] && [ "$OWNER" != "root" ] && command -v runuser >/dev/null 2>&1; then
    runuser -u "$OWNER" -- "$@"
  else
    "$@"
  fi
}

if [ ! -d .git ]; then
  log "ERROR: $APP_DIR is not a git checkout; cannot self-update."
  exit 1
fi

log "current commit: $(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "fetching latest code..."
as_owner git -C "$APP_DIR" fetch origin "$BRANCH" --quiet
as_owner git -C "$APP_DIR" reset --hard "origin/$BRANCH" --quiet
log "now at: $(git -C "$APP_DIR" rev-parse --short HEAD)"

if [ -d .venv ]; then
  PY="$APP_DIR/.venv/bin/python3"
else
  PY="python3"
fi

log "installing dependencies..."
as_owner "$PY" -m pip install --quiet --upgrade pip
as_owner "$PY" -m pip install --quiet -r requirements.txt
log "dependencies OK"

# Keep this script root-owned and non-writable by the service account (it is
# executed by root via netai-update.service).
if [ "$(id -u)" -eq 0 ]; then
  chown root:root "$APP_DIR/scripts/update.sh" 2>/dev/null || true
  chmod 755 "$APP_DIR/scripts/update.sh" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Load the new code: prefer the systemd unit; if there is no unit (or no
# systemd at all, e.g. inside a container), gracefully reload the running
# gunicorn master so manual setups also pick up the new version.
# A plain `systemctl restart` from inside this script would kill this script
# too (systemd tears down the whole cgroup), so prefer a detached timer.
# ---------------------------------------------------------------------------
new_code_live=0

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl cat netai.service >/dev/null 2>&1; then
    log "restarting netai service..."
    if command -v systemd-run >/dev/null 2>&1 && systemd-run --quiet --on-active=2 systemctl restart netai >/dev/null 2>&1; then
      log "restart scheduled (detached) - giving it 5s..."
      sleep 5
    else
      systemctl restart netai || true
      sleep 1
    fi
    if systemctl is-active --quiet netai; then
      log "service restarted and active."
      new_code_live=1
    else
      log "WARNING: service not active after restart — check: journalctl -u netai -n 50"
      exit 1
    fi
  else
    log "systemd is running but the netai unit is not installed."
    log "run the installer once to install the service + the self-update unit:"
    log "    cd ~/NetAI && git pull && sudo bash install.sh"
  fi
fi

if [ "$new_code_live" != "1" ]; then
  # Find the gunicorn MASTER precisely:
  #  1) the process holding the app's listening port (authoritative), or
  #  2) the oldest pgrep match that is NOT a shell wrapper - wrappers that
  #     launched the app carry the same words on their command line, and
  #     HUP-ing one of those does nothing to the app.
  GW_PORT="$( (grep -E '^PORT=' "$APP_DIR/.env" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]') || true )"
  GW_PORT="${GW_PORT:-8000}"
  master=""
  if command -v ss >/dev/null 2>&1; then
    # workers inherit the master's listening socket - the OLDEST holder is the master
    master="$( (ss -tlnp 2>/dev/null | awk -v p=":${GW_PORT}" '$4 ~ p' | grep -oP 'pid=\K[0-9]+' | sort -n | head -1) || true )"
  fi
  if [ -z "$master" ] && command -v pgrep >/dev/null 2>&1; then
    for p in $(pgrep -f 'gunicorn.*wsgi:app' 2>/dev/null); do
      c="$( (ps -o comm= -p "$p" 2>/dev/null) || true )"
      case "$c" in
        bash|sh|dash|nohup) continue ;;
        *) master="$p"; break ;;
      esac
    done
  fi
  if [ -n "$master" ]; then
    log "no systemd unit — gracefully reloading the running app (master pid $master)..."
    kill -HUP "$master" 2>/dev/null || true
    ok_reload=0
    for _ in 1 2 3 4 5 6; do
      sleep 2
      if kill -0 "$master" 2>/dev/null; then ok_reload=1; break; fi
    done
    if [ "$ok_reload" = "1" ]; then
      log "app reloaded gracefully — new code is live (zero downtime)."
      new_code_live=1
    else
      log "WARNING: app did not survive the reload — start it again:"
      log "    sudo systemctl start netai   # (after running install.sh)"
    fi
  else
    log "the app does not appear to be running."
    log "start it with:  sudo systemctl start netai   # (after running install.sh)"
  fi
fi

if [ "$new_code_live" = "1" ]; then
  log "update complete — new code is live."
else
  log "update complete — ACTION REQUIRED: restart the app to load the new code."
fi
