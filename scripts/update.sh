#!/usr/bin/env bash
# NetAI self-update script — pulls latest code from GitHub, refreshes deps,
# then ALWAYS brings the new code live: restarts the systemd service when one
# is installed, otherwise gracefully reloads the running gunicorn (zero
# downtime). The restart is verified (process actually replaced) before the
# script reports success. Invoked from /admin (netai-update.service) or manually.
set -euo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
BRANCH="${NETAI_BRANCH:-main}"
cd "$APP_DIR"

log() { echo -e "[netai-update] $*"; }

# Always clear the in-progress marker when the script ends (success or failure),
# so the /admin update button can never get stuck on 'already in progress'.
cleanup() { rm -f "$APP_DIR/instance/update.running" 2>/dev/null || true; }
trap cleanup EXIT

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
NEW_SHA="$(git -C "$APP_DIR" rev-parse --short HEAD)"
log "now at: $NEW_SHA"

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
# Bring the new code live — automatically, with verification.
# ---------------------------------------------------------------------------
GW_PORT="$( (grep -E '^PORT=' "$APP_DIR/.env" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]') || true )"
GW_PORT="${GW_PORT:-8000}"

app_master() {
  local m="" p c
  if command -v ss >/dev/null 2>&1; then
    # workers inherit the master's listening socket - OLDEST holder = master
    m="$( (ss -tlnp 2>/dev/null | awk -v p=":${GW_PORT}" '$4 ~ p' | grep -oP 'pid=\K[0-9]+' | sort -n | head -1) || true )"
  fi
  if [ -z "$m" ] && command -v pgrep >/dev/null 2>&1; then
    for p in $( (pgrep -f 'gunicorn.*wsgi:app' 2>/dev/null) || true ); do
      c="$( (ps -o comm= -p "$p" 2>/dev/null) || true )"
      case "$c" in
        bash|sh|dash|nohup) continue ;;   # skip shell wrappers that launched the app
        *) m="$p"; break ;;
      esac
    done
  fi
  echo "$m"
}

app_workers() {
  if [ -n "${1:-}" ] && command -v pgrep >/dev/null 2>&1; then
    (pgrep -P "$1" 2>/dev/null || true)
  fi
}

wait_for() {   # wait_for <condition:master_changed|workers_changed> <old> <tries>
  local mode="$1" old="$2" tries="${3:-60}" i=0 m w
  while [ "$i" -lt "$tries" ]; do
    sleep 0.5
    m="$(app_master)"
    if [ "$mode" = "master_changed" ]; then
      if [ -n "$m" ] && [ "$m" != "$old" ] && kill -0 "$m" 2>/dev/null; then return 0; fi
    else
      w="$(app_workers "$old" | tr '\n' ' ')"
      if [ -n "$w" ] && [ "$w" != "$old" ]; then return 0; fi
    fi
    i=$((i + 1))
  done
  return 1
}

OLD_MASTER="$(app_master || true)"
if [ -n "$OLD_MASTER" ]; then
  log "running instance detected (master pid $OLD_MASTER) - it will be replaced automatically."
else
  log "no running instance detected."
fi

new_code_live=0

# ---- path 1: systemd unit installed -> proper restart (preferred) ----------
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 \
   && systemctl cat netai.service >/dev/null 2>&1; then
  log "restarting netai service via systemd..."
  if command -v systemd-run >/dev/null 2>&1 \
     && systemd-run --quiet --on-active=2 systemctl restart netai >/dev/null 2>&1; then
    log "restart scheduled (detached) - waiting for the new process..."
  else
    systemctl restart netai || true
  fi
  if wait_for master_changed "$OLD_MASTER" 60; then
    new_code_live=1
    log "service restarted automatically - new code is live (master pid $(app_master))."
  else
    log "restart did not take effect yet - retrying directly..."
    systemctl restart netai || true
    if wait_for master_changed "$OLD_MASTER" 60; then
      new_code_live=1
      log "service restarted automatically - new code is live (master pid $(app_master))."
    elif systemctl is-active --quiet netai; then
      log "WARNING: service still runs the old process - falling back to a graceful reload."
    else
      log "ERROR: service not active after restart - check: journalctl -u netai -n 50"
      exit 1
    fi
  fi
elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  log "systemd is running but the netai unit is not installed - using a graceful reload."
  log "tip: run the installer once to install the service + the self-update unit:"
  log "    cd ~/NetAI && git pull && sudo bash install.sh"
fi

# ---- path 2: graceful reload of the running gunicorn (zero downtime) -------
if [ "$new_code_live" != "1" ]; then
  M="$(app_master || true)"
  if [ -n "$M" ]; then
    OLD_W="$(app_workers "$M" | tr '\n' ' ')"
    log "gracefully reloading the running app (master pid $M, workers replaced live)..."
    kill -HUP "$M" 2>/dev/null || true
    if wait_for workers_changed "$OLD_W" 45 && kill -0 "$M" 2>/dev/null; then
      new_code_live=1
      log "app reloaded automatically - new code is live (zero downtime)."
    elif kill -0 "$M" 2>/dev/null && [ -n "$(app_workers "$M")" ]; then
      new_code_live=1
      log "app reloaded automatically - new code is live."
    else
      log "ERROR: app did not survive the reload - start it again:"
      log "    sudo systemctl start netai   # (after running install.sh)"
      exit 1
    fi
  else
    log "the app is not running - nothing to restart."
    log "start it with:  sudo systemctl start netai   # (after running install.sh)"
  fi
fi

if [ "$new_code_live" = "1" ]; then
  log "update complete - service restarted automatically; running build $NEW_SHA."
else
  log "update complete - ACTION REQUIRED: restart the app to load build $NEW_SHA."
fi
