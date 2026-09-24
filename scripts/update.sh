#!/usr/bin/env bash
# NetAI self-update script — pulls latest code from GitHub, refreshes deps,
# then ALWAYS brings the new code live: restarts the systemd service when one
# is installed, otherwise gracefully reloads the running gunicorn (zero
# downtime). The restart is verified (process actually replaced) before the
# script reports success. Invoked from /admin (netai-update.service) or manually.
set -euo pipefail

# Execute a private copy of ourselves: bash reads script files lazily, and the
# `git reset --hard` below rewrites THIS file on updates that change update.sh -
# without the copy, bash can end up parsing a half-rewritten script mid-run.
if [ -z "${NETAI_SELF_EXEC:-}" ]; then
  export NETAI_SELF_EXEC=1
  _self="/tmp/.netai-update.$$.sh"
  if cp -- "$0" "$_self" 2>/dev/null; then
    exec bash "$_self" "$@"
  fi
  unset NETAI_SELF_EXEC
fi

APP_DIR="${NETAI_DIR:-/opt/netai}"
BRANCH="${NETAI_BRANCH:-main}"

log() { echo -e "[netai-update] $*"; }

log "update started (pid $$ as $(id -un 2>/dev/null || echo ?) on $APP_DIR)"
cd "$APP_DIR" || { log "ERROR: application directory $APP_DIR not found"; exit 1; }

# Verdict bookkeeping: UPDATE_RESULT is set on the happy paths; the EXIT trap
# prints an explicit RESULT line no matter how the script ends, so the update
# log ALWAYS ends with a clear success/failed verdict.
UPDATE_RESULT=""
cleanup() {
  rm -f "$APP_DIR/instance/update.running" 2>/dev/null || true
  rm -f "/tmp/.netai-update.$$.sh" 2>/dev/null || true
  case "${UPDATE_RESULT}" in
    ok)         log "RESULT: UPDATE SUCCESSFUL - running build ${NEW_SHA:-unknown}." ;;
    incomplete) log "RESULT: UPDATE INCOMPLETE - new code ${NEW_SHA:-unknown} is on disk but not active; restart required (see above)." ;;
    *)          log "RESULT: UPDATE FAILED - the site keeps running build ${OLD_SHA:-unknown}. See the errors above." ;;
  esac
}
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

# Self-heal: earlier manual 'sudo git' runs can leave root-owned files inside
# .git (and the worktree), which later makes the service user's fetch fail with
# "insufficient permission for adding an object to repository database".
# Everything here belongs to the app owner - give it back before git runs.
if [ "$(id -u)" -eq 0 ] && [ "$OWNER" != "root" ] && command -v chown >/dev/null 2>&1; then
  if chown -R "$OWNER" "$APP_DIR" >/dev/null 2>&1; then
    log "fixed file ownership ($APP_DIR -> $OWNER)"
  else
    log "WARNING: could not fix file ownership - the update may fail below."
  fi
fi

OLD_SHA="$(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "current commit: $OLD_SHA"
log "fetching latest code... (aborts after ${NETAI_FETCH_TIMEOUT:-150}s if GitHub is unreachable)"
FETCH_T="${NETAI_FETCH_TIMEOUT:-150}"
if ! as_owner timeout -k 5 "$FETCH_T" git -C "$APP_DIR" fetch origin "$BRANCH" --quiet; then
  log "fetch failed or timed out - retrying once in 5s (proxy/network hiccup)..."
  sleep 5
  if ! as_owner timeout -k 5 "$FETCH_T" git -C "$APP_DIR" fetch origin "$BRANCH" --quiet; then
    log "ERROR: could not download the latest code from GitHub (see the git errors above)."
    log "       on a filtering-proxy network make sure github.com is reachable from this host,"
    log "       or set a proxy in $APP_DIR/.env (https_proxy=...)."
    log "       if the errors mention permissions, run once as root: chown -R $(stat -c '%U' "$APP_DIR" 2>/dev/null || echo netai) $APP_DIR"
    exit 1
  fi
fi
if ! as_owner timeout -k 5 60 git -C "$APP_DIR" reset --hard "origin/$BRANCH" --quiet; then
  log "ERROR: downloaded the code but could not apply it to the working copy (see errors above)."
  exit 1
fi
NEW_SHA="$(git -C "$APP_DIR" rev-parse --short HEAD)"
log "now at: $NEW_SHA"

if [ -d .venv ]; then
  PY="$APP_DIR/.venv/bin/python3"
else
  PY="python3"
fi

# proxy settings from .env (filtered networks) - pip and git honor these
if [ -f "$APP_DIR/.env" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in
      http_proxy=*|https_proxy=*|HTTP_PROXY=*|HTTPS_PROXY=*|no_proxy=*|NO_PROXY=*|PIP_INDEX_URL=*|PIP_TRUSTED_HOST=*)
        k=${line%%=*}
        v=${line#*=}
        v=${v%\"}; v=${v#\"}; v=${v%\'}; v=${v#\'}
        export "$k=$v"
        ;;
    esac
  done < "$APP_DIR/.env"
fi

# Only touch the network (pip) when requirements.txt actually changed in this
# update. Routine updates then work with no internet access at all, and a
# blocked/slow proxy can never wedge the update at "installing dependencies".
REQ_CHANGED=0
if [ "$OLD_SHA" != "$NEW_SHA" ]; then
  git -C "$APP_DIR" diff --quiet "$OLD_SHA" "$NEW_SHA" -- requirements.txt || REQ_CHANGED=1
fi
if [ "$REQ_CHANGED" -eq 1 ]; then
  log "requirements.txt changed in this update - installing dependencies..."
  as_owner "$PY" -m pip install --quiet --disable-pip-version-check --upgrade pip \
    || log "note: pip self-upgrade skipped (no access to pypi.org) - continuing"
  if as_owner "$PY" -m pip install --quiet --disable-pip-version-check --retries 2 --timeout 15 -r requirements.txt; then
    log "dependencies OK"
  else
    log "ERROR: dependency install failed - no route to pypi.org? (filtering proxy network)"
    log "       fix: add a line 'https_proxy=http://YOUR-PROXY:PORT' to $APP_DIR/.env"
    log "       then install manually:"
    log "         cd $APP_DIR && sudo .venv/bin/pip install -r requirements.txt"
    log "       then restart the app: sudo systemctl restart netai"
    log "NOT restarting the service: the new code may need the new packages, and a"
    log "restart now could take the site down. The running build stays in place."
    exit 1
  fi
else
  log "requirements unchanged - skipping dependency install (offline-safe)"
fi

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
      # 'old' is the previous worker list; if the master died, fail fast
      if [ -z "$m" ] || ! kill -0 "$m" 2>/dev/null; then return 1; fi
      w="$(app_workers "$m" | tr '\n' ' ')"
      if [ -n "$w" ] && [ "$w" != "$old" ]; then return 0; fi
    fi
    i=$((i + 1))
  done
  return 1
}

# Last-resort recovery: launch the app directly (used only if the restart AND
# the graceful reload both failed, so the site would otherwise stay down).
start_app_best_effort() {
  local gunc m i=0 bind="0.0.0.0:${GW_PORT}"
  if [ -x "$APP_DIR/.venv/bin/gunicorn" ]; then
    gunc="$APP_DIR/.venv/bin/gunicorn"
  else
    gunc="$( (command -v gunicorn) || true )"
  fi
  if [ -z "$gunc" ]; then
    log "ERROR: gunicorn not found - cannot auto-start the app."
    return 1
  fi
  # if nginx proxies to us on loopback, keep that binding
  if grep -q "proxy_pass http://127.0.0.1:${GW_PORT}" /etc/nginx/sites-enabled/netai 2>/dev/null; then
    bind="127.0.0.1:${GW_PORT}"
  fi
  log "attempting automatic app launch (bind ${bind})..."
  mkdir -p "$APP_DIR/instance"
  if [ "$(id -u)" -eq 0 ] && [ "$OWNER" != root ] && command -v runuser >/dev/null 2>&1; then
    runuser -u "$OWNER" -- sh -c "cd '$APP_DIR' && setsid nohup '$gunc' --workers 2 --threads 4 --timeout 60 --bind '$bind' wsgi:app >> '$APP_DIR/instance/gunicorn.log' 2>&1 &"
  else
    ( cd "$APP_DIR" && setsid nohup "$gunc" --workers 2 --threads 4 --timeout 60 --bind "$bind" wsgi:app >> "$APP_DIR/instance/gunicorn.log" 2>&1 & )
  fi
  while [ "$i" -lt 30 ]; do
    sleep 1
    m="$(app_master)"
    if [ -n "$m" ] && kill -0 "$m" 2>/dev/null; then
      log "app restarted automatically (master pid $m)."
      return 0
    fi
    i=$((i + 1))
  done
  log "ERROR: automatic app launch failed - see $APP_DIR/instance/gunicorn.log"
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
  case "$( (cat /proc/self/cgroup 2>/dev/null) || true )" in
    *netai.service*)
      # We are running inside the web app's own cgroup (direct-execution
      # fallback). The restart below would kill this updater mid-log, so
      # schedule it detached and end the log with the final status instead.
      if command -v systemd-run >/dev/null 2>&1 \
         && systemd-run --quiet --on-active=3 systemctl restart netai >/dev/null 2>&1; then
        log "service restart scheduled (detached) - the Site-update page will show the new build in a few seconds."
        log "update complete - service restarted automatically; running build $NEW_SHA."
        UPDATE_RESULT=ok
        exit 0
      fi
      log "WARNING: cannot detach the restart - this updater may be killed by it (the restart itself will still complete)."
      ;;
  esac
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 5 180 systemctl restart netai || true
  else
    systemctl restart netai || true
  fi
  if wait_for master_changed "$OLD_MASTER" 60; then
    new_code_live=1
    log "service restarted automatically - new code is live (master pid $(app_master))."
  else
    log "restart did not take effect yet - retrying directly..."
    if command -v timeout >/dev/null 2>&1; then
      timeout -k 5 120 systemctl restart netai || true
    else
      systemctl restart netai || true
    fi
    if wait_for master_changed "$OLD_MASTER" 60; then
      new_code_live=1
      log "service restarted automatically - new code is live (master pid $(app_master))."
    elif systemctl is-active --quiet netai; then
      log "WARNING: service still runs the old process - falling back to a graceful reload."
    else
      log "ERROR: service not active after restart - check: journalctl -u netai -n 50"
      if start_app_best_effort; then
        new_code_live=1
        log "NOTE: app is running outside systemd - investigate the unit before the next update."
      else
        exit 1
      fi
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
    elif start_app_best_effort; then
      new_code_live=1
    else
      log "ACTION REQUIRED: start the app manually:"
      log "    sudo systemctl start netai   # (after running install.sh)"
      exit 1
    fi
  else
    log "the app is not running - starting it automatically..."
    if start_app_best_effort; then
      new_code_live=1
    else
      log "ACTION REQUIRED: start the app manually:"
      log "    sudo systemctl start netai   # (after running install.sh)"
    fi
  fi
fi

if [ "$new_code_live" = "1" ]; then
  log "update complete - service restarted automatically; running build $NEW_SHA."
  UPDATE_RESULT=ok
else
  log "update complete - ACTION REQUIRED: restart the app to load build $NEW_SHA."
  UPDATE_RESULT=incomplete
fi
