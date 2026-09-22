"""JSON API endpoints (admin realtime data, update subsystem, topology data)."""
import datetime as dt
import json
import os
import shutil
import subprocess  # nosec B404 - fixed argv, admin-only
import time
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, request, session

from .geo import resolve_pending
from .models import Heartbeat, LoginEvent, Setting, User, db, utcnow
from .security import admin_required, check_csrf, client_ip

bp = Blueprint("api", __name__)


# --------------------------------------------------------------------------- realtime sessions
@bp.route("/live-sessions")
@admin_required
def live_sessions():
    resolve_pending()
    cutoff = utcnow() - dt.timedelta(minutes=5)
    hbs = (Heartbeat.query.filter(Heartbeat.last_seen >= cutoff)
           .order_by(Heartbeat.last_seen.desc()).all())
    sessions = []
    for hb in hbs:
        u = db.session.get(User, hb.user_id) if hb.user_id else None
        sessions.append({
            "username": u.username if u else "?",
            "ip": hb.ip,
            "location": ", ".join(x for x in (hb.city, hb.region, hb.country) if x) or "resolving…",
            "lat": hb.lat, "lon": hb.lon,
            "last_seen": hb.last_seen.isoformat(),
            "agent": (hb.user_agent or "")[:80],
        })
    logins = (LoginEvent.query.filter(LoginEvent.success.is_(True))
              .order_by(LoginEvent.ts.desc()).limit(50).all())
    history = [{
        "username": ev.username, "ip": ev.ip, "ok": ev.success, "ts": ev.ts.isoformat(),
        "location": ", ".join(x for x in (ev.city, ev.region, ev.country) if x) or "",
        "lat": ev.lat, "lon": ev.lon,
    } for ev in logins]
    return jsonify({"sessions": sessions, "history": history, "server_time": utcnow().isoformat()})


# --------------------------------------------------------------------------- updater
def _gh_headers():
    tok = current_app.config.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json", "User-Agent": "NetAI-updater"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


def _repo_root():
    return Path(current_app.root_path).parent


@bp.route("/update-check")
@admin_required
def update_check():
    cfg = current_app.config
    local = cfg.get("SITE_VERSION", "")
    remote_sha, commits, error = None, [], None
    url = f"https://api.github.com/repos/{cfg['GITHUB_REPO']}/commits"
    params = {"sha": cfg["GITHUB_BRANCH"], "per_page": 5}
    try:
        import requests

        r = requests.get(url, headers=_gh_headers(), params=params, timeout=10)
        if r.status_code == 200:
            arr = r.json()
            if arr:
                remote_sha = arr[0]["sha"][:7]
                commits = [{
                    "sha": c["sha"][:7],
                    "message": (c["commit"]["message"].splitlines() or [""])[0][:100],
                    "date": c["commit"]["author"]["date"],
                    "author": c["commit"]["author"].get("name", ""),
                } for c in arr]
        else:
            error = f"GitHub API returned {r.status_code}"
    except Exception as e:
        error = str(e)[:200]
    up_to_date = bool(remote_sha and local and remote_sha.startswith(local))
    return jsonify({"local": local, "remote": remote_sha, "up_to_date": up_to_date,
                    "commits": commits, "error": error, "running": update_running()})


MARKER_TIMEOUT_SECONDS = 900  # hard cap: an update may never legitimately run longer


def _marker_path():
    return Path(current_app.config["UPLOAD_FOLDER"]).parent / "update.running"


def _pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True      # exists but owned by another user (e.g. root via sudo)
    except OSError:
        return False


def update_running():
    """True only while the updater process is actually alive AND fresh.
    Stale markers (finished/crashed update, reboot, timeout) are cleared here so
    the admin can always retry — the 'stuck in progress' bug can not recur."""
    marker = _marker_path()
    if not marker.exists():
        return False
    pid, started = 0, 0.0
    try:
        data = json.loads(marker.read_text() or "{}")
        pid = int(data.get("pid", 0) or 0)
        started = float(data.get("started", 0) or 0)
    except (ValueError, OSError):
        # legacy/plain-text marker: fall back to file age
        try:
            started = marker.stat().st_mtime
        except OSError:
            marker.unlink(missing_ok=True)
            return False
    stale = (started and (time.time() - started) > MARKER_TIMEOUT_SECONDS) or not _pid_alive(pid)
    if stale:
        try:
            marker.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def _update_log_path():
    return Path(current_app.config["UPLOAD_FOLDER"]).parent / "update.log"


@bp.route("/update-run", methods=["POST"])
@admin_required
def update_run():
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    if update_running():
        return jsonify({"ok": False, "error": "An update is already in progress."}), 409
    script = Path(current_app.config["UPDATE_SCRIPT"])
    if not script.exists():
        return jsonify({"ok": False, "error": f"Update script not found: {script}"}), 500
    logp = _update_log_path()
    marker = _marker_path()
    try:
        logp.write_text("")  # truncate
        # guard against double-click races before the process exists
        marker.write_text(json.dumps({"pid": 0, "started": time.time()}))
        # prefer sudo rule (production), fall back to direct exec (dev/preview)
        sudo = shutil.which("sudo")
        cmd = ([sudo, "-n", str(script)] if sudo else ["bash", str(script)])
        with open(logp, "ab") as lf:
            proc = subprocess.Popen(  # nosec B603 - cmd is [sudo|-n|bash, script-from-config]; no user input
                cmd, stdout=lf, stderr=subprocess.STDOUT,
                start_new_session=True, cwd=str(_repo_root()))
        marker.write_text(json.dumps({"pid": proc.pid, "started": time.time()}))
    except Exception as e:
        marker.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": str(e)[:200]}), 500
    from .security import audit

    audit("admin.update_run", "site update initiated")
    return jsonify({"ok": True})


@bp.route("/update-status")
@admin_required
def update_status():
    logp = _update_log_path()
    running = update_running()
    try:
        text = logp.read_text(errors="replace")[-8000:] if logp.exists() else ""
    except OSError:
        text = ""
    return jsonify({"running": running, "log": text,
                    "version": current_app.config.get("SITE_VERSION", "")})
