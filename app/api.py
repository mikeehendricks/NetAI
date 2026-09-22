"""JSON API endpoints (admin realtime data, update subsystem, topology data)."""
import datetime as dt
import json
import os
import re
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
MARKER_TIMEOUT_SECONDS = 900  # hard cap: an update may never legitimately run longer
UPDATE_UNIT = "netai-update.service"


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
    # The deployed code is what is in the repo checkout - get the real HEAD sha.
    # (SITE_VERSION is a display string like "v1.2.0 (build c7ab740)" and must
    # never be string-compared against a remote sha; that broke "up to date".)
    local_full = ""
    try:
        r = subprocess.run(  # nosec B603, B607 - fixed argv 'git rev-parse'
            ["git", "rev-parse", "HEAD"], cwd=str(_repo_root()),
            capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            local_full = r.stdout.strip()
    except Exception:
        pass
    if not local_full:
        m = re.search(r"[0-9a-f]{7,40}", cfg.get("SITE_VERSION", "") or "")
        local_full = m.group(0) if m else ""
    local = local_full[:7]
    remote_full, remote_sha, commits, error = None, None, [], None
    url = f"https://api.github.com/repos/{cfg['GITHUB_REPO']}/commits"
    params = {"sha": cfg["GITHUB_BRANCH"], "per_page": 5}
    try:
        import requests

        r = requests.get(url, headers=_gh_headers(), params=params, timeout=10)
        if r.status_code == 200:
            arr = r.json()
            if arr:
                remote_full = arr[0]["sha"]
                remote_sha = remote_full[:7]
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
    # up to date = the deployed commit IS the remote commit (full-sha equality,
    # with short-sha fallback if git was unavailable and we only have 7 chars)
    up_to_date = bool(
        remote_full and local_full
        and (remote_full == local_full or remote_full.startswith(local) or local_full.startswith(remote_sha))
    )
    return jsonify({"local": local, "remote": remote_sha, "up_to_date": up_to_date,
                    "commits": commits, "error": error, "running": update_running()})


def _marker_path():
    return Path(current_app.config["UPLOAD_FOLDER"]).parent / "update.running"


def _pid_alive(pid):
    if not pid:
        return False
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        # state comes right after the final ')' in the stat stream; a zombie
        # ('Z') has exited but not been reaped - os.kill would still report
        # it alive, which once glued the 'update running' marker forever.
        return not data.rsplit(b")", 1)[1].split()[0].startswith(b"Z")
    except ProcessLookupError:
        return False
    except (OSError, ValueError, IndexError):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True      # exists but owned by another user (e.g. root via systemd)
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
        # legacy/plain-text marker from an older version: always stale
        marker.unlink(missing_ok=True)
        return False
    if started and (time.time() - started) > MARKER_TIMEOUT_SECONDS:
        marker.unlink(missing_ok=True)
        return False
    if pid == -1:
        # systemd-managed run: the one-shot unit state is the source of truth
        try:
            r = subprocess.run(  # nosec B603 - fixed argv
                ["systemctl", "is-active", UPDATE_UNIT],
                capture_output=True, text=True, timeout=8)
            if r.stdout.strip() == "active":
                return True
        except Exception:
            pass
        marker.unlink(missing_ok=True)
        return False
    if not _pid_alive(pid):
        marker.unlink(missing_ok=True)
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
    systemctl = shutil.which("systemctl")
    default_script = Path(_repo_root()) / "scripts" / "update.sh"

    # Truncate the log up-front: every path below (unit or direct) starts a
    # fresh, visible run.
    logp.write_text("")

    # Preferred path (production): systemd runs the root one-shot unit. This works
    # even though the web service has NoNewPrivileges=true (sudo can never work
    # there) because authorization is handled by polkit, not setuid.
    if systemctl and script == default_script:
        try:
            unit_installed = subprocess.run(  # nosec B603 - fixed argv
                [systemctl, "cat", UPDATE_UNIT], capture_output=True, text=True, timeout=8
            ).returncode == 0
        except Exception:
            unit_installed = False
        if unit_installed:
            note = ""
            try:  # clear a stale 'failed' state so start cannot be refused
                subprocess.run(  # nosec B603 - fixed argv
                    [systemctl, "reset-failed", UPDATE_UNIT], capture_output=True, text=True, timeout=8)
            except Exception:
                pass
            r = None
            try:
                r = subprocess.run(  # nosec B603 - fixed argv, no user input
                    [systemctl, "--no-block", "start", UPDATE_UNIT],
                    capture_output=True, text=True, timeout=15)
            except Exception as e:
                note = f"systemctl error: {str(e)[:120]}"
            if r is not None and r.returncode == 0:
                marker.write_text(json.dumps({"pid": -1, "started": time.time()}))
                # Verify the unit actually does something: a stale/broken unit
                # that dies instantly would otherwise leave an empty log and a
                # silent no-op ("no output yet") with no fallback.
                deadline = time.time() + 6
                alive = False
                while time.time() < deadline:
                    time.sleep(0.7)
                    try:
                        if logp.exists() and logp.stat().st_size > 0:
                            alive = True
                            break
                    except OSError:
                        pass
                    try:
                        state = subprocess.run(  # nosec B603 - fixed argv
                            [systemctl, "is-active", UPDATE_UNIT],
                            capture_output=True, text=True, timeout=8).stdout.strip()
                        if state == "failed":
                            break
                    except Exception:
                        break
                if alive:
                    from .security import audit

                    audit("admin.update_run", "site update started via systemd unit")
                    return jsonify({"ok": True})
                note = note or "the unit produced no output"
            elif r is not None:
                note = f"systemctl returned {r.returncode}"
            # The unit path failed - say so in the log the admin is watching,
            # then fall back to running the updater directly. update.sh is
            # cgroup-aware: from inside the web app it schedules the service
            # restart detached, so it can no longer be killed by its own
            # restart (the old frozen-log failure mode).
            try:
                with open(logp, "ab") as lf:
                    lf.write(f"[netai-update] NOTE: {UPDATE_UNIT} could not run"
                             f"{(' - ' + note) if note else ''}.\n".encode())
                    lf.write("[netai-update] Falling back to direct execution - "
                             "the update will still complete.\n".encode())
                    lf.write("[netai-update] To repair the service for future updates, run once as root: "
                             "bash scripts/fix-update-service.sh\n".encode())
                    lf.write(f"[netai-update] diagnose the unit with: journalctl -u {UPDATE_UNIT} -n 30\n".encode())
            except OSError:
                pass

    # Fallback (dev/preview or custom script): execute directly as the current user.
    try:
        logp.write_text("")
        # guard against double-click races before the process exists
        marker.write_text(json.dumps({"pid": 0, "started": time.time()}))
        with open(logp, "ab") as lf:
            proc = subprocess.Popen(  # nosec B603 - fixed argv from config; no user input
                ["bash", str(script)], stdout=lf, stderr=subprocess.STDOUT,
                start_new_session=True, cwd=str(_repo_root()),
                env={**os.environ,
                     "NETAI_DIR": str(_repo_root()),
                     "NETAI_BRANCH": current_app.config.get("GITHUB_BRANCH", "main")})
        marker.write_text(json.dumps({"pid": proc.pid, "started": time.time()}))
    except Exception as e:
        marker.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": str(e)[:200]}), 500
    from .security import audit

    audit("admin.update_run", "site update started (direct)")
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
