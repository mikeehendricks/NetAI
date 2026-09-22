"""Admin portal: statistics, users, realtime sessions, update, settings, audit."""
import datetime as dt
import secrets
import subprocess  # nosec B404 - update flow uses fixed script path only

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for,
)

from .geo import lookup, resolve_pending
from .models import (
    AuditLog, ConfigFile, Heartbeat, LoginEvent, Project, Setting, User, db, gen_tmp_password, utcnow,
)
from .security import admin_required, audit, check_csrf

bp = Blueprint("admin", __name__)


def _weeks_sev_color():
    return {"critical": "#f43f5e", "high": "#fb923c", "medium": "#facc15", "low": "#38bdf8", "info": "#94a3b8"}


@bp.route("/")
@admin_required
def overview():
    now = utcnow()
    d1 = now - dt.timedelta(hours=24)
    d7 = now - dt.timedelta(days=7)
    stats = {
        "users_total": User.query.count(),
        "users_active": User.query.filter(User.is_active.is_(True)).count(),
        "logins_24h": LoginEvent.query.filter(LoginEvent.success.is_(True), LoginEvent.ts >= d1).count(),
        "logins_7d": LoginEvent.query.filter(LoginEvent.success.is_(True), LoginEvent.ts >= d7).count(),
        "projects": Project.query.count(),
        "files": ConfigFile.query.count(),
    }
    # findings aggregate
    sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    total_score, n = 0, 0
    for p in Project.query.all():
        for f in p.findings:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        total_score += p.risk_score
        n += 1
    stats["findings"] = sev
    stats["avg_score"] = round(total_score / n) if n else 0
    # logins per day, last 14 days
    days = []
    for i in range(13, -1, -1):
        day = (now - dt.timedelta(days=i)).date()
        nxt = day + dt.timedelta(days=1)
        c = LoginEvent.query.filter(LoginEvent.success.is_(True),
                                    LoginEvent.ts >= day, LoginEvent.ts < nxt).count()
        days.append((day.strftime("%m-%d"), c))
    recent_users = User.query.order_by(User.created_at.desc()).limit(6).all()
    recent_logins = LoginEvent.query.order_by(LoginEvent.ts.desc()).limit(8).all()
    top_countries = {}
    for ev in LoginEvent.query.filter(LoginEvent.success.is_(True), LoginEvent.country.isnot(None)).all():
        if ev.country:
            top_countries[ev.country] = top_countries.get(ev.country, 0) + 1
    top_countries = sorted(top_countries.items(), key=lambda kv: -kv[1])[:5]
    return render_template("admin/overview.html", stats=stats, days=days,
                           recent_users=recent_users, recent_logins=recent_logins,
                           top_countries=top_countries, colors=_weeks_sev_color())


@bp.route("/users")
@admin_required
def users():
    q = request.args.get("q", "").strip()
    query = User.query
    if q:
        query = query.filter(User.username.ilike(f"%{q}%"))
    users = query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users, q=q)


@bp.route("/users/add", methods=["POST"])
@admin_required
def users_add():
    """Provision a normal (Analyst) user account. Password can be supplied by the
    admin or auto-generated (shown once, user must change it at first login)."""
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    from .auth import USERNAME_RE, _validate_password

    username = (request.form.get("username") or "").strip()
    pw = request.form.get("password") or ""
    if not USERNAME_RE.match(username):
        flash("Username must be 3-64 chars: letters, digits, dot, dash, underscore or @.", "danger")
        return redirect(url_for("admin.users"))
    if db.session.query(User.id).filter(User.username == username).first():
        flash(f"Username '{username}' already exists.", "warn")
        return redirect(url_for("admin.users"))
    if pw:
        err = _validate_password(pw)
        if err:
            flash(f"Password not accepted: {err}", "danger")
            return redirect(url_for("admin.users"))
        must_reset = False
    else:
        pw = gen_tmp_password()
        must_reset = True
    u = User(username=username, role="user")
    u.set_password(pw)
    u.must_reset = must_reset
    db.session.add(u)
    db.session.commit()
    audit("admin.user_add", username)
    if must_reset:
        flash(f"Analyst account created for {username}. One-time password: {pw} "
              f"(shown once - the user must set a new password at first login)", "success")
    else:
        flash(f"Analyst account created for {username} with the password you supplied.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/reset", methods=["POST"])
@admin_required
def user_reset(uid):
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    u = db.session.get(User, uid)
    if u is None:
        abort(404)
    if u.id == session.get("uid"):
        flash("Use your account page to change your own password.", "warn")
        return redirect(url_for("admin.users"))
    tmp = gen_tmp_password()
    u.set_password(tmp)
    u.must_reset = True
    u.failed_attempts = 0
    u.locked_until = None
    db.session.commit()
    audit("admin.user_reset", u.username)
    flash(f"Temporary password for {u.username}: {tmp}  (shown once - user must change it at next login)", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def user_toggle(uid):
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    u = db.session.get(User, uid)
    if u is None:
        abort(404)
    if u.id == session.get("uid"):
        flash("You cannot disable your own account.", "warn")
        return redirect(url_for("admin.users"))
    u.is_active = not u.is_active
    db.session.commit()
    audit("admin.user_toggle", f"{u.username} -> {'active' if u.is_active else 'disabled'}")
    flash(f"Account {u.username} {'enabled' if u.is_active else 'disabled'}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/role", methods=["POST"])
@admin_required
def user_role(uid):
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    u = db.session.get(User, uid)
    if u is None:
        abort(404)
    if u.id == session.get("uid"):
        flash("You cannot change your own role.", "warn")
        return redirect(url_for("admin.users"))
    u.role = "admin" if u.role != "admin" else "user"
    db.session.commit()
    audit("admin.user_role", f"{u.username} -> {u.role}")
    flash(f"Role for {u.username} set to {u.role}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def user_delete(uid):
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    u = db.session.get(User, uid)
    if u is None:
        abort(404)
    if u.id == session.get("uid"):
        flash("You cannot delete your own account.", "warn")
        return redirect(url_for("admin.users"))
    name = u.username
    Project.query.filter(Project.user_id == uid).delete()
    Heartbeat.query.filter(Heartbeat.user_id == uid).delete()
    db.session.delete(u)
    db.session.commit()
    audit("admin.user_delete", name)
    flash(f"User {name} deleted.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/live")
@admin_required
def live():
    resolve_pending()
    return render_template("admin/live.html")


@bp.route("/update")
@admin_required
def update():
    ver = current_app.config.get("SITE_VERSION", "")
    return render_template("admin/update.html", current_sha=ver,
                           repo=current_app.config["GITHUB_REPO"],
                           branch=current_app.config["GITHUB_BRANCH"],
                           running=False)


@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        if not check_csrf():
            abort(400, "Invalid CSRF token")
        allow = "1" if request.form.get("allow_signup") == "on" else "0"
        Setting.put("allow_signup", allow)
        audit("admin.settings", f"allow_signup={allow}")
        flash("Settings saved.", "success")
        return redirect(url_for("admin.settings"))
    from .analysis import ai as ai_mod

    cfg = current_app.config
    provider = (cfg.get("AI_PROVIDER") or "").lower()
    ai_status = {
        "provider": cfg.get("AI_PROVIDER") or "",
        "available": ai_mod.ai_available(cfg),
        "model": cfg.get("ANTHROPIC_MODEL") if provider == "anthropic" else cfg.get("OPENAI_MODEL"),
        "key_set": bool(cfg.get("ANTHROPIC_API_KEY") if provider == "anthropic" else cfg.get("OPENAI_API_KEY")),
    }
    return render_template("admin/settings.html",
                           allow_signup=Setting.get("allow_signup", "1") == "1",
                           ai_status=ai_status)


@bp.route("/audit")
@admin_required
def audit_log():
    page = max(1, request.args.get("page", 1, type=int))
    q = AuditLog.query.order_by(AuditLog.ts.desc())
    rows = q.paginate(page=page, per_page=50, error_out=False)
    return render_template("admin/audit.html", rows=rows)
