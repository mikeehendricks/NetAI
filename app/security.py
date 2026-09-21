"""Security helpers: CSRF, rate limiting, decorators, client IP, audit."""
import datetime as dt
import functools
import hmac
import ipaddress
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import (
    current_app, flash, redirect, request, session, url_for,
)
from markupsafe import Markup, escape

from .models import AuditLog, db, utcnow

# --------------------------------------------------------------------------- CSRF
def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


def check_csrf():
    sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    good = session.get("_csrf")
    if not good or not sent or not hmac.compare_digest(sent, good):
        return False
    # Origin check for state-changing requests (defense in depth)
    origin = request.headers.get("Origin", "")
    if origin:
        host = request.host
        try:
            from urllib.parse import urlsplit

            if urlsplit(origin).netloc and urlsplit(origin).netloc != host:
                return False
        except Exception:
            return False
    return True


# --------------------------------------------------------------------------- client IP
def client_ip() -> str:
    ip = request.remote_addr or "0.0.0.0"  # nosec B104 - placeholder string, not a bind
    if current_app.config.get("TRUST_PROXY"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            candidate = fwd.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
                ip = candidate
            except ValueError:
                pass
    return ip


# --------------------------------------------------------------------------- rate limiter
class _SlidingWindow:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = defaultdict(deque)
        self.last_gc = time.monotonic()

    def allow(self, key, n, window):
        now = time.monotonic()
        with self.lock:
            if now - self.last_gc > 120:
                for k in [k for k, q in self.hits.items() if not q or now - q[-1] > 600]:
                    self.hits.pop(k, None)
                self.last_gc = now
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= n:
                q.append(now)
                return False, n - len(q)
            q.append(now)
            return True, 0


_limiter = _SlidingWindow()


def rate_limit():
    """Return a 429 response when limits are exceeded, else None."""
    cfg = current_app.config
    ip = client_ip()
    method = request.method
    rule = request.path
    if method == "GET":
        ok, _ = _limiter.allow(f"get:{ip}", *cfg["RATE_LIMIT_GET"])
    elif rule == "/login":
        ok, _ = _limiter.allow(f"login:{ip}", *cfg["RATE_LIMIT_LOGIN"])
    elif method == "POST":
        ok, _ = _limiter.allow(f"post:{ip}", *cfg["RATE_LIMIT_POST"])
    else:
        ok = True
    if not ok:
        return (
            Markup("<h1>429</h1><p>Too many requests. Slow down and try again shortly.</p>"),
            429,
        )
    return None


# --------------------------------------------------------------------------- presence
def touch_session():
    """Track realtime presence for the admin portal (throttled to 20s)."""
    if request.endpoint in ("static",) or request.method != "GET":
        return
    uid = session.get("uid")
    if not uid:
        return
    now = time.monotonic()
    if now - session.get("_hb_ts", 0) < 20:
        return
    session["_hb_ts"] = now
    try:
        from .models import Heartbeat

        sid = session.get("_sid")
        if not sid:
            sid = secrets.token_hex(16)
            session["_sid"] = sid
        hb = db.session.get(Heartbeat, sid)
        if hb is None:
            hb = Heartbeat(session_id=sid)
            db.session.add(hb)
        hb.user_id = uid
        hb.ip = client_ip()
        ua = request.headers.get("User-Agent", "")[:250]
        if ua:
            hb.user_agent = ua
        hb.last_seen = utcnow()
        hb.geo_pending = True
        db.session.commit()
    except Exception:
        db.session.rollback()


# --------------------------------------------------------------------------- decorators
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("uid"):
            flash("Please sign in to continue.", "warn")
            return redirect(url_for("auth.login", next=request.path))
        return view(*a, **kw)

    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("auth.login", next=request.path))
        if session.get("role") != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("main.index")), 403
        return view(*a, **kw)

    return wrapped


def audit(action, detail=""):
    try:
        from .models import User

        actor = "anonymous"
        if session.get("uid"):
            u = db.session.get(User, session["uid"])
            if u:
                actor = u.username
        db.session.add(
            AuditLog(actor=actor, action=action[:120], detail=str(detail)[:500], ip=client_ip())
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
