"""Best-effort IP geolocation for the realtime admin map (ip-api.com free tier)."""
import ipaddress
import logging
import threading

import requests

log = logging.getLogger("netai.geo")

_cache_lock = threading.Lock()
_cache = {}  # ip -> geo dict


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
    )


def lookup(ip: str, timeout: float = 2.5) -> dict:
    """Return {'city','region','country','lat','lon'}; safe to call from anywhere."""
    if not ip or not _is_public(ip):
        return {"city": "Local network", "region": "", "country": "Private IP", "lat": None, "lon": None}
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]
    geo = {"city": "", "region": "", "country": "", "lat": None, "lon": None}
    try:
        from flask import current_app

        url = current_app.config.get("GEOIP_URL", "http://ip-api.com/json/{ip}").format(ip=ip)
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                geo = {
                    "city": str(d.get("city", ""))[:100],
                    "region": str(d.get("regionName", ""))[:100],
                    "country": str(d.get("country", ""))[:100],
                    "lat": d.get("lat"),
                    "lon": d.get("lon"),
                }
    except Exception as e:  # network blocked / offline -> degrade quietly
        log.debug("geo lookup failed for %s: %s", ip, e)
    with _cache_lock:
        if geo["country"]:
            _cache[ip] = geo
    return geo


def resolve_pending(max_records=20):
    """Fill geo for pending heartbeats and unanswered login events (called from admin views)."""
    from .models import Heartbeat, LoginEvent, db, utcnow

    try:
        pending = (
            Heartbeat.query.filter(Heartbeat.geo_pending.is_(True))
            .order_by(Heartbeat.last_seen.desc())
            .limit(max_records)
            .all()
        )
        for hb in pending:
            g = lookup(hb.ip or "")
            hb.city, hb.region, hb.country = g["city"], g["region"], g["country"]
            hb.lat, hb.lon = g["lat"], g["lon"]
            hb.geo_pending = False
        recent = (
            LoginEvent.query.filter(LoginEvent.ts >= utcnow() - __import__("datetime").timedelta(hours=24))
            .order_by(LoginEvent.ts.desc()).limit(50).all()
        )
        for ev in recent:
            if ev.country is None:
                g = lookup(ev.ip or "")
                ev.city, ev.region, ev.country = g["city"], g["region"], g["country"]
                ev.lat, ev.lon = g["lat"], g["lon"]
        db.session.commit()
    except Exception:
        db.session.rollback()


def geo_thread_lookup(ip):
    """Fire-and-forget lookup used at login time so login latency is unaffected."""
    def _run():
        lookup(ip)
    threading.Thread(target=_run, daemon=True).start()
