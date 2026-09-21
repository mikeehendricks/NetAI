#!/usr/bin/env python3
"""NetAI performance benchmark: latency + throughput of key endpoints.
Usage: python3 tests/perf_test.py [base_url] [admin_password]
Server must be running. Anonymous + authenticated (admin) measurements."""
import os
import statistics
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from security_test import Client, get_csrf  # noqa: E402  (reuse hardened client)

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
ADMIN_PW = sys.argv[2] if len(sys.argv) > 2 else None


def _req(path, headers=None, data=None):
    h = {"User-Agent": "NetAI-PerfTest/1.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, headers=h, data=data)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def fetch(path, cookie=None):
    t0 = time.perf_counter()
    headers = {"Cookie": cookie} if cookie else None
    try:
        code, body, _ = _req(path, headers)
        n = len(body)
    except urllib.error.HTTPError as e:
        code, n = e.code, 0
    except Exception:
        code, n = 0, 0
    return time.perf_counter() - t0, n, code


def bench(name, path, cookie=None, n=60, conc=8):
    with ThreadPoolExecutor(max_workers=conc) as ex:
        rs = list(ex.map(lambda _: fetch(path, cookie), range(n)))
    lat = sorted(r[0] for r in rs) * 1000
    p50 = statistics.median(lat)
    p95 = lat[int(len(lat) * 0.95)]
    ok = sum(1 for r in rs if r[2] in (200, 302))
    print(f"{name:34s} {p50:7.1f} ms p50   {p95:7.1f} ms p95   {ok}/{n} ok")
    return p95


def login(username, password):
    c = Client()
    get_csrf(c, "/login")
    st, _, _ = c.post("/login", data={"username": username, "password": password, "next": "/"})
    if st != 302:
        return None
    return "; ".join(f"{k}={v}" for k, v in c.cookies.items())


if __name__ == "__main__":
    print(f"NetAI performance benchmark against {BASE}  (concurrency 8, n=60)\n")
    req = urllib.request.Request(BASE + "/login", headers={"Accept-Encoding": "gzip"})
    r = urllib.request.urlopen(req, timeout=10)
    enc = r.headers.get("Content-Encoding", "none")
    print(f"gzip compression on /login:      Content-Encoding: {enc}")
    print(f"login page transfer size:        {len(r.read())} bytes\n")
    bench("GET /login (anonymous)", "/login")
    bench("GET / ->302 (anonymous)", "/")

    cookie = None
    if ADMIN_PW:
        cookie = login("admin", ADMIN_PW)
        if cookie:
            print()
            bench("GET / (dashboard, admin)", "/", cookie)
            bench("GET /admin/ (stats+charts)", "/admin/", cookie)
            bench("GET /admin/users", "/admin/users", cookie)
            bench("GET /project/1 (findings)", "/project/1", cookie)
            bench("GET /project/1/topology", "/project/1/topology", cookie)
            bench("GET /project/1/summary", "/project/1/summary", cookie)
            bench("GET /api/live-sessions (json)", "/api/live-sessions", cookie)
        else:
            print("admin login failed - skipping authenticated benches (check credentials/limits)")
    print()
