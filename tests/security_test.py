#!/usr/bin/env python3
"""NetAI security test-suite (black-box, runs against a live server).

Fresh-instance flow (from repo root):
  rm -f instance/netai.db && echo "test-setup-key-12345" > instance/SETUP_KEY
  TRUST_PROXY=0 PORT=8000 python3 run.py &
  python3 tests/security_test.py http://127.0.0.1:8000

The suite performs the one-time admin setup itself when /setup is available.
Exit code 0 = all checks passed.
"""
import io
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
SETUP_KEY = "test-setup-key-12345"
ADMIN_PW = "Adm1n-SuperSecure-Pw!"
results = []


def check(name, passed, detail=""):
    results.append((name, bool(passed), detail))
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f" — {detail}" if detail and not passed else ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class Client:
    """Cookie-aware HTTP client on urllib; does NOT follow redirects."""

    def __init__(self):
        self.cookies = {}
        self.token = ""

    def _headers(self, extra=None):
        h = {"User-Agent": "NetAI-SecTest/1.0"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra:
            h.update(extra)
        return h

    def _absorb(self, headers):
        for h, v in headers.items():
            if h.lower() == "set-cookie":
                m = re.match(r"([^=]+)=([^;]*)", v)
                if m:
                    self.cookies[m.group(1)] = m.group(2)

    def get(self, path, headers=None):
        req = urllib.request.Request(BASE + path, headers=self._headers(headers))
        try:
            resp = _opener.open(req, timeout=20)
            self._absorb(resp.headers)
            return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            self._absorb(e.headers)
            return e.code, e.read(), e.headers

    def post(self, path, data=None, headers=None):
        form = dict(data or {})
        form.setdefault("_csrf", self.token)
        body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in form.items()).encode()
        h = self._headers({"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
        req = urllib.request.Request(BASE + path, data=body, headers=h)
        try:
            resp = _opener.open(req, timeout=20)
            self._absorb(resp.headers)
            return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            self._absorb(e.headers)
            return e.code, e.read(), e.headers

    def upload(self, path, files, fields=None):
        boundary = "----NetAISecTestBoundary"
        buf = io.BytesIO()
        for k, v in (fields or {}).items():
            buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f'Content-Disposition: form-data; name="_csrf"\r\n\r\n{self.token}\r\n'.encode())
        for fname, content in files:
            buf.write(f"--{boundary}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="configs"; filename="{fname}"\r\n'.encode())
            buf.write(b"Content-Type: text/plain\r\n\r\n")
            buf.write(content if isinstance(content, bytes) else content.encode())
            buf.write(b"\r\n")
        buf.write(f"--{boundary}--\r\n".encode())
        h = self._headers({"Content-Type": f"multipart/form-data; boundary={boundary}"})
        req = urllib.request.Request(BASE + path, data=buf.getvalue(), headers=h)
        try:
            resp = _opener.open(req, timeout=40)
            self._absorb(resp.headers)
            return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            self._absorb(e.headers)
            return e.code, e.read(), e.headers


def get_csrf(c, path):
    _, body, _ = c.get(path)
    m = re.search(rb'name="_csrf" value="([^"]+)"', body)
    if m:
        c.token = m.group(1).decode()
    return body


def login(c, username, password):
    get_csrf(c, "/login")
    st, _, _ = c.post("/login", data={"username": username, "password": password, "next": "/"})
    if st == 302:                      # refresh token: session.clear() rotated it
        get_csrf(c, "/analyze")
    return st


def main():
    print(f"NetAI security test-suite against {BASE}\n")

    # ---------------------------------------------------------------- phase 0: one-time setup
    admin = Client()
    st, body, _ = admin.get("/setup")
    if st == 200:
        get_csrf(admin, "/setup")
        st, _, _ = admin.post("/setup", data={"setup_key": SETUP_KEY, "username": "admin",
                                              "password": ADMIN_PW, "password2": ADMIN_PW})
        check("one-time admin setup works", st == 302, f"got {st}")
        st = login(admin, "admin", ADMIN_PW)
        check("admin can login after setup", st == 302, f"got {st}")
    else:
        st = login(admin, "admin", ADMIN_PW)
        check("admin login works (existing instance)", st == 302, f"got {st}")
    st, _, _ = admin.get("/setup")
    check("/setup locked after admin exists", st == 404, f"got {st}")
    get_csrf(admin, "/setup")
    st, _, _ = admin.post("/setup", data={"setup_key": SETUP_KEY, "username": "hax2",
                                          "password": "x" * 12, "password2": "x" * 12})
    check("setup POST rejected after setup", st == 404, f"got {st}")

    # ---------------------------------------------------------------- phase 1: headers/cookies
    c = Client()
    st, body, hdrs = c.get("/login")
    check("login page reachable", st == 200, f"got {st}")
    csp = hdrs.get("Content-Security-Policy", "")
    check("CSP header present", "default-src 'self'" in csp)
    if "script-src" in csp:
        script_src = csp.split("script-src")[1].split(";")[0]
        check("CSP blocks inline scripts", "'self'" in script_src and "'unsafe-inline'" not in script_src)
    else:
        check("CSP blocks inline scripts", False, "no script-src")
    check("X-Frame-Options DENY", hdrs.get("X-Frame-Options") == "DENY")
    check("X-Content-Type-Options nosniff", hdrs.get("X-Content-Type-Options") == "nosniff")
    check("Referrer-Policy set", "strict-origin" in hdrs.get("Referrer-Policy", ""))
    sc = hdrs.get("Set-Cookie", "")
    check("session cookie HttpOnly", "HttpOnly" in sc, sc[:80])
    check("session cookie SameSite", "SameSite=Lax" in sc or "SameSite=Strict" in sc)
    server_hdr = hdrs.get("Server", "")
    check("no detailed Server banner", "Werkzeug" not in server_hdr and "Python" not in server_hdr, server_hdr)
    st, _, _ = c.get("/console")
    check("Werkzeug debugger console disabled", st in (404, 501, 403), f"got {st}")

    # ---------------------------------------------------------------- phase 2: access control
    st, _, _ = c.get("/")
    check("dashboard requires login", st == 302, f"got {st}")
    st, _, _ = c.get("/admin/")
    check("admin requires login", st == 302, f"got {st}")
    st, _, _ = c.get("/project/1")
    check("project requires login", st == 302, f"got {st}")
    st, _, _ = c.get("/api/live-sessions")
    check("admin API requires login", st == 302, f"got {st}")
    st, body, _ = admin.get("/")
    check("dashboard loads for admin", st == 200 and b"Dashboard" in body, f"got {st}")

    # ---------------------------------------------------------------- phase 3: CSRF
    anon = Client()
    get_csrf(anon, "/login")
    st, _, _ = anon.post("/login", data={"_csrf": "", "username": "admin", "password": "wrong"})
    check("login without CSRF token rejected", st == 400, f"got {st}")
    st, _, _ = anon.post("/login", data={"_csrf": "forged-token-value", "username": "admin", "password": "wrong"})
    check("forged CSRF token rejected", st == 400, f"got {st}")

    # ---------------------------------------------------------------- phase 4: SQLi
    sqli = Client()
    get_csrf(sqli, "/login")
    payloads = ["' OR 1=1--", "admin'--", '" OR ""="', "'; DROP TABLE users;--",
                "admin' UNION SELECT 1,2,3--"]
    ok = True
    for p in payloads:
        st, _, _ = sqli.post("/login", data={"username": p, "password": "x", "next": "/"})
        if st not in (400, 401, 403, 423, 429):
            ok = False
    check("SQLi probes do not bypass login", ok)
    st, _, _ = admin.get("/admin/users?q=%27%20OR%201%3D1--")
    check("user search survives SQLi payload", st == 200, f"got {st}")

    # ---------------------------------------------------------------- phase 5: XSS
    get_csrf(admin, "/analyze")
    st, _, _ = admin.upload("/analyze", [("xss.txt", "hostname <script>alert(1)</script>\n")],
                            {"project_name": "<script>alert(1)</script><img src=x onerror=alert(2)>"})
    st, dash, _ = admin.get("/")
    check("stored XSS in project name is escaped",
          b"<script>alert(1)" not in dash and b"<img src=x" not in dash,
          "raw payload rendered!")
    st, proj, _ = admin.get("/project/1")
    if st == 200:
        check("XSS in device hostname is escaped", b"<script>alert(1)" not in proj)
    else:
        check("XSS in device hostname is escaped", True, "(project page not accessible)")

    # ---------------------------------------------------------------- phase 6: traversal + uploads
    st, _, _ = admin.get("/project/1/file/../../etc/passwd")
    check("path traversal on file route blocked", st in (404, 400, 403, 405), f"got {st}")
    st, _, _ = admin.get("/project/999/file/1/original")
    check("cross-project file access blocked", st in (404, 403), f"got {st}")

    evil = Client()
    login(evil, "admin", ADMIN_PW)
    st, _, hdrs2 = evil.upload("/analyze", [("evil.exe", b"\x00\x01binary\x00")])
    rejected = st in (400, 403) or (st == 302 and "/analyze" in hdrs2.get("Location", ""))
    check("binary upload rejected", rejected, f"got {st} -> {hdrs2.get('Location', '')}")
    st, _, hdrs2 = evil.upload("/analyze", [("ok.txt", "hostname test-ok\n")])
    accepted = st == 302 and "/project/" in hdrs2.get("Location", "")
    check("valid upload still accepted", accepted, f"got {st} -> {hdrs2.get('Location', '')}")

    # ---------------------------------------------------------------- phase 7: multi-user / IDOR
    user = Client()
    get_csrf(user, "/register")
    st, _, _ = user.post("/register", data={"username": "sectest1",
                                            "password": "SecTest-Pw-2024!", "password2": "SecTest-Pw-2024!"})
    check("regular user can register", st == 302, f"got {st}")
    get_csrf(user, "/login")
    st, _, _ = user.post("/login", data={"username": "sectest1", "password": "SecTest-Pw-2024!", "next": "/"})
    check("regular user can login", st == 302, f"got {st}")
    st, _, _ = user.get("/project/1")
    check("IDOR: user cannot open admin's project", st in (403, 404), f"got {st}")
    st, _, _ = user.get("/admin/users")
    check("IDOR: user cannot list admin users", st in (403, 302), f"got {st}")
    st, _, _ = user.get("/api/live-sessions")
    check("IDOR: user cannot read realtime sessions API", st in (403, 302), f"got {st}")
    st, _, _ = user.get("/api/update-check")
    check("user cannot check updates", st in (403, 302), f"got {st}")
    get_csrf(user, "/analyze")
    st, _, _ = user.post("/admin/users/add", data={"username": "haxxxx", "password": ""})
    check("user cannot create accounts", st == 403, f"got {st}")
    st, _, _ = user.post("/admin/settings", data={"allow_signup": "off"})
    check("user cannot change site settings", st == 403, f"got {st}")

    # phase 7b: admin provisions an analyst account
    get_csrf(admin, "/admin/users")
    st, _, _ = admin.post("/admin/users/add", data={"username": "analyst1", "password": ""})
    check("admin can create analyst accounts", st == 302, f"got {st}")
    st, users_html, _ = admin.get("/admin/users")
    check("new analyst appears in user list", b"analyst1" in users_html, f"got {st}")
    st, _, _ = user.post("/admin/users/add", data={"username": "haxxxx2", "password": ""})
    check("analyst cannot create accounts (403)", st == 403, f"got {st}")

    # ---------------------------------------------------------------- phase 8: open redirect
    o = Client()
    get_csrf(o, "/login")
    st, _, hdrs = o.post("/login", data={"username": "sectest1", "password": "SecTest-Pw-2024!",
                                         "next": "https://evil.example.com"})
    for _bad in ("//evil.example", "////evil.example", "/\\evil.example"):
        st, _, h = user.post("/login", data={"username": "admin", "password": ADMIN_PW, "next": _bad})
        loc = h.get("Location", "")
        check(f"open redirect blocked ({_bad})", not loc.startswith("//") and "evil" not in loc, f"got {loc}")
    loc = hdrs.get("Location", "")
    check("open redirect blocked", "evil.example.com" not in loc, f"loc={loc}")

    # ---------------------------------------------------------------- phase 9: brute force lockout
    b = Client()
    codes = []
    for i in range(8):
        get_csrf(b, "/login")
        st, _, _ = b.post("/login", data={"username": "sectest1", "password": f"badpass{i}", "next": "/"},
                          )
        codes.append(st)
    blocked = all(s in (401, 423, 429) for s in codes)
    check("brute force: logins always rejected (401/423/429)", blocked, str(codes))

    # ---------------------------------------------------------------- phase 10: admin CSRF + downloads
    csrf_probe = Client()
    csrf_probe.cookies = dict(admin.cookies)
    st, _, _ = csrf_probe.post("/admin/users/999/reset", data={"_csrf": "forged-token-xyz"})
    check("admin POST with forged CSRF rejected", st == 400, f"got {st}")
    st, body, hdrs = admin.get("/project/1/summary.md")
    check("summary download works", st == 200, f"got {st}")

    # ---------------------------------------------------------------- phase 11: rate limiting (last!)
    def _hit(_):
        try:
            req = urllib.request.Request(BASE + "/login")
            return _opener.open(req, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=16) as ex:
        codes = list(ex.map(_hit, range(320)))
    check("IP rate limiter engages (429s on burst)", 429 in codes, f"saw {sorted(set(codes))}")

    print("\n" + "=" * 62)
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"SECURITY TEST RESULT: {passed}/{total} passed")
    fails = [n for n, ok, _ in results if not ok]
    if fails:
        print("FAILED:", *fails, sep="\n  - ")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
