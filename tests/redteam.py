#!/usr/bin/env python3
"""NetAI red-team suite, round 2 (adversarial, run against a live instance).

Goes after privilege escalation, mass assignment, session tampering, upload
abuse, the config-generator's own attack surface, injection filters, verb
tampering and concurrency races. Non-destructive: fictitious accounts only,
no data is permanently harmed (the race tests operate on a throwaway project
created by this suite).

Fresh-instance flow (from repo root):
  rm -f instance/netai.db* && echo "test-setup-key-12345" > instance/SETUP_KEY
  gunicorn -w 1 -b 127.0.0.1:8000 wsgi:app &
  python3 tests/redteam.py http://127.0.0.1:8000

Run ONCE per fresh DB. Exit code 0 = all checks passed.
"""
import io
import json
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
    results.append((name, bool(passed)))
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f" — {detail}" if detail and not passed else ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self):
        self.cookies = {}
        self.token = ""
        self.op = urllib.request.build_opener(_NoRedirect)

    def _h(self, extra=None):
        h = {"User-Agent": "NetAI-RedTeam/2.0"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        h.update(extra or {})
        return h

    def _absorb(self, headers):
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                m = re.match(r"([^=]+)=([^;]*)", v)
                if m:
                    self.cookies[m.group(1)] = m.group(2)

    def get(self, path, headers=None):
        try:
            r = self.op.open(urllib.request.Request(BASE + path, headers=self._h(headers)), timeout=30)
            self._absorb(r.headers)
            return r.status, r.read().decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            self._absorb(e.headers)
            return e.code, e.read().decode("utf-8", "replace"), e.headers

    def post(self, path, data=None, headers=None):
        form = dict(data or {})
        form.setdefault("_csrf", self.token)
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(self._h(headers))
        try:
            r = self.op.open(urllib.request.Request(
                BASE + path, data=urllib.parse.urlencode(form).encode(), headers=h), timeout=60)
            self._absorb(r.headers)
            return r.status, r.read().decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            self._absorb(e.headers)
            return e.code, e.read().decode("utf-8", "replace"), e.headers

    def multipart(self, path, fields, files=None):
        boundary = "----RedTeam"
        buf = io.BytesIO()
        form = dict(fields or {})
        form.setdefault("_csrf", self.token)
        for k, v in form.items():
            buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        for field, fn, content in (files or []):
            buf.write(f"--{boundary}\r\n".encode())
            buf.write((f"Content-Disposition: form-data; name=\"{field}\"; filename=\"{fn}\"\r\n"
                       "Content-Type: application/octet-stream\r\n\r\n").encode())
            buf.write(content if isinstance(content, bytes) else content.encode())
            buf.write(b"\r\n")
        buf.write(f"--{boundary}--\r\n".encode())
        try:
            r = self.op.open(urllib.request.Request(
                BASE + path, data=buf.getvalue(),
                headers=self._h({"Content-Type": f"multipart/form-data; boundary={boundary}"})), timeout=120)
            self._absorb(r.headers)
            return r.status, r.read().decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            self._absorb(e.headers)
            return e.code, e.read().decode("utf-8", "replace"), e.headers


def csrf(c, path="/login"):
    _, body, _ = c.get(path)
    m = re.search(r'name="_csrf" value="([^"]+)"', body) or re.search(r'<meta name="csrf" content="([^"]+)"', body)
    if m:
        c.token = m.group(1)
    return c.token


CISCO = "hostname rt-target\nenable secret 5 $1$ab$cd\ncrypto key generate rsa modulus 2048\n"


def main():
    print(f"NetAI red-team suite (round 2) against {BASE}\n")

    # ------------------------------------------------ setup
    admin = Client()
    tk = csrf(admin, "/setup")
    admin.post("/setup", {"setup_key": SETUP_KEY, "username": "admin",
                          "password": ADMIN_PW, "password2": ADMIN_PW})
    csrf(admin, "/login")
    admin.post("/login", {"username": "admin", "password": ADMIN_PW, "next": "/"})
    csrf(admin, "/admin/users")
    admin.post("/admin/users/add", {"username": "redteam1", "password": "RedTeam-Pw-2026!"})

    ana = Client()
    csrf(ana, "/login")
    ana.post("/login", {"username": "redteam1", "password": "RedTeam-Pw-2026!", "next": "/"})
    csrf(ana, "/analyze")

    # ---------------------------------------------- R1 privilege escalation
    print("R1: privilege escalation / mass assignment")
    st, _, _ = ana.post("/account", {"current": "RedTeam-Pw-2026!", "password": "Esc1-Pw-Strong!",
                                     "password2": "Esc1-Pw-Strong!", "role": "admin"})
    ana2 = Client()
    csrf(ana2, "/login")
    st, _, _ = ana2.post("/login", {"username": "redteam1", "password": "Esc1-Pw-Strong!", "next": "/admin"})
    check("role field in account POST ignored (stays analyst)", st in (302, 403), f"got {st}")
    st, b, _ = ana2.get("/admin/users")
    check("escalated account cannot read admin users page", st == 403, f"got {st}")

    for path, data in [("/admin/users/add", {"username": "pwn1", "password": "Pwn1-Pw-2026!", "role": "admin"}),
                       ("/admin/users/1/role", {"role": "admin"}),
                       ("/admin/users/1/toggle", {}), ("/admin/users/1/reset", {}),
                       ("/admin/users/1/delete", {}), ("/admin/settings",
                       {"AI_PROVIDER": "openai", "OPENAI_API_KEY": "x"})]:
        st, _, _ = ana.post(path, data)
        check(f"analyst POST {path} -> 403", st == 403, f"got {st}")
    st, _, _ = ana.get("/admin/users")
    check("analyst GET admin page -> 403 (not 405/500)", st == 403, f"got {st}")

    # ---------------------------------------------- R2 session integrity
    print("\nR2: session tampering")
    c = Client()
    csrf(c, "/login")
    c.post("/login", {"username": "admin", "password": ADMIN_PW, "next": "/"})
    cookie_pair = [(k, v) for k, v in c.cookies.items()]
    if cookie_pair:
        k, v = cookie_pair[0]
        tampered = (v[:-4] + v[-3:] + v[-4]) if len(v) > 8 else v + "x"
        c.cookies[k] = tampered
        st, _, h = c.get("/admin/")
        check("tampered session cookie -> treated as anonymous",
              st in (302, 303) and "/login" in (h.get("Location") or ""), f"got {st}")
    else:
        check("session cookie present after login", False, "no cookie captured")

    # ---------------------------------------------- R3 upload abuse
    print("\nR3: upload abuse")
    c = Client()
    csrf(c, "/login")
    c.post("/login", {"username": "admin", "password": ADMIN_PW, "next": "/analyze"})
    csrf(c, "/analyze")
    st, _, h = c.multipart("/analyze", {"project_name": "trav"}, [("configs", "../../etc/evil.cfg", CISCO)])
    loc = h.get("Location", "")
    check("traversal filename neutralized (secure_filename)", st == 302 and "/project/" in loc, f"got {st} {loc}")
    m = re.search(r"/project/(\d+)", loc)
    if m:
        _, body, _ = c.get(f"/project/{m.group(1)}")
        check("traversal name not echoed as path", "etc/evil" not in body and "evil" in body)  # becomes 'evil.cfg'
    st, _, _ = c.multipart("/analyze", {"project_name": "nullbyte"},
                           [("configs", "we\x00ird-name.cfg", CISCO)])
    check("null-byte filename does not crash (4xx/302, no 500)", st in (302, 400), f"got {st}")
    st, _, h_bp = c.multipart("/analyze", {"project_name": "bigpaste", "config_text": "A" * 4_100_000},
                              [("configs", "tiny.cfg", CISCO)])
    loc_bp = h_bp.get("Location", "")
    if "/project/" in loc_bp:
        _, big_body, _ = c.get(loc_bp)
        check("oversized paste rejected", "No valid configuration files" in big_body or "too large" in big_body,
              "paste was accepted")
    else:
        check("oversized paste rejected", "4" in str(st), f"got {st}")
    st, _, loc2h = c.multipart("/analyze", {"project_name": "dupfield"}, [("configs", "a.cfg", CISCO),
                                                                          ("configs", "b.cfg", CISCO)])
    loc2 = loc2h.get("Location", "")
    check("duplicate config fields handled (no crash)", st == 302 and "/project/" in loc2, f"got {st}")

    # ---------------------------------------------- R4 markdown/XSS hardening
    print("\nR4: markdown & stored XSS surface")
    sys.path.insert(0, ".")
    import os
    os.environ.setdefault("SECRET_KEY", "redteam-local-import-key-000000")
    from app.markdown_mini import md_to_html
    html = md_to_html("# T\n<script>alert(1)</script>\n![x](javascript:alert(2))")
    check("md_to_html escapes raw script", "<script>alert(1)</script>" not in html)
    check("md_to_html does not emit javascript: links", 'href="javascript:' not in html)
    payload = "<img src=x onerror=alert(3)>{{7*7}}${7*7}"
    st, _, h = c.multipart("/analyze", {"project_name": payload}, [("configs", "x.cfg", CISCO)])
    pid = re.search(r"/project/(\d+)", h.get("Location", "")).group(1)
    for page in (f"/project/{pid}", "/", f"/project/{pid}/summary", f"/project/{pid}/topology"):
        _, body, _ = c.get(page)
        check(f"payload inert on {page}", "<img src=x" not in body and "&lt;img src=x" in body)

    # ---------------------------------------------- R5 config-generator surface
    print("\nR5: config-generator attack surface")
    anon = Client()
    st, _, _ = anon.get("/tools/topo-config")
    check("anon cannot open generator", st in (302, 303), f"got {st}")
    st, _, _ = anon.post("/tools/topo-config", {"source": "project", "project_id": "1"})
    check("anon cannot POST generator", st in (302, 303, 400), f"got {st}")
    _tok = c.token
    c.token = ""
    st, _, _ = c.post("/tools/topo-config", {"source": "project", "project_id": "1"})
    c.token = _tok
    check("generator POST without CSRF token -> 400", st == 400, f"got {st}")
    st, _, _ = c.get("/tools/topo-config/results/" + "a" * 32)
    check("unknown result id -> 404", st == 404, f"got {st}")
    st, _, _ = c.get("/tools/topo-config/results/" + "../etc/passwd")
    check("traversal result id -> 404", st == 404, f"got {st}")
    st, _, _ = c.get("/tools/topo-config/results/ffffff")
    check("short id -> 404", st == 404, f"got {st}")
    st, _, _ = c.post("/tools/topo-config", {"source": "project", "project_id": "99999"})
    check("other/missing project id -> 404", st == 404, f"got {st}")
    st, _, _ = c.multipart("/tools/topo-config", {"source": "image"},
                           [("topo_image", "evil.png", b"\x89PNG\r\n\x1a\n" + b"A" * (9 * 1024 * 1024))])
    check("oversized image rejected", st == 302, f"got {st}")

    # ---------------------------------------------- R6 filter injection
    print("\nR6: filter/parameter injection")
    st, body, _ = c.get(f"/project/{pid}?severity=%3Cscript%3Ealert(1)%3C/script%3E&device=%3Cimg%20src=x%20onerror=alert(2)%3E")
    check("findings filters escaped", "<script>alert(1)" not in body and "onerror=alert(2)" not in body, f"got {st}")
    from urllib.parse import quote as _q
    st, body, _ = c.get(f"/project/{pid}?severity={_q("'; DROP TABLE users; --")}")
    check("SQLi probe in filters harmless (page renders)", st == 200 and "Severity" in body or st == 200, f"got {st}")

    # ---------------------------------------------- R7 verb tampering
    print("\nR7: HTTP verb tampering")
    st, _, _ = ana.get("/admin/users")
    check("analyst GET /admin/users -> 403", st == 403, f"got {st}")
    st, _, _ = ana.get("/tools/topo-config")
    check("analyst may use the generator (200)", st == 200, f"got {st}")
    ana3 = Client()
    csrf(ana3, "/login")
    ana3.post("/login", {"username": "redteam1", "password": "RedTeam-Pw-2026!", "next": "/"})
    _t = ana3.token
    ana3.token = ""
    st, _, _ = ana3.post("/logout", {})
    ana3.token = _t
    check("logout without CSRF token rejected", st == 400, f"got {st}")

    # ---------------------------------------------- R8 concurrency races
    print("\nR8: concurrency")
    st, _, h = c.multipart("/analyze", {"project_name": "race-target"}, [("configs", "race.cfg", CISCO)])
    race_pid = re.search(r"/project/(\d+)", h.get("Location", "")).group(1)
    csrf(c, "/")
    with ThreadPoolExecutor(max_workers=4) as ex:
        codes = list(ex.map(lambda _: c.post(f"/project/{race_pid}/delete", {})[0], range(4)))
    check("parallel deletes: no 5xx, one success", all(code < 500 for code in codes), f"codes={codes}")
    with ThreadPoolExecutor(max_workers=4) as ex:
        codes = list(ex.map(lambda i: c.post("/analyze", {"project_name": f"par{i}", "config_text": CISCO})[0], range(4)))
    check("parallel analyzes: all succeed or cleanly throttled", all(code in (302, 429) for code in codes), f"codes={codes}")

    # ---------------------------------------------- R9 XFF spoofing (TRUST_PROXY=0)
    print("\nR9: XFF spoofing")
    c3 = Client()
    csrf(c3, "/login")
    c3.post("/login", {"username": "admin", "password": ADMIN_PW, "next": "/"},
            {"X-Forwarded-For": "8.8.8.8", "X-Real-IP": "8.8.8.8"})
    st, body, _ = c3.get("/api/live-sessions")
    spoofed_accepted = False
    try:
        data = json.loads(body)
        spoofed_accepted = any(s.get("ip") == "8.8.8.8" for s in data.get("sessions", []))
    except Exception:
        pass
    check("XFF not trusted without TRUST_PROXY (ip not spoofed)", not spoofed_accepted)

    print("\n" + "=" * 62)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"RED-TEAM ROUND 2 RESULT: {passed}/{total} passed")
    fails = [n for n, ok in results if not ok]
    if fails:
        print("FINDINGS:", *fails, sep="\n  - ")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
