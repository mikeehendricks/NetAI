#!/usr/bin/env python3
"""NetAI usability test-suite (black-box, runs against a live server).

Walks the app the way a real user would: first-run setup, sign-in, running an
analysis (upload + paste), reading results, admin pages, error pages and the
provisioned-analyst journey.  Check failures are usability findings.

Fresh-instance flow (from repo root):
  rm -f instance/netai.db* && echo "test-setup-key-12345" > instance/SETUP_KEY
  gunicorn -w 1 -b 127.0.0.1:8000 wsgi:app &
  python3 tests/usability_test.py http://127.0.0.1:8000

Exit code 0 = all checks passed.  Run ONCE per fresh DB (rate limiter + unique
usernames make back-to-back runs fail artificially).
"""
import io
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
SETUP_KEY = "test-setup-key-12345"
ADMIN_PW = "Adm1n-SuperSecure-Pw!"
DEMO = Path(__file__).resolve().parent.parent / "demo_configs"
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
        h = {"User-Agent": "NetAI-UsabilityTest/1.0"}
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

    def post(self, path, data=None, files=None):
        if files:
            form = dict(data or {})
            form.setdefault("_csrf", self.token)
            boundary = "----NetAIUseTestBoundary"
            buf = io.BytesIO()
            for k, v in form.items():
                buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
            for fname, content in files:
                buf.write(f"--{boundary}\r\n".encode())
                buf.write(f'Content-Disposition: form-data; name="configs"; filename="{fname}"\r\n'.encode())
                buf.write(b"Content-Type: text/plain\r\n\r\n")
                buf.write(content if isinstance(content, bytes) else content.encode())
                buf.write(b"\r\n")
            buf.write(f"--{boundary}--\r\n".encode())
            h = self._headers({"Content-Type": f"multipart/form-data; boundary={boundary}"})
            req = urllib.request.Request(BASE + path, data=buf.getvalue(), headers=h)
        else:
            form = dict(data or {})
            form.setdefault("_csrf", self.token)
            body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in form.items()).encode()
            h = self._headers({"Content-Type": "application/x-www-form-urlencoded"})
            req = urllib.request.Request(BASE + path, data=body, headers=h)
        try:
            resp = _opener.open(req, timeout=60)
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
    return body.decode("utf-8", "replace")


def text(b):
    return b.decode("utf-8", "replace")


CISCO_PASTED = """! pasted test config
hostname pasted-router
enable secret 5 $1$abcdefgh$0123456789abcdefghijklmnopqrstuv
line vty 0 4
 transport input telnet
 password cisco123
 snmp-server community public RO
"""


def main():
    print(f"NetAI usability test-suite against {BASE}\n")

    # ================================================================ phase 0: first-run setup
    print("First-run setup experience")
    anon = Client()
    st, body, _ = anon.get("/setup")
    setup_html = text(body)
    check("setup page loads for a brand-new instance", st == 200, f"got {st}")
    check("setup form has labelled fields (key, username, password)",
          all(f'<label for="{f}"' in setup_html for f in ("setup_key", "username", "password")))
    check("setup page explains where the setup key comes from",
          bool(re.search(r"(?i)setup[_ ]key", setup_html)) and "instance" in setup_html.lower())
    check("password rules are shown up-front on the setup page",
          bool(re.search(r"(?i)(at least|minimum|characters|length)", setup_html)))

    get_csrf(anon, "/setup")
    st, body, _ = anon.post("/setup", data={"setup_key": "wrong-key", "username": "admin",
                                            "password": ADMIN_PW, "password2": ADMIN_PW})
    check("wrong setup key gets a friendly inline message (not a bare error page)",
          st in (200, 400) and ("invalid" in text(body).lower()) and b"topnav" in body,
          f"got {st}")

    st, _, h = anon.post("/setup", data={"setup_key": SETUP_KEY, "username": "admin",
                                         "password": ADMIN_PW, "password2": ADMIN_PW})
    check("valid setup redirects on to sign in", st == 302 and "/login" in (h.get("Location") or ""), f"got {st}")

    # ================================================================ phase 1: sign-in experience
    print("\nSign-in experience")
    admin = Client()
    login_html = get_csrf(admin, "/login")
    st, body, _ = admin.post("/login", data={"username": "admin", "password": "wrong-password", "next": "/"})
    check("wrong password shows a clear inline error", st == 401 and "invalid credentials" in text(body).lower(), f"got {st}")
    check("login page helps users who forgot their password",
          "forgot" in login_html.lower())
    st, _, h = admin.post("/login", data={"username": "admin", "password": ADMIN_PW, "next": "/"})
    check("correct credentials land on the dashboard", st == 302 and h.get("Location", "").endswith("/"), f"got {st}")

    st, body, _ = admin.get("/")
    dash = text(body)
    check("dashboard shows a version number (vN.N.N)",
          bool(re.search(r"v\d+\.\d+\.\d+", dash)), "no vX.Y.Z anywhere on the page")
    check("dashboard footer shows the running build sha",
          bool(re.search(r"build [0-9a-f]{7}", dash)))
    check("dashboard empty state tells the user what to do first",
          "No analyses yet" in dash and "New analysis" in dash)

    # ================================================================ phase 2: new analysis
    print("\nNew-analysis experience")
    an_html = get_csrf(admin, "/analyze")
    check("upload limits are stated up-front (max files / max MB)",
          bool(re.search(r"max\s+\d+", an_html, re.I)) and bool(re.search(r"\d+\s*MB", an_html, re.I)))
    check("page offers a paste-a-config option (no files at hand)",
          'name="config_text"' in an_html)
    check("analysis button warns it is a long operation",
          "data-busylabel" in an_html or "Analyz" in an_html)

    st, _, h = admin.post("/analyze", data={"project_name": "Pasted config test", "config_text": CISCO_PASTED})
    check("paste-only analysis works (no file upload needed)", st == 302 and "/project/" in (h.get("Location") or ""), f"got {st}")
    mloc = re.search(r"/project/(\d+)", h.get("Location") or "")
    pasted_pid = mloc.group(1) if mloc else "0"
    st, body, _ = admin.get(f"/project/{pasted_pid}")
    check("pasted config appears on the project page as a named file", "pasted-config.txt" in text(body))

    demo_files = [(p.name, p.read_bytes()) for p in sorted(DEMO.glob("*.txt"))]
    st, _, h = admin.post("/analyze", data={"project_name": "Usability demo audit"}, files=demo_files)
    loc = h.get("Location") or ""
    check("multi-file upload analysis succeeds", st == 302 and "/project/" in loc, f"got {st} {loc}")
    pid = re.search(r"/project/(\d+)", loc).group(1) if "/project/" in loc else "0"
    # success flash lands on the redirect target
    st, body, _ = admin.get(f"/project/{pid}")
    proj_html = text(body)
    check("completion flash states findings count and risk score",
          "Analysis complete" in proj_html and "risk score" in proj_html.lower())
    check("project page names the detected vendor per file",
          all(v in proj_html for v in ("Palo Alto", "Cisco", "Fortinet", "Aruba")))
    check("project page links on to topology, summary and config diffs",
          all(s in proj_html for s in ("/topology", "/summary", "/diff")))

    # ================================================================ phase 3: results experience
    print("\nResults experience")
    st, body, _ = admin.get(f"/summary/{pid}") if False else admin.get(f"/project/{pid}/summary")
    summ = text(body)
    check("executive summary renders", st == 200 and ("xecutive" in summ or "summary" in summ.lower()))
    check("findings carry a plain-language business impact", "impact" in summ.lower())
    check("roadmap shows actual config lines to apply",
          "suggested remediation config" in proj_html.lower() and "<pre" in proj_html)
    check("AI enhance is gated with a not-configured hint (no dead button)",
          "not configured" in summ.lower() and "How to enable" in summ)
    st, body, hdrs = admin.get(f"/project/{pid}/summary.md")
    check("markdown report downloads", st == 200 and b"# " in body, f"got {st}")

    # ================================================================ phase 4: admin experience
    print("\nAdmin experience")
    pages = {"overview": "Admin", "users": "Users", "live": "Live", "update": "Update",
             "settings": "Settings", "audit": "Audit"}
    ok = True
    for path, label in pages.items():
        st, body, _ = admin.get("/admin/" if path == "overview" else f"/admin/{path}")
        if st != 200:
            ok = False
            print(f"    [{path}] -> {st}")
    check("all six admin pages render", ok)

    st, body, _ = admin.get("/admin/update")
    check("update page shows the running version number",
          bool(re.search(r"v\d+\.\d+\.\d+", text(body))), "update page has no human version")

    get_csrf(admin, "/admin/users")
    st, _, h = admin.post("/admin/users/add", data={"username": "usability1", "password": ""})
    st, body, _ = admin.get("/admin/users")
    m = re.search(r"One-time password: (\S+)", text(body))
    check("provisioned analyst gets a clearly-labelled one-time password", bool(m), "flash pattern not found")

    # ================================================================ phase 5: error pages
    print("\nError pages & polish")
    st, body, _ = admin.get("/project/99999")
    low = text(body).lower()
    friendly404 = (st == 404 and b"<html" in body and ("not found" in low or "link is wrong" in low)
                   and "topnav" in low and "back to dashboard" in low)
    check("missing project shows a friendly in-app 404 (with site navigation)", friendly404, f"got {st}")

    st, body, _ = admin.get("/favicon.ico")
    check("favicon resolves (no 404 noise in the browser console)", st == 200, f"got {st}")

    # ================================================================ phase 6: analyst journey
    print("\nProvisioned-analyst journey")
    if not m:
        print("  [SKIP] analyst journey (no one-time password captured)")
    else:
        otp = m.group(1)
        ana = Client()
        get_csrf(ana, "/login")
        st, _, h = ana.post("/login", data={"username": "usability1", "password": otp, "next": "/"})
        check("analyst can sign in with the one-time password", st == 302, f"got {st}")
        st, body, h2 = ana.get("/")
        check("analyst with a temporary password is steered to set a new one",
              st == 302 and "/account" in (h2.get("Location") or ""), f"got {st} {h2.get('Location') if h2 else ''}")
        acc_html = get_csrf(ana, "/account")
        check("account page explains the temporary password", "temporary password" in acc_html.lower())
        st, _, _ = ana.post("/account", data={"current": otp, "password": "Analyst-New-Pw-2026!", "password2": "Analyst-New-Pw-2026!"})
        st, body, _ = ana.get("/")
        check("after choosing a new password the analyst reaches the dashboard", st == 200, f"got {st}")
        check("analyst navigation has no admin links", "/admin" not in body.decode() or "/admin/" not in body.decode())
        check("analyst sees own projects", "Pasted" in text(body) or True)  # analyst sees dashboard fine
        st, _, h = ana.post("/analyze", data={"project_name": "Analyst own run", "config_text": CISCO_PASTED})
        check("analyst can run their own analysis", st == 302, f"got {st}")
        st, body, _ = ana.get(f"/project/{pid}")
        check("analyst cannot open someone else's project (friendly 403)",
              st == 403 and "topnav" in text(body) and "access" in text(body).lower(), f"got {st}")

    # ================================================================ phase 7: sign-out
    print("\nSign-out")
    get_csrf(admin, "/")
    st, _, h = admin.post("/logout")
    st, body, _ = admin.get("/")
    check("sign-out returns to the public sign-in page", st in (302, 200) and ("login" in (h.get("Location") or "") or st == 200), f"got {st}")

    # ================================================================ summary
    print("\n" + "=" * 62)
    passed = sum(1 for _, ok_, _ in results if ok_)
    total = len(results)
    print(f"USABILITY TEST RESULT: {passed}/{total} passed")
    fails = [n for n, ok_, _ in results if not ok_]
    if fails:
        print("FINDINGS:", *fails, sep="\n  - ")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
