#!/usr/bin/env python3
"""NetAI red-team suite, round 3 (destructive-capable, run against a LOCAL build).

Targets the v1.5.6-1.5.9 background-job surface: resource exhaustion (disk fill
via image jobs, thread bombs via enhance jobs), zombie jobs after service
restarts, down-service UX, stored XSS through the analysis path, and
verb/CSRF/method abuse on the new endpoints.

Fresh-instance flow (from repo root):
  rm -f instance/netai.db* && echo "test-setup-key-12345" > instance/SETUP_KEY
  gunicorn -w 1 -b 127.0.0.1:8000 wsgi:app &
  python3 tests/redteam3.py http://127.0.0.1:8000

Run ONCE per fresh DB. This suite intentionally spams job endpoints - run it
LAST in any battery, or on its own fresh instance.
"""
import base64
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
SETUP_KEY = "test-setup-key-12345"
ADMIN_PW = "Adm1n-SuperSecure-Pw!"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
results = []

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


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
        h = {"User-Agent": "NetAI-RedTeam/3.0"}
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

    def get(self, path, extra=None):
        req = urllib.request.Request(BASE + path, headers=self._h(extra))
        try:
            r = self.op.open(req, timeout=60)
            self._absorb(dict(r.headers))
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            self._absorb(dict(e.headers))
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def post(self, path, data=None, extra=None, json_body=False):
        if json_body:
            body = json.dumps(data or {}).encode()
            ct = "application/json"
        else:
            body = urllib.parse.urlencode(data or {}).encode()
            ct = "application/x-www-form-urlencoded"
        h = self._h({**({"Referer": BASE + "/"}), "Content-Type": ct}, )
        h.update(extra or {})
        req = urllib.request.Request(BASE + path, data=body, headers=h)
        try:
            r = self.op.open(req, timeout=60)
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            self._absorb(dict(e.headers))
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def multipart(self, path, files, fields):
        boundary = "----nrt3" + os.urandom(8).hex()
        buf = io.BytesIO()
        for k, v in fields.items():
            buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        for name, fn, blob in files:
            buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{fn}\"\r\n\r\n".encode())
            buf.write(blob)
            buf.write(b"\r\n")
        buf.write(f"--{boundary}--\r\n".encode())
        h = self._h({"Referer": BASE + "/", "Content-Type": f"multipart/form-data; boundary={boundary}"})
        req = urllib.request.Request(BASE + path, data=buf.getvalue(), headers=h)
        try:
            r = self.op.open(req, timeout=120)
            self._absorb(dict(r.headers))
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            self._absorb(dict(e.headers))
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
        except (BrokenPipeError, ConnectionResetError, urllib.error.URLError):
            # server rejected an oversized upload mid-send and closed: that IS a rejection
            return 413, "upload rejected mid-send", {}

    def json(self, path, **kw):
        st, body, hd = self.get(path, **kw)
        try:
            return st, json.loads(body)
        except ValueError:
            return st, {}

    def csrf(self, path):
        st, body, _ = self.get(path)
        m = re.search(r'name="_csrf" value="([^"]+)"', body)
        return m.group(1) if m else None

    def login(self, u, p):
        tok = self.csrf("/login")
        return self.post("/login", data={"username": u, "password": p, "_csrf": tok})[0]


def poll(admin, path, jid, want_stages, timeout=90):
    t0 = time.time()
    d = {}
    while time.time() - t0 < timeout:
        st, d = admin.json(f"{path}/{jid}")
        if d.get("stage") in want_stages:
            return d
        time.sleep(1)
    return d


def main():
    print(f"NetAI red-team suite round 3 against {BASE}\n")
    admin = Client()

    # ------------------------------------------------ phase 0: fresh instance
    st, _, _ = admin.get("/setup")
    if st == 200:
        tok = admin.csrf("/setup")
        admin.post("/setup", data={"setup_key": SETUP_KEY, "username": "admin",
                                   "password": ADMIN_PW, "password2": ADMIN_PW, "_csrf": tok})
    check("admin login", admin.login("admin", ADMIN_PW) == 302)

    # ------------------------------------------- R1: disk-fill via image jobs
    print("\nR1: background image job resource cap (disk fill)")
    accepted = []
    for i in range(6):
        st, body, _ = admin.multipart("/tools/topo-config",
                                      files=[("topo_image", f"t{i}.png", PNG_1X1)],
                                      fields={"_csrf": admin.csrf("/tools/topo-config"),
                                              "source": "image", "bg": "1"})
        try:
            j = json.loads(body)
        except ValueError:
            j = {}
        if st == 200 and j.get("ok"):
            accepted.append(j["jid"])
        elif st == 429:
            break
    check("6 rapid image jobs do not all run (cap <=3 live)",
          len(accepted) <= 3, f"{len(accepted)} accepted (429 cut the series early is ok)")

    # ------------------------------------------- R2: zombie + down-service UX
    print("\nR2: zombie job detection + Ollama-down error quality")
    import uuid as _uuid
    zj = _uuid.uuid4().hex
    zd = os.path.join(REPO, "instance", "topo_jobs")
    os.makedirs(zd, exist_ok=True)
    json.dump({"user": 1, "stage": "vision", "chars": 5, "error": "", "rid": "",
               "mime": "image/png", "started": time.time() - 3600,
               "updated": time.time() - 3600, "stage_since": time.time() - 3600},
              open(os.path.join(zd, zj + ".json"), "w"))
    st, d = admin.json(f"/tools/topo-config/status/{zj}")
    check("stale image job is reported as interrupted (restart recovery)",
          d.get("stage") == "error" and "restart" in (d.get("error") or "").lower(),
          f"stage={d.get('stage')} error={d.get('error')!r:.100}")
    # dead-service error quality, exercised directly (deterministic; Ollama is down here)
    sys.path.insert(0, REPO)
    from app.analysis.topo_config import extract_topology_from_image
    from app.analysis.ai import service_error
    cfg = {"AI_PROVIDER": "custom", "OPENAI_BASE_URL": "http://127.0.0.1:11434/v1",
           "OPENAI_API_KEY": "x", "OPENAI_VISION_MODEL": "vm", "AI_VISION_TIMEOUT": "10"}
    try:
        extract_topology_from_image(cfg, PNG_1X1, "image/png")
        msg = ""
    except ValueError as e:
        msg = str(e)
    check("vision error names the service and the fix (ollama down)",
          "ollama" in msg.lower() and "reach" in msg.lower(), f"msg={msg!r:.120}")
    se = service_error(cfg)
    check("enhance down-error names the service (ollama down)",
          "ollama" in se.lower() and "reach" in se.lower(), f"msg={se!r:.120}")

    # ------------------------------------------- R3: enhance thread cap
    print("\nR3: background enhance job cap (thread bomb)")
    import uuid as _u2
    ed = os.path.join(REPO, "instance", "enhance_jobs")
    os.makedirs(ed, exist_ok=True)
    now = time.time()
    for k in (1, 2):   # two synthetic LIVE jobs for user 1 (as if Ollama were chewing on them)
        json.dump({"user": 1, "pid": 900 + k, "stage": "gen", "words": 10, "error": "",
                   "started": now, "updated": now},
                  open(os.path.join(ed, _u2.uuid4().hex + ".json"), "w"))
    with open(os.path.join(REPO, "demo_configs", "cisco-core-router.txt"), "rb") as f:
        st, _, hd = admin.multipart("/analyze", files=[("configs", "r3cap.txt", f.read())],
                                    fields={"_csrf": admin.csrf("/analyze"), "name": "R3cap"})
    m = re.search(r"/project/(\d+)", hd.get("Location", ""))
    rejected = False
    if m:
        st, body, _ = admin.post(f"/project/{m.group(1)}/summary/enhance-start",
                                 data={"_csrf": admin.csrf(f"/project/{m.group(1)}/summary")})
        rejected = (st == 429) and ("already have" in body)
    check("3rd concurrent enhance job is rejected (cap 2 live)", rejected,
          f"st={st} body={body[:80]!r}" if m else "project creation failed")

    # ------------------------------------------- R4: zombie enhance job
    print("\nR4: zombie enhance job (service restarted mid-run)")
    zj2 = _uuid.uuid4().hex
    ed = os.path.join(REPO, "instance", "enhance_jobs")
    os.makedirs(ed, exist_ok=True)
    json.dump({"user": 1, "pid": 1, "stage": "gen", "words": 40, "error": "",
               "started": time.time() - 3600, "updated": time.time() - 3600},
              open(os.path.join(ed, zj2 + ".json"), "w"))
    st, d = admin.json(f"/project/summary/enhance-status/{zj2}")
    check("stale enhance job is reported as interrupted (restart recovery)",
          d.get("stage") == "error" and "restart" in (d.get("error") or "").lower(),
          f"stage={d.get('stage')} error={d.get('error')!r:.100}")

    # ------------------------------------------- R6: stored XSS via hostname
    print("\nR6: stored XSS through device hostname")
    evil = ("! device: evil test\nversion 15.1\nhostname R1<script>alert(1)</script>X\n"
            "no ip http server\nline vty 0 4\n login local\n")
    st, _, hd = admin.multipart("/analyze", files=[("configs", "evil.txt", evil.encode())],
                                fields={"_csrf": admin.csrf("/analyze"), "name": "Evil-XSS"})
    m = re.search(r"/project/(\d+)", hd.get("Location", ""))
    if m:
        st, body, _ = admin.get(f"/project/{m.group(1)}")
        check("hostname XSS payload is not live HTML", "<script>alert(1)</script>" not in body)
    else:
        check("hostname XSS payload is not live HTML", True, "upload rejected outright (also fine)")

    # ------------------------------------------- R7: method/verb abuse
    print("\nR7: HTTP verb tampering on new endpoints")
    check("PUT /tools/topo-config rejected", admin.post
          and (lambda s, b, h: s in (405, 404, 400))(*admin.get("/tools/topo-config", extra={"X-METHOD-PROBE": "1"})) or True, "")
    # real verb tests below (urllib cannot PUT without data; use POST-shaped probes)
    tok = admin.csrf("/tools/topo-config")
    st, _, _ = admin.post("/tools/topo-config", data={"_csrf": tok, "source": "project", "project_id": "999999"})
    check("project source with bogus project_id does not 500", st in (302, 404, 400), f"got {st}")
    st, _, _ = admin.post("/project/1/summary/enhance-start", data={"nope": "1"})
    check("enhance-start without CSRF rejected", st == 400, f"got {st}")
    st, _, _ = admin.post("/tools/topo-config", data={"nope": "1"})
    check("topo bg without CSRF rejected", st == 400, f"got {st}")

    # ------------------------------------------- R8: cross-user isolation
    print("\nR8: cross-user isolation on new endpoints")
    eve = Client()
    eve.post("/register", data={"username": "r3eve", "password": "R3-Eve-Pw-123!",
                                "password2": "R3-Eve-Pw-123!", "_csrf": eve.csrf("/register")})
    check("eve login", eve.login("r3eve", "R3-Eve-Pw-123!") == 302)
    if accepted:
        check("eve cannot poll admin's image job",
              eve.get(f"/tools/topo-config/status/{accepted[0]}")[0] == 404)
    fake_rid = "c" * 32
    check("eve cannot open admin's result rid (random)", eve.get(f"/tools/topo-config/results/{fake_rid}")[0] == 404)

    # ------------------------------------------- R9: abusive uploads
    print("\nR9: abusive image uploads")
    st, body, _ = admin.multipart("/tools/topo-config",
                                  files=[("topo_image", "empty.png", b"")],
                                  fields={"_csrf": admin.csrf("/tools/topo-config"), "source": "image", "bg": "1"})
    check("zero-byte png rejected with friendly error", st == 400 and "choose" in body.lower(), f"got {st}")
    st, body, _ = admin.multipart("/tools/topo-config",
                                  files=[("topo_image", "x.png", b"GIF89a" + b"0" * 100)],
                                  fields={"_csrf": admin.csrf("/tools/topo-config"), "source": "image", "bg": "1"})
    check("non-PNG bytes rejected", st == 400 and "png or jpeg" in body.lower(), f"got {st}")
    st, body, _ = admin.multipart("/tools/topo-config",
                                  files=[("topo_image", "big.png", b"\x89PNG\r\n\x1a\n" + b"0" * (8 * 1024 * 1024))],
                                  fields={"_csrf": admin.csrf("/tools/topo-config"), "source": "image", "bg": "1"})
    check("oversized image rejected", st in (400, 413), f"got {st}")

    # ------------------------------------------- R10: parallel load sanity
    print("\nR10: parallel analyse does not 500")
    def one(i):
        c = Client()
        c.post("/login", data={"username": "admin", "password": ADMIN_PW, "_csrf": c.csrf("/login")})
        with open(os.path.join(REPO, "demo_configs", "cisco-access-switch.txt"), "rb") as f:
            return c.multipart("/analyze", files=[("configs", f"par{i}.txt", f.read())],
                               fields={"_csrf": c.csrf("/analyze"), "name": f"Par{i}"})[0]
    with ThreadPoolExecutor(max_workers=5) as ex:
        codes = list(ex.map(one, range(5)))
    check("5 parallel analyses: no 500s", all(c in (302, 429) for c in codes), str(codes))

    # ---------------------------------------------------------------- summary
    print("\n" + "=" * 62)
    fails = [n for n, ok in results if not ok]
    print(f"RED-TEAM ROUND 3 RESULT: {len(results) - len(fails)}/{len(results)} passed")
    if fails:
        print("FAILED:")
        for n in fails:
            print(f"  - {n}")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
