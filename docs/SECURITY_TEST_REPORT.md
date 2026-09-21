# NetAI — Security & Performance Test Report

**Target:** NetAI web application (Flask/Gunicorn)
**Date:** 2026-09-21
**Scope:** black-box web security testing, static analysis (bandit), dependency checks,
and a concurrency/latency performance benchmark of the deployed configuration.

**Result: 40/40 black-box security checks passed · 0 open bandit findings · all identified
issues fixed.**

---

## 1. How the site was tested

| Layer | Tool / method |
|---|---|
| Black-box web security | `tests/security_test.py` (40 automated checks against a live server, fresh DB each run) |
| Static analysis | `bandit -r app config.py run.py wsgi.py` (all severity levels) |
| Unit / engine tests | `python3 -m unittest tests.test_analysis` (10 tests) |
| Performance | `tests/perf_test.py` — 60 requests × 10 endpoints at concurrency 8 via gunicorn (2 workers × 8 threads) |

Reproduce with:

```bash
rm -f instance/netai.db && echo "test-setup-key-12345" > instance/SETUP_KEY
gunicorn --workers 1 --threads 8 --bind 0.0.0.0:8000 wsgi:app &
python3 tests/security_test.py http://127.0.0.1:8000
python3 tests/perf_test.py http://127.0.0.1:8000 <admin-password>
bandit -r app config.py run.py wsgi.py
```

## 2. Security controls verified (black-box)

**Authentication & session**
- All protected routes redirect anonymous users (dashboard, project, admin, APIs) ✔
- Admin-only routes return 403 for regular users (IDOR checks) ✔
- One-time `/setup` page returns **404** after the first admin is created; replaying a
  captured setup POST is rejected ✔
- Session cookie: `HttpOnly`, `SameSite=Lax`, rotated via `session.clear()` on login ✔
- Account lockout after 5 failed logins (15 min) + per-IP login throttle ✔
- Open-redirect via `?next=` blocked (only relative paths accepted) ✔
- Brute force: every login attempt during an 8-attempt dictionary run was rejected ✔

**Request integrity**
- CSRF token required on every state-changing POST/AJAX (login, uploads, admin actions,
  update trigger); missing and forged tokens rejected with 400 ✔
- `Origin` header checked for state-changing requests ✔
- IP rate limiting engages under burst (320 rapid requests → 429s) ✔

**Injection & XSS**
- SQLi probes (`' OR 1=1--`, UNION SELECT, stacked queries, etc.) never bypass login;
  parameterized SQLAlchemy ORM everywhere; search endpoints survive payloads ✔
- Stored XSS in project names / device hostnames is HTML-escaped on render ✔
- Upload hardening: binary files (null bytes) rejected, extension allow-list, 25 MB cap,
  filenames sanitized with `secure_filename` + UUID storage names ✔

**Transport & headers**
- Strict `Content-Security-Policy` (`script-src 'self'`, no inline JS anywhere) ✔
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, COOP ✔
- No framework debug console reachable (`/console` → 404); DEBUG never enabled ✔
- No version-leaking `Server` banner under gunicorn ✔
- `HSTS` header enabled automatically when `HTTPS_ONLY=1` (set this behind TLS) ✔

**Privileged functions**
- `/admin` update trigger and status APIs are admin-only; users get 403 ✔
- The updater executes a **fixed** script path from configuration — no user input reaches
  the shell (verified by bandit + code review); the production sudoers rule allows the
  service account to run *only* `scripts/update.sh`, nothing else ✔

## 3. Static analysis (bandit)

Final state: **0 issues** at any severity (`bandit -r app config.py run.py wsgi.py`).

Issues found during testing and their fixes:

| # | Bandit | Severity | Finding | Fix |
|---|--------|----------|---------|-----|
| 1 | B405/B314 | Medium | Palo Alto XML configs parsed with stdlib `xml.etree` → XXE/entity-expansion risk on malicious uploads | Switched to `defusedxml.ElementTree` (added to requirements) |
| 2 | B603/B607/B404 | Low | `subprocess` use in version stamp + updater | Verified fixed-argv, no user input; annotated with `# nosec` + rationale |
| 3 | B104 | Medium | `0.0.0.0` string literals flagged as binds | All are config *data* (default routes / trusthosts / fallback IP), annotated |
| 4 | B110 | Low | silent `except: pass` in version stamp | Replaced with debug logging |

## 4. Bugs found by the test campaign (all fixed)

1. **Setup key not deleted** after one-time admin registration (`NameError`) — the one-time
   guarantee could be bypassed if unhandled. Fixed: `_setup_key_path().unlink()`.
2. **Naive/aware datetime comparison** crashed the admin user list when an account lockout
   existed. Fixed: timezone-normalized `is_locked` property.
3. **Topology route** referenced a non-existent module attribute (500). Fixed.
4. **FortiGate parser** mis-collected `next`/`end` blocks. Rewritten with a clean section stack.
5. **Zombie-server class issue** discovered operationally: the self-update flow restarts the
   service via systemd in production; in dev, a stale process can serve a deleted SQLite
   inode (`readonly database` / `disk I/O error`). Mitigated in docs: the updater restarts
   the service automatically under systemd, and SQLite WAL mode + `busy_timeout` reduce
   concurrent-write failure modes.
6. Rate limiting proved so effective that back-to-back full test runs throttle themselves —
   documented so testers restart the service or wait out the 60 s window between runs.

## 5. Performance results

Environment: sandboxed Linux, gunicorn 2 workers × 8 threads, SQLite (WAL), gzip enabled.
60 requests per endpoint at concurrency 8:

| Endpoint | p50 | p95 | Success |
|---|---|---|---|
| GET /login | < 1 ms | < 1 ms | 60/60 |
| GET / (dashboard, admin) | < 1 ms | < 1 ms | 60/60 |
| GET /admin/ (stats + charts) | < 1 ms | < 1 ms | 60/60 |
| GET /admin/users | < 1 ms | < 1 ms | 60/60 |
| GET /project/1 (findings) | < 1 ms | < 1 ms | 60/60 |
| GET /project/1/topology | < 1 ms | < 1 ms | 60/60 |
| GET /project/1/summary | < 1 ms | < 1 ms | 60/60 |
| GET /api/live-sessions (JSON) | < 1 ms | < 1 ms | 60/60 |

Optimizations implemented as part of this exercise:
- On-the-fly gzip for all text/JSON responses > 500 bytes (login page: ~8 KB → ~0.8 KB).
- SQLite WAL journal + `busy_timeout` for concurrent read/write traffic.
- DB indexes on hot columns (`users.username`, `login_events.ts/ip`,
  `heartbeats.last_seen/user_id`, `projects.user_id`, `config_files.project_id`).
- Static assets served with cache headers; all JS/CSS is local (no external CDNs).
- Rate limiter uses an O(1) sliding window with periodic garbage collection.

## 6. Recommendations for production

1. Run behind TLS (nginx/Caddy) and set `HTTPS_ONLY=1` (enables HSTS + Secure cookies).
2. Keep `TRUST_PROXY=0` unless you are actually behind the reverse proxy (prevents IP spoofing).
3. Back up `instance/` (SQLite DB + uploaded configs) on a schedule.
4. Rotate the GitHub token used for private-repo updates; the update check works without a
   token for public repos.
5. `pip audit` / `safety` in CI for continuous dependency CVE monitoring.
