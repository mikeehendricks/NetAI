# Security Policy

## Reporting

Please open a GitHub issue for non-sensitive issues. For sensitive disclosures contact the
repository owner directly.

## Built-in protections

- One-time administrator setup (installer-generated key, burned after use)
- CSRF tokens on all state-changing requests + Origin checking
- Session cookies: HttpOnly, SameSite=Lax, signed with a server-generated SECRET_KEY;
  Secure flag when `HTTPS_ONLY=1`
- Login lockout (5 attempts / 15 min) and sliding-window IP rate limits
- Strict Content-Security-Policy (no inline JavaScript anywhere)
- Role-based access control (user / admin) with server-side enforcement
- Parameterized SQL (SQLAlchemy ORM), HTML auto-escaping (Jinja2), defusedxml for uploads
- Upload validation: extension allow-list, size cap, binary sniffing, sanitized storage
- Audit log of administrative actions
- Hardened systemd unit (dedicated no-login user, NoNewPrivileges, ProtectSystem) and a
  sudoers rule limited to the app's own update script

## Deployment hardening checklist

1. Terminate TLS at nginx/Caddy and set `HTTPS_ONLY=1` (HSTS + Secure cookies).
2. Set `TRUST_PROXY=1` **only** when behind your reverse proxy.
3. Keep the server patched: `sudo apt update && sudo apt upgrade`.
4. Restrict database/uploads: `chmod 700 /opt/netai/instance` (installer does this).
5. Back up `instance/netai.db` regularly; it contains user hashes and analysis history.
6. Never reuse a GitHub token across systems; scope it to this repository only.
7. Review `/admin/audit` and `/admin/live` periodically.

## Known limitations

- The realtime location feature uses the free ip-api.com endpoint (HTTP, 45 req/min);
  self-host it or use a licensed feed for strict privacy environments
  (`GEOIP_URL` is configurable, `GEOIP_ENABLED=0` disables lookups).
- SQLite is ideal up to a few dozen concurrent users; use `DATABASE_URL` with PostgreSQL
  for larger deployments.
