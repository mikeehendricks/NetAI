#!/usr/bin/env bash
# fix-deps.sh — bring the NetAI venv up to the patched dependency floors
# (remediates the 14 OSV/SkillsLLM advisories: Flask CVE-2026-27205,
# requests CVE-2024-35195/CVE-2024-47081/CVE-2026-25645, python-dotenv
# CVE-2026-28684, gunicorn CVE-2024-1135/CVE-2024-6827).
#
#   sudo bash /opt/netai/scripts/fix-deps.sh
#
# Works WITHOUT pypi.org (blocked networks): tries pypi/proxy first, then
# falls back to this project's GitHub release that carries a prebuilt
# pure-Python wheel bundle, then to a local $APP_DIR/wheels folder.
# Idempotent: exits 0 immediately when everything is already compliant.
set -uo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
REQ="$APP_DIR/requirements.txt"
WHEELS_URL="${NETAI_WHEELS_URL:-https://github.com/mikeehendricks/NetAI/releases/download/wheels-v1/wheels-linux-any.tar.gz}"
WORK="${TMPDIR:-/var/tmp}/netai-fix-deps"

say()  { echo "[fix-deps] $*"; }
fail() { echo "[fix-deps] ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root: sudo bash $0"
[ -f "$REQ" ] || fail "$REQ not found - is NetAI installed at $APP_DIR?"

PY="$APP_DIR/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
[ -x "$PY" ] || fail "no python found"
[ -x "$APP_DIR/.venv/bin/pip" ] && PIP="$APP_DIR/.venv/bin/pip" || PIP="$PY -m pip"

# ---------------------------------------------------------------- floors
# package | minimum patched version
FLOORS="flask=3.1.3
requests=2.33.0
python-dotenv=1.2.2
gunicorn=22.0.0"

ver_ge() { # ver_ge <installed> <floor>  -> 0 if installed >= floor
  [ "$(python3 - "$1" "$2" <<'PY'
import sys
v = [int(x) for x in sys.argv[1].split(".") if x.isdigit()]
f = [int(x) for x in sys.argv[2].split(".") if x.isdigit()]
n = max(len(v), len(f))
v += [0] * (n - len(v)); f += [0] * (n - len(f))
print("y" if v >= f else "n")
PY
)" = "y" ]
}

cur() { "$PY" -c "import importlib.metadata as m; print(m.version('$1'))" 2>/dev/null; }

check_all() { # prints "pkg floor ok|VULNERABLE(installed)" per line; returns 0 iff all ok
  local bad=0 line pkg floor have
  while IFS= read -r line; do
    pkg="${line%%=*}"; floor="${line#*=}"
    have="$(cur "$pkg")"
    if [ -z "$have" ]; then
      echo "$pkg $floor MISSING"; bad=1
    elif ver_ge "$have" "$floor"; then
      echo "$pkg $floor ok($have)"
    else
      echo "$pkg $floor VULNERABLE($have)"; bad=1
    fi
  done <<< "$FLOORS"
  return $bad
}

echo
say "checking installed dependency versions against patched floors..."
COMPLIANT=0; DETAIL="$(check_all)" || COMPLIANT=1
echo "$DETAIL" | sed 's/^/[fix-deps]   /'

if [ "$COMPLIANT" -eq 0 ]; then
  say "all dependencies are already at or above the patched floors - nothing to do."
  exit 0
fi

# python < 3.10 cannot run requests>=2.33: fall back to 2.32.4 (fixes 2 of the
# 3 requests advisories) instead of failing the whole remediation
if [ "$("$PY" -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')" != "1" ]; then
  say "python < 3.10 detected - using requests 2.32.4 (2.33 needs python>=3.10)"
  REQ_WORK="$WORK/requirements.txt"; mkdir -p "$WORK"
  sed -E 's/requests[>=<!~0-9.]+/requests==2.32.4/' "$REQ" > "$REQ_WORK"
  REQ="$REQ_WORK"
fi

# ---------------------------------------------------------------- pip ladder
PIPFLAGS="--disable-pip-version-check --quiet"

try_install() { # try_install <mode>
  case "$1" in
    pypi)
      $PIP install $PIPFLAGS --retries 1 --timeout 20 -r "$REQ" ;;
    wheels_dir)
      [ -d "$APP_DIR/wheels" ] && ls "$APP_DIR"/wheels/*.whl >/dev/null 2>&1 || return 1
      $PIP install $PIPFLAGS --no-index --find-links "$APP_DIR/wheels" -r "$REQ" ;;
    release)
      rm -rf "$WORK"; mkdir -p "$WORK"
      say "downloading the prebuilt wheel bundle from the NetAI GitHub release..."
      # cache-buster: release assets are CDN-cached; republished bundles must arrive
      curl -fsSL --retry 2 --retry-delay 2 -m 300 \
        -o "$WORK/wheels.tar.gz" "$WHEELS_URL?cb=$RANDOM$RANDOM$RANDOM" || return 1
      tar -C "$WORK" -xzf "$WORK/wheels.tar.gz" || return 1
      $PIP install $PIPFLAGS --no-index --find-links "$WORK/wheels" -r "$REQ" ;;
  esac
}

# corporate proxy support: export proxy vars from .env if present
if [ -f "$APP_DIR/.env" ]; then
  for var in https_proxy http_proxy no_proxy; do
    val="$(grep -E "^$var=" "$APP_DIR/.env" | tail -1 | cut -d= -f2- | tr -d '\"')"
    [ -n "$val" ] && export "$var=$val"
  done
fi

INSTALLED=""
if [ "${NETAI_FORCE_OFFLINE:-0}" != "1" ]; then
  say "attempt 1/3: install via pypi (or the proxy configured in .env)..."
  if try_install pypi; then INSTALLED="pypi"; fi
fi
if [ -z "$INSTALLED" ]; then
  say "attempt 2/3: install offline from the NetAI GitHub release wheel bundle..."
  if try_install release; then INSTALLED="release"; fi
fi
if [ -z "$INSTALLED" ]; then
  say "attempt 3/3: install offline from $APP_DIR/wheels (if you placed wheels there)..."
  if try_install wheels_dir; then INSTALLED="wheels_dir"; fi
fi

if [ -z "$INSTALLED" ]; then
  cat <<EOF
[fix-deps] ERROR: could not install the patched dependencies automatically.

  Last resort (fully manual): on any internet-connected machine run
      pip download -r requirements.txt -d wheels/
  copy that wheels/ folder next to this script's app dir:
      scp -r wheels/ root@SERVER-IP:$APP_DIR/wheels/
  then run on this server:
      $PIP install --no-index --find-links $APP_DIR/wheels -r $REQ
      sudo systemctl restart netai
EOF
  exit 1
fi
say "dependencies installed via: $INSTALLED"

# ---------------------------------------------------------------- verify
say "verifying..."
FINAL="$(check_all)" || { echo "$FINAL" | sed 's/^/[fix-deps]   /'; fail "some dependencies are still below the patched floors - see above."; }
echo "$FINAL" | sed 's/^/[fix-deps]   /'

if [ -d /run/systemd/system ] && systemctl cat netai >/dev/null 2>&1; then
  say "restarting netai to load the patched libraries..."
  systemctl restart netai && say "netai restarted"
else
  say "NOTE: restart the NetAI service manually: sudo systemctl restart netai"
fi
say "DONE - all dependency vulnerabilities remediated."
exit 0
