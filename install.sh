#!/usr/bin/env bash
# =============================================================================
#  NetAI installer for Ubuntu Server (20.04 / 22.04 / 24.04)
#
#  Usage:
#    sudo bash install.sh                       # install from GitHub to /opt/netai
#    sudo bash install.sh --port 8080           # custom port
#    sudo bash install.sh --dir /srv/netai      # custom directory
#    sudo bash install.sh --repo owner/NetAI    # custom GitHub repo
#    sudo bash install.sh --local               # install from the current directory
#
#  What it does:
#    1. installs system dependencies (python3, venv, git, curl)
#    2. clones the NetAI repository (or copies the local tree)
#    3. creates an isolated virtualenv and installs Python dependencies
#    4. generates a secret key + a ONE-TIME admin setup key
#    5. creates a locked-down systemd service (dedicated system user)
#    6. grants the service a passwordless sudo rule ONLY for its update script
#    7. starts the site and prints the admin setup instructions
# =============================================================================
set -euo pipefail

REPO="${NETAI_REPO:-mikeehendricks/NetAI}"
BRANCH="${NETAI_BRANCH:-main}"
APP_DIR="/opt/netai"
PORT="8000"
SERVICE_USER="netai"
FROM_LOCAL=0
WITH_NGINX=0

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
say()  { echo -e "${CYAN}[netai]${NC} $*"; }
ok()   { echo -e "${GREEN}[ ok ]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
die()  { echo -e "${RED}[fail]${NC} $*"; exit 1; }

# ---------------------------------------------------------------- parse args
while [ $# -gt 0 ]; do
  case "$1" in
    --port)   PORT="$2"; shift 2 ;;
    --dir)    APP_DIR="$2"; shift 2 ;;
    --repo)   REPO="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --local)  FROM_LOCAL=1; shift ;;
    --with-nginx) WITH_NGINX=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# ---------------------------------------------------------------- pre-flight
[ "$(id -u)" -eq 0 ] || die "run with sudo:  sudo bash install.sh"
. /etc/os-release 2>/dev/null || true
case "${ID:-ubuntu}" in
  ubuntu|debian) ok "detected ${PRETTY_NAME:-debian-like}" ;;
  *) warn "unsupported distro '${ID:-?}' — continuing, but this installer targets Ubuntu." ;;
esac

say "installing system packages (python3, venv, git, curl)..."
export DEBIAN_FRONTEND=noninteractive

APT_PKGS="python3 python3-venv python3-pip git curl"

# Corporate networks often route apt through a filtering proxy/IPS that can 403 package
# downloads — detect and warn up front so failures are easy to diagnose.
if grep -rqiE 'Acquire::.*(Proxy|Mirror)' /etc/apt/apt.conf.d/ /etc/apt/apt.conf 2>/dev/null; then
  warn "apt proxy/mirror config detected in /etc/apt/apt.conf.d/ — if downloads fail with"
  warn "403/blocked errors, that appliance must allowlist archive.ubuntu.com and security.ubuntu.com"
fi

apt_ok=0
for attempt in 1 2 3; do
  if apt-get update -qq && apt-get install -y -qq --fix-missing $APT_PKGS >/dev/null; then
    apt_ok=1
    break
  fi
  warn "apt attempt ${attempt}/3 failed — retrying..."
  sleep 3
  apt-get update -qq
done

if [ "$apt_ok" != "1" ]; then
  echo -e "${RED}[fail]${NC} could not install packages via apt." >&2
  echo -e "       The download is most likely being blocked by a network proxy/firewall" >&2
  echo -e "       (look for '403 Forbidden' and an internal IP in the apt error above)." >&2
  echo -e "       Fix options:" >&2
  echo -e "         1. ask your network team to allowlist archive.ubuntu.com + security.ubuntu.com" >&2
  echo -e "         2. check/fix the proxy in /etc/apt/apt.conf.d/ (grep -ri proxy /etc/apt/apt.conf.d/)" >&2
  echo -e "         3. switch apt sources to an internal Ubuntu mirror" >&2
  echo -e "       Then run the failing command manually:" >&2
  echo -e "           sudo apt update && sudo apt install -y --fix-missing $APT_PKGS" >&2
  echo -e "       and re-run this installer — it resumes where it left off." >&2
  exit 1
fi
ok "system packages installed"

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
python3 - "$PYVER" <<'EOF' || die "python3 >= 3.9 required"
import sys
v = tuple(int(x) for x in sys.argv[1].split("."))
sys.exit(0 if v >= (3, 9) else 1)
EOF
ok "python3 $PYVER"

# ---------------------------------------------------------------- app source
if [ "$FROM_LOCAL" = "1" ]; then
  SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  [ -f "$SRC_DIR/wsgi.py" ] || die "--local used but wsgi.py not found next to install.sh"
  mkdir -p "$APP_DIR"
  rsync -a --exclude instance --exclude .venv --exclude .git "$SRC_DIR"/ "$APP_DIR"/ 2>/dev/null \
    || cp -r "$SRC_DIR/." "$APP_DIR/"
  ok "copied local tree into $APP_DIR"
else
  if [ -d "$APP_DIR/.git" ]; then
    say "$APP_DIR already exists — pulling latest..."
    git -C "$APP_DIR" fetch origin "$BRANCH" --quiet
    git -C "$APP_DIR" reset --hard "origin/$BRANCH" --quiet
  else
    say "cloning https://github.com/$REPO (branch $BRANCH)..."
    rm -rf "$APP_DIR"
    git clone --depth 1 -b "$BRANCH" "https://github.com/$REPO.git" "$APP_DIR"
  fi
  ok "source ready in $APP_DIR"
fi
cd "$APP_DIR"

# ---------------------------------------------------------------- python env
say "creating virtualenv and installing Python dependencies..."
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
ok "python environment ready"

# ---------------------------------------------------------------- secrets
mkdir -p instance
chmod 700 instance
if [ ! -f .env ]; then
  SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  cat > .env <<EOF
SECRET_KEY=$SECRET
PORT=$PORT
GITHUB_REPO=$REPO
GITHUB_BRANCH=$BRANCH
TRUST_PROXY=0
HTTPS_ONLY=0
ALLOW_SIGNUP=1
EOF
  chmod 600 .env
  ok "generated .env with a fresh SECRET_KEY"
else
  warn "existing .env kept (set PORT=$PORT manually if needed)"
fi

SETUP_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
echo "$SETUP_KEY" > instance/SETUP_KEY
chmod 600 instance/SETUP_KEY
ok "generated ONE-TIME admin setup key"

# ---------------------------------------------------------------- service user
if id "$SERVICE_USER" &>/dev/null; then
  ok "system user '$SERVICE_USER' exists"
else
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "created system user '$SERVICE_USER' (no login shell)"
fi
chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR"
chmod 750 "$APP_DIR"

# sudoers: the service user may ONLY run the app's own update script as root
SUDOERS_FILE="/etc/sudoers.d/netai-update"
cat > "$SUDOERS_FILE" <<EOF
$SERVICE_USER ALL=(root) NOPASSWD: $APP_DIR/scripts/update.sh
EOF
chmod 440 "$SUDOERS_FILE"
visudo -c -f "$SUDOERS_FILE" >/dev/null || { rm -f "$SUDOERS_FILE"; die "sudoers validation failed"; }
ok "sudoers rule installed (update only, no shell)"

# ---------------------------------------------------------------- systemd unit
cat > /etc/systemd/system/netai.service <<EOF
[Unit]
Description=NetAI - AI network configuration analysis
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/.venv/bin:/usr/local/bin:/usr/bin:/bin
Environment=NETAI_DIR=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/.venv/bin/gunicorn --workers 2 --threads 4 --timeout 60 \
    --bind 0.0.0.0:${PORT} --access-logfile - --error-logfile - wsgi:app
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$APP_DIR/instance

[Install]
WantedBy=multi-user.target
EOF
chmod 640 "$APP_DIR/scripts/update.sh"
systemctl daemon-reload
systemctl enable --now netai.service
sleep 2
systemctl is-active --quiet netai && ok "netai service is running" || { journalctl -u netai -n 30 --no-pager; die "service failed to start"; }

# ---------------------------------------------------------------- firewall (best effort)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" >/dev/null 2>&1 && ok "ufw: allowed port $PORT" || warn "could not open ufw port"
fi

# ---------------------------------------------------------------- optional nginx
if [ "$WITH_NGINX" = "1" ]; then
  apt-get install -y -qq nginx >/dev/null
  cat > /etc/nginx/sites-available/netai <<EOF
server {
    listen 80;
    server_name _;
    client_max_body_size 30m;
    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/netai /etc/nginx/sites-enabled/netai
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 && systemctl reload nginx && ok "nginx reverse proxy configured (set TRUST_PROXY=1 in .env)" \
    || warn "nginx config failed - check manually"
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-<server-ip>}
echo
echo -e "${GREEN}==============================================================${NC}"
echo -e "${GREEN}  NetAI installed successfully!${NC}"
echo -e "${GREEN}==============================================================${NC}"
echo -e "  URL:          ${CYAN}http://${IP}:${PORT}${NC}"
echo
echo -e "  ONE-TIME ADMIN SETUP (do this now):"
echo -e "    1. open ${CYAN}http://${IP}:${PORT}/setup${NC}"
echo -e "    2. paste this setup key (also stored in ${YELLOW}$APP_DIR/instance/SETUP_KEY${NC}, root-only):"
echo
echo -e "        ${YELLOW}${SETUP_KEY}${NC}"
echo
echo -e "    3. choose the admin username/password -> the key is then burned"
echo -e "       and the /setup page is permanently disabled."
echo
echo -e "  Service:      systemctl {status|restart|stop} netai"
echo -e "  Logs:         journalctl -u netai -f"
echo -e "  Update site:  sign in as admin -> Admin -> Update -> 'Install update'"
echo -e "  Uninstall:    sudo bash $APP_DIR/uninstall.sh"
echo -e "${GREEN}==============================================================${NC}"
