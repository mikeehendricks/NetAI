"""NetAI configuration — all runtime settings come from environment / .env file."""
import os
import secrets
import sys
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

# Load .env from the app root (installer writes it there)
load_dotenv(BASE_DIR / ".env")
load_dotenv(INSTANCE_DIR / ".env")  # fallback


def _env(name, default=None):
    return os.environ.get(name, default)


def _bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


# Human-readable application version. Bump on every release; shown in the site
# footer, on the admin update page, and stamped into error reports.
APP_VERSION = "1.2.0"

class Config:
    SECRET_KEY = _env("SECRET_KEY")
    if not SECRET_KEY:
        # Dev/bootstrap fallback: persist a random key so sessions survive restarts.
        keyfile = INSTANCE_DIR / ".secret_key"
        if keyfile.exists():
            SECRET_KEY = keyfile.read_text().strip()
        else:
            SECRET_KEY = secrets.token_hex(32)
            try:
                keyfile.write_text(SECRET_KEY)
                keyfile.chmod(0o600)
            except OSError:
                pass
        if keyfile.exists():
            sys.stderr.write("NetAI: WARNING - SECRET_KEY not set, using generated instance key.\n")

    SQLALCHEMY_DATABASE_URI = _env("DATABASE_URL", "sqlite:///" + str(INSTANCE_DIR / "netai.db"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Uploads / analysis
    UPLOAD_FOLDER = str(INSTANCE_DIR / "uploads")
    MAX_CONTENT_LENGTH = int(_env("MAX_UPLOAD_MB", "25")) * 1024 * 1024
    ALLOWED_UPLOAD_EXT = {".txt", ".cfg", ".conf", ".running", ".xml", ".set", ".log", ""}
    MAX_UPLOAD_FILES = 20

    # Site
    SITE_NAME = _env("SITE_NAME", "NetAI")
    SITE_VERSION = _env("SITE_VERSION", "")          # filled from git at runtime
    GITHUB_REPO = _env("GITHUB_REPO", "mikeehendricks/NetAI")
    GITHUB_BRANCH = _env("GITHUB_BRANCH", "main")
    GITHUB_TOKEN = _env("GITHUB_TOKEN", "")          # optional, only for private repos
    UPDATE_SCRIPT = _env("UPDATE_SCRIPT", str(BASE_DIR / "scripts" / "update.sh"))

    # Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("HTTPS_ONLY", False)   # enable behind TLS termination
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8             # 8h
    TRUST_PROXY = _bool("TRUST_PROXY", False)            # trust X-Forwarded-* (behind reverse proxy)
    ALLOW_SIGNUP_DEFAULT = _bool("ALLOW_SIGNUP", True)
    HTTPS_ONLY = _bool("HTTPS_ONLY", False)

    # GeoIP (realtime visitor location for /admin) - ip-api.com free endpoint
    GEOIP_URL = _env("GEOIP_URL", "http://ip-api.com/json/{ip}")
    GEOIP_ENABLED = _bool("GEOIP_ENABLED", True)

    # Optional AI (LLM) enhancement of executive summaries.
    # Leave empty to use the built-in deterministic engine only.
    AI_PROVIDER = _env("AI_PROVIDER", "")                # "", "openai", "anthropic", "custom"
    OPENAI_API_KEY = _env("OPENAI_API_KEY", "")
    OPENAI_BASE_URL = _env("OPENAI_BASE_URL", "https://api.openai.com/v1")
    OPENAI_MODEL = _env("OPENAI_MODEL", "gpt-4o-mini")
    ANTHROPIC_API_KEY = _env("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = _env("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    # Login hardening
    LOGIN_MAX_ATTEMPTS = int(_env("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_SECONDS = int(_env("LOGIN_LOCKOUT_SECONDS", "900"))
    RATE_LIMIT_GET = (int(_env("RL_GET_N", "240")), int(_env("RL_GET_WIN", "60")))    # per IP/min
    RATE_LIMIT_POST = (int(_env("RL_POST_N", "40")), int(_env("RL_POST_WIN", "60")))
    RATE_LIMIT_LOGIN = (int(_env("RL_LOGIN_N", "10")), int(_env("RL_LOGIN_WIN", "60")))

    PORT = int(_env("PORT", "8000"))
