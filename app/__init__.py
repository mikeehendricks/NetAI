"""NetAI — AI-assisted network configuration analysis platform."""
import logging
from pathlib import Path

from flask import Flask, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config

log = logging.getLogger("netai")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

db_module_import_fix = Path(__file__).parent / "models.py"  # ensure included in packaging


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    from .models import db
    db.init_app(app)
    with app.app_context():
        db.create_all()

    if app.config.get("TRUST_PROXY"):
        # Behind a reverse proxy (nginx / preview proxy): derive real client IP.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # ------------------------------------------------------------------ security headers
    @app.after_request
    def set_security_headers(resp):
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'",
        )
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if app.config.get("HTTPS_ONLY"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # lightweight gzip for text responses
        if (
            not resp.direct_passthrough
            and resp.status_code == 200
            and (resp.mimetype or "").startswith(("text/", "application/json"))
            and 500 < resp.calculate_content_length() < 5 * 1024 * 1024
        ):
            import gzip as _gz

            accept = request.headers.get("Accept-Encoding", "")
            if "gzip" in accept and "Content-Encoding" not in resp.headers:
                resp.set_data(_gz.compress(resp.get_data(), compresslevel=6))
                resp.headers["Content-Encoding"] = "gzip"
                resp.headers["Content-Length"] = str(len(resp.get_data()))
                resp.headers.add("Vary", "Accept-Encoding")
        return resp

    # ------------------------------------------------------------------ session + rate limit hooks
    from .security import rate_limit, touch_session

    @app.before_request
    def _hooks():
        touch_session()
        verdict = rate_limit()
        if verdict is not None:
            return verdict

    from . import geo  # noqa: F401  (registers background geo resolution)

    # ------------------------------------------------------------------ blueprints
    from .auth import bp as auth_bp
    from .main import bp as main_bp
    from .admin import bp as admin_bp
    from .api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api")

    # runtime version stamp (git describe) for the admin update page
    try:
        import subprocess  # nosec B404 - fixed argv, no user input

        sha = subprocess.run(  # nosec B603, B607 - fixed argv 'git rev-parse', no user input
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(Path(__file__).resolve().parent.parent),
            capture_output=True, text=True, timeout=5,
        )
        if sha.returncode == 0:
            app.config["SITE_VERSION"] = sha.stdout.strip()
    except Exception as e:
        log.debug("version stamp failed: %s", e)

    return app
