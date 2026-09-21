#!/usr/bin/env python3
"""NetAI development entry point. Production uses gunicorn (see wsgi.py)."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=app.config["PORT"], debug=False)  # nosec B104 - server must listen for external access
