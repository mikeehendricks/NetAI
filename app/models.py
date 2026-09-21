"""Database models."""
import datetime as dt
import secrets

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Engine, Index, event
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _rec):
    """SQLite tuning: WAL journal + NORMAL sync for concurrent reads/writes."""
    import sqlite3

    if isinstance(dbapi_conn, sqlite3.Connection):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), default="user", nullable=False)  # user | admin
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    must_reset = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime(timezone=True))
    last_ip = db.Column(db.String(64))
    last_city = db.Column(db.String(128))
    last_country = db.Column(db.String(128))
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True))

    projects = db.relationship("Project", backref="owner", lazy="dynamic")

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, pw):
        try:
            return check_password_hash(self.password_hash, pw)
        except Exception:
            return False

    @property
    def is_locked(self):
        lu = self.locked_until
        if not lu:
            return False
        if lu.tzinfo is None:          # sqlite returns naive UTC
            lu = lu.replace(tzinfo=dt.timezone.utc)
        return lu > utcnow()

    def to_dict(self):
        return dict(
            id=self.id, username=self.username, role=self.role, active=self.is_active,
            created=self.created_at.isoformat() if self.created_at else None,
            last_login=self.last_login_at.isoformat() if self.last_login_at else None,
            ip=self.last_ip, city=self.last_city, country=self.last_country,
        )


class LoginEvent(db.Model):
    __tablename__ = "login_events"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    username = db.Column(db.String(64), index=True)
    success = db.Column(db.Boolean, nullable=False)
    ip = db.Column(db.String(64), index=True)
    user_agent = db.Column(db.String(256))
    city = db.Column(db.String(128))
    region = db.Column(db.String(128))
    country = db.Column(db.String(128))
    lat = db.Column(db.Float)
    lon = db.Column(db.Float)
    ts = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)

    __table_args__ = (Index("ix_login_ts_user", "ts", "user_id"),)


class Heartbeat(db.Model):
    """Per-session presence for the realtime admin view."""
    __tablename__ = "heartbeats"
    session_id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ip = db.Column(db.String(64), index=True)
    user_agent = db.Column(db.String(256))
    last_seen = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    # geo resolved lazily
    city = db.Column(db.String(128))
    region = db.Column(db.String(128))
    country = db.Column(db.String(128))
    lat = db.Column(db.Float)
    lon = db.Column(db.Float)
    geo_pending = db.Column(db.Boolean, default=True, nullable=False)


class Project(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    grade = db.Column(db.String(2), default="A")
    findings_json = db.Column(db.Text, default="[]")     # list of finding dicts
    devices_json = db.Column(db.Text, default="[]")      # parsed device inventory
    summary_json = db.Column(db.Text, default="{}")      # exec summary data
    ai_enhanced = db.Column(db.Boolean, default=False)

    files = db.relationship(
        "ConfigFile", backref="project", lazy="joined", cascade="all, delete-orphan"
    )

    @property
    def findings(self):
        import json

        return json.loads(self.findings_json or "[]")

    @property
    def devices(self):
        import json

        return json.loads(self.devices_json or "[]")

    @property
    def summary(self):
        import json

        return json.loads(self.summary_json or "{}")


class ConfigFile(db.Model):
    __tablename__ = "config_files"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    orig_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)   # uuid-based, on disk
    vendor = db.Column(db.String(32), default="unknown")
    hostname = db.Column(db.String(128), default="")
    size = db.Column(db.Integer, default=0)
    sha256 = db.Column(db.String(64), default="")
    device_json = db.Column(db.Text, default="{}")            # parsed device model
    topo_json = db.Column(db.Text, default="{}")              # nodes/edges contributed

    @property
    def device(self):
        import json

        return json.loads(self.device_json or "{}")


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(256))

    @classmethod
    def get(cls, key, default=None):
        row = db.session.get(cls, key)
        return row.value if row else default

    @classmethod
    def put(cls, key, value):
        row = db.session.get(cls, key)
        if row:
            row.value = str(value)
        else:
            db.session.add(cls(key=key, value=str(value)))


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(64), index=True)
    action = db.Column(db.String(128))
    detail = db.Column(db.String(512))
    ip = db.Column(db.String(64))
    ts = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)


def gen_tmp_password(n=16):
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%*-+?"
    return "".join(secrets.choice(alphabet) for _ in range(n))
