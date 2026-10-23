"""Shared infrastructure: database, CSRF, rate limiting, bot check, sealing and auditing."""

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet
from flask import abort, current_app, render_template, request, session

DB_PATH = Path(os.environ.get("AUTH_DB", "auth.sqlite3")).expanduser().resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    mfa_secret_enc TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_last_counter INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket TEXT NOT NULL,
    client_hash TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    hits INTEGER NOT NULL,
    PRIMARY KEY (bucket, client_hash)
);
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    answer_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_hash TEXT,
    redirect_uris TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('approved', 'revoked')),
    scopes TEXT NOT NULL,
    origin TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (user_id, client_id)
);
CREATE TABLE IF NOT EXISTS connection_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'declined')),
    created_at INTEGER NOT NULL,
    decided_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_requests_user ON connection_requests(user_id, status);
CREATE TABLE IF NOT EXISTS service_data (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    data_key TEXT NOT NULL,
    content_type TEXT NOT NULL,
    body BLOB NOT NULL,
    size INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id, data_key)
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    nonce TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    auth_time INTEGER NOT NULL,
    amr TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    private_key_enc TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
"""

# Columns added after the first release; applied to existing databases.
MIGRATIONS = {
    "users": {
        "mfa_secret_enc": "TEXT",
        "mfa_enabled": "INTEGER NOT NULL DEFAULT 0",
        "mfa_last_counter": "INTEGER NOT NULL DEFAULT -1",
    },
    "connection_requests": {
        # Service callbacks: pinged by Local Auth when the user accepts or declines.
        "done_url": "TEXT NOT NULL DEFAULT ''",
        "deny_url": "TEXT NOT NULL DEFAULT ''",
        "callback_status": "TEXT NOT NULL DEFAULT ''",  # '', 'delivered' or 'failed'
        "callback_at": "INTEGER",
    },
}


def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 10000")
    db.execute("PRAGMA foreign_keys = ON")
    return db


@contextmanager
def db_conn():
    """Open a connection, commit on success, roll back on error, always close."""
    db = connect_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    db = connect_db()
    try:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(SCHEMA)
        for table, columns in MIGRATIONS.items():
            existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in existing:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------- crypto helpers

def keyed_hash(text, purpose="generic"):
    """HMAC-SHA256 keyed by the app secret. Used for codes, secrets and fingerprints."""
    return hmac.new(
        current_app.secret_key.encode(), f"{purpose}:{text}".encode(), hashlib.sha256
    ).hexdigest()


def _fernet():
    digest = hashlib.sha256(b"seal-v1:" + current_app.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal(text):
    """Encrypt a secret value before it is written to the database."""
    return _fernet().encrypt(text.encode()).decode()


def unseal(token):
    return _fernet().decrypt(token.encode()).decode()


def ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    supplied = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        abort(400, "The form expired or was invalid. Please reload and try again.")


# ---------------------------------------------------------------- rate limiting

def rate_limit(bucket, limit, seconds, key=None):
    """SQLite fixed-window limiter; returns seconds to wait, or zero.

    `key` defaults to a keyed hash of the client IP. Pass another identifier
    (for example an OAuth client ID) to limit that identity instead.
    """
    now = int(time.time())
    window_start = now - (now % seconds)
    if key is None:
        key = request.remote_addr or "unknown"
    client_hash = keyed_hash(key, purpose=f"rl:{bucket}")
    with db_conn() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT window_start, hits FROM rate_limits WHERE bucket = ? AND client_hash = ?",
            (bucket, client_hash),
        ).fetchone()
        if row is None or row["window_start"] != window_start:
            db.execute(
                "INSERT INTO rate_limits(bucket, client_hash, window_start, hits) VALUES (?, ?, ?, 1) "
                "ON CONFLICT(bucket, client_hash) DO UPDATE SET window_start=excluded.window_start, hits=1",
                (bucket, client_hash, window_start),
            )
            wait = 0
        elif row["hits"] >= limit:
            wait = seconds - (now - window_start)
        else:
            db.execute(
                "UPDATE rate_limits SET hits = hits + 1 WHERE bucket = ? AND client_hash = ?",
                (bucket, client_hash),
            )
            wait = 0
        db.execute("DELETE FROM rate_limits WHERE window_start < ?", (now - 2 * 24 * 60 * 60,))
    return wait


def enforce_rate_limit(bucket, limit, seconds, key=None):
    wait = rate_limit(bucket, limit, seconds, key)
    if wait:
        abort(429, f"Too many requests. Try again in about {wait} seconds.")


# ---------------------------------------------------------------- local bot check

def new_challenge():
    first, second = secrets.randbelow(8) + 2, secrets.randbelow(8) + 2
    challenge_id = secrets.token_urlsafe(24)
    answer = str(first + second)
    answer_hash = keyed_hash(f"{challenge_id}:{answer}", purpose="challenge")
    now = int(time.time())
    with db_conn() as db:
        db.execute("DELETE FROM challenges WHERE expires_at < ?", (now,))
        db.execute(
            "INSERT INTO challenges(id, answer_hash, expires_at) VALUES (?, ?, ?)",
            (challenge_id, answer_hash, now + 10 * 60),
        )
    return {"challenge_id": challenge_id, "question": f"What is {first} + {second}?"}


def verify_challenge():
    challenge_id = request.form.get("challenge_id", "")
    answer = request.form.get("challenge_answer", "").strip()
    if not challenge_id or len(challenge_id) > 100 or len(answer) > 20:
        return False
    now = int(time.time())
    with db_conn() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT answer_hash, expires_at FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        db.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
    if row is None or row["expires_at"] < now:
        return False
    submitted = keyed_hash(f"{challenge_id}:{answer}", purpose="challenge")
    return hmac.compare_digest(submitted, row["answer_hash"])


def bot_check():
    return not request.form.get("website", "").strip() and verify_challenge()


# ---------------------------------------------------------------- users and audit

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db_conn() as db:
        return db.execute(
            "SELECT id, username, display_name, created_at, mfa_enabled FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def require_user():
    user = current_user()
    if not user:
        abort(403, "Please sign in first.")
    return user


def audit(db, user_id, event, detail=""):
    db.execute(
        "INSERT INTO audit_events(user_id, event, detail, created_at) VALUES (?, ?, ?, ?)",
        (user_id, event, detail[:500], int(time.time())),
    )


def safe_next(target):
    """Only allow same-site relative redirects after sign-in."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


def render_page(template, title, **context):
    """Render a page with the shared context (current user and CSRF token)."""
    ensure_csrf()
    context.setdefault("user", current_user())
    return render_template(template, title=title, csrf=session.get("csrf", ""), **context)
