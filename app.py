import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "Set FLASK_SECRET_KEY before starting the app. Generate one with: "
        "python -c 'import secrets; print(secrets.token_hex(32))'"
    )
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=16 * 1024,
)

DB_PATH = Path(os.environ.get("AUTH_DB", "auth.sqlite3")).expanduser().resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 10000")
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
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
            """
        )


init_db()


def render_page(template, title, **context):
    ensure_csrf()
    return render_template(
        template,
        title=title,
        user=current_user(),
        csrf=session.get("csrf", ""),
        **context,
    )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with connect_db() as db:
        return db.execute(
            "SELECT id, username, display_name, created_at FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    supplied = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        abort(400, "The form expired or was invalid. Please reload and try again.")


def ip_fingerprint():
    # Do not trust X-Forwarded-For unless a trusted proxy is explicitly configured.
    address = request.remote_addr or "unknown"
    return hmac.new(app.secret_key.encode(), address.encode(), hashlib.sha256).hexdigest()


def rate_limit(bucket, limit, seconds):
    """SQLite fixed-window limiter; returns seconds to wait, or zero."""
    now = int(time.time())
    window_start = now - (now % seconds)
    client_hash = ip_fingerprint()
    with connect_db() as db:
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
        db.commit()
    return wait


def enforce_rate_limit(bucket, limit, seconds):
    wait = rate_limit(bucket, limit, seconds)
    if wait:
        abort(429, f"Too many requests. Try again in about {wait} seconds.")


def new_challenge():
    first, second = secrets.randbelow(8) + 2, secrets.randbelow(8) + 2
    challenge_id = secrets.token_urlsafe(24)
    answer = str(first + second)
    answer_hash = hmac.new(
        app.secret_key.encode(), f"{challenge_id}:{answer}".encode(), hashlib.sha256
    ).hexdigest()
    now = int(time.time())
    with connect_db() as db:
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
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT answer_hash, expires_at FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        db.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
        db.commit()
    if row is None or row["expires_at"] < now:
        return False
    submitted_hash = hmac.new(
        app.secret_key.encode(), f"{challenge_id}:{answer}".encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(submitted_hash, row["answer_hash"])


def bot_check():
    return not request.form.get("website", "").strip() and verify_challenge()


def get_user_id(username):
    with connect_db() as db:
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        return row["id"] if row else None


@app.before_request
def prepare_session():
    ensure_csrf()


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(400)
@app.errorhandler(429)
def handle_client_error(error):
    return render_page("error.html", "Request error", message=error.description), error.code


@app.route("/")
def home():
    return render_page("home.html", "Home")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        enforce_rate_limit("register", 5, 60 * 60)
        check_csrf()
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not bot_check():
            error = "The bot check was incorrect or expired. Please try again."
        elif not USERNAME_RE.fullmatch(username):
            error = "Use a username of 3–32 letters, numbers, dots, underscores, or hyphens."
        elif not display_name or len(display_name) > 60:
            error = "Display name must be between 1 and 60 characters."
        elif len(password) < 12 or len(password) > 128:
            error = "Use a password between 12 and 128 characters."
        elif password != confirm:
            error = "The passwords did not match."
        else:
            try:
                with connect_db() as db:
                    db.execute(
                        "INSERT INTO users(username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                        (username, display_name, generate_password_hash(password), int(time.time())),
                    )
                session.clear()
                session["user_id"] = get_user_id(username)
                ensure_csrf()
                session.permanent = True
                flash("Your account was created.")
                return redirect(url_for("account"))
            except sqlite3.IntegrityError:
                error = "That username may already be in use. Try another."
    return render_page("register.html", "Create account", error=error, challenge=new_challenge())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        enforce_rate_limit("login", 10, 15 * 60)
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        valid_bot = bot_check()
        with connect_db() as db:
            user = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if valid_bot and user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            ensure_csrf()
            session.permanent = True
            flash("You are signed in.")
            return redirect(url_for("account"))
        error = "Sign-in failed. Check your details and local bot check, then try again."
    return render_page("login.html", "Sign in", error=error, challenge=new_challenge())


@app.route("/account")
def account():
    if not current_user():
        return redirect(url_for("login"))
    return render_page(
        "account.html",
        "Account",
        profile_challenge=new_challenge(),
        password_challenge=new_challenge(),
    )


def require_user():
    user = current_user()
    if not user:
        abort(403, "Please sign in first.")
    return user


@app.route("/account/profile", methods=["POST"])
def update_profile():
    enforce_rate_limit("profile", 15, 60 * 60)
    check_csrf()
    user = require_user()
    display_name = request.form.get("display_name", "").strip()
    if not bot_check():
        flash("Profile was not changed: local bot check failed or expired.")
    elif not display_name or len(display_name) > 60:
        flash("Display name must be between 1 and 60 characters.")
    else:
        with connect_db() as db:
            db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user["id"]))
        flash("Display name updated.")
    return redirect(url_for("account"))


@app.route("/account/password", methods=["POST"])
def change_password():
    enforce_rate_limit("password-change", 5, 60 * 60)
    check_csrf()
    user = require_user()
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    with connect_db() as db:
        record = db.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not bot_check():
        flash("Password was not changed: local bot check failed or expired.")
    elif not record or not check_password_hash(record["password_hash"], old_password):
        flash("Password was not changed: current password is incorrect.")
    elif len(new_password) < 12 or len(new_password) > 128:
        flash("Use a new password between 12 and 128 characters.")
    elif new_password != confirm:
        flash("The new passwords did not match.")
    else:
        with connect_db() as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), user["id"]),
            )
        flash("Password updated.")
    return redirect(url_for("account"))


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    flash("You are signed out.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    # Local-only development binding. Use a production WSGI server and HTTPS for public use.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
