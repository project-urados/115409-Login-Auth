import argparse
import os
import sqlite3
import sys
import time

from flask import Flask, flash, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import connections
import mfa
import oauth
from core import (
    USERNAME_RE,
    audit,
    bot_check,
    check_csrf,
    current_user,
    db_conn,
    enforce_rate_limit,
    ensure_csrf,
    init_db,
    new_challenge,
    render_page,
    require_user,
    safe_next,
)
from footer import init_footer

app = Flask(__name__)
secret_key = os.environ.get("FLASK_SECRET_KEY", "")
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
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    OIDC_ISSUER=os.environ.get("OIDC_ISSUER", ""),
)

init_db()
init_footer(app)
with app.app_context():
    # Create the signing key at startup so the JWKS is populated before the first token.
    oauth.load_or_create_signing_key()


@app.template_filter("timestamp")
def format_timestamp(value):
    if not value:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(value)))
app.register_blueprint(mfa.bp)
app.register_blueprint(oauth.bp)
app.register_blueprint(connections.bp)


@app.before_request
def prepare_session():
    ensure_csrf()


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    # Stored service data may carry any content type; endpoints that return it set their own CSP.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self' https:; "
        "frame-ancestors 'none'; base-uri 'self'",
    )
    if not request.path.startswith(("/.well-known/", "/static/")) and "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    if os.environ.get("HTTPS_ONLY", "0") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(429)
def handle_client_error(error):
    if request.path.startswith(("/api/", "/oauth/", "/.well-known/")):
        return jsonify(error="request_failed", error_description=error.description), error.code
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
                with db_conn() as db:
                    cursor = db.execute(
                        "INSERT INTO users(username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                        (username, display_name, generate_password_hash(password), int(time.time())),
                    )
                    user_id = cursor.lastrowid
                    audit(db, user_id, "account.created")
                session.clear()
                session["user_id"] = user_id
                session["amr"] = ["pwd"]
                session["auth_time"] = int(time.time())
                ensure_csrf()
                session.permanent = True
                flash("Your account was created. Consider turning on two-step verification.")
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
        with db_conn() as db:
            user = db.execute(
                "SELECT id, password_hash, mfa_enabled FROM users WHERE username = ?", (username,)
            ).fetchone()
            password_ok = bool(user) and check_password_hash(user["password_hash"], password)
            if valid_bot and password_ok:
                audit(db, user["id"], "login.password_ok")
        if valid_bot and password_ok:
            if user["mfa_enabled"]:
                # Password accepted; the session is not signed in until the second factor passes.
                next_url = safe_next(request.args.get("next"))
                session.clear()
                session["mfa_pending_user"] = user["id"]
                session["mfa_next"] = next_url
                ensure_csrf()
                return redirect(url_for("mfa.login_mfa"))
            session.clear()
            session["user_id"] = user["id"]
            session["amr"] = ["pwd"]
            session["auth_time"] = int(time.time())
            ensure_csrf()
            session.permanent = True
            with db_conn() as db:
                audit(db, user["id"], "login.success", "password")
            flash("You are signed in.")
            return redirect(safe_next(request.args.get("next")) or url_for("account"))
        error = "Sign-in failed. Check your details and local bot check, then try again."
    return render_page("login.html", "Sign in", error=error, challenge=new_challenge())


@app.route("/cannot_provide")
def cannot_provide():
    if not current_user():
        return redirect(url_for("cannot_provide"))


@app.route("/account")
def account():
    if not current_user():
        return redirect(url_for("login"))
    with db_conn() as db:
        counts = db.execute(
            """SELECT
                 (SELECT COUNT(*) FROM connection_requests WHERE user_id = ? AND status = 'pending') AS pending,
                 (SELECT COUNT(*) FROM connections WHERE user_id = ? AND status = 'approved') AS connected""",
            (current_user()["id"], current_user()["id"]),
        ).fetchone()
    return render_page(
        "account.html",
        "Account",
        profile_challenge=new_challenge(),
        password_challenge=new_challenge(),
        counts=counts,
    )


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
        with db_conn() as db:
            db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user["id"]))
            audit(db, user["id"], "account.profile_changed")
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
    with db_conn() as db:
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
        with db_conn() as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), user["id"]),
            )
            audit(db, user["id"], "account.password_changed")
        flash("Password updated.")
    return redirect(url_for("account"))


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    flash("You are signed out.")
    return redirect(url_for("home"))


class GunicornApplication:
    """Run the Flask application through Gunicorn when app.py is executed."""

    def __init__(self, application, options=None):
        from gunicorn.app.base import BaseApplication

        class Application(BaseApplication):
            def load_config(self):
                for key, value in (options or {}).items():
                    if value is not None:
                        self.cfg.set(key.lower(), value)

            def load(self):
                return application

        self.application = Application()

    def run(self):
        self.application.run()


def main():
    parser = argparse.ArgumentParser(description="Run the application with Gunicorn.")
    parser.add_argument(
        "--host",
        "--ip",
        dest="host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="IP address to bind to (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "5000")),
        help="TCP port to bind to (default: %(default)s)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("WEB_CONCURRENCY", "1")),
        help="Number of Gunicorn worker processes (default: %(default)s)",
    )
    args = parser.parse_args()

    GunicornApplication(
        app,
        {
            "bind": f"{args.host}:{args.port}",
            "workers": args.workers,
            "accesslog": "-",
            "errorlog": "-",
        },
    ).run()


if __name__ == "__main__":
    main()
