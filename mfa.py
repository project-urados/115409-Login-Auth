"""Multi-factor authentication: RFC 6238 TOTP with single-use recovery codes.

Secrets are sealed (encrypted) at rest. Each accepted TOTP counter is recorded so
a code cannot be replayed within its validity window.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from core import (
    audit,
    bot_check,
    check_csrf,
    db_conn,
    enforce_rate_limit,
    ensure_csrf,
    keyed_hash,
    new_challenge,
    render_page,
    require_user,
    seal,
    unseal,
)

bp = Blueprint("mfa", __name__)

TOTP_STEP = 30
TOTP_DIGITS = 6
ISSUER = "Local Auth"


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret, code, last_counter):
    """Return the matched counter (for replay tracking) or None."""
    code = code.replace(" ", "")
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return None
    now_counter = int(time.time()) // TOTP_STEP
    for counter in range(now_counter - 1, now_counter + 2):  # one step of clock drift
        if counter > last_counter and hmac.compare_digest(totp_at(secret, counter), code):
            return counter
    return None


def otpauth_uri(username, secret):
    label = quote(f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&digits={TOTP_DIGITS}&period={TOTP_STEP}"


def qr_svg(text):
    """Render a QR code as inline SVG when `segno` is installed; otherwise return None."""
    try:
        import io

        import segno
    except ImportError:
        return None
    buffer = io.BytesIO()
    segno.make(text, error="m").save(buffer, kind="svg", scale=4, dark="#0f172a", border=2)
    return buffer.getvalue().decode()


def make_recovery_codes(db, user_id):
    db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(8):
        raw = secrets.token_hex(5)
        code = f"{raw[:5]}-{raw[5:]}"
        codes.append(code)
        db.execute(
            "INSERT INTO mfa_recovery_codes(user_id, code_hash) VALUES (?, ?)",
            (user_id, keyed_hash(code.replace("-", "").lower(), purpose="recovery")),
        )
    return codes


def consume_recovery_code(db, user_id, code):
    digest = keyed_hash(code.replace("-", "").replace(" ", "").lower(), purpose="recovery")
    row = db.execute(
        "SELECT id FROM mfa_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
        (user_id, digest),
    ).fetchone()
    if not row:
        return False
    db.execute("UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?", (int(time.time()), row["id"]))
    return True


def complete_sign_in(user_id, amr):
    next_url = session.get("mfa_next")
    session.clear()
    session["user_id"] = user_id
    session["amr"] = amr
    session["auth_time"] = int(time.time())
    session.permanent = True
    ensure_csrf()
    return next_url


# ------------------------------------------------------------------ second step at sign-in

@bp.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    user_id = session.get("mfa_pending_user")
    if not user_id:
        return redirect(url_for("login"))
    error = ""
    if request.method == "POST":
        enforce_rate_limit("mfa", 10, 15 * 60)
        enforce_rate_limit("mfa-user", 10, 15 * 60, key=str(user_id))
        check_csrf()
        code = request.form.get("code", "").strip()[:32]
        valid_bot = bot_check()
        with db_conn() as db:
            user = db.execute(
                "SELECT id, mfa_secret_enc, mfa_last_counter FROM users WHERE id = ? AND mfa_enabled = 1",
                (user_id,),
            ).fetchone()
            ok, amr = False, ["pwd"]
            if user and valid_bot:
                counter = verify_totp(unseal(user["mfa_secret_enc"]), code, user["mfa_last_counter"])
                if counter is not None:
                    db.execute("UPDATE users SET mfa_last_counter = ? WHERE id = ?", (counter, user_id))
                    ok, amr = True, ["pwd", "otp", "mfa"]
                elif consume_recovery_code(db, user_id, code):
                    ok, amr = True, ["pwd", "mfa"]
                    audit(db, user_id, "mfa.recovery_code_used")
            if ok:
                audit(db, user_id, "login.success", "mfa")
        if ok:
            next_url = complete_sign_in(user_id, amr)
            flash("You are signed in.")
            return redirect(next_url or url_for("account"))
        error = "That code was not accepted. Check the authenticator app or use a recovery code."
    return render_page("login_mfa.html", "Two-step verification", error=error, challenge=new_challenge())


# ------------------------------------------------------------------ management on the account

@bp.route("/account/security", methods=["GET"])
def security():
    user = require_user()
    with db_conn() as db:
        row = db.execute("SELECT mfa_enabled, mfa_secret_enc FROM users WHERE id = ?", (user["id"],)).fetchone()
        audit_rows = db.execute(
            "SELECT event, detail, created_at FROM audit_events WHERE user_id = ? ORDER BY id DESC LIMIT 15",
            (user["id"],),
        ).fetchall()
    enrolling = bool(row["mfa_secret_enc"]) and not row["mfa_enabled"]
    setup_secret, qr = None, None
    if enrolling:
        setup_secret = unseal(row["mfa_secret_enc"])
        uri = otpauth_uri(user["username"], setup_secret)
        qr = qr_svg(uri)
    return render_page(
        "security.html",
        "Security",
        mfa_enabled=bool(row["mfa_enabled"]),
        enrolling=enrolling,
        setup_secret=setup_secret,
        qr=qr,
        challenge=new_challenge(),
        audit_rows=audit_rows,
    )


@bp.route("/account/security/mfa/start", methods=["POST"])
def mfa_start():
    enforce_rate_limit("mfa-setup", 10, 60 * 60)
    check_csrf()
    user = require_user()
    if not bot_check():
        flash("Setup was not started: local bot check failed or expired.")
        return redirect(url_for("mfa.security"))
    with db_conn() as db:
        row = db.execute("SELECT mfa_enabled FROM users WHERE id = ?", (user["id"],)).fetchone()
        if row["mfa_enabled"]:
            flash("Two-step verification is already on.")
            return redirect(url_for("mfa.security"))
        db.execute(
            "UPDATE users SET mfa_secret_enc = ?, mfa_last_counter = -1 WHERE id = ?",
            (seal(new_totp_secret()), user["id"]),
        )
    return redirect(url_for("mfa.security"))


@bp.route("/account/security/mfa/confirm", methods=["POST"])
def mfa_confirm():
    enforce_rate_limit("mfa-setup", 10, 60 * 60)
    check_csrf()
    user = require_user()
    code = request.form.get("code", "").strip()
    if not bot_check():
        flash("Setup was not completed: local bot check failed or expired.")
        return redirect(url_for("mfa.security"))
    recovery = None
    with db_conn() as db:
        row = db.execute(
            "SELECT mfa_secret_enc, mfa_enabled FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if not row["mfa_secret_enc"] or row["mfa_enabled"]:
            flash("There is no pending two-step setup to confirm.")
            return redirect(url_for("mfa.security"))
        counter = verify_totp(unseal(row["mfa_secret_enc"]), code, -1)
        if counter is None:
            flash("That code did not match. Check the time on your device and try again.")
            return redirect(url_for("mfa.security"))
        db.execute(
            "UPDATE users SET mfa_enabled = 1, mfa_last_counter = ? WHERE id = ?", (counter, user["id"])
        )
        recovery = make_recovery_codes(db, user["id"])
        audit(db, user["id"], "mfa.enabled")
    session["recovery_codes"] = recovery  # shown once on the next page load
    return redirect(url_for("mfa.recovery_codes_page"))


@bp.route("/account/security/recovery-codes")
def recovery_codes_page():
    user = require_user()
    codes = session.pop("recovery_codes", None)
    if not codes:
        flash("Recovery codes are only shown once, right after they are generated.")
        return redirect(url_for("mfa.security"))
    return render_page("recovery_codes.html", "Recovery codes", codes=codes)


@bp.route("/account/security/mfa/disable", methods=["POST"])
def mfa_disable():
    enforce_rate_limit("mfa-setup", 10, 60 * 60)
    check_csrf()
    user = require_user()
    password = request.form.get("password", "")
    with db_conn() as db:
        record = db.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not bot_check():
            flash("Two-step verification was not changed: local bot check failed or expired.")
        elif not check_password_hash(record["password_hash"], password):
            flash("Two-step verification was not changed: password is incorrect.")
        else:
            db.execute(
                "UPDATE users SET mfa_enabled = 0, mfa_secret_enc = NULL, mfa_last_counter = -1 WHERE id = ?",
                (user["id"],),
            )
            db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user["id"],))
            audit(db, user["id"], "mfa.disabled")
            flash("Two-step verification is off.")
    return redirect(url_for("mfa.security"))
