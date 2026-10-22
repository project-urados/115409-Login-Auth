"""Connection requests, user-facing connection controls, and the per-service data API.

Flow
----
1. A registered service calls POST /api/v1/connection-requests with its own
   credentials and a target account. The request is stored for that user.
2. The user sees it on the Account page and accepts or declines it.
3. An accepted request becomes an approved connection. The service can then
   exchange it for a token (connection grant) and read/write its own data.

Isolation
---------
Every data row is keyed by (user_id, client_id, data_key). The client_id always
comes from the verified access token or the authenticated client, never from
the request body or URL, so a service cannot address another service's data.
"""

import json
import secrets
import time

from flask import Blueprint, Response, abort, current_app, jsonify, request, url_for
from werkzeug.security import check_password_hash

from flask import flash, redirect

from core import audit, check_csrf, db_conn, enforce_rate_limit, render_page, require_user
from oauth import (
    SCOPE_DESCRIPTIONS,
    approve_connection,
    abort_json,
    client_credentials_from_request,
    get_client,
    parse_scopes,
    principal_from_bearer,
    verify_client_secret,
)

bp = Blueprint("connections", __name__)

MAX_DATA_BYTES = 1024 * 1024  # 1 MiB per service data item
MAX_KEY_LENGTH = 100
MAX_MESSAGE = 500


def valid_key(key):
    return bool(key) and len(key) <= MAX_KEY_LENGTH and all(c.isalnum() or c in "._-/" for c in key) and ".." not in key


# ================================================================== account UI

@bp.route("/account/connections")
def connections_page():
    user = require_user()
    with db_conn() as db:
        pending = db.execute(
            """
            SELECT r.public_id, r.scopes, r.message, r.created_at, c.name, c.client_id
            FROM connection_requests r JOIN oauth_clients c ON c.client_id = r.client_id
            WHERE r.user_id = ? AND r.status = 'pending' ORDER BY r.created_at DESC
            """,
            (user["id"],),
        ).fetchall()
        active = db.execute(
            """
            SELECT c.public_id, c.scopes, c.created_at, c.updated_at, o.name, o.client_id,
                   (SELECT COUNT(*) FROM service_data d WHERE d.user_id = c.user_id AND d.client_id = c.client_id) AS items,
                   (SELECT COALESCE(SUM(size), 0) FROM service_data d WHERE d.user_id = c.user_id AND d.client_id = c.client_id) AS bytes_used
            FROM connections c JOIN oauth_clients o ON o.client_id = c.client_id
            WHERE c.user_id = ? AND c.status = 'approved' ORDER BY o.name
            """,
            (user["id"],),
        ).fetchall()
    return render_page(
        "connections.html",
        "Connected services",
        pending=pending,
        active=active,
        descriptions=SCOPE_DESCRIPTIONS,
    )


def _find_request(db, user_id, public_id):
    return db.execute(
        "SELECT * FROM connection_requests WHERE public_id = ? AND user_id = ? AND status = 'pending'",
        (public_id, user_id),
    ).fetchone()


@bp.route("/account/connections/requests/<public_id>/<decision>", methods=["POST"])
def decide_request(public_id, decision):
    if decision not in {"accept", "decline"}:
        abort(404)
    check_csrf()
    user = require_user()
    now = int(time.time())
    with db_conn() as db:
        req = _find_request(db, user["id"], public_id)
        if req is None:
            return render_page("error.html", "Not found", message="That request no longer exists."), 404
        db.execute(
            "UPDATE connection_requests SET status = ?, decided_at = ? WHERE id = ?",
            ("accepted" if decision == "accept" else "declined", now, req["id"]),
        )
        if decision == "accept":
            approve_connection(db, user["id"], req["client_id"], parse_scopes(req["scopes"]), "request")
            audit(db, user["id"], "connection.accepted", req["client_id"])
        else:
            audit(db, user["id"], "connection.declined", req["client_id"])
    return redirect_to_connections("Connection accepted." if decision == "accept" else "Request declined.")


@bp.route("/account/connections/<public_id>/revoke", methods=["POST"])
def revoke_connection(public_id):
    check_csrf()
    user = require_user()
    with db_conn() as db:
        row = db.execute(
            "SELECT client_id FROM connections WHERE public_id = ? AND user_id = ? AND status = 'approved'",
            (public_id, user["id"]),
        ).fetchone()
        if row is None:
            return render_page("error.html", "Not found", message="That connection no longer exists."), 404
        # Revoking removes the connection and its stored data for this service only.
        db.execute("DELETE FROM service_data WHERE user_id = ? AND client_id = ?", (user["id"], row["client_id"]))
        db.execute("DELETE FROM connections WHERE public_id = ? AND user_id = ?", (public_id, user["id"]))
        db.execute("DELETE FROM auth_codes WHERE user_id = ? AND client_id = ?", (user["id"], row["client_id"]))
        audit(db, user["id"], "connection.revoked", row["client_id"])
    return redirect_to_connections("Connection removed and its stored data was deleted.")


def redirect_to_connections(message):
    flash(message)
    return redirect(url_for("connections.connections_page"))


# ================================================================== service API

def authenticate_service():
    """Client-credentials authentication for a registered confidential service."""
    client_id, secret = client_credentials_from_request()
    enforce_rate_limit("service-auth", 60, 60, key=f"client:{client_id}")
    client = get_client(client_id)
    if client is None or not client["secret_hash"] or not verify_client_secret(client, secret):
        abort_json(401, "invalid_client", "Service authentication failed.")
    return client


@bp.route("/api/v1/connection-requests", methods=["POST"])
def create_connection_request():
    """A service asks to connect to a specific user account.

    Body (JSON): {"username": "...", "scopes": ["profile", "data"], "message": "..."}
    Auth: the service's client_id and secret (Basic or form fields).
    """
    client = authenticate_service()
    enforce_rate_limit("connection-request", 20, 60 * 60, key=f"client:{client['client_id']}")
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    message = str(body.get("message", ""))[:MAX_MESSAGE]
    scopes = body.get("scopes") or []
    if not isinstance(scopes, list) or not scopes or not all(isinstance(s, str) for s in scopes):
        return jsonify(error="invalid_request", error_description="scopes must be a non-empty list."), 400
    requested = sorted(set(scopes))
    allowed = set(parse_scopes(client["allowed_scopes"]))
    if not set(requested) <= allowed:
        return jsonify(error="invalid_scope", error_description="Requested scopes exceed the registration."), 400
    with db_conn() as db:
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        # Respond identically whether or not the user exists, to avoid account enumeration.
        if user is None:
            return jsonify(status="pending", message="If the account exists, the request was delivered."), 202
        pending = db.execute(
            "SELECT public_id FROM connection_requests WHERE user_id = ? AND client_id = ? AND status = 'pending'",
            (user["id"], client["client_id"]),
        ).fetchone()
        if pending:
            return jsonify(status="pending", request_id=pending["public_id"]), 202
        public_id = secrets.token_urlsafe(18)
        db.execute(
            """INSERT INTO connection_requests(public_id, user_id, client_id, scopes, message, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            (public_id, user["id"], client["client_id"], " ".join(requested), message, int(time.time())),
        )
        audit(db, user["id"], "connection.requested", client["client_id"])
    return jsonify(status="pending", request_id=public_id), 202


@bp.route("/api/v1/connection-requests/<public_id>", methods=["GET"])
def get_connection_request(public_id):
    """Service polls the status of its own request."""
    client = authenticate_service()
    with db_conn() as db:
        row = db.execute(
            "SELECT status, scopes FROM connection_requests WHERE public_id = ? AND client_id = ?",
            (public_id, client["client_id"]),
        ).fetchone()
        if row is None:
            abort_json(404, "not_found", "No such request.")
        connection = None
        if row["status"] == "accepted":
            # Look up the connection through the request's owner. The request row holds
            # user_id and client_id, so re-query by those two columns.
            request_row = db.execute(
                "SELECT user_id FROM connection_requests WHERE public_id = ? AND client_id = ?",
                (public_id, client["client_id"]),
            ).fetchone()
            connection = db.execute(
                "SELECT public_id FROM connections WHERE user_id = ? AND client_id = ? AND status = 'approved'",
                (request_row["user_id"], client["client_id"]),
            ).fetchone()
    return jsonify(status=row["status"], connection_id=connection["public_id"] if connection else None)


# ---------------------------------------------------------------- service data

def _service_context():
    """Return (user_id, client_id) for a request authenticated with a connection token."""
    user_id, client_id, scopes = principal_from_bearer(required_scope="data")
    return user_id, client_id


@bp.route("/api/v1/data", methods=["GET"])
def list_data():
    user_id, client_id = _service_context()
    with db_conn() as db:
        rows = db.execute(
            "SELECT data_key, content_type, size, updated_at FROM service_data "
            "WHERE user_id = ? AND client_id = ? ORDER BY data_key",
            (user_id, client_id),
        ).fetchall()
    return jsonify(items=[dict(r) for r in rows])


@bp.route("/api/v1/data/<path:key>", methods=["GET", "PUT", "DELETE"])
def item(key):
    user_id, client_id = _service_context()
    if not valid_key(key):
        abort_json(400, "invalid_key", "Keys may contain letters, digits, '.', '_', '-' and '/' (max 100).")
    if request.method == "GET":
        with db_conn() as db:
            row = db.execute(
                "SELECT content_type, body FROM service_data WHERE user_id = ? AND client_id = ? AND data_key = ?",
                (user_id, client_id, key),
            ).fetchone()
        if row is None:
            abort_json(404, "not_found", "No data stored under that key.")
        # Stored bodies are untrusted: sandbox them so a browser never runs script from them.
        return Response(
            bytes(row["body"]),
            mimetype=row["content_type"],
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": "sandbox; default-src 'none'",
                "X-Content-Type-Options": "nosniff",
            },
        )

    if request.method == "DELETE":
        with db_conn() as db:
            deleted = db.execute(
                "DELETE FROM service_data WHERE user_id = ? AND client_id = ? AND data_key = ?",
                (user_id, client_id, key),
            ).rowcount
        if not deleted:
            abort_json(404, "not_found", "No data stored under that key.")
        return jsonify(deleted=key)

    # PUT: any content type, stored as-is. Size is capped.
    body = request.get_data(cache=False)
    if len(body) > MAX_DATA_BYTES:
        abort_json(413, "too_large", "Data items are limited to 1 MiB.")
    content_type = (request.content_type or "application/octet-stream")[:100]
    now = int(time.time())
    with db_conn() as db:
        db.execute(
            """INSERT INTO service_data(user_id, client_id, data_key, content_type, body, size, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, client_id, data_key) DO UPDATE SET
                 content_type = excluded.content_type, body = excluded.body,
                 size = excluded.size, updated_at = excluded.updated_at""",
            (user_id, client_id, key, content_type, body, len(body), now),
        )
    return jsonify(stored=key, size=len(body), updated_at=now)
