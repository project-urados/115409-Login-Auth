"""OpenID Connect / OAuth 2.0 provider.

- Authorization code flow with PKCE (S256) is mandatory.
- Tokens are JWTs signed with RS256. The private key is sealed in the database.
- Every access token is re-checked against the live connection row, so a revoked
  connection stops working immediately, even before the token expires.
"""

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from urllib.parse import urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from core import (
    audit,
    check_csrf,
    current_user,
    db_conn,
    enforce_rate_limit,
    ensure_csrf,
    keyed_hash,
    render_page,
    seal,
    unseal,
)

bp = Blueprint("oauth", __name__)

ALL_SCOPES = {"openid", "profile", "data"}
CONNECTION_GRANT = "urn:local-auth:params:oauth:grant-type:connection"
SCOPE_DESCRIPTIONS = {
    "openid": "Confirm who you are (required for OpenID Connect ID tokens).",
    "profile": "Read your display name and username.",
    "data": "Store and read its own data in your account.",
}
ACCESS_TOKEN_TTL = 15 * 60
CODE_TTL = 60

_private_keys = {}  # kid -> RSA private key object (process cache)


# ------------------------------------------------------------------ helpers

def issuer():
    configured = current_app.config.get("OIDC_ISSUER") or ""
    return configured.rstrip("/") or request.url_root.rstrip("/")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def load_or_create_signing_key():
    """Return (kid, private key). Creates a key on first use."""
    with db_conn() as db:
        row = db.execute(
            "SELECT kid, private_key_enc FROM signing_keys ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
            kid = uuid.uuid4().hex
            db.execute(
                "INSERT INTO signing_keys(kid, private_key_enc, created_at) VALUES (?, ?, ?)",
                (kid, seal(pem), int(time.time())),
            )
            _private_keys[kid] = key
            return kid, key
    kid = row["kid"]
    if kid not in _private_keys:
        _private_keys[kid] = serialization.load_pem_private_key(
            unseal(row["private_key_enc"]).encode(), password=None
        )
    return kid, _private_keys[kid]


def public_jwks():
    keys = []
    with db_conn() as db:
        rows = db.execute("SELECT kid, private_key_enc FROM signing_keys").fetchall()
    for row in rows:
        if row["kid"] not in _private_keys:
            _private_keys[row["kid"]] = serialization.load_pem_private_key(
                unseal(row["private_key_enc"]).encode(), password=None
            )
        numbers = _private_keys[row["kid"]].public_key().public_numbers()
        keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": row["kid"],
            "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        })
    return {"keys": keys}


def sign_jwt(claims):
    kid, key = load_or_create_signing_key()
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def verify_jwt(token):
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or "kid" not in header:
        raise jwt.InvalidTokenError("unsupported token header")
    with db_conn() as db:
        row = db.execute("SELECT kid, private_key_enc FROM signing_keys WHERE kid = ?", (header["kid"],)).fetchone()
    if row is None:
        raise jwt.InvalidTokenError("unknown signing key")
    if row["kid"] not in _private_keys:
        _private_keys[row["kid"]] = serialization.load_pem_private_key(
            unseal(row["private_key_enc"]).encode(), password=None
        )
    public = _private_keys[row["kid"]].public_key()
    # Audience is checked by the caller against the connection's client_id.
    return jwt.decode(
        token,
        public,
        algorithms=["RS256"],
        issuer=issuer(),
        options={"require": ["exp", "iat", "iss", "sub", "aud"], "verify_aud": False},
    )


def get_client(client_id):
    with db_conn() as db:
        return db.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()


def get_connection(user_id, client_id):
    with db_conn() as db:
        return db.execute(
            "SELECT * FROM connections WHERE user_id = ? AND client_id = ?", (user_id, client_id)
        ).fetchone()


def parse_scopes(text):
    return sorted(set(text.split())) if text else []


def oauth_error(error, description, status=400):
    return jsonify({"error": error, "error_description": description}), status


def verify_client_secret(client, supplied):
    """Client authentication for confidential clients (secret stored as a salted hash)."""
    if not client["secret_hash"]:
        return False
    return check_password_hash(client["secret_hash"], supplied or "")


def client_credentials_from_request():
    auth = request.authorization
    if auth and auth.type and auth.type.lower() == "basic":
        return auth.username or "", auth.password or ""
    return request.form.get("client_id", ""), request.form.get("client_secret", "")


def bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def principal_from_bearer(required_scope=None):
    """Validate a user-bound access token and the live connection behind it.

    Returns (user_id, client_id, scopes) or aborts with a JSON 401/403.
    """
    token = bearer_token()
    if not token:
        abort_json(401, "invalid_token", "Missing bearer token.")
    try:
        claims = verify_jwt(token)
    except jwt.PyJWTError:
        abort_json(401, "invalid_token", "The access token is invalid or expired.")
    if claims.get("typ") != "access":
        abort_json(401, "invalid_token", "An access token is required.")
    client_id = claims.get("azp")
    try:
        user_id = int(claims["sub"])
    except (TypeError, ValueError):
        abort_json(401, "invalid_token", "Malformed subject.")
    connection = get_connection(user_id, client_id)
    if connection is None or connection["status"] != "approved":
        abort_json(401, "invalid_token", "This connection is no longer active.")
    scopes = set(parse_scopes(connection["scopes"])) & set(parse_scopes(claims.get("scope", "")))
    if required_scope and required_scope not in scopes:
        abort_json(403, "insufficient_scope", f"The '{required_scope}' scope is required.")
    return user_id, client_id, scopes


def abort_json(status, error, description):
    response = jsonify({"error": error, "error_description": description})
    response.status_code = status
    if status == 401:
        response.headers["WWW-Authenticate"] = f'Bearer error="{error}"'
    abort(response)


def validate_authorize_params(params):
    """Return (client, error_dict). error_dict is None when valid."""
    client = get_client(params.get("client_id", ""))
    if client is None:
        return None, {"fatal": "Unknown client. The service is not registered with this account provider."}
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in client["redirect_uris"].split():
        return None, {"fatal": "The redirect address does not match the one registered for this service."}
    state = params.get("state", "")
    base = {"redirect_uri": redirect_uri, "state": state}
    if params.get("response_type") != "code":
        return None, {**base, "error": "unsupported_response_type", "description": "Only response_type=code is supported."}
    if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
        return None, {**base, "error": "invalid_request", "description": "PKCE with code_challenge_method=S256 is required."}
    if len(params.get("code_challenge", "")) < 43 or len(params.get("code_challenge", "")) > 128:
        return None, {**base, "error": "invalid_request", "description": "Invalid code_challenge."}
    requested = parse_scopes(params.get("scope", ""))
    allowed = set(parse_scopes(client["allowed_scopes"]))
    if not requested or not set(requested) <= allowed:
        return None, {**base, "error": "invalid_scope", "description": "The requested scope is not allowed for this service."}
    return client, None


def redirect_with(params, **extra):
    query = {k: v for k, v in {**extra}.items() if v}
    if params.get("state"):
        query["state"] = params["state"]
    query["iss"] = issuer()
    separator = "&" if urlparse(params["redirect_uri"]).query else "?"
    return redirect(params["redirect_uri"] + separator + urlencode(query))


# ------------------------------------------------------------------ discovery

@bp.route("/.well-known/openid-configuration")
def discovery():
    base = issuer()
    return jsonify({
        "issuer": base,
        "authorization_endpoint": base + url_for("oauth.authorize"),
        "token_endpoint": base + url_for("oauth.token"),
        "userinfo_endpoint": base + url_for("oauth.userinfo"),
        "jwks_uri": base + url_for("oauth.jwks"),
        "scopes_supported": sorted(ALL_SCOPES),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "name", "preferred_username", "auth_time", "amr", "nonce"],
        "authorization_response_iss_parameter_supported": True,
    })


@bp.route("/.well-known/jwks.json")
def jwks():
    response = jsonify(public_jwks())
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


# ------------------------------------------------------------------ authorization endpoint

@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    params = {k: v for k, v in request.values.items() if k not in ("csrf", "decision")}
    client, error = validate_authorize_params(params)
    if error and "fatal" in error:
        return render_page("error.html", "Authorization failed", message=error["fatal"]), 400
    if error:
        return redirect_with(params, error=error["error"], error_description=error["description"])

    user = current_user()
    if user is None:
        query = urlencode({k: v for k, v in params.items()})
        return redirect(url_for("login", next=f"{url_for('oauth.authorize')}?{query}"))

    requested = parse_scopes(params["scope"])
    connection = get_connection(user["id"], client["client_id"])
    approved = set(parse_scopes(connection["scopes"])) if connection and connection["status"] == "approved" else set()

    if request.method == "POST":
        check_csrf()
        if request.form.get("decision") != "approve":
            with db_conn() as db:
                audit(db, user["id"], "connection.denied", client["client_id"])
            return redirect_with(params, error="access_denied", error_description="The user denied access.")
        with db_conn() as db:
            scopes = sorted(approved | set(requested))
            approve_connection(db, user["id"], client["client_id"], scopes, "oauth")
            audit(db, user["id"], "connection.approved", f"{client['client_id']} {' '.join(scopes)}")
        return issue_code(params, client, user, requested)

    if set(requested) <= approved:
        return issue_code(params, client, user, requested)

    ensure_csrf()
    return render_template(
        "consent.html",
        title="Authorize service",
        user=user,
        csrf=session.get("csrf", ""),
        client=client,
        requested=requested,
        new_scopes=[s for s in requested if s not in approved],
        descriptions=SCOPE_DESCRIPTIONS,
        params=params,
    )


def approve_connection(db, user_id, client_id, scopes, origin):
    """Create or update an approved connection. Returns its public_id."""
    now = int(time.time())
    scope_text = " ".join(sorted(set(scopes)))
    existing = db.execute(
        "SELECT public_id FROM connections WHERE user_id = ? AND client_id = ?", (user_id, client_id)
    ).fetchone()
    public_id = existing["public_id"] if existing else secrets.token_urlsafe(18)
    db.execute(
        """
        INSERT INTO connections(public_id, user_id, client_id, status, scopes, origin, created_at, updated_at)
        VALUES (?, ?, ?, 'approved', ?, ?, ?, ?)
        ON CONFLICT(user_id, client_id) DO UPDATE SET
            status = 'approved', scopes = excluded.scopes, origin = excluded.origin,
            updated_at = excluded.updated_at
        """,
        (public_id, user_id, client_id, scope_text, origin, now, now),
    )
    return public_id


def issue_code(params, client, user, scopes):
    code = secrets.token_urlsafe(32)
    now = int(time.time())
    with db_conn() as db:
        db.execute(
            """
            INSERT INTO auth_codes(code_hash, user_id, client_id, redirect_uri, scopes, nonce,
                                   code_challenge, auth_time, amr, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                keyed_hash(code, purpose="authcode"),
                user["id"],
                client["client_id"],
                params["redirect_uri"],
                " ".join(scopes),
                params.get("nonce", "")[:200],
                params["code_challenge"],
                int(session.get("auth_time", now)),
                " ".join(session.get("amr", ["pwd"])),
                now + CODE_TTL,
            ),
        )
    return redirect_with(params, code=code)


# ------------------------------------------------------------------ token endpoint

def issue_access_token(client_id, user_id, scopes):
    now = int(time.time())
    token = sign_jwt({
        "iss": issuer(),
        "sub": str(user_id),
        "aud": client_id,
        "azp": client_id,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "scope": " ".join(sorted(scopes)),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    })
    response = jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
        "scope": " ".join(sorted(scopes)),
    })
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def connection_grant(client):
    """Service-initiated grant: an approved connection is exchanged for an access token.

    The connection must belong to the authenticated client, and the user must have approved it.
    """
    if not client["secret_hash"]:
        return oauth_error("unauthorized_client", "Only confidential clients may use this grant.", 401)
    connection_id = request.form.get("connection_id", "")
    with db_conn() as db:
        row = db.execute(
            "SELECT * FROM connections WHERE public_id = ? AND client_id = ?",
            (connection_id, client["client_id"]),
        ).fetchone()
        if row is None or row["status"] != "approved":
            return oauth_error("invalid_grant", "No approved connection matches this request.")
        audit(db, row["user_id"], "token.issued", f"{client['client_id']} (connection)")
    return issue_access_token(client["client_id"], row["user_id"], set(parse_scopes(row["scopes"])))


@bp.route("/oauth/token", methods=["POST"])
def token():
    client_id, client_secret = client_credentials_from_request()
    enforce_rate_limit("oauth-token", 30, 60, key=f"client:{client_id}")
    client = get_client(client_id)
    if client is None:
        return oauth_error("invalid_client", "Unknown client.", 401)
    if client["secret_hash"]:
        if not verify_client_secret(client, client_secret):
            return oauth_error("invalid_client", "Client authentication failed.", 401)
    elif client_secret:
        return oauth_error("invalid_client", "This client is public and must not send a secret.", 401)

    grant = request.form.get("grant_type", "")
    if grant == CONNECTION_GRANT:
        return connection_grant(client)
    if grant != "authorization_code":
        return oauth_error("unsupported_grant_type", "Supported: authorization_code, " + CONNECTION_GRANT)

    code = request.form.get("code", "")
    verifier = request.form.get("code_verifier", "")
    redirect_uri = request.form.get("redirect_uri", "")
    if not code or not (43 <= len(verifier) <= 128):
        return oauth_error("invalid_request", "Missing code or code_verifier.")

    now = int(time.time())
    code_hash = keyed_hash(code, purpose="authcode")
    with db_conn() as db:
        # Single-use: only the request that flips used 0 -> 1 may proceed.
        marked = db.execute(
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND used = 0 AND expires_at >= ?",
            (code_hash, now),
        ).rowcount
        row = db.execute("SELECT * FROM auth_codes WHERE code_hash = ?", (code_hash,)).fetchone()
        if marked != 1 or row is None:
            return oauth_error("invalid_grant", "The code is invalid, expired, or already used.")
        if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
            return oauth_error("invalid_grant", "The code was issued to a different client or redirect address.")
        expected = b64url(hashlib.sha256(verifier.encode()).digest())
        if not hmac.compare_digest(expected, row["code_challenge"]):
            return oauth_error("invalid_grant", "PKCE verification failed.")
        connection = db.execute(
            "SELECT status FROM connections WHERE user_id = ? AND client_id = ?", (row["user_id"], client_id)
        ).fetchone()
        if connection is None or connection["status"] != "approved":
            return oauth_error("invalid_grant", "The user has not approved this connection.")
        audit(db, row["user_id"], "token.issued", client_id)
        user = db.execute("SELECT id, username, display_name FROM users WHERE id = ?", (row["user_id"],)).fetchone()

    scopes = row["scopes"]
    base_claims = {"iss": issuer(), "sub": str(user["id"]), "aud": client_id, "azp": client_id, "iat": now}
    access_claims = {
        **base_claims,
        "aud": client_id,
        "exp": now + ACCESS_TOKEN_TTL,
        "scope": scopes,
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    response = {
        "access_token": sign_jwt(access_claims),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
        "scope": scopes,
    }
    if "openid" in scopes.split():
        id_claims = {
            **base_claims,
            "exp": now + ACCESS_TOKEN_TTL,
            "auth_time": row["auth_time"],
            "amr": row["amr"].split(),
            "nonce": row["nonce"] or None,
            "preferred_username": user["username"],
            "name": user["display_name"],
            "typ": "id",
        }
        response["id_token"] = sign_jwt({k: v for k, v in id_claims.items() if v is not None})
    response_obj = jsonify(response)
    response_obj.headers["Cache-Control"] = "no-store"
    response_obj.headers["Pragma"] = "no-cache"
    return response_obj


# ------------------------------------------------------------------ userinfo

@bp.route("/oauth/userinfo", methods=["GET", "POST"])
def userinfo():
    user_id, _client_id, scopes = principal_from_bearer()
    if not ({"openid", "profile"} & scopes):
        abort_json(403, "insufficient_scope", "The 'profile' or 'openid' scope is required.")
    with db_conn() as db:
        user = db.execute("SELECT id, username, display_name FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        abort_json(401, "invalid_token", "Unknown user.")
    return jsonify({
        "sub": str(user["id"]),
        "name": user["display_name"],
        "preferred_username": user["username"],
    })
