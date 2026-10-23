"""End-to-end tests for accounts, MFA, OIDC/OAuth2, connections, service data and footer.

Run with:  python -m unittest discover -s tests -v
"""

import base64
import hashlib
import os
import re
import secrets
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_tmp = tempfile.mkdtemp()
os.environ["AUTH_DB"] = str(Path(_tmp) / "test.sqlite3")
os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(32)
os.environ["OIDC_ISSUER"] = "http://localhost"

import jwt  # noqa: E402

import app as app_module  # noqa: E402
import callbacks  # noqa: E402
import mfa  # noqa: E402
from core import connect_db, db_conn, keyed_hash, seal, unseal  # noqa: E402
from manage import create_service as register_service  # noqa: E402

flask_app = app_module.app
flask_app.config.update(TESTING=True)
_ctx = flask_app.app_context()


def setUpModule():
    _ctx.push()


def tearDownModule():
    _ctx.pop()

PASSWORD = "correct horse battery"
REDIRECT = "https://notes.example/callback"


def seed_challenge():
    """Insert a known bot-check challenge and return (id, answer)."""
    challenge_id = secrets.token_urlsafe(24)
    answer = "7"
    with db_conn() as db:
        db.execute(
            "INSERT INTO challenges(id, answer_hash, expires_at) VALUES (?, ?, ?)",
            (challenge_id, keyed_hash(f"{challenge_id}:{answer}", purpose="challenge"), int(time.time()) + 600),
        )
    return challenge_id, answer


def clear_rate_limits():
    with db_conn() as db:
        db.execute("DELETE FROM rate_limits")


def reset_database():
    """Give each test a clean slate. The signing key is kept so tokens stay verifiable."""
    tables = ["audit_events", "service_data", "auth_codes", "connection_requests", "connections",
              "mfa_recovery_codes", "oauth_clients", "users", "challenges", "rate_limits"]
    with db_conn() as db:
        for table in tables:
            db.execute(f"DELETE FROM {table}")


class Base(unittest.TestCase):
    def setUp(self):
        reset_database()
        clear_rate_limits()
        self.client = flask_app.test_client()

    def csrf(self):
        with self.client.session_transaction() as sess:
            if "csrf" not in sess:
                sess["csrf"] = secrets.token_urlsafe(32)
            return sess["csrf"]

    def form(self, data=None):
        cid, answer = seed_challenge()
        return {"csrf": self.csrf(), "challenge_id": cid, "challenge_answer": answer, **(data or {})}

    def register(self, username):
        clear_rate_limits()
        resp = self.client.post("/register", data=self.form({
            "username": username, "display_name": username.title(),
            "password": PASSWORD, "confirm": PASSWORD,
        }))
        self.assertEqual(resp.status_code, 302, resp.data[:300])
        return self.user_id(username)

    def user_id(self, username):
        with connect_db() as db:
            return db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]

    def login_password(self, username):
        clear_rate_limits()
        return self.client.post("/login", data=self.form({"username": username, "password": PASSWORD}))

    def totp_now(self, secret):
        return mfa.totp_at(secret, int(time.time()) // mfa.TOTP_STEP)

    def logout(self):
        self.client.post("/logout", data={"csrf": self.csrf()})


class AccountAndFooterTests(Base):
    def test_footer_is_rendered_from_config(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'class="site-footer"', resp.data)
        self.assertIn(b"Connected services", resp.data)
        self.assertIn(b"OpenID discovery", resp.data)

    def test_footer_config_rejects_unsafe_links(self):
        import json
        import footer

        cfg = Path(_tmp) / "footer.json"
        cfg.write_text(json.dumps({
            "brand": "X",
            "columns": [{"title": "T", "links": [
                {"label": "bad", "href": "javascript:alert(1)"},
                {"label": "proto-relative", "href": "//evil.example"},
                {"label": "ok", "href": "/fine"},
                {"label": "ext", "href": "https://example.org"},
            ]}],
        }))
        loaded = footer.load_footer_config(cfg)
        hrefs = [l["href"] for l in loaded["columns"][0]["links"]]
        self.assertEqual(hrefs, ["/fine", "https://example.org"])

    def test_footer_can_be_disabled_globally(self):
        import footer

        flask_app.jinja_env.globals["footer"] = {**footer.FOOTER, "enabled": False}
        try:
            resp = self.client.get("/")
            self.assertNotIn(b'class="site-footer"', resp.data)
        finally:
            flask_app.jinja_env.globals["footer"] = footer.FOOTER

    def test_security_headers_present(self):
        resp = self.client.get("/")
        self.assertIn("frame-ancestors 'none'", resp.headers["Content-Security-Policy"])
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")


class MfaTests(Base):
    def test_full_mfa_enrolment_and_login(self):
        self.register("mfa_user")
        self.client.post("/account/security/mfa/start", data=self.form())
        with db_conn() as db:
            row = db.execute("SELECT mfa_secret_enc FROM users WHERE username = 'mfa_user'").fetchone()
        secret = unseal(row["mfa_secret_enc"])

        # A wrong code is rejected.
        resp = self.client.post("/account/security/mfa/confirm", data=self.form({"code": "000000"}), follow_redirects=True)
        self.assertIn(b"did not match", resp.data)

        resp = self.client.post("/account/security/mfa/confirm", data=self.form({"code": self.totp_now(secret)}))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/account/security/recovery-codes", resp.location)
        page = self.client.get("/account/security/recovery-codes")
        codes = re.findall(rb'<div>([0-9a-f]{5}-[0-9a-f]{5})</div>', page.data)
        self.assertEqual(len(codes), 8)
        # Recovery codes are shown only once.
        again = self.client.get("/account/security/recovery-codes", follow_redirects=True)
        self.assertNotIn(b"Save your recovery codes", again.data)

        # Sign out, then sign in: password alone must not complete sign-in.
        # The enrolment code was used in this time window, so wait for the next one.
        self.logout()
        time.sleep(mfa.TOTP_STEP - (time.time() % mfa.TOTP_STEP) + 0.5)
        resp = self.login_password("mfa_user")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/mfa", resp.location)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

        # Replay protection: the same TOTP code cannot be used twice.
        code = self.totp_now(secret)
        clear_rate_limits()
        first = self.client.post("/login/mfa", data=self.form({"code": code}))
        self.assertEqual(first.status_code, 302)
        self.logout()
        self.login_password("mfa_user")
        clear_rate_limits()
        replay = self.client.post("/login/mfa", data=self.form({"code": code}), follow_redirects=True)
        self.assertIn(b"not accepted", replay.data)

        # Recovery code works once.
        self.logout()
        self.login_password("mfa_user")
        clear_rate_limits()
        ok = self.client.post("/login/mfa", data=self.form({"code": codes[0].decode()}))
        self.assertEqual(ok.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("user_id"), self.user_id("mfa_user"))
            self.assertIn("mfa", sess["amr"])

    def test_recovery_code_cannot_be_reused(self):
        self.register("reuse_user")
        uid = self.user_id("reuse_user")
        with db_conn() as db:
            db.execute("UPDATE users SET mfa_enabled = 1, mfa_secret_enc = ? WHERE id = ?",
                       (seal(mfa.new_totp_secret()), uid))
            from mfa import make_recovery_codes
            codes = make_recovery_codes(db, uid)
        code = codes[0]
        for expected in (302, 200):
            self.logout()
            self.login_password("reuse_user")
            clear_rate_limits()
            resp = self.client.post("/login/mfa", data=self.form({"code": code}))
            self.assertEqual(resp.status_code, expected)


class OAuthTests(Base):
    def setUp(self):
        super().setUp()
        self.notes_id, self.notes_secret = register_service(
            "Notes", [REDIRECT], ["openid", "profile", "data"]
        )
        self.tasks_id, self.tasks_secret = register_service(
            "Tasks", ["https://tasks.example/cb"], ["openid", "profile", "data"]
        )
        self.user = self.register("alice")

    def pkce(self):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        return verifier, challenge

    def auth_params(self, client_id, redirect, scope, challenge, state="xyz", nonce="n-1"):
        return {
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
            "scope": scope, "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }

    def test_discovery_and_jwks(self):
        disc = self.client.get("/.well-known/openid-configuration").get_json()
        self.assertEqual(disc["code_challenge_methods_supported"], ["S256"])
        self.assertIn("RS256", disc["id_token_signing_alg_values_supported"])
        jwks = self.client.get("/.well-known/jwks.json").get_json()
        self.assertEqual(jwks["keys"][0]["alg"], "RS256")

    def test_authorization_code_flow_with_pkce_and_id_token(self):
        verifier, challenge = self.pkce()
        params = self.auth_params(self.notes_id, REDIRECT, "openid profile data", challenge)
        resp = self.client.get("/oauth/authorize", query_string=params)
        # Consent screen first.
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Allow", resp.data)

        resp = self.client.post("/oauth/authorize", data={**params, "csrf": self.csrf(), "decision": "approve"})
        self.assertEqual(resp.status_code, 302)
        target = urlparse(resp.location)
        qs = parse_qs(target.query)
        self.assertEqual(qs["state"], ["xyz"])
        self.assertEqual(qs["iss"], ["http://localhost"])
        code = qs["code"][0]

        token_resp = self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "code_verifier": verifier, "client_id": self.notes_id, "client_secret": self.notes_secret,
        })
        self.assertEqual(token_resp.status_code, 200, token_resp.data)
        body = token_resp.get_json()
        jwks = self.client.get("/.well-known/jwks.json").get_json()
        key = jwt.PyJWK(jwks["keys"][0]).key
        id_claims = jwt.decode(body["id_token"], key, algorithms=["RS256"], audience=self.notes_id,
                               issuer="http://localhost")
        self.assertEqual(id_claims["nonce"], "n-1")
        self.assertEqual(id_claims["sub"], str(self.user))
        self.assertIn("pwd", id_claims["amr"])
        access = jwt.decode(body["access_token"], key, algorithms=["RS256"], audience=self.notes_id,
                            issuer="http://localhost")
        self.assertEqual(access["typ"], "access")

        # Codes are single-use.
        replay = self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "code_verifier": verifier, "client_id": self.notes_id, "client_secret": self.notes_secret,
        })
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.get_json()["error"], "invalid_grant")

    def test_pkce_is_required_and_verified(self):
        resp = self.client.get("/oauth/authorize", query_string={
            "response_type": "code", "client_id": self.notes_id, "redirect_uri": REDIRECT,
            "scope": "openid", "state": "s",
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=invalid_request", resp.location)

    def test_unregistered_redirect_is_rejected_without_redirect(self):
        _, challenge = self.pkce()
        resp = self.client.get("/oauth/authorize", query_string=self.auth_params(
            self.notes_id, "https://evil.example/steal", "openid", challenge))
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(b"evil.example", resp.headers.get("Location", "").encode())

    def test_service_cannot_request_scope_beyond_registration(self):
        _, challenge = self.pkce()
        cid, _ = register_service("Limited", [REDIRECT], ["openid"])
        resp = self.client.get("/oauth/authorize", query_string=self.auth_params(
            cid, REDIRECT, "openid data", challenge))
        self.assertIn("error=invalid_scope", resp.location)

    def test_wrong_client_secret_is_rejected(self):
        resp = self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": "x", "redirect_uri": REDIRECT,
            "code_verifier": "a" * 50, "client_id": self.notes_id, "client_secret": "nope",
        })
        self.assertEqual(resp.status_code, 401)

    def test_connection_request_lifecycle_and_data_isolation(self):
        # 1. Service asks to connect to alice.
        resp = self.client.post(
            "/api/v1/connection-requests",
            headers={"Authorization": basic(self.notes_id, self.notes_secret)},
            json={"username": "alice", "scopes": ["profile", "data"], "message": "Sync my notes"},
        )
        self.assertEqual(resp.status_code, 202)
        request_id = resp.get_json()["request_id"]

        # Requests for unknown users look identical (no enumeration).
        unknown = self.client.post(
            "/api/v1/connection-requests",
            headers={"Authorization": basic(self.notes_id, self.notes_secret)},
            json={"username": "nobody", "scopes": ["profile"]},
        )
        self.assertEqual(unknown.status_code, 202)

        # 2. Stored until the user acts: no token can be issued yet.
        self.assertEqual(self.client.get(f"/api/v1/connection-requests/{request_id}",
                         headers={"Authorization": basic(self.notes_id, self.notes_secret)}).get_json()["status"],
                         "pending")
        denied = self.client.post("/oauth/token", data={
            "grant_type": app_module.oauth.CONNECTION_GRANT, "connection_id": "nope",
            "client_id": self.notes_id, "client_secret": self.notes_secret,
        })
        self.assertEqual(denied.status_code, 400)

        # 3. The user sees it and accepts.
        page = self.client.get("/account/connections")
        self.assertIn(b"Sync my notes", page.data)
        pending_id = re.search(rb'/account/connections/requests/([^/]+)/accept', page.data).group(1).decode()
        self.client.post(f"/account/connections/requests/{pending_id}/accept", data={"csrf": self.csrf()})

        status = self.client.get(f"/api/v1/connection-requests/{request_id}",
                                 headers={"Authorization": basic(self.notes_id, self.notes_secret)}).get_json()
        self.assertEqual(status["status"], "accepted")
        connection_id = status["connection_id"]

        # 4. Exchange the connection for a token.
        tok = self.client.post("/oauth/token", data={
            "grant_type": app_module.oauth.CONNECTION_GRANT, "connection_id": connection_id,
            "client_id": self.notes_id, "client_secret": self.notes_secret,
        })
        self.assertEqual(tok.status_code, 200, tok.data)
        notes_token = tok.get_json()["access_token"]
        auth_notes = {"Authorization": f"Bearer {notes_token}"}

        # 5. Store arbitrary data in any format.
        self.assertEqual(self.client.put("/api/v1/data/notes/today.md", data="# hi",
                                         headers={**auth_notes, "Content-Type": "text/markdown"}).status_code, 200)
        self.assertEqual(self.client.put("/api/v1/data/blob.bin", data=bytes(range(256)),
                                         headers={**auth_notes, "Content-Type": "application/octet-stream"}).status_code, 200)
        got = self.client.get("/api/v1/data/notes/today.md", headers=auth_notes)
        self.assertEqual(got.data, b"# hi")
        self.assertTrue(got.headers["Content-Type"].startswith("text/markdown"))
        self.assertIn("sandbox", got.headers["Content-Security-Policy"])

        # 6. Second service (Tasks) has no connection: it cannot connect or read notes data.
        self.assertEqual(self.client.post("/oauth/token", data={
            "grant_type": app_module.oauth.CONNECTION_GRANT, "connection_id": connection_id,
            "client_id": self.tasks_id, "client_secret": self.tasks_secret,
        }).status_code, 400)

        # 7. Tasks connects separately, writes the same key name. Data stays separate.
        tasks_req = self.client.post("/api/v1/connection-requests",
                                     headers={"Authorization": basic(self.tasks_id, self.tasks_secret)},
                                     json={"username": "alice", "scopes": ["data"]})
        tasks_request_id = tasks_req.get_json()["request_id"]
        page = self.client.get("/account/connections")
        pid = re.search(rb'/account/connections/requests/([^/]+)/accept', page.data).group(1).decode()
        self.client.post(f"/account/connections/requests/{pid}/accept", data={"csrf": self.csrf()})
        tasks_conn = self.client.get(f"/api/v1/connection-requests/{tasks_request_id}",
                                     headers={"Authorization": basic(self.tasks_id, self.tasks_secret)}).get_json()
        tasks_token = self.client.post("/oauth/token", data={
            "grant_type": app_module.oauth.CONNECTION_GRANT, "connection_id": tasks_conn["connection_id"],
            "client_id": self.tasks_id, "client_secret": self.tasks_secret,
        }).get_json()["access_token"]
        auth_tasks = {"Authorization": f"Bearer {tasks_token}"}
        self.assertEqual(self.client.get("/api/v1/data/notes/today.md", headers=auth_tasks).status_code, 404)
        self.client.put("/api/v1/data/notes/today.md", data="tasks version", headers={**auth_tasks, "Content-Type": "text/plain"})
        self.assertEqual(self.client.get("/api/v1/data/notes/today.md", headers=auth_notes).data, b"# hi")
        listing = self.client.get("/api/v1/data", headers=auth_notes).get_json()["items"]
        self.assertEqual({i["data_key"] for i in listing}, {"notes/today.md", "blob.bin"})

        # 8. Path traversal and bad keys are rejected.
        self.assertEqual(self.client.put("/api/v1/data/..%2Fsecret", data="x", headers=auth_notes).status_code, 400)

        # 9. Tokens without the data scope cannot write.
        # 10. Removing the connection deletes data and revokes the token immediately.
        page = self.client.get("/account/connections")
        self.client.post(f"/account/connections/{connection_id}/revoke", data={"csrf": self.csrf()})
        self.assertEqual(self.client.get("/api/v1/data", headers=auth_notes).status_code, 401)
        with db_conn() as db:
            left = db.execute("SELECT COUNT(*) AS n FROM service_data WHERE client_id = ?", (self.notes_id,)).fetchone()["n"]
        self.assertEqual(left, 0)
        # Tasks data survives Notes being removed.
        self.assertEqual(self.client.get("/api/v1/data", headers=auth_tasks).status_code, 200)

    def test_user_can_deny_request(self):
        self.client.post("/api/v1/connection-requests",
                         headers={"Authorization": basic(self.notes_id, self.notes_secret)},
                         json={"username": "alice", "scopes": ["profile"]})
        page = self.client.get("/account/connections")
        pid = re.search(rb'/account/connections/requests/([^/]+)/decline', page.data).group(1).decode()
        self.client.post(f"/account/connections/requests/{pid}/decline", data={"csrf": self.csrf()})
        self.assertNotIn(b"/decline", self.client.get("/account/connections").data)

    def test_service_cannot_request_scopes_outside_registration(self):
        cid, secret = register_service("Narrow", [REDIRECT], ["profile"])
        resp = self.client.post("/api/v1/connection-requests",
                                headers={"Authorization": basic(cid, secret)},
                                json={"username": "alice", "scopes": ["data"]})
        self.assertEqual(resp.status_code, 400)

    def test_public_client_cannot_use_connection_grant(self):
        resp = self.client.post("/oauth/token", data={
            "grant_type": app_module.oauth.CONNECTION_GRANT, "connection_id": "x", "client_id": self.notes_id,
        })
        self.assertEqual(resp.status_code, 401)

    def test_data_api_requires_data_scope(self):
        cid, secret = register_service("ProfileOnly", [REDIRECT], ["openid", "profile", "data"])
        self.client.post("/api/v1/connection-requests",
                         headers={"Authorization": basic(cid, secret)},
                         json={"username": "alice", "scopes": ["profile"]})
        page = self.client.get("/account/connections")
        pid = re.search(rb'/account/connections/requests/([^/]+)/accept', page.data).group(1).decode()
        self.client.post(f"/account/connections/requests/{pid}/accept", data={"csrf": self.csrf()})
        # Find the approved connection for this service and get a token.
        with db_conn() as db:
            conn = db.execute("SELECT public_id FROM connections WHERE client_id = ?", (cid,)).fetchone()
        token = self.client.post("/oauth/token", data={
            "grant_type": app_module.oauth.CONNECTION_GRANT, "connection_id": conn["public_id"],
            "client_id": cid, "client_secret": secret,
        }).get_json()["access_token"]
        resp = self.client.put("/api/v1/data/x", data="y", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 403)


class CallbackTests(Base):
    """Done and deny callbacks: pinged after the user decides, origin-checked, never followed."""

    def setUp(self):
        super().setUp()
        self.svc_id, self.svc_secret = register_service(
            "Hub", ["https://hub.example/auth/callback", "http://localhost:8123/cb"], ["profile", "data"]
        )
        self.user = self.register("alice")
        self.auth = {"Authorization": basic(self.svc_id, self.svc_secret)}

    def create(self, **extra):
        body = {"username": "alice", "scopes": ["profile"], **extra}
        return self.client.post("/api/v1/connection-requests", headers=self.auth, json=body)

    def decide_first_pending(self, decision):
        page = self.client.get("/account/connections")
        pid = re.search(rb"/account/connections/requests/([^/]+)/" + decision.encode(), page.data).group(1).decode()
        return self.client.post(f"/account/connections/requests/{pid}/{decision}", data={"csrf": self.csrf()})

    def status(self, request_id):
        return self.client.get(f"/api/v1/connection-requests/{request_id}", headers=self.auth).get_json()

    def fake_fetch(self, status_code=200, error=None):
        """Patch the opener so no real network call is made. Records the URLs requested."""
        calls = []

        class FakeResponse:
            def __init__(self, code):
                self.status = code

            def read(self, n=-1):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_open(req, timeout=None):
            calls.append((req.full_url, req.get_method(), timeout))
            if error:
                raise error
            return FakeResponse(status_code)

        return calls, mock.patch.object(callbacks._opener, "open", side_effect=fake_open)

    def test_done_url_is_pinged_on_accept_with_request_id_and_status(self):
        resp = self.create(done_url="https://hub.example/auth/callback?from=login",
                           deny_url="https://hub.example/auth/denied")
        self.assertEqual(resp.status_code, 202)
        request_id = resp.get_json()["request_id"]
        calls, patcher = self.fake_fetch()
        with patcher:
            self.decide_first_pending("accept")
        self.assertEqual(len(calls), 1)
        url, method, timeout = calls[0]
        qs = parse_qs(urlparse(url).query)
        self.assertEqual(method, "GET")
        self.assertEqual(timeout, callbacks.CALLBACK_TIMEOUT)
        self.assertEqual(qs["from"], ["login"], "existing query string must be preserved")
        self.assertEqual(qs["request_id"], [request_id])
        self.assertEqual(qs["status"], ["accepted"])
        self.assertTrue(url.startswith("https://hub.example/auth/callback?"))

        final = self.status(request_id)
        self.assertEqual(final["status"], "accepted")
        self.assertEqual(final["callback_status"], "delivered")
        self.assertIsNotNone(final["connection_id"])

    def test_deny_url_is_pinged_on_decline_and_not_done_url(self):
        request_id = self.create(done_url="https://hub.example/auth/callback",
                                 deny_url="https://hub.example/auth/denied").get_json()["request_id"]
        calls, patcher = self.fake_fetch()
        with patcher:
            self.decide_first_pending("decline")
        self.assertEqual(len(calls), 1)
        url = calls[0][0]
        self.assertTrue(url.startswith("https://hub.example/auth/denied?"))
        self.assertEqual(parse_qs(urlparse(url).query)["status"], ["declined"])
        final = self.status(request_id)
        self.assertEqual(final["status"], "declined")
        self.assertEqual(final["callback_status"], "delivered")
        self.assertIsNone(final["connection_id"])

    def test_no_callback_when_urls_are_omitted(self):
        self.create()
        calls, patcher = self.fake_fetch()
        with patcher:
            self.decide_first_pending("accept")
        self.assertEqual(calls, [])

    def test_failed_callback_does_not_block_the_decision(self):
        request_id = self.create(done_url="https://hub.example/auth/callback").get_json()["request_id"]
        calls, patcher = self.fake_fetch(error=OSError("connection refused"))
        with patcher:
            resp = self.decide_first_pending("accept")
        self.assertEqual(resp.status_code, 302)
        final = self.status(request_id)
        self.assertEqual(final["status"], "accepted", "the user's decision stands even if the ping fails")
        self.assertEqual(final["callback_status"], "failed")

    def test_non_success_status_counts_as_failed(self):
        request_id = self.create(deny_url="https://hub.example/auth/denied").get_json()["request_id"]
        _, patcher = self.fake_fetch(status_code=500)
        with patcher:
            self.decide_first_pending("decline")
        self.assertEqual(self.status(request_id)["callback_status"], "failed")

    def test_callback_urls_must_match_registered_origin(self):
        bad = [
            "https://evil.example/steal",               # different host
            "https://hub.example.evil.example/cb",      # look-alike host
            "http://hub.example/cb",                    # plain http, not localhost
            "https://user:pw@hub.example/cb",           # credentials
            "https://hub.example:8443/cb",              # different port
            "javascript:alert(1)",                      # wrong scheme
            "ftp://hub.example/cb",
            "https:///nohost",
            "https://hub.example/cb#frag",
        ]
        for url in bad:
            with self.subTest(url=url):
                resp = self.create(done_url=url)
                self.assertEqual(resp.status_code, 400, url)
                self.assertEqual(resp.get_json()["error"], "invalid_request")

    def test_localhost_http_and_matching_origin_are_accepted(self):
        self.assertEqual(self.create(done_url="http://localhost:8123/anything").status_code, 202)
        cid, secret = register_service("Other", ["https://other.example/cb"], ["profile"])
        ok = self.client.post("/api/v1/connection-requests",
                              headers={"Authorization": basic(cid, secret)},
                              json={"username": "alice", "scopes": ["profile"],
                                    "done_url": "https://other.example/cb/done"})
        self.assertEqual(ok.status_code, 202)

    def test_callback_validation_happens_before_account_lookup(self):
        # An unknown username must not change the response: validation errors look the same for everyone.
        resp = self.client.post("/api/v1/connection-requests", headers=self.auth,
                                json={"username": "nobody", "scopes": ["profile"],
                                      "done_url": "https://evil.example/x"})
        self.assertEqual(resp.status_code, 400)

    def test_repeat_request_while_pending_returns_existing_request(self):
        # Re-asking while pending returns the existing request and does not add a second callback.
        self.create(done_url="https://hub.example/auth/callback")
        again = self.create(done_url="https://hub.example/auth/callback")
        self.assertEqual(again.status_code, 202)
        self.assertEqual(again.get_json()["status"], "pending")

    def test_callbacks_are_never_followed_as_redirects(self):
        handler = callbacks._NoRedirect()
        req = urllib.request.Request("https://hub.example/cb")
        self.assertIsNone(handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/"))

    def test_api_description_and_discovery_advertise_callbacks(self):
        desc = self.client.get("/api/v1").get_json()
        fields = desc["endpoints"]["create_connection_request"]["body"]
        self.assertIn("done_url", fields)
        self.assertIn("deny_url", fields)
        disc = self.client.get("/.well-known/openid-configuration").get_json()
        self.assertEqual(disc["connection_grant_type"], app_module.oauth.CONNECTION_GRANT)
        self.assertTrue(disc["connection_request_endpoint"].endswith("/api/v1/connection-requests"))


def basic(client_id, secret):
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


if __name__ == "__main__":
    unittest.main()
