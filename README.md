# Local Auth: accounts, MFA, OIDC/OAuth 2.0 and connected services

<p align="center">
  <img
    src="assets/tutorial.gif"
    alt="Demonstration of the Login Auth application"
    width="800"
  />
</p>

A Flask identity provider. Users sign in with a password plus a TOTP second factor
and decide which external services may connect to their account and what data
each one may store.

## Features

- **Accounts** in SQLite: registration, sign-in, profile and password changes, CSRF protection, rate limits, and a local bot check.
- **MFA**: RFC 6238 TOTP (authenticator apps), 8 single-use recovery codes, replay protection per time step, and an activity log.
- **OpenID Connect / OAuth 2.0**: authorization code flow with **PKCE (S256) required**, RS256-signed JWT ID and access tokens, JWKS, discovery, and userinfo.
- **Connection requests**: a registered service asks to connect to a user. The request is stored for that user until they accept or decline it.
- **Per-service data**: an approved service can store and read any content in any format (up to 1 MiB per item). A service can only touch its own data.
- **Global footer**: configured in `footer_config.json`, applied to every page, can be disabled with one setting.

## Folder layout

```text
.
├── app.py              routes for the public site and account
├── core.py             database, CSRF, rate limits, bot check, sealing, shared helpers
├── mfa.py              TOTP, recovery codes, MFA setup and sign-in step
├── oauth.py            OIDC discovery, JWKS, authorize, token, userinfo
├── connections.py      connection requests, connected-services UI, service data API
├── footer.py           footer loader (self-contained)
├── footer_config.json  edit this to change the footer everywhere
├── manage.py           CLI to register and manage services
├── requirements.txt
├── templates/          Jinja templates
├── static/             CSS, favicon
└── tests/test_app.py   end-to-end tests
```

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py --host <ip> --port <port>
```

Open <http://127.0.0.1:5000>. Environment variables:

| Variable | Purpose |
| --- | --- |
| `FLASK_SECRET_KEY` | Required. Also seeds the key that seals secrets at rest. Changing it invalidates sessions, MFA secrets, and signing keys. |
| `AUTH_DB` | SQLite path (default `auth.sqlite3`). |
| `OIDC_ISSUER` | Public issuer URL, e.g. `https://id.example.com`. Defaults to the request host. Set it in production. |
| `HTTPS_ONLY` | `1` to set Secure cookies and HSTS. Use this in production. |
| `FOOTER_CONFIG` | Path to an alternative footer JSON file. |

Without `segno`, the MFA page shows the manual setup key but no QR code.

## Registering a service

Services cannot register themselves, so an unknown site cannot create a client.

```bash
python manage.py add-service --name "Notes App" \
  --redirect https://notes.example/callback \
  --scopes openid profile data
python manage.py list-services
python manage.py rotate-secret <client_id>
python manage.py remove-service <client_id>
```

The secret is printed once and stored only as a salted hash.

## How a service connects

1. **Ask.** The service calls `POST /api/v1/connection-requests` with Basic auth (`client_id:secret`) and body `{"username": "...", "scopes": ["profile", "data"], "message": "..."}`. The response is identical for unknown usernames, so you can't enumerate accounts.
2. **Stored.** The request appears under *Connected services* for that user. It cannot grant access until the user accepts it.
3. **Approve.** The user clicks *Accept* or *Decline*. Accepting creates an approved connection.
4. **Exchange.** The service polls `GET /api/v1/connection-requests/<id>` for its `connection_id`, then calls `POST /oauth/token` with `grant_type=urn:local-auth:params:oauth:grant-type:connection`, `connection_id`, and its client credentials. Only confidential clients may use this grant.
5. **Use.** The service calls the data API with `Authorization: Bearer <token>`.

### Browser sign-in (authorization code + PKCE)

Redirect the user to `/oauth/authorize` with `response_type=code`, `client_id`, `redirect_uri` (must match a registered URI exactly), `scope`, `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`. The user is shown a consent screen. Then exchange the code at `/oauth/token` with `code_verifier`. The response has an `access_token`, and an `id_token` when `openid` is requested.

Discovery: `/.well-known/openid-configuration`. Keys: `/.well-known/jwks.json`. Userinfo: `/oauth/userinfo`.

### Data API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/data` | List this service's items for the user |
| `GET` | `/api/v1/data/<key>` | Read an item, returned with its stored content type |
| `PUT` | `/api/v1/data/<key>` | Write an item. Body is stored as-is with the request `Content-Type`. |
| `DELETE` | `/api/v1/data/<key>` | Delete an item |

Keys may contain letters, digits, `.`, `_`, `-`, and `/`. They cannot contain `..`. Stored content is served with `Content-Security-Policy: sandbox`, so a browser will not run script from it.

### Isolation rules

- Every row is keyed by `(user_id, client_id, key)`. `user_id` and `client_id` come from the verified token and the authenticated client, never from the request.
- Revoking a connection deletes that service's data for that user and invalidates its tokens immediately, because every token is checked against the live connection row.
- Revoking one service never touches another service's data.
- Access tokens expire after 15 minutes. Authorization codes last 60 seconds and are single-use.

## Footer

Edit `footer_config.json`:

- `"enabled": false` hides the footer on every page.
- `brand`, `tagline`, `copyright`, and `show_year` set the text.
- `columns` define the link groups. Only same-site paths and `http(s)` URLs are accepted. Other schemes are dropped.

The footer loads once per process, so restart the app after editing.

## Security notes

- Passwords are hashed with Werkzeug's scrypt/PBKDF2 defaults. MFA secrets, signing keys, and recovery codes are never stored in plaintext: secrets are encrypted with a key derived from `FLASK_SECRET_KEY`, and recovery codes are keyed hashes.
- Tokens are signed with RS256. The verifier pins the algorithm, so `alg: none` and HS/RS confusion are rejected.
- The CSP forbids inline scripts and styles. Templates have no inline `style` attributes or scripts.
- The local bot check and honeypot are friction only, not a real CAPTCHA.
- This is a single-instance design. The SQLite rate limiter and key cache are per process. For production, use a WSGI server (for example, gunicorn with one worker, or a shared database), HTTPS, `HTTPS_ONLY=1`, and a managed secret.
- Not included yet: email verification, password reset, account deletion, and admin tooling. Account deletion is the main gap, since it's needed to meet data-erasure requirements.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers the footer, MFA enrolment and login (including TOTP replay and single-use recovery codes), PKCE and redirect validation, scope limits, the connection-request lifecycle, data isolation between services, scope enforcement on the data API, and revocation.
