# Local Flask authentication demo

This small app stores accounts in a local SQLite database and does not call external services. It includes registration, sign-in/out, profile-name and password changes, password hashing, CSRF checks, basic SQLite-backed rate limits, and a local math challenge plus honeypot.

## Folder layout

```text
flask_auth_demo/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── account.html
│   └── error.html
└── static/
    └── css/
        └── style.css
```

Flask discovers `templates/` and `static/` automatically relative to `app.py`.

## Run locally

```bash
cd flask_auth_demo
python -m venv .venv
. .venv/bin/activate             # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open <http://127.0.0.1:5000>. `auth.sqlite3` is created in the current directory. Set `AUTH_DB=/path/to/auth.sqlite3` to choose another location. Keep `FLASK_SECRET_KEY` stable and secret; changing it invalidates existing sessions.

## Security limits

The math challenge and honeypot provide lightweight friction, not a robust CAPTCHA or proof against a determined bot. This example has no email verification, password-reset flow, or account-deletion feature. The SQLite limiter is intended for a small single-instance app. Do not expose Flask's development server directly to the internet. For public deployment, use a production WSGI server, HTTPS, `HTTPS_ONLY=1`, a securely managed secret key, backups, monitoring, and a reviewed security design. Forwarded client IP headers are intentionally not trusted.
