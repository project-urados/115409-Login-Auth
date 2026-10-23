#!/usr/bin/env python3
"""Exercise Local Auth's connection-request and per-service data APIs.

This is intentionally an external client: it talks to Local Auth over HTTP and
never opens or modifies the Local Auth SQLite database directly.
"""

import argparse
import base64
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class LocalAuthError(RuntimeError):
    pass


def api_url(base_url, path):
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def request_json(base_url, path, *, method="GET", headers=None, body=None, expected=200):
    request = Request(api_url(base_url, path), method=method, headers=headers or {}, data=body)
    try:
        with urlopen(request, timeout=10) as response:
            status = response.status
            raw = response.read()
    except HTTPError as error:
        status = error.code
        raw = error.read()
    except URLError as error:
        raise LocalAuthError(f"Cannot reach Local Auth at {base_url}: {error.reason}") from error

    try:
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = {"raw": raw.decode("utf-8", errors="replace")}
    if status != expected:
        description = payload.get("error_description") or payload.get("error") or payload.get("raw")
        raise LocalAuthError(f"{method} {path} returned HTTP {status}: {description}")
    return payload


def basic_auth(client_id, client_secret):
    value = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {"Authorization": f"Basic {value}"}


def connection_status(base_url, request_id, client_id, client_secret):
    return request_json(
        base_url,
        f"/api/v1/connection-requests/{request_id}",
        headers=basic_auth(client_id, client_secret),
    )


def main():
    parser = argparse.ArgumentParser(
        description="Run an end-to-end Local Auth connection and data API test."
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LOCAL_AUTH_URL", "http://127.0.0.1:5000"),
        help="Local Auth URL (default: %(default)s)",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("LOCAL_AUTH_CLIENT_ID"),
        required=not os.environ.get("LOCAL_AUTH_CLIENT_ID"),
        help="Registered Local Auth service client ID (or LOCAL_AUTH_CLIENT_ID)",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("LOCAL_AUTH_CLIENT_SECRET"),
        required=not os.environ.get("LOCAL_AUTH_CLIENT_SECRET"),
        help="Registered service secret (or LOCAL_AUTH_CLIENT_SECRET)",
    )
    parser.add_argument("--username", required=True, help="Local Auth user to request")
    parser.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        default=None,
        help="Requested scope; repeat for multiple scopes (default: data)",
    )
    parser.add_argument("--message", default="Localhost connection API test")
    parser.add_argument("--data-key", default="connection-test/status")
    parser.add_argument("--data", default="connection test passed\n")
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=2.0,
        help="Seconds between approval checks (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=300.0,
        help="How long to wait for the user to approve or decline (default: %(default)s)",
    )
    parser.add_argument(
        "--request-only",
        action="store_true",
        help="Create the request and exit without waiting for approval",
    )
    args = parser.parse_args()
    scopes = args.scopes or ["data"]

    try:
        # This also provides an immediate, useful connectivity check.
        description = request_json(args.base_url, "/api/v1")
        print(f"Connected to {description.get('name', 'Local Auth')} at {args.base_url}")

        request_body = json.dumps(
            {"username": args.username, "scopes": scopes, "message": args.message}
        ).encode()
        created = request_json(
            args.base_url,
            "/api/v1/connection-requests",
            method="POST",
            headers={
                **basic_auth(args.client_id, args.client_secret),
                "Content-Type": "application/json",
            },
            body=request_body,
            expected=202,
        )
        request_id = created.get("request_id")
        if not request_id:
            print(created.get("message", "The request was accepted without a visible request ID."))
            return 0
        print(f"Connection request created: {request_id}")
        print("Open Local Auth, sign in as the target user, and accept the pending request.")

        if args.request_only:
            return 0

        deadline = time.monotonic() + args.timeout_seconds
        status = None
        while time.monotonic() < deadline:
            status = connection_status(
                args.base_url, request_id, args.client_id, args.client_secret
            )
            print(f"  status: {status.get('status')}")
            if status.get("status") in {"accepted", "declined"}:
                break
            time.sleep(max(0.1, args.poll_seconds))
        else:
            raise LocalAuthError("Timed out waiting for the user to decide the request.")

        if status.get("status") != "accepted":
            raise LocalAuthError("The Local Auth user declined the connection request.")
        connection_id = status.get("connection_id")
        if not connection_id:
            raise LocalAuthError("Local Auth accepted the request but returned no connection ID.")

        token_form = urlencode(
            {
                "grant_type": "urn:local-auth:params:oauth:grant-type:connection",
                "connection_id": connection_id,
                "client_id": args.client_id,
                "client_secret": args.client_secret,
            }
        ).encode()
        token = request_json(
            args.base_url,
            "/oauth/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=token_form,
        )
        access_token = token.get("access_token")
        if not access_token:
            raise LocalAuthError("Token response did not contain an access_token.")
        bearer = {"Authorization": f"Bearer {access_token}"}

        stored = request_json(
            args.base_url,
            f"/api/v1/data/{args.data_key}",
            method="PUT",
            headers={**bearer, "Content-Type": "text/plain; charset=utf-8"},
            body=args.data.encode("utf-8"),
        )
        retrieved = request_json(
            args.base_url,
            f"/api/v1/data/{args.data_key}",
            headers=bearer,
            expected=200,
        )
        # A text data item is returned as raw bytes, not JSON.
        if retrieved.get("raw", "").encode("utf-8") != args.data.encode("utf-8"):
            raise LocalAuthError("The stored data did not match the data read back.")
        print(f"Stored and verified {stored.get('size', len(args.data.encode('utf-8')))} bytes")
        print("Connection test passed.")
        return 0
    except LocalAuthError as error:
        print(f"Connection test failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
