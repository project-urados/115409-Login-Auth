"""Done and deny callbacks for connection requests.

When a service creates a connection request it may include:

  done_url  pinged after the user accepts the request
  deny_url  pinged after the user declines the request

Local Auth sends a GET to the URL, adding these query parameters (any existing
query string is kept):

  request_id  the public request ID returned by the connection-request API
  status      "accepted" or "declined"

A callback is a notification only. It is not proof of anything: the service
must still poll GET /api/v1/connection-requests/<id> with its own credentials
to learn the outcome and exchange the connection for a token.

Safety rules:
  * Callback URLs must share an origin (scheme, host, port) with one of the
    service's registered redirect URIs, so a service cannot make Local Auth
    contact arbitrary hosts.
  * Only https is accepted. Plain http is allowed only for localhost.
  * No userinfo, no fragments, and no redirects are followed.
  * Delivery has a short timeout and never blocks or fails the user's decision.
"""

import ipaddress
import logging
import time
import urllib.request
from urllib.parse import urlencode, urlsplit, urlunsplit

from core import db_conn

log = logging.getLogger("local_auth.callbacks")

MAX_CALLBACK_URL = 500
CALLBACK_TIMEOUT = 5  # seconds
STATUS_ACCEPTED = "accepted"
STATUS_DECLINED = "declined"


def _origin(parts):
    host = (parts.hostname or "").lower()
    port = parts.port
    default = {"https": 443, "http": 80}.get(parts.scheme)
    if port is None or port == default:
        return (parts.scheme, host, default)
    return (parts.scheme, host, port)


def _is_localhost(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_callback_url(url, redirect_uris):
    """Return None if the URL is acceptable, otherwise a short error message.

    `redirect_uris` is the list of URIs registered for the service.
    """
    if len(url) > MAX_CALLBACK_URL:
        return "Callback URLs are limited to 500 characters."
    try:
        parts = urlsplit(url)
        parts.port  # raises ValueError for a malformed port
    except ValueError:
        return "Callback URL is malformed."
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return "Callback URLs must be absolute https:// URLs."
    if parts.scheme == "http" and not _is_localhost(parts.hostname):
        return "Plain http callbacks are allowed only for localhost."
    if parts.username is not None or parts.password is not None:
        return "Callback URLs must not contain credentials."
    if parts.fragment:
        return "Callback URLs must not contain a fragment."
    origin = _origin(parts)
    for registered in redirect_uris:
        try:
            if _origin(urlsplit(registered)) == origin:
                return None
        except ValueError:
            continue
    return "Callback URL must share an origin with one of the service's registered redirect URIs."


def build_callback_url(base_url, request_id, status):
    """Add request_id and status to the URL, keeping any existing query string."""
    parts = urlsplit(base_url)
    existing = parts.query
    extra = urlencode({"request_id": request_id, "status": status})
    query = f"{existing}&{extra}" if existing else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: the callback target is fixed by the service."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def deliver_callback(public_id, base_url, status):
    """Ping the service and record the outcome on the request row.

    Called after the decision has been committed, so a slow or failing service
    never affects the user's decision. Returns "delivered" or "failed".
    """
    if not base_url:
        return ""
    url = build_callback_url(base_url, public_id, status)
    outcome = "failed"
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "LocalAuth-Callback/1"})
        with _opener.open(req, timeout=CALLBACK_TIMEOUT) as resp:
            resp.read(1024)  # discard the body; only the status code matters
            if 200 <= resp.status < 400:
                outcome = "delivered"
    except Exception as exc:  # network error, timeout, non-2xx/3xx status, etc.
        log.warning("callback for request %s failed: %s", public_id, exc.__class__.__name__)
    with db_conn() as db:
        db.execute(
            "UPDATE connection_requests SET callback_status = ?, callback_at = ? WHERE public_id = ?",
            (outcome, int(time.time()), public_id),
        )
    return outcome
