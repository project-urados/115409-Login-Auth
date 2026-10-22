#!/usr/bin/env python3
"""Administrative CLI: register services (OAuth clients) and inspect them.

Services cannot register themselves over the web. An operator runs this tool,
which prints the client secret once. Only a salted hash is stored.

Examples:
  python manage.py add-service --name "Notes App" --redirect https://notes.example/callback \
      --scopes openid profile data
  python manage.py list-services
  python manage.py rotate-secret <client_id>
  python manage.py remove-service <client_id>
"""

import argparse
import secrets
import sys
import time

from werkzeug.security import generate_password_hash

from core import db_conn, init_db


def new_client_id(name):
    slug = "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")[:30] or "service"
    return f"{slug}-{secrets.token_hex(6)}"


def create_service(name, redirects, scopes):
    """Register a confidential service. Returns (client_id, client_secret)."""
    client_id = new_client_id(name)
    secret = secrets.token_urlsafe(32)
    with db_conn() as db:
        db.execute(
            "INSERT INTO oauth_clients(client_id, name, secret_hash, redirect_uris, allowed_scopes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                client_id,
                name,
                generate_password_hash(secret),
                " ".join(redirects),
                " ".join(sorted(set(scopes))),
                int(time.time()),
            ),
        )
    return client_id, secret


def add_service(args):
    client_id, secret = create_service(args.name, args.redirect, args.scopes)
    print(f"client_id:     {client_id}")
    print(f"client_secret: {secret}")
    print("Store the secret now. It cannot be shown again.")


def list_services(_args):
    with db_conn() as db:
        rows = db.execute("SELECT client_id, name, redirect_uris, allowed_scopes FROM oauth_clients ORDER BY name").fetchall()
    for row in rows:
        print(f"{row['client_id']}\t{row['name']}\tscopes=[{row['allowed_scopes']}]\tredirect={row['redirect_uris']}")


def rotate_secret(args):
    secret = secrets.token_urlsafe(32)
    with db_conn() as db:
        updated = db.execute(
            "UPDATE oauth_clients SET secret_hash = ? WHERE client_id = ?",
            (generate_password_hash(secret), args.client_id),
        ).rowcount
    if not updated:
        sys.exit("No such client.")
    print(f"client_secret: {secret}")


def remove_service(args):
    # Foreign keys cascade: removing a service deletes its connections, requests and stored data.
    with db_conn() as db:
        deleted = db.execute("DELETE FROM oauth_clients WHERE client_id = ?", (args.client_id,)).rowcount
    if not deleted:
        sys.exit("No such client.")
    print("Service removed, along with its connections and stored data.")


def main():
    init_db()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add-service", help="register a service")
    add.add_argument("--name", required=True)
    add.add_argument("--redirect", action="append", required=True, help="allowed redirect URI (repeatable)")
    add.add_argument("--scopes", nargs="+", default=["openid", "profile"], choices=["openid", "profile", "data"])
    add.set_defaults(func=add_service)

    sub.add_parser("list-services").set_defaults(func=list_services)

    rot = sub.add_parser("rotate-secret")
    rot.add_argument("client_id")
    rot.set_defaults(func=rotate_secret)

    rm = sub.add_parser("remove-service")
    rm.add_argument("client_id")
    rm.set_defaults(func=remove_service)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
