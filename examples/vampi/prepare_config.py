"""Create two VAmPI test accounts and fill a GrantTrace draft for them.

Usage:
    python prepare_config.py http://127.0.0.1:5002 draft.json vampi.local.json

The draft comes from `granttrace --spec openapi3.yml --init-config draft.json`.
The script registers an Owner and a Visitor, logs both in, adds one book for
each, and writes a configuration that keeps the scan read-only. Run it only
against a VAmPI instance you started yourself; it needs no third-party packages.
The output holds live tokens: keep the `.local.json` suffix, which Git ignores.
See docs/case-studies/vampi.md.
"""

from __future__ import annotations

import json
import secrets
import sys
import urllib.error
import urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(base: str, method: str, path: str, body=None, token=None) -> dict:
    request = urllib.request.Request(base + path, method=method,
                                      data=json.dumps(body).encode() if body is not None else None)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with OPENER.open(request, timeout=10) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} {path} failed with HTTP {error.code}: {error.read()[:200]!r}")


def main(base: str, draft_path: str, output_path: str) -> None:
    suffix = secrets.token_hex(3)
    accounts = {}
    for role in ("owner", "visitor"):
        username, password = f"gt_{role}_{suffix}", secrets.token_urlsafe(12)
        call(base, "POST", "/users/v1/register",
             {"username": username, "password": password, "email": f"{username}@example.test"})
        token = call(base, "POST", "/users/v1/login", {"username": username, "password": password})["auth_token"]
        book = f"gt-{role}-book-{suffix}"
        call(base, "POST", "/books/v1", {"book_title": book, "secret": f"{role} secret {suffix}"}, token)
        accounts[role] = {"username": username, "token": token, "book": book}

    # The Owner's position in the public user list locates its password in /users/v1/_debug.
    users = call(base, "GET", "/users/v1")["users"]
    owner_index = [user["username"] for user in users].index(accounts["owner"]["username"])

    with open(draft_path, encoding="utf-8") as handle:
        config = json.load(handle)
    config.pop("_granttrace_draft")
    for role, account in accounts.items():
        config["identities"][role].update({"id": account["username"], "token": "Bearer " + account["token"]})
    config["parameter_values"] = {
        "GET /books/v1/{book_title}": {role: {"book_title": a["book"]} for role, a in accounts.items()},
        "GET /users/v1/{username}": {role: {"username": a["username"]} for role, a in accounts.items()},
    }
    config["readbacks"] = {}        # first scan is read-only: no PUT readbacks
    config["write_allowlist"] = []
    config["bola"] = {
        # VAmPI: only the owner of a book may see its secret.
        "GET /books/v1/{book_title}": {"resource_id_paths": ["book_title"], "private_data_paths": ["secret"]},
        # VAmPI: unregistered users may see basic user information.
        "GET /users/v1/{username}": {"expected_public": True},
        # A user's password is private; the debug endpoint lists every user.
        "GET /users/v1/_debug": {"private_data_paths": [f"users[{owner_index}].password"]},
    }
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    print(f"Owner {accounts['owner']['username']} and Visitor {accounts['visitor']['username']} "
          f"configured in {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    main(*sys.argv[1:4])
