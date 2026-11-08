"""Create two crAPI test users with their own objects and fill a GrantTrace draft.

Usage:
    python prepare_config.py http://127.0.0.1:8888 http://127.0.0.1:8025 draft.json crapi.local.json
    python prepare_config.py --post-field-rules http://127.0.0.1:8888 http://127.0.0.1:8025 draft.json posts.local.json

The draft comes from `granttrace --spec crapi-openapi-spec.json --init-config draft.json`.
The Owner is the administrator crAPI seeds (admin@example.com, with the password
published in crAPI's source), so one scan covers both object-level checks and
the administrator-only user list. The Visitor is a new user: the script signs it
up and adds the vehicle whose VIN and pincode crAPI mails to Mailhog. For both,
it asks a mechanic for service (a report), places an order, writes a community
post and uploads a small profile video. It then fills the draft so the scan
stays read-only. Run it only against a crAPI instance you started yourself; it
needs no third-party packages. The output holds live tokens: keep the
`.local.json` suffix, which Git ignores.

--post-field-rules adds BOPLA field rules: the author's email and vehicle ID in
a community post may be read by the author only. While any BOPLA rule is set,
reports omit response bodies, URLs and reasons for every check, so run it as a
separate scan. See docs/case-studies/crapi.md.
"""

from __future__ import annotations

import html
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email import message_from_string

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
SEEDED_ADMIN = ("admin@example.com", "Admin!123")  # crAPI's own seed data (TestUsers.java)


def call(base: str, method: str, path: str, body=None, token=None):
    request = urllib.request.Request(base + path, method=method,
                                      data=json.dumps(body).encode() if body is not None else None)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with OPENER.open(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} {path} failed with HTTP {error.code}: {error.read()[:300]!r}")


def upload_video(base: str, token: str, name: str) -> int:
    """A small random file as the profile video; crAPI stores it without decoding."""
    boundary = "granttrace" + secrets.token_hex(8)
    content = secrets.token_bytes(2048)
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            "Content-Type: video/mp4\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(base + "/identity/api/v2/user/videos", data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Authorization", "Bearer " + token)
    with OPENER.open(request, timeout=30) as response:
        return json.loads(response.read())["id"]


def vehicle_from_mail(mailhog: str, email: str) -> tuple:
    """The VIN and pincode crAPI mails after signup; a fresh instance can take a minute."""
    for _ in range(120):
        query = urllib.parse.urlencode({"kind": "to", "query": email})
        found = call(mailhog, "GET", "/api/v2/search?" + query)
        for item in found.get("items", []):
            # Parse the raw message: Mailhog's decoded Content.Body can be empty.
            message = message_from_string(item["Raw"]["Data"])
            payload = message.get_payload(decode=True) or b""
            text = html.unescape(re.sub(r"<[^>]+>", " ", payload.decode("utf-8", "replace")))
            vin = re.search(r"VIN:\s*([A-Z0-9]{17})", text)
            pincode = re.search(r"Pincode:\s*(\d{4})", text)
            if vin and pincode:
                return vin.group(1), pincode.group(1)
        time.sleep(1)
    raise SystemExit(f"No vehicle mail for {email} in Mailhog")


def sign_up(base: str, mailhog: str, role: str, suffix: str) -> tuple:
    """A new user with the vehicle crAPI mails to it."""
    email = f"gt.{role}.{suffix}@example.test"
    password = "Gt!" + secrets.token_hex(4) + "a1"
    number = "55" + "".join(secrets.choice("0123456789") for _ in range(8))
    call(base, "POST", "/identity/api/auth/signup",
         {"name": f"GT {role.title()} {suffix}", "email": email, "number": number, "password": password})
    token = call(base, "POST", "/identity/api/auth/login", {"email": email, "password": password})["token"]
    vin, pincode = vehicle_from_mail(mailhog, email)
    call(base, "POST", "/identity/api/v2/vehicle/add_vehicle", {"vin": vin, "pincode": pincode}, token)
    return email, token


def create_objects(base: str, email: str, token: str, role: str, suffix: str) -> dict:
    vehicle = call(base, "GET", "/identity/api/v2/vehicle/vehicles", token=token)[0]
    vin = vehicle["vin"]
    mechanic = call(base, "GET", "/workshop/api/mechanic/", token=token)["mechanics"][0]["mechanic_code"]
    contact = call(base, "POST", "/workshop/api/merchant/contact_mechanic", {
        "mechanic_code": mechanic, "problem_details": f"GrantTrace {role} test report {suffix}", "vin": vin,
        "mechanic_api": "https://crapi-workshop:8000/workshop/api/mechanic/receive_report",
        "repeat_request_if_failed": False, "number_of_repeats": 1,
    }, token)
    report_id = str(contact["response_from_mechanic_api"]["id"])
    product = call(base, "GET", "/workshop/api/shop/products", token=token)["products"][0]["id"]
    order = call(base, "POST", "/workshop/api/shop/orders", {"product_id": product, "quantity": 1}, token)
    post = call(base, "POST", "/community/api/v2/community/posts",
                {"title": f"GrantTrace {role} post {suffix}", "content": f"Test post by the {role}"}, token)
    video_id = upload_video(base, token, f"gt-{role}-{suffix}.mp4")
    return {"email": email, "token": token, "vehicle_id": vehicle["uuid"], "report_id": report_id,
            "order_id": order["id"], "post_id": post["id"], "video_id": video_id}


def main(base: str, mailhog: str, draft_path: str, output_path: str, post_field_rules: bool = False) -> None:
    suffix = secrets.token_hex(3)
    admin_email, admin_password = SEEDED_ADMIN
    admin_token = call(base, "POST", "/identity/api/auth/login",
                       {"email": admin_email, "password": admin_password})["token"]
    accounts = {
        "owner": create_objects(base, admin_email, admin_token, "owner", suffix),
        "visitor": create_objects(base, *sign_up(base, mailhog, "visitor", suffix), "visitor", suffix),
    }
    with open(draft_path, encoding="utf-8") as handle:
        config = json.load(handle)
    config.pop("_granttrace_draft")
    for role, account in accounts.items():
        config["identities"][role].update({"id": account["email"], "token": "Bearer " + account["token"]})
    selectors = {
        "GET /identity/api/v2/vehicle/{vehicleId}/location": ("vehicleId", "vehicle_id"),
        "GET /workshop/api/mechanic/mechanic_report": ("report_id", "report_id"),
        "GET /workshop/api/shop/orders/{order_id}": ("order_id", "order_id"),
        "GET /community/api/v2/community/posts/{postId}": ("postId", "post_id"),
        "GET /identity/api/v2/user/videos/{video_id}": ("video_id", "video_id"),
    }
    config["parameter_values"] = {
        operation: {role: {name: account[key]} for role, account in accounts.items()}
        for operation, (name, key) in selectors.items()
    }
    config["readbacks"] = {}        # read-only scan: no PUT readbacks
    config["write_allowlist"] = []
    config["bola"] = {
        # Challenge 1: any user's vehicle location, with the owner's name and email.
        "GET /identity/api/v2/vehicle/{vehicleId}/location": {
            "resource_id_paths": ["carId"], "private_data_paths": ["email"]},
        # Challenge 2: any user's mechanic report, with the vehicle's VIN and owner.
        "GET /workshop/api/mechanic/mechanic_report": {
            "resource_id_paths": ["id"], "private_data_paths": ["vehicle.vin"]},
        # Challenge 14: the order lookup checks no token at all.
        "GET /workshop/api/shop/orders/{order_id}": {
            "resource_id_paths": ["order.id"], "private_data_paths": ["order.user.email"]},
        # Forum posts are meant for every signed-in user.
        "GET /community/api/v2/community/posts/{postId}": {
            "resource_id_paths": ["id"], "expected_visitor_access": "allow"},
        # crAPI answers another user's video with 404 "Video not found".
        "GET /identity/api/v2/user/videos/{video_id}": {
            "resource_id_paths": ["id"], "not_found_is_denial": True},
        # An administrator view of every user, which checks only that a token is present.
        "GET /workshop/api/management/users/all": {
            "required_role": "admin", "owner_role": "admin", "visitor_role": "user",
            "private_data_paths": ["users[0].user.email"]},
    }
    if post_field_rules:
        # Challenge 4: every signed-in user may read a post, but not its author's email or vehicle ID.
        def rule(field: str) -> dict:
            return {"rule_id": f"author-{field}-private", "path": f"author.{field}",
                    "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                    "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}
        config["bopla"] = {"GET /community/api/v2/community/posts/{postId}": {
            "policy_id": "crapi-post-author", "context_id": "owner-post",
            "resource_binding": {"id": accounts["owner"]["post_id"]},
            "fields": [rule("email"), rule("vehicleid")],
        }}
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    print(json.dumps({role: {k: v for k, v in a.items() if k != "token"} for role, a in accounts.items()}, indent=1))


if __name__ == "__main__":
    arguments = [argument for argument in sys.argv[1:] if argument != "--post-field-rules"]
    if len(arguments) != 4:
        raise SystemExit(__doc__)
    main(*arguments, post_field_rules="--post-field-rules" in sys.argv[1:])
