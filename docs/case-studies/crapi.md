# Case study: GrantTrace against crAPI

[Back to the README](../../README.md) · [VAmPI case study](vampi.md)

[crAPI](https://github.com/OWASP/crAPI) ("completely ridiculous API") is an
OWASP project: a car-owner portal split into identity (Java), community (Go)
and workshop (Python) services behind an nginx gateway, with a published list
of challenges. This page records a read-only GrantTrace run against it: what it
found, what it missed and why, and where crAPI's own behavior got in the way.

| | |
|---|---|
| Date | 2026-11-08 |
| crAPI | release `v1.1.6` (commit `700f03d`), images tagged `latest` (built 2025-09-22; digests [below](#reproduce)), run with Docker Compose on `127.0.0.1` |
| Not deployed | the LLM chatbot and its vector database, which need an OpenAI key |
| GrantTrace | 2.6.0 ([#80](https://github.com/ysc070528/granttrace/pull/80) to [#83](https://github.com/ysc070528/granttrace/pull/83) included) |
| Specification | crAPI's own `openapi-spec/crapi-openapi-spec.json`, unmodified (44 operations, 16 of them GET) |
| Identities | Owner: crAPI's seeded administrator; Visitor: a new user; Anonymous |
| Scan | read-only; 43 GET requests per scan, no other method |

## Summary

- GrantTrace **confirmed** four authorization flaws: another user's mechanic
  report (challenge 2), an order lookup without authentication (challenge 14),
  an administrator-only user list any signed-in user can read (not in crAPI's
  published list), and, with BOPLA field rules in a separate scan, post authors'
  email addresses and vehicle IDs exposed to every user (challenge 4).
- Challenge 1, another user's vehicle location, is reported only as
  `SUSPICIOUS`. The Visitor did receive the Owner's location, but the identity
  service answers requests without a token with a Java `toString()` instead of
  JSON, so GrantTrace cannot use that answer as a clean denial.
- The same body makes the secure video lookup `SUSPICIOUS` too: a lead that
  manual review rejects, not a confirmed finding.
- The remaining published challenges need POST, PUT or DELETE tests, payload
  injection, request flooding or token forgery, which GrantTrace does not
  attempt; challenge 5 crosses no identity boundary, and the chatbot challenges
  had no chatbot to test.

## crAPI's challenges

| Challenge | Endpoint | Result | Notes |
|---|---|---|---|
| 1. Another user's vehicle details | `GET /identity/api/v2/vehicle/{vehicleId}/location` | `SUSPICIOUS` | Missed as a confirmation. See [the identity service's 401](#the-identity-services-401). |
| 2. Another user's mechanic reports | `GET /workshop/api/mechanic/mechanic_report?report_id=` | **`CONFIRMED`** (`GT-BOLA-001`) | The Visitor reads the Owner's report, including the VIN. |
| 3. Reset another user's password | `POST .../check-otp` | – | Out of scope: OTP brute force. |
| 4. Sensitive information of other users | `GET /community/api/v2/community/posts/{postId}` | **`CONFIRMED`** with field rules (`GT-BOPLA-001`) | Posts are meant for every signed-in user, but not the author's email and vehicle ID; see [field rules](#challenge-4-field-rules). |
| 5. An internal property of a video | `GET /identity/api/v2/user/videos/{video_id}` | – | Out of scope: users see `conversion_params` of their own video; no identity boundary is crossed. |
| 6. Layer 7 DoS with "contact mechanic" | `POST /workshop/api/merchant/contact_mechanic` | – | Out of scope: request repetition. |
| 7. Delete another user's video | `DELETE /identity/api/v2/admin/videos/{video_id}` | – | Out of scope: no DELETE tests. |
| 8–10. Mass assignment | `POST` / `PUT` order and video operations | – | Out of scope: writes against external APIs are refused. |
| 11. SSRF | `POST /workshop/api/merchant/contact_mechanic` | – | Out of scope. |
| 12–13. NoSQL and SQL injection | coupon operations (`POST`) | – | Out of scope. |
| 14. An endpoint without authentication | `GET /workshop/api/shop/orders/{order_id}` | **`CONFIRMED`** Broken Authentication (`GT-AUTH-001`) | Anonymous reads the Owner's order and email. BOLA is `SUSPICIOUS` for the same reason. |
| 15. Forge JWTs | – | – | Out of scope. |
| 16–18. LLM chatbot | – | – | Not deployed. |
| Not in the list: administrator user list | `GET /workshop/api/management/users/all` | **`CONFIRMED`** BFLA (`GT-BFLA-001`) | The view is for administrators but checks only that a token is present. |

## All results

The standard scan's 53 checks; the 28 POST, PUT and DELETE operations are
`SKIPPED` (no detector, or writes disabled).

| Operation | Check | Result |
|---|---|---|
| `GET /identity/api/v2/user/videos/convert_video` | BOLA | `SKIPPED`: blocked by the read-only safety policy |
| `GET /workshop/api/mechanic/receive_report` | BOLA | `SKIPPED`: blocked by the read-only safety policy |
| `GET /workshop/api/shop/return_qr_code` | BOLA | `SKIPPED`: no object selector or collection policy |
| `GET /identity/api/v2/user/dashboard` | BOLA / Broken Authentication | `INCONCLUSIVE` / `INCONCLUSIVE` |
| `GET /identity/api/v2/vehicle/vehicles` | BOLA / Broken Authentication | `INCONCLUSIVE` / `INCONCLUSIVE` |
| `GET /identity/api/v2/vehicle/{vehicleId}/location` | BOLA / Broken Authentication | `SUSPICIOUS` / `INCONCLUSIVE` |
| `GET /identity/api/v2/user/videos/{video_id}` | BOLA | `SUSPICIOUS` |
| `GET /community/api/v2/community/posts/{postId}` | BOLA | `AUTHORIZED` (configured as shared) |
| `GET /community/api/v2/community/posts/recent` | BOLA | `INCONCLUSIVE` |
| `GET /workshop/api/shop/products` | BOLA / Broken Authentication | `INCONCLUSIVE` / `SECURE` |
| `GET /workshop/api/shop/orders/{order_id}` | BOLA / Broken Authentication | `SUSPICIOUS` / **`CONFIRMED`** |
| `GET /workshop/api/shop/orders/all` | BOLA | `INCONCLUSIVE` |
| `GET /workshop/api/management/users/all` | BOLA / Broken Authentication / BFLA | **`CONFIRMED`** / `SECURE` / **`CONFIRMED`** |
| `GET /workshop/api/mechanic/` | BOLA / Broken Authentication | `INCONCLUSIVE` / `SECURE` |
| `GET /workshop/api/mechanic/service_requests` | BOLA | `INCONCLUSIVE` |
| `GET /workshop/api/mechanic/mechanic_report` | BOLA / Broken Authentication | **`CONFIRMED`** / `SECURE` |

| Checks | Standard scan | With field rules |
|---|---|---|
| Confirmed | 4 | 6 (the two BOPLA results form one leak group; the scan counts 5) |
| Secure | 4 | 6 (adds Anonymous on both fields) |
| Suspicious | 3 | 3 |
| Authorized | 1 | 1 |
| Inconclusive | 10 | 10 |
| Skipped | 31 | 31 |
| Attempted / conclusive coverage | 29.5% / 6.8% | 29.5% / 6.8% |
| HTTP requests sent | 43 | 43 |

The confirmed BOLA and BFLA on the administrator user list come from the same
three responses: one flaw under two labels, which the standard scan counts as
two confirmed checks.

## The identity service's 401

crAPI's identity service rejects a request without a token like this:

```text
HTTP/1.1 401
Content-Type: application/json

CRAPIResponse(message=Invalid Token, status=401)
```

Its `JwtAuthEntryPoint` writes the response object with
`getWriter().println(crapiResponse)`, which prints Java's `toString()` instead
of JSON. GrantTrace only treats a 401 or 403 as a clean denial when it can read
the whole body as a denial; anything else might carry data. Three results
depend on that body:

- **Vehicle location (challenge 1):** the Visitor received the Owner's
  location, name and email address, but without a clean anonymous denial BOLA
  stays `SUSPICIOUS`.
- **Video lookup:** crAPI answers another user's video with 404, and the
  operation sets [`not_found_is_denial`](../configuration.md#用-404-隐藏他人资源的-api).
  This would be `SECURE`; the anonymous body makes it `SUSPICIOUS`.
- **Broken Authentication on the vehicle location:** `INCONCLUSIVE`.

Recognizing this one non-JSON format would turn the first two into
`CONFIRMED` and `SECURE`. It is not done here: the format is a crAPI bug, and
teaching the tool one benchmark's bug would flatter the result. The dashboard
and vehicle list behave differently again: without a token they answer
`404 {"message": "Given Email is not registered! "}`, neither a denial nor
data, so Broken Authentication is `INCONCLUSIVE` there.

## Challenge 4: field rules

Every signed-in user may read a forum post; the standard scan configures the
post as shared (`expected_visitor_access: "allow"`) and reports `AUTHORIZED`.
The leak is inside the post: its `author` object carries the author's email
address and vehicle ID, which is also the key challenge 1 needs. BOPLA field
rules state that these two fields belong to the author alone:

```json
{"bopla": {"GET /community/api/v2/community/posts/{postId}": {
  "policy_id": "crapi-post-author",
  "context_id": "owner-post",
  "resource_binding": {"id": "<the Owner's post ID>"},
  "fields": [
    {"rule_id": "author-email-private", "path": "author.email",
     "baseline_representation": "full_private_value", "value_is_resource_specific": true,
     "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}},
    {"rule_id": "author-vehicleid-private", "path": "author.vehicleid",
     "baseline_representation": "full_private_value", "value_is_resource_specific": true,
     "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}
  ]
}}}
```

Both fields are `CONFIRMED` for the Visitor, in one leak group, and `SECURE` for
Anonymous, which the community service denies cleanly. Every other verdict
matches the standard scan. As in the [VAmPI case study](vampi.md#the-debug-endpoint),
the rules run as a separate scan: while any BOPLA rule is configured, the HTML
and JSON reports omit response bodies, concrete URLs and reasons for every
check of that scan.

## Limits this run showed

- **Non-JSON denials are not clean denials**, as described above.
- **Pagination parameters count as object selectors.** `posts/recent`,
  `orders/all` and `mechanic/service_requests` take `limit` and `offset`, so
  GrantTrace compares them as single objects and reports `INCONCLUSIVE` for a
  missing Visitor baseline. The result is right; the reason could be clearer.
- **The specification sets the boundaries.** A post being shared, the author's
  fields being private and the administrator role are configuration, as the
  specification cannot state them.

## Safety observations

- `GET /workshop/api/mechanic/receive_report` ("Create and Assign a Service
  Report") and `GET /identity/api/v2/user/videos/convert_video` ("Convert
  Profile Video") were skipped before any request because their descriptions
  state a change of state. In crAPI, `receive_report` does create a service
  request.
- `--dry-run` sent no requests: the gateway log has no GrantTrace request for
  it.
- Each scan sent exactly 43 requests, all GET, according to the gateway log
  filtered by GrantTrace's user agent (30 × 200, 11 × 401, 2 × 404). The
  accounts, vehicles, reports, orders, posts and videos were created beforehand
  by the helper script, not by GrantTrace.
- A read can still have effects the specification does not state: crAPI writes
  a PDF of the service report each time `mechanic_report` is read.
- Neither token, no JWT and no test account's email address appears in the
  HTML, JSON or SARIF reports; email addresses in evidence are redacted.

## Reproduce

Run crAPI only on your own machine. You need Docker with Compose, about 3 GB
for the images, and GrantTrace 2.6.0 or later (`pip install granttrace`). The
helper files are in [`examples/crapi/`](../../examples/crapi/).

```bash
git clone https://github.com/OWASP/crAPI && git -C crAPI checkout v1.1.6
# crAPI's .env selects the `latest` images and listens on 127.0.0.1 only.
# The override lets the gateway start without the chatbot.
docker compose --project-directory crAPI/deploy/docker \
  -f crAPI/deploy/docker/docker-compose.yml -f examples/crapi/no-chatbot.compose.yml \
  up -d crapi-web mailhog api.mypremiumdealership.com

cp crAPI/openapi-spec/crapi-openapi-spec.json .
granttrace --spec crapi-openapi-spec.json --init-config draft.json
python examples/crapi/prepare_config.py http://127.0.0.1:8888 http://127.0.0.1:8025 draft.json crapi.local.json
granttrace --spec crapi-openapi-spec.json --config crapi.local.json --validate-config
granttrace --spec crapi-openapi-spec.json --config crapi.local.json --dry-run
granttrace --spec crapi-openapi-spec.json --config crapi.local.json \
  --target http://127.0.0.1:8888 --allow-http \
  -o crapi.html --export-json crapi.json --export-sarif crapi.sarif

# Challenge 4's field rules, as a separate scan.
python examples/crapi/prepare_config.py --post-field-rules http://127.0.0.1:8888 http://127.0.0.1:8025 draft.json posts.local.json
granttrace --spec crapi-openapi-spec.json --config posts.local.json \
  --target http://127.0.0.1:8888 --allow-http \
  -o posts.html --export-json posts.json --export-sarif posts.sarif
```

`prepare_config.py` logs in as the administrator crAPI seeds
(`admin@example.com`, password from crAPI's `TestUsers.java`) and signs up a new
Visitor, whose vehicle it adds with the VIN and pincode crAPI mails to Mailhog.
For both it then creates a mechanic report, an order, a forum post and a
profile video, and fills the draft: the tokens, each identity's object IDs,
resource identifiers, private fields, the post as shared, the video lookup's
`not_found_is_denial`, and the administrator role for the user list. The
configuration holds live tokens; the `.local.json` name keeps it out of Git and
out of release archives.

Images used (`latest` on 2026-11-08):

| Image | Digest |
|---|---|
| `crapi/crapi-identity` | `sha256:5d1db5b3ba8e02bc68711ec6fc4e35ed7cd8b87e63785ece9e7ff5b5e36c5260` |
| `crapi/crapi-community` | `sha256:8ba0c7eda86ae065a673f1fa554d0109a24f25c5a8d65097ae024e5ee715c54e` |
| `crapi/crapi-workshop` | `sha256:d4d2d94d35a31e211b04d5a771881f5ae13e358e8fa0804463ae3bace05dd815` |
| `crapi/crapi-web` | `sha256:b27d246c646bd33898e7d1d2095b6e7576c0993a7b81a73aa7386929493d7151` |
| `crapi/gateway-service` | `sha256:97dade9daf0e758547b1686e2d3303c8c9b79838167f728a9211f0ee1f4622b0` |
| `crapi/mailhog` | `sha256:015c23f79d40c9dc1800cd0a458503b89aeda3b585a12c37d53829d6c7d61fdd` |
| `postgres:14` | `sha256:834a046089d76edd1d2e81c4741f3ad5d1853646ededc86c2708936aad31c1ed` |
| `mongo:4.4` | `sha256:4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef` |
