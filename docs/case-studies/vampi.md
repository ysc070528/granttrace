# Case study: GrantTrace against VAmPI

[Back to the README](../../README.md)

[VAmPI](https://github.com/erev0s/VAmPI) is a deliberately vulnerable REST API
with a switch between a vulnerable and a secure mode, which makes it useful for
checking both missed findings and false positives. This page records a run of
GrantTrace against both modes: what it found, what it missed and why, and what
the run changed in GrantTrace itself.

| | |
|---|---|
| Date | 2026-11-08 |
| VAmPI | commit `f16052d`, run from source on `127.0.0.1` (Python 3.11, Flask 2.2.2, connexion 2.14.2) |
| Modes | vulnerable (`vulnerable=1`, port 5002) and secure (`vulnerable=0`, port 5001) |
| GrantTrace | 2.6.0 with [#80](https://github.com/ysc070528/granttrace/pull/80) |
| Specification | VAmPI's own `openapi_specs/openapi3.yml`, unmodified (14 operations) |
| Scan | read-only; 14 GET requests per mode, no writes |

## Summary

- GrantTrace **confirmed** VAmPI's broken object level authorization: a
  logged-in user can read another user's book, including its secret. The secure
  mode produced **no false positive**.
- The first run did not confirm it. VAmPI denies anonymous requests with an
  RFC 9457 Problem Details body, which GrantTrace did not recognize as a clean
  denial, so the finding stayed `SUSPICIOUS`. That was fixed in
  [#80](https://github.com/ysc070528/granttrace/pull/80); the results below are
  from the fixed version, with the first run shown for comparison.
- Of VAmPI's nine listed vulnerabilities, one is the kind GrantTrace confirms
  today. One more (the debug endpoint) is an authorization problem it reported
  only as `INCONCLUSIVE`. The rest need write tests, POST tests or techniques
  GrantTrace does not attempt.

## VAmPI's vulnerabilities

| VAmPI vulnerability | Vulnerable mode | Secure mode | Notes |
|---|---|---|---|
| Broken Object Level Authorization (`GET /books/v1/{book_title}`) | **`CONFIRMED`** (SARIF `GT-BOLA-001`) | `INCONCLUSIVE` | Found. In secure mode VAmPI answers another user's book with 404, which GrantTrace does not treat as proof of a denial (see [limits](#limits-this-run-showed)). |
| Excessive data exposure (`GET /users/v1/_debug`) | `INCONCLUSIVE` | `INCONCLUSIVE` | **Missed.** The endpoint returns every user's password to anyone, in both modes (VAmPI notes that some issues stay in secure mode). Its specification declares it without authentication, so GrantTrace has no documented boundary to test. |
| Unauthorized password change (`PUT /users/v1/{username}/password`) | `SKIPPED` | `SKIPPED` | Out of scope: writes against external APIs are refused. |
| Mass assignment (`admin` in `POST /users/v1/register`) | `SKIPPED` | `SKIPPED` | Out of scope: no POST tests, and mass assignment runs only in the built-in demo. |
| SQL injection, user and password enumeration, ReDoS, missing rate limiting, weak JWT signing key | – | – | Out of scope: GrantTrace compares identities' access; it does not inject payloads, measure timing or forge tokens. |

## All results

The fixed version's verdicts for all 17 checks. `/createdb` is listed once; the
other skipped operations have no detector or need writes.

| Operation | Check | Vulnerable mode | Secure mode |
|---|---|---|---|
| `GET /createdb` | BOLA | `SKIPPED`: blocked by the read-only safety policy | `SKIPPED` |
| `GET /`, `GET /users/v1`, `GET /books/v1` | BOLA | `SKIPPED`: no object selector or collection policy | `SKIPPED` |
| `GET /me` | BOLA | `INCONCLUSIVE` | `INCONCLUSIVE` |
| `GET /me` | Broken Authentication | `SECURE` | `SECURE` |
| `GET /users/v1/_debug` | BOLA (collection) | `INCONCLUSIVE` | `INCONCLUSIVE` |
| `GET /users/v1/_debug` | Broken Authentication | `INCONCLUSIVE`: not applicable, no authentication required by the specification | `INCONCLUSIVE` |
| `GET /books/v1/{book_title}` | BOLA | **`CONFIRMED`** | `INCONCLUSIVE`: Visitor got 404 |
| `GET /books/v1/{book_title}` | Broken Authentication | `SECURE` | `SECURE` |
| `GET /users/v1/{username}` | BOLA | `PUBLIC` (configured as public) | `PUBLIC` |
| `POST` / `DELETE` operations (4) | – | `SKIPPED`: no detector | `SKIPPED` |
| `PUT /users/v1/{username}/email`, `.../password` | Mass Assignment | `SKIPPED`: writes disabled | `SKIPPED` |

| Checks (17 per mode) | Vulnerable mode | Secure mode |
|---|---|---|
| Confirmed | 1 | 0 |
| Secure | 2 | 2 |
| Public | 1 | 1 |
| Inconclusive | 3 | 4 |
| Skipped | 10 | 10 |
| Attempted / conclusive coverage | 28.6% / 14.3% | 28.6% / 7.1% |
| HTTP requests sent | 14 | 14 |

Coverage is low by design: four of the 14 operations are POST or DELETE, two
PUT operations need writes, and list endpoints need a collection policy before
they are compared. The report says so instead of counting them as passed.

## The confirmed finding

The Owner, the Visitor and Anonymous each requested the Owner's book:

| Identity | Status | Response |
|---|---|---|
| Owner | 200 | `{"book_title": "gt-owner-book-…", "owner": "gt_owner_…", "secret": "[REDACTED]"}` |
| Visitor | 200 | identical to the Owner's response (SHA-256 equal) |
| Anonymous | 401 | `{"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": "No authorization token provided"}` (as VAmPI sent it) |
| Visitor, own book | 200 | the Visitor's own book, so the Visitor's credentials work |

The Anonymous denial shows the resource is protected, and the Visitor's
response contains the Owner's identifiers, so the result is `CONFIRMED` with
confidence 0.99. The report redacts the secret, and also every response
`title` field, since titles can carry business data.

## What the run changed in GrantTrace

The first run used the same configuration and the same 14 requests:

| Check | First run | After #80 |
|---|---|---|
| Vulnerable `GET /books/v1/{book_title}` BOLA | `SUSPICIOUS` | **`CONFIRMED`** |
| `GET /books/v1/{book_title}` Broken Authentication, both modes | `INCONCLUSIVE` | `SECURE` |
| `GET /me` Broken Authentication, both modes | `INCONCLUSIVE` | `SECURE` |

VAmPI is built on connexion, which sends 401 responses as
`application/problem+json`. GrantTrace accepted a fixed set of denial envelopes:
the Problem Details members `type` and `title` were not among them, a numeric
`status` was not accepted, and "No authorization token provided" did not match
its denial grammar. It therefore treated the body as possible business data and
refused to use it as a clean denial. That is the conservative failure: a weaker
verdict, never a false confirmation. ASP.NET Core and Spring can be configured
to send the same shape. [#80](https://github.com/ysc070528/granttrace/pull/80)
accepts a problem body as a denial only when all of its members are standard,
its status is 401 or 403, and its text is a denial message; anything else still
keeps it suspicious.

## Limits this run showed

- **A 404 is not treated as a denial.** Secure VAmPI looks up books by title
  *and* owner, so another user's book is "not found". GrantTrace reports
  `INCONCLUSIVE` rather than `SECURE`, because a 404 can also mean a wrong
  parameter value. An opt-in to accept 404 as a denial when the Owner received
  200 for the same URL would make this case conclusive.
- **Unauthenticated endpoints are only tested against the specification.**
  `GET /users/v1/_debug` hands every user's password to anyone, but VAmPI's
  specification documents it without authentication, so Broken Authentication
  does not apply and the collection check has no clean anonymous denial to
  compare with. A configuration option stating that an operation must not
  expose `private_data_paths` to Anonymous would let GrantTrace confirm this.
- **Writes and POST are out of scope.** Unauthorized password change and mass
  assignment need requests that change state; GrantTrace refuses those against
  external APIs.

## Safety observations

- `GET /createdb` was skipped before any request: its summary ("Creates and
  populates the database with dummy data") marks it as state-changing. The
  database was populated by hand before the scan.
- `--dry-run` sent no requests; the VAmPI access log stayed empty.
- Each scan sent exactly 14 requests, all GET, according to VAmPI's access log.
  The test accounts and books were created beforehand by the helper script, not
  by GrantTrace.
- Bearer tokens, book secrets, and the passwords and email addresses returned
  by `_debug` were redacted in the HTML, JSON and SARIF reports.

## Reproduce

Run VAmPI only on your own machine. You need GrantTrace 2.6.0 or later
(`pip install granttrace`) and, for VAmPI's pinned dependencies, Python 3.11.
The helper scripts are in [`examples/vampi/`](../../examples/vampi/).

```bash
git clone https://github.com/erev0s/VAmPI && git -C VAmPI checkout f16052d
python3.11 -m venv vampi-venv && vampi-venv/bin/pip install -r VAmPI/requirements.txt

# Vulnerable mode on 127.0.0.1:5002, without the Flask debugger.
# Each mode needs its own checkout: VAmPI keeps its SQLite database inside it.
cp -r VAmPI VAmPI-secure
vampi-venv/bin/python examples/vampi/run_vampi.py VAmPI 5002 1 &
# Once it listens, populate the database. GrantTrace itself never calls /createdb.
curl http://127.0.0.1:5002/createdb

cp VAmPI/openapi_specs/openapi3.yml .
granttrace --spec openapi3.yml --init-config draft.json
python examples/vampi/prepare_config.py http://127.0.0.1:5002 draft.json vampi.local.json
granttrace --spec openapi3.yml --config vampi.local.json --validate-config
granttrace --spec openapi3.yml --config vampi.local.json --dry-run
granttrace --spec openapi3.yml --config vampi.local.json \
  --target http://127.0.0.1:5002 --allow-http \
  -o vampi.html --export-json vampi.json --export-sarif vampi.sarif
```

For the secure mode, start `run_vampi.py VAmPI-secure 5001 0`, request
`/createdb` on port 5001, and repeat the `prepare_config.py` and `granttrace`
steps against port 5001 with a new configuration file.
`prepare_config.py` registers two fresh accounts each time, logs them in, adds
one book for each, and fills the draft: the tokens, the parameter values for
both identities, `book_title` as the resource identifier, `secret` as private
data, `GET /users/v1/{username}` as public (VAmPI shows basic user information
to everyone), and the Owner's password in `/users/v1/_debug` as private data.
The configuration holds live tokens; the `.local.json` name keeps it out of
Git and out of release archives. The launcher raises VAmPI's token lifetime
from 60 seconds to an hour so that tokens do not expire mid-scan.
