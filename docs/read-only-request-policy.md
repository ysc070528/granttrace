# Read-only request policy

GrantTrace must never send a request that changes state unless the operator
explicitly enabled the gated write checks. This page describes how the
read-only request policy is layered, what each layer reads and how a refusal
is reported. It is for maintainers and for code that drives `HttpTransport`
directly.

## Threat model

The specification, its examples, enums and defaults, remote `$ref`
documents and configured parameter values are **untrusted**: they may be
wrong, stale or hostile. The operator's own configuration (`--target`,
identities, `read_only` declarations, request bodies) is trusted to be what
the operator intended, but is still validated. The target server is assumed
to route the way common frameworks do, including permissive behaviour:
case-insensitive routing, method-override parameters and headers, matrix
parameters handed to handlers, and lenient request-line parsing.

The policy holds for the CLI and for the supported Python extension points
(constructor arguments, `request_guard`, the documented auditor overrides
`_http_request` and `_authoritative_patch_state`). It is not a sandbox
against code running in the same Python process.

## Layers

Every request passes these decisions in order; any refusal wins and nothing is
sent.

| Layer (`policy_layer`) | Where | Decides on |
| --- | --- | --- |
| configuration validation | `core.config_validator` | identities, method-override headers, read-only POST bodies, before any request |
| `auditor` | `APISentinelAuditor._http_request` → `_request_risk` | method token; ambiguity; documented template metadata; concrete path |
| `transport_request` | `HttpTransport.request_decision` → `request_refusal_risk` | method-override headers, write query strings, write POST bodies |
| `transport_base` | `HttpTransport.read_policy_decision` → `concrete_request_risk` | method token; ambiguity; concrete path below the fixed `base_url` |
| `transport_guard` | the optional `request_guard` (the auditor installs `_transport_request_risk`) | additional refusals only |

The transport layers read the `urllib.request.Request` that is about to be
sent: `get_method()`, `full_url` (after urllib unwrapped `<URL:...>` and
stripped spaces), the headers urllib keeps (one per case-insensitive name)
and the JSON body decoded from its bytes. The checked object is the sent
object.

## Path rules

A concrete path is what the server routes. Every segment and matrix piece is
checked, as sent and once decoded:

* a leading action word, read as words (`deleteReport`) and in the single case
  a case-insensitive router compares (`wItHdRaW`, `wıthdraw`, `WİTHDRAW`, full
  width);
* a compound write (`getOrCreate`, `findAndLock`, `createIfNotExists`);
* a `name=value` pair (matrix `;action=delete`, an exploded object) gets the
  query string's write-switch rules.

### Routed positions and data positions

OpenAPI serialises a path parameter in `simple`, `label` or `matrix` style. A
value the router dispatches on is in a *routed position* and is checked as an
action word. A value the router does not dispatch on is in a *data position*
and is treated exactly like a query value: only explicit write switches are
refused.

| Serialisation | Example sent | Position of `withdraw` |
| --- | --- | --- |
| simple scalar | `/reports/withdraw` | routed: refused |
| label scalar | `/reports/.withdraw` | routed: refused |
| simple array, first element | `/reports/withdraw,a` | routed prefix: refused |
| matrix flag | `/reports;withdraw` | routed piece: refused |
| matrix value | `/reports;kind=withdraw` | data (like `?kind=withdraw`) |
| later array element | `/reports/a,withdraw` | data |
| behind a literal prefix | `/reports/report-withdraw` | data, same as the literal path |

A literal path and a template filled with the same value always get the same
decision.

## Query strings and bodies

A read request's query string and a read-only POST body are checked for write
switches: a GraphQL mutation, an action, `op` or `mode` naming a write, a
method override to a state-changing method (every method the IANA HTTP Method
Registry lists as not safe, plus PURGE; POST and safe methods are not
overrides), a true write flag, or a dry-run switch turned off. A body is
checked as the JSON it is sent as.

## Refusals

A refusal is reported, never sent:

* `HTTPResult.refusal = {"safety_reason", "safety_signal", "policy_layer"}`,
  with `error` equal to the reason. A result with an `error` and no `refusal`
  is a transport failure.
* A check that had a request refused records `safety_refusals`,
  `policy_layer` and `safety_signal` in its evidence. It never concludes
  SECURE, PUBLIC or AUTHORIZED; such a decision becomes ERROR, the verdict a
  refused observation already produces. A refusal before any request (the
  detectors' own pre-checks) is SKIPPED with `reason_category: safety_policy`.
* Reasons are fixed texts. No key, value or credential is ever echoed.

## Known limits

* The vocabulary is heuristic. A read endpoint whose path or documentation
  names an action in words the rules do not know, or a write described only in
  prose such as "Permanently deletes jobs older than 30 days" (an adverb with a
  bare plural object), is not recognised.
* Values in data positions are data, as query values are; a handler that
  dispatches on a parameter value is outside what a request check can see.
* `HttpTransport` sends a valid PATCH, PUT or DELETE passed to it directly: the
  read-only rules cover GET, HEAD and POST, the methods the auditor reads
  with.
