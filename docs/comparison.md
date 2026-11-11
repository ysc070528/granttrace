# How GrantTrace compares

[Back to the README](../README.md)

Several tools test authorization by repeating requests as different users.
They differ in where the requests come from, how they decide that access was
wrong, and how much they assume. This page compares GrantTrace's approach with
four widely used ones, from their own documentation. It compares approaches,
not detection rates: none of these tools was run on the targets of the
[VAmPI](case-studies/vampi.md) and [crAPI](case-studies/crapi.md) case studies.

## At a glance

| | GrantTrace | Autorize | AuthMatrix | ZAP Access Control Testing | Akto |
|---|---|---|---|---|---|
| Form | Command-line tool | Burp Suite extension | Burp Suite extension | ZAP add-on | API security platform |
| Where requests come from | An OpenAPI 2.0 / 3.x specification | Traffic of a high-privileged user, proxied through Burp | Requests sent to it from Burp | URLs in ZAP's site tree, within a context | An API inventory from traffic connectors or imported OpenAPI / Postman files |
| Identities | Owner, Visitor (with a resource of its own) and Anonymous; optional named roles for a role matrix (2.7.0) | Low-privileged users' cookies or headers, and optionally unauthenticated | Users assigned to roles | Users of a context | The original user and an "attacker" token |
| What is expected | Explicit policy: shared or private objects, private field paths, required roles, field rules | Nothing configured; access should be denied | Which roles may make each request | Which users should or should not reach each URL | Defined by each YAML test template |
| How a result is decided | Concrete Owner values or trusted identifiers in the Visitor's response, against a clean Anonymous denial and the Visitor's own resource | Response comparison and enforcement fingerprints (string, regex, content length) | Success or failure regular expressions per request | Whether each request passed or failed its access rule | The template's checks, comparing original and attacker responses |
| Uncertain cases | `SUSPICIOUS` or `INCONCLUSIVE`, never a finding | "Is enforced???" until a fingerprint is configured | A separate "possible false positive" color | Not stated in the pages read | Not stated in the pages read |
| Methods | GET reads, and POST operations you declare read-only (2.7.0); writes to external targets are refused | Whatever traffic passes its filters | Any request in the table | Any URL in the context | Any method the templates cover |
| Runs headless | Yes, with JSON, HTML and SARIF output | No; used inside Burp | No; configurations can be saved and reloaded | Through ZAP's API, after rules are set in the desktop UI | Runs in the platform; see its documentation for automation |

## Where GrantTrace differs

- **The specification is the input.** GrantTrace needs no browsing session or
  captured traffic: every operation in the OpenAPI document is planned, and
  `--init-config` drafts what each needs. The flip side is that endpoints
  missing from the specification are never tested, and each identity's
  resource values must be configured.
- **Findings need evidence, not a different status code.** A BOLA is
  `CONFIRMED` only when the Owner's own request succeeds, Anonymous is cleanly
  denied, and the Visitor's response carries the Owner's concrete values or
  identifiers, not just something similar to the Visitor's own resource.
  Anything weaker is reported, with the reason, as `SUSPICIOUS` or
  `INCONCLUSIVE`. That costs coverage: in the crAPI study, one real BOLA stays
  `SUSPICIOUS` because the API's denial is not a readable body.
- **Policy is written down.** Sharing, private fields and roles are
  configuration, so the same scan can run again in CI and a reviewer can see
  what was assumed. Proxy-based tools leave that judgment to the tester while
  testing.
- **It plans before it sends.** `--validate-config` and `--dry-run` work
  offline, GET operations that describe a change of state are skipped before
  any request, and writes against external targets are refused.
- **Its output fits pipelines.** SARIF goes to code scanning; JSON reports
  carry the evidence behind each verdict.

## When another tool fits better

- **Manual testing of a web application through a browser:** Autorize and
  AuthMatrix work on the traffic you generate, including requests no
  specification describes, and AuthMatrix handles CSRF tokens and
  re-authentication with its chains.
- **Write operations, any HTTP method, or flows across requests:** the Burp
  extensions, ZAP and Akto send whatever their tables, contexts or templates
  contain. GrantTrace 2.7.1 reads only: GET, plus query-style POST operations
  you declare `read_only`.
- **API discovery from live traffic and a large test library:** Akto builds its
  inventory from traffic connectors and runs templated tests across many
  categories beyond authorization.
- **An existing ZAP setup:** the Access Control Testing add-on uses the same
  contexts and users as the rest of ZAP.

GrantTrace is meant to complement these: a repeatable, conservative check of
documented API operations that can run on every change.

## Sources

- Autorize: [README](https://github.com/PortSwigger/autorize)
- AuthMatrix: [README](https://github.com/SecurityInnovation/AuthMatrix)
- ZAP: [Access Control Testing](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/),
  [context options](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/contextoptions/),
  [status tab](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/tab)
- Akto: [user configuration and attacker tokens](https://docs.akto.io/testing/create-user-config),
  [Postman import](https://docs.akto.io/traffic-connections/postman),
  [OpenAPI import](https://www.akto.io/blog/import-open-api-spec-file-to-akto),
  [test library](https://www.akto.io/blog/experience-akto-1000-api-security-tests)

Read in November 2026. These tools change; check their documentation for the
current state.
