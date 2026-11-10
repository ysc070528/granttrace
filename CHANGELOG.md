# Changelog

## 2.7.0 - Unreleased

### Added

- Read-only POST BOLA auditing: operations configured with explicit `read_only: true`
  and a request `body` now execute cross-identity BOLA comparison using POST transport.
  Supports both shared JSON payloads and explicit identity-mapped request bodies (`owner`,
  `visitor`, `visitor_self`, `roles`). Unconfigured or state-modifying POST operations
  remain safely skipped without sending write requests.
- Heuristic BOPLA sensitive property exposure detection (OWASP API3:2023): detects
  unmasked sensitive properties (such as credentials, phone numbers, ID cards, salaries)
  exposed to unauthorized visitors when `detect_sensitive_exposure: true` is configured.
  Enforces strict exact-path matching, ignores booleans, masked strings, and null/empty
  scalars, respects authorization policies, and suppresses false positives on legitimate access.
- Multi-role RBAC access matrix: supports optional `identities.roles` definitions to
  probe access permissions across multiple user roles under global rate-limiting and throttling,
  evaluating privileged role baselines and detecting privilege violations against `required_role`.
  Renders a structured RBAC matrix table in the HTML report and sanitized JSON output.

### Changed

- Synchronize package, runtime, Windows distribution and release-workflow versions to `2.7.0`.

## 2.6.0 - 2026-11-09

### Added

- Read-only Broken Authentication (CWE-306, SARIF `GT-AUTH-001`) and Broken
  Function Level Authorization (CWE-285, `GT-BFLA-001`) checks, and private-data
  checks for collection endpoints (CWE-639). Confirmation requires explicitly
  configured `private_data_paths` and role policy; names and keywords alone stay
  leads (#43).
- PUT mass-assignment checks that use complete replacement snapshots and verified
  rollback. Like PATCH, they run only with independent authoritative resource
  state, which only internal test fixtures provide (the bundled demo tests
  PATCH); external CLI targets stay blocked before any write (#43).
- Evidence-bound read-only property authorization (BOPLA, CWE-200) driven by
  explicit per-operation `bopla` field rules and resource bindings (#44).
- GET header and cookie parameters, including header arrays and objects, sent
  from `parameter_values`; authentication headers and cookies stay
  identity-scoped and cookie arrays/objects are rejected under RFC 6265
  (#45, #46). Swagger 2 header values are validated before transport (#47).
- Opt-in remote `$ref` resolution over HTTPS (`--allow-remote-refs` with
  `--remote-ref-host`): exact host allowlist, SSRF and DNS-rebinding defences,
  no redirects, size/count/depth/time limits, and no fetching in offline modes.
  See [docs/remote-references.md](docs/remote-references.md) (#48).
- `--init-config` drafts the remaining inputs a scan needs, as placeholders
  that still block validation until replaced. Required GET business headers and
  cookies get one value per requesting identity (owner, visitor and anonymous)
  in `parameter_values`; required authentication headers go to owner's and
  visitor's `identities.*.headers`, and required authentication cookies to their
  `identities.*.parameters` (#74 stopped drafting optional authentication
  headers). PUT operations get parameter values and a readback
  draft like PATCH, with the extra PUT rules in the checklist. Optional
  parameters, ignored headers such as `Accept` and unsupported cookie forms
  are not drafted, and the checklist says why for each. A draft completed with
  real values now plans every drafted GET check, where previously its required
  headers and cookies were missing. The checklist no longer marks parameters of
  operations GrantTrace does not test, such as DELETE, as included in the
  draft (#73).
- A case study of a scan of VAmPI, a deliberately vulnerable API, in its
  vulnerable and secure modes: which of its vulnerabilities GrantTrace confirms,
  which it misses and why, and the request log of the read-only scan. Helper
  scripts in `examples/vampi/` reproduce it. See
  [docs/case-studies/vampi.md](docs/case-studies/vampi.md) (#81).
- `bola.<operation>.not_found_is_denial` reads a 404 as a denial, for APIs
  that hide other users' objects with "not found" instead of 403. A Visitor or
  Anonymous 404 counts only when the Owner received a valid response to the
  same request, the body is empty or only says the object was not found (a
  full-message grammar with at most one word naming the resource type, in a
  known error envelope or Problem Details), and none of the Owner's values
  appears in it; any other 404 keeps its default meaning, `INCONCLUSIVE`.
  BOLA, Broken Authentication, BFLA and collection checks of the operation
  apply it; BOPLA field rules do not. A 404 denial gives `SECURE` with
  confidence 0.95, below an explicit 401 or 403, and the evidence records the
  setting. Secure-mode VAmPI's book lookup now reports `SECURE` instead of
  `INCONCLUSIVE` (#82).
- The VAmPI case study confirms the debug endpoint's password exposure with a
  BOPLA field rule: the Owner's password in `/users/v1/_debug` may be read by
  the Owner only, although the specification leaves the endpoint open, so both
  the Visitor and Anonymous results are `CONFIRMED` (`GT-BOPLA-001`) in both
  modes. `examples/vampi/prepare_config.py --debug-field-rule` writes the rule;
  it runs as a separate scan because BOPLA's privacy boundary omits response
  details from the whole report. The configuration guide now points to field
  rules for private fields on operations without an authentication
  requirement (#83).
- A case study of a read-only scan of OWASP crAPI 1.1.6: GrantTrace confirms
  another user's mechanic report (challenge 2), the order lookup without
  authentication (challenge 14), an administrator user list any user can read,
  and, with BOPLA field rules, post authors' email addresses and vehicle IDs
  (challenge 4). Challenge 1 stays `SUSPICIOUS` because crAPI's identity service
  answers requests without a token with a Java `toString()` instead of JSON.
  `examples/crapi/` holds the setup script and a Compose override that runs
  crAPI without its chatbot. See
  [docs/case-studies/crapi.md](docs/case-studies/crapi.md) (#85).
- A comparison of GrantTrace's approach with Autorize, AuthMatrix, ZAP's Access
  Control Testing add-on and Akto, from their documentation: where requests come
  from, what is expected, how a result is decided, and when another tool fits
  better. It compares approaches, not detection rates. See
  [docs/comparison.md](docs/comparison.md) (#86).

### Changed

- Synchronize package, runtime, Windows distribution and release-workflow
  versions to `2.6.0`, a minor release for the checks and options added since
  2.5.3. The remote `$ref` fetcher's User-Agent now follows the runtime version
  instead of a hard-coded `2.5.3`. Refresh release documentation and the example
  reports.
- Rewrite the README as an English project page, with a Chinese translation in
  `README.zh-CN.md`: what GrantTrace does and a quick start first, a table of the
  checks with what each needs, and a plain list of what is not supported. Mass
  assignment is described as demo-only, as it is for external APIs. The report
  screenshot is retaken from the 2.6.0 demo, a confirmed-finding screenshot is
  added, and the README no longer states a release status that each release had
  to update. Chinese documentation links back to the Chinese README (#79).
- Report BOLA reasons in English, like every other check. The JSON `reason`,
  finding `details` and per-response `reason` evidence of BOLA checks were the
  only Chinese reasons; the HTML report shows the same text. Verdicts,
  `reason_category` and evidence fields are unchanged, and Chinese denial
  messages returned by a target API are still recognized. Consumers that
  matched the Chinese text should match the verdict or `reason_category`.
  Offline validation messages no longer append a Chinese note. The HTML
  report's interface text stays Chinese (#57).
- Store every text file with LF line endings (`.gitattributes` now normalizes
  them; the Windows portable build still writes CRLF for its batch launcher),
  and name 13 test modules after the behavior they cover instead of the PR or
  release that added them. No runtime change (#58).
- Regenerate the example reports in `examples/` from the built-in demo. They
  were still the 2.5.3 output, with Chinese BOLA reasons and without the newer
  statistics, and showed PATCH results that a CLI scan of an external target no
  longer produces, because such scans stop PATCH checks before any write.
  `scripts/verify_examples.py --update-examples` now copies a fresh
  `granttrace demo` run after verifying the CLI scans, and a new test fails when
  the committed examples no longer match a fresh demo run. No runtime change (#70).

### Performance

- Parse each response once and reuse comparison data in BOLA evaluation, cache
  key normalization, precompile evidence scrubbing patterns and skip redundant
  path resolution while resolving schemas. Outputs are unchanged; on 150 KB
  responses and 300-operation specifications these paths run about twice as
  fast (#50).
- Reuse response assessments across BOPLA field rules: ten rules on a 496 KB
  response took 271 ms and now take 14 ms, with identical decisions (#55).

### Fixed

- Recognize RFC 9457 (RFC 7807) Problem Details bodies as clean 401/403 denials.
  connexion sends them as `application/problem+json`, for example `{"type":
  "about:blank", "title": "Unauthorized", "status": 401, "detail": "No
  authorization token provided"}`, and ASP.NET Core and Spring can be configured
  to. GrantTrace treated these members as possible business data, so a scan of
  VAmPI, a deliberately vulnerable API, reported its book BOLA as `SUSPICIOUS`
  instead of `CONFIRMED`, and Broken Authentication on its protected reads as
  `INCONCLUSIVE` instead of `SECURE`: the anonymous denial could not serve as a
  clean baseline. A problem body now counts as a denial only when every member
  is `type`, `title`, `status`, `detail` or a tracing ID, `status` is 401 or
  403, `type` is `about:blank` or an HTTP RFC status link, and `title` and
  `detail` are denial messages. Any other member or text keeps it suspicious,
  including `instance`: the check does not know the request path, so it cannot
  tell whether the URI names the requested resource or another user's. Ordinary
  JSON envelopes also accept a numeric `status` of 401 or 403 and messages such
  as "No authorization token provided" (#80).
- Refuse checks of operations that send a credential in the query string, before
  any request. Each URL is built from the resource owner's parameter values and
  sent by every identity, so an `apiKey` scheme `in: query` (or the RFC 6750
  `access_token` parameter) made the visitor and anonymous requests carry the
  owner's key: against a correctly secured API they appeared to read the owner's
  resource, giving false `SUSPICIOUS` or `CONFIRMED` results. Such checks are now
  `INCONCLUSIVE` (`invalid_input`) with a reason saying query-string credentials
  are not supported, and `--init-config` no longer drafts them as resource
  parameters. Ordinary query parameters, including names such as `page_token`,
  are unaffected (#75).
- Stop refusing GET checks over an optional authentication header that neither
  owner nor visitor configures. A header parameter classified as authentication
  (for example `X-Session-Id`, or an API-key scheme's header) blocked the check
  as `INCONCLUSIVE` unless both identities sent it, even when the specification
  marks it optional, and the reason wrongly said a value was "supplied via
  parameter values". It is now omitted, like an optional authentication cookie.
  A value from `parameter_values` and a header configured for only one of owner
  and visitor are still refused, and a missing required one is refused with a
  reason that says to configure it under `identities.*.headers` (#74).
- Stop sending invented values for optional query parameters that nobody
  configured. Every declared query parameter got a generated value, so a scan
  could request `?as_user=sample_text&status=active&include_deleted=false`:
  such values can filter out the tested resource, make the target reject the
  request or change its behavior, so the comparison no longer measured
  authorization. An unconfigured optional query parameter is now omitted, or
  sent with its declared `default`, as header and cookie parameters already
  were. Required parameters and resource identifiers such as `owner_id` keep
  their previous values (#76).
- Use an identity's `id` for its resource parameter exactly or not at all.
  Lenient integer parsing turned `"007"`, `"1_001"` or `" 1002 "` into 7, 1001
  or 1002, and an id outside the schema (such as `"abc"`, or `"0"` below a
  minimum) was silently replaced by the specification's example value, so the
  check tested a resource the Owner does not own. Such ids now follow the
  canonical rules of `parameter_values`, and a check that cannot use them is
  `INCONCLUSIVE` (`invalid_input`) before any request (#55).
- Ignore non-string media types instead of crashing with `AttributeError`, for
  example a Swagger 2 `consumes: [123, "application/json"]` (#55).
- Reject header parameter values with leading or trailing whitespace, which
  servers strip inconsistently, so the tested value always matches the
  configured one; whitespace inside a value is still allowed (#55).
- Publish secret values discovered while building request headers by atomic
  replacement. The in-place update raced with evidence sanitization in other
  workers and could drop a value from later redaction (#50).
- Report the specific "without precision loss" diagnostic for number parameter
  strings instead of the generic message that replaced it (#50).
- Require TLS 1.2 or later for remote schema fetches (#50).
- Retry rate-limited reads instead of recording them as inconclusive. GET
  requests answered with HTTP 429 (or 503 with `Retry-After`) are retried up
  to twice, honoring `Retry-After` in seconds or as an HTTP date (otherwise
  waiting 1 s, then 2 s), and every worker pauses meanwhile. A requested wait
  beyond 30 s fails closed with the original response. PATCH/PUT are never
  retried. The new `rate_limit_retries` statistic counts retries; a scan of
  the bundled mock target that rate-limits each path's first request now
  reaches the same verdicts as an unlimited one (#53).
- Enforce the remote `$ref` fetch timeout as an absolute deadline. Socket
  timeouts applied per receive, so a server dripping header or body bytes held
  a 0.3 s fetch for 3 s or longer; a close-delimited body cut off at the
  deadline is no longer accepted as complete (#52).
- Reject remote documents that end before their declared Content-Length, and
  turn malformed HTTP responses and over-nested JSON into per-reference
  resolution failures instead of errors that aborted the whole scan (#52).
- Check the IPv4 destination embedded in 6to4, Teredo and NAT64 addresses and
  block IPv4-compatible, local-use NAT64 and site-local IPv6 ranges. CPython
  releases before its 2024 `ipaddress` update (e.g. 3.9.19, 3.12.3) treated
  6to4 addresses embedding 169.254.169.254 or 127.0.0.1 as global (#52).
- Report a path item whose remote `$ref` fails as `INCONCLUSIVE`
  (`unresolved_reference`), as documented, instead of a skipped "UNKNOWN"
  method that `--fail-on-error` did not count (#52).
- Reject `--remote-ref-host` values that can never match a `$ref` URL host:
  a scheme, port, path, credentials, wildcard, whitespace, non-ASCII
  characters (use the IDNA form) or an empty value. Such values were accepted
  and then authorized nothing, so every remote reference failed later as
  "not in the authorized allowlist". The CLI exits 2 and names the value. IPv6
  literals are compared in canonical form, with or without brackets.
- Bound YAML anchor/alias expansion in local specifications, referenced YAML
  files and remote `$ref` documents. A ~1 KB alias "bomb" previously stalled
  parsing for 13 s or more (merge keys inside `yaml.safe_load` itself); aliases
  may now add at most max(250,000, 10 x the document's own nodes) nodes, and
  recursive aliases are rejected before any object is built or request is sent (#51).
- Fail closed before external CLI PATCH tests when authoritative resource state
  cannot be independently observed; write flags, mappings and a declared strong
  readback cannot supply that proof. Existing CLI/config syntax remains accepted.
- Check initial, post-write and restored HTTP documents against actual backing
  state in the owned disposable Demo. Retain global write halt on unavailable
  or contradictory restoration evidence, including queued concurrent callers.
- Preserve and retest both original unmarked-cache counterexamples; distinguish
  generic HTTP blocking from state-backed fixture detection statistics.

- PR #42 follow-up review: reject explicitly aged/stale state evidence, require
  previously observed business structure before confirming persistence, and
  serialize direct write-audit calls so waiting callers observe recovery failures.
- Add independent adversarial regressions and disclose two unresolved unmarked
  stale-response probes; distinguish statement, branch and combined code coverage.
- Require complete HTTP 200 JSON state readbacks without Content-Range before
  using them as PATCH snapshots, persistence evidence or restoration evidence.
  Preserve generic write acknowledgement handling, recovery and fail-closed write halting.
- Retain strong Owner-object matches in 4xx/5xx response bodies as suspicious
  leads only, without changing confirmation or SARIF export requirements.
- Include explicitly readOnly fields with ordinary names in mutation candidates;
  configured field mappings, write opt-in, allowlists and reversible snapshots still gate execution.
- Prefer a declared JSON consumes format for Swagger 2 bodies and explain more
  existing preflight exclusions in offline plans.
- Add fixed-truth loopback acceptance scenarios, regression tests and a source-linked
  capability audit with before/after measurements. No new vulnerability class is implemented.

### Maintenance

- Restructure the largest modules and functions without changing behavior
  (#59 to #69). Snapshot tests of the JSON, HTML and console output of mock-target
  scans came first and passed unchanged through the series; a deliberate output
  change regenerates them with `GRANTTRACE_UPDATE_SNAPSHOTS=1` (#59).
  `core/auditor.py` shrank from 2283 to 1499 lines: HTTP transport moved to
  `core/transport.py`, request construction to `core/request_builder.py`, and
  result recording and coverage to `core/results.py` (#61, #62, #63).
  `core/config_validator.py` shrank from 1735 to 250 lines: its checks moved to
  the `core/config_validation/` package, one module per configuration section,
  and `ConfigValidator` and its result types are still imported from
  `core.config_validator` (#65). The mass-assignment check, request header
  construction, readback validation, schema value validation, the CLI `main`,
  BOLA evaluation and the HTML report were split into smaller steps (#62, #63,
  #64, #66, #67, #68, #69). Moved code is unchanged apart from names. Most
  splits were compared with the previous code over large random inputs, and the
  CLI over 34 command lines, with identical results; new tests cover the
  per-field branches of the mass-assignment check. The seven hash-pinned write
  methods are untouched, and a new test fails if production code uses another
  module's private member (#60).
- Split `ConfigValidator.validate` (220 lines) into named steps with one
  section runner instead of five copies of the same error handling. A
  differential run over 40,000 mutated configurations gave identical results
  (#77).
- Code that imports `core` directly needs these changes; the CLI and
  `granttrace demo` are unaffected:
  - Helpers used across modules lost their leading underscore, and the old
    names were removed: `ResponseDiffEngine.assess_response`,
    `assessment_evidence`, `normalise_key`, `is_request_metadata_key` and
    `denial_body_is_clean`; `AuthorizationEvidence.assess`, `valid`,
    `private_values` and `clean_denial`; `SmartDataGenerator.parameter_schema`
    and `is_resource_identifier`; `APISentinelAuditor.identity_headers`. The new
    `APISentinelAuditor.secret_values()` returns an immutable snapshot of the
    published secrets (#60).
  - `RETRYABLE_METHODS`, `RATE_LIMIT_RETRIES`, `RATE_LIMIT_BACKOFF` and
    `MAX_RETRY_WAIT` moved from `APISentinelAuditor` to
    `core.transport.HttpTransport`. The redirect handler is
    `core.transport.NoRedirectHandler` (was `core.auditor._NoRedirectHandler`),
    and the auditor's opener is `_transport.opener` (was `_opener`) (#61).
  - `request_delay`, `request_timeout` and `max_response_bytes` are read-only
    properties of `APISentinelAuditor`. Pass them to the constructor: assigning
    them afterwards raises `AttributeError` (#61).
  - `_http_request` and `_authoritative_patch_state` are documented extension
    points and keep their names and signatures (#60).
- Documentation: the v2.5.3 post-release acceptance records (#36 to #41), user
  documentation synced with merged behavior (#54), the contributing guide's
  output checks (#72) and the first release-preparation record (#78). Before
  release, SECURITY.md, the command-line reference and the configuration guide
  now state that write checks against an external target stop before any write;
  the package description no longer lists mass assignment, which only the
  built-in demo performs; the command-line reference documents `--workers` and
  `--timeout`; a Code of Conduct (Contributor Covenant 2.1) is added; and the
  Windows guide describes the released state (#87).

## 2.5.3 - 2026-10-15

### Fixed

- [PR #33](https://github.com/ysc070528/granttrace/pull/33): recognize complete
  authentication and permission denial messages, including JWT denials, without
  treating rejected responses containing business data as clean denials. Explain
  Owner, Visitor self-resource and Anonymous evidence and missing prerequisites;
  retain conservative BOLA / IDOR confirmation requirements.
- Validate selected BOLA policies before HTTP requests and accept the existing
  `items[].id` trusted-evidence selector syntax in configuration validation.
- Count actual transport attempts and distinct method/path operations for
  attempted and conclusive coverage. Exclude zero-request preflight outcomes
  and recovery rows from endpoint coverage; explain skip and evidence categories
  in reports. `SUSPICIOUS` and `INCONCLUSIVE` remain non-conclusive.
- Apply read-only side-effect checks using operation identifiers, paths,
  summaries and descriptions during BOLA preflight, dry-run planning and final
  HTTP execution. Reject unsafe independent readbacks before any PATCH.
- [PR #34](https://github.com/ysc070528/granttrace/pull/34): validate each concrete
  GET / HEAD path, including the target base path, before route-cache lookup and
  transport. Reject ambiguous encodings, invalid UTF-8, dot/matrix-dot segments,
  repeated slashes, boundary encoded slashes, backslashes and control characters.
  Apply the same guard to BOLA, offline plans and PATCH readbacks without rewriting
  URLs; ordinary supported encoded identifiers remain supported.

### Changed

- Reuse cached immutable read-safety metadata and route patterns from PR #33
  while continuing to validate every concrete URL before requests.
- Synchronize package, runtime, Windows distribution and release-workflow
  versions to `2.5.3`; refresh release documentation and generated loopback
  examples. This release preparation introduces no new detector or API behavior.

Static read-safety checks do not prove that every GET is harmless. Verification
scope and remaining post-release acceptance are recorded in [VERIFICATION.md](VERIFICATION.md).

## 2.5.2 - 2026-10-05

### Maintenance

- Documentation / distribution metadata maintenance release: package the current
  README for the PyPI project page, retaining the corrected Windows download,
  unsigned-program notice, macOS / Linux installation and workflow explanation.
- Align package/runtime versions and Windows portable filenames, launcher,
  bundled instructions and release workflow metadata at `2.5.2`.
- No changes to BOLA / IDOR / Mass Assignment detection, the security model,
  default read-only behavior, CLI semantics or core implementation.

## 2.5.1 - 2026-10-05

### Fixed

- Reject unsafe Merge Patch probes before writes when the original state cannot be restored exactly.
- Preserve array record associations during BOLA comparison to avoid overstating confirmed authorization bypasses.
- Harden report target/metadata redaction for known credentials and prevent report outputs from overwriting specification, configuration, or loaded local `$ref` inputs.
- Improve local and conditional schema resolution plus configuration-to-spec operation validation.
- Preserve legacy v2.5.0 scalar parameter configurations while applying strict schema-aware normalization and validation for canonical integer, number, and boolean values.
- Preserve Swagger 2.0 `uniqueItems` parameter constraints during schema extraction so duplicate configured arrays fail validation before requests.

## 2.5.0 - 2026-10-04

### Added

- Export SARIF 2.1.0 with `--export-sarif`, alongside HTML and JSON reports.
  Only existing CONFIRMED findings produce results: BOLA / IDOR maps to
  `GT-BOLA-001` / `CWE-639`, and Mass Assignment to `GT-MASS-001` / `CWE-915`.
  A safely represented OpenAPI file inside the workspace supplies the artifact
  location for GitHub Code Scanning; no source lines or endpoint files are invented.
- Add safe cURL reproduction templates and copy buttons to confirmed HTML finding
  cards. Use the actual tested URL and confirmed injected payload where safe,
  Visitor credential placeholders, POSIX shell quoting and `curl --globoff`.
  Clipboard fallback supports offline reports; manual selection works without
  JavaScript. Real credentials never enter the templates, including when sensitive
  report evidence is enabled.
- Guide configuration onboarding from draft generation and manual review through
  validation, a local dry-run and a read-only first real scan. Distinguish
  config-only from spec-aware validation, summarize dry-run counts, and format
  next-step commands safely for POSIX shells or PowerShell.

### Changed

- Align README, configuration and advanced guidance with the first API onboarding
  flow and the SARIF / cURL outputs, without changing configuration formats.
- Explain validation scope, warnings and dry-run write eligibility more clearly.
  An active PATCH configuration is separate from enabling active execution;
  the recommended first real scan remains read-only.
- Promote the release source to `2.5.0` across package metadata, runtime version
  and generated examples; prepare the release checklist and OIDC workflow for
  the new tag without publishing it during release preparation.

### Security / Safety

- Preserve BOLA / IDOR verdicts and Mass Assignment detection criteria, default
  read-only auditing, and the existing TLS / HTTP / redirect / proxy boundaries.
- Active PATCH still requires explicit `--allow-write-tests`, an explicit write
  allowlist, independent GET readback, original-state snapshots, rollback and
  rollback verification. Failed recovery still halts further writes.
- SARIF, cURL templates and onboarding output do not expose real credentials;
  onboarding also omits configured resource values. Workspace-external specs
  never expose absolute local paths in SARIF.
- Validation and dry-run remain offline; dry-run sends zero requests. No active
  POST / PUT testing or automated OAuth / login is added.

### Quality

- Retain the 486-test baseline, Python 3.9 / 3.12 / 3.14 CI, blocking mypy and Ruff,
  Runtime dependency audit, CodeQL and the branch-aware coverage gate of 80%.
- Fresh release-prep acceptance passes all 486 tests with **82.78%** branch-aware
  local coverage, mypy reporting no issues in 18 source files, Ruff and the runtime
  dependency audit. All six bundled business scenarios match their expected
  outcomes; JSON / YAML scans restore the full mock database. A fresh wheel
  installed outside the checkout passes both demo modes and verifies version
  `2.5.0`, read-only 0 PATCH, active rollback and local server shutdown. See
  [VERIFICATION.md](VERIFICATION.md) for the exact scope and remote check results.

## 2.4.1 - 2026-10-03

### Added

- Add `granttrace demo` with packaged OpenAPI, configuration and fictional mock
  data, so an installed wheel can demonstrate identity comparison, BOLA / IDOR,
  Mass Assignment, independent readback and rollback verification outside a Git
  checkout without user credentials or external API access.
- Start the disposable mock on a dynamic loopback port, close it on completion
  or failure, and retain HTML / JSON reports in a unique output directory.
- Add `--output-dir` and optional `--read-only` controls for the built-in demo.

### Changed

- Put the single-command installed-package demo before the source-checkout
  walkthrough and retain configuration onboarding and safety boundaries. During
  release preparation, distinguish the upcoming package from the published stable
  version and do not claim an unpublished PyPI release is available.
- Give missing spec/config files and offline configuration failures a concise
  next step; an empty write allowlist still sends no PATCH requests.
- Promote the 2.4.1.dev0 development package to 2.4.1 consistently across runtime,
  package metadata and generated reports; update the release acceptance checklist.

### Quality

- Resolve the existing 20 mypy errors in six files using accurate annotations and
  type narrowing, without new suppression directives or weaker mypy settings.
- Make mypy a blocking CI check and add a minimum 80% branch-aware coverage gate.
- Add weekly Dependabot checks for pip dependencies and GitHub Actions, without
  automatic merging; exclude the release workflow from dependency updates.
- Verify installed demo resources, source-independent startup, both demo modes,
  complete database restoration and local server shutdown.

### Security / Safety

- The demo accepts no external target or user credentials. Its active PATCH checks
  run only against bundled, disposable data on a dynamic `127.0.0.1` server.
- Keep auditing users' own APIs read-only by default; `granttrace demo --read-only`
  sends no PATCH requests.
- Preserve the BOLA / IDOR and Mass Assignment detection criteria, explicit write
  allowlists, independent GET readback, original-state snapshots and rollback
  verification. Failed recovery still blocks subsequent writes.
- Keep the existing `granttrace --spec ...` CLI, TLS / HTTP / redirect / proxy
  safety boundaries and evidence minimisation unchanged.

## 2.4.0 - 2026-10-03

### Added

- Generate offline OpenAPI configuration drafts and missing-input checklists;
  reject unresolved drafts and refuse to overwrite existing files.
- Add offline HTML report search/status filters and compact severity labels.
- Support strict OpenAPI style/explode and Swagger collectionFormat parameter
  serialization in scans/readbacks, including arrays and lowercase booleans;
  decline unsupported or ambiguous formats before sending requests.
- Add explicit per-pair expected_visitor_access for legitimate sharing/admin
  reads, recorded as AUTHORIZED, and six local authorization truth fixtures with
  false-positive/false-negative accounting.
- Add mandatory Ruff checks, real unittest branch coverage with text/XML/JSON
  evidence, runtime dependency auditing with pip-audit, and a Python CodeQL
  workflow. Keep mypy advisory while recording existing type debt.
- Add simple issue templates and contribution guidance with private vulnerability
  reporting and reminders to exclude credentials and sensitive target data.

### Changed

- Promote the previously identified 2.4.0.dev0 development build to 2.4.0 across
  runtime, package metadata and reports; retain api_sentinel.py and
  APISentinelAuditor compatibility.
- Use granttrace_report.html when no output path is supplied and align package
  description, version status and GrantTrace branding.
- Keep a concise five-minute README walkthrough, add identity/readback/restoration
  highlights, and preserve the visible report preview and detailed guide links.
- Explain identity/resource access, changed fields, restoration and next steps
  before raw evidence. JSON report schema is version 2.
- Remove tests' dependence on untracked config.json; automate JSON/YAML mock
  restoration and clean wheel installation outside the checkout in CI.
- Maintain reproducible release verification and local-output ignore rules;
  remove an unused demo image while preserving the report preview.
- Include example configuration, guides and verification scripts in the source
  distribution so its documented local checks can be reproduced.

### Security / Safety

- Preserve default read-only auditing and explicit allowlisted JSON PATCH checks;
  active POST/PUT checks and automated authentication are not added.
- Preserve independent GET readback, original-state snapshots, finally-protected
  restoration and rollback verification. Failed recovery halts subsequent writes.
- Preserve TLS verification by default, explicit non-loopback HTTP opt-in and
  minimized/redacted evidence by default.
- Retain denial, anonymous-leak and invalid-baseline boundaries without changing
  the BOLA / IDOR or Mass Assignment detection criteria during release preparation.

Historical release tags and assets, including v2.3.1, remain unchanged.

## 2.3.1 - Verified authorization, snapshot and credential fixes

- Require trustworthy, clean anonymous rejection before a visitor-denial branch
  can produce endpoint-level SECURE; leaked business data remains suspicious.
- Reject non-standard JSON constants and overflowing floats in response parsing.
  Validate the original snapshot and finite request payloads before any PATCH;
  preserve recovery when a post-write readback is invalid.
- Redact component values from request Cookie headers, including names such as
  path/domain/secure/version, quoted/encoded echoes and known numeric credentials.
- Align readback parameter arrays, elements and override mappings between the
  editor schema, semantic validator and runtime.
- Load the same JSON/YAML specification authentication context in configuration
  validation and scanning; reject explicit invalid specifications cleanly.
- Validate the effective CLI write allowlist against its own readback mappings.
- Add 45 regression tests across four release modules; all 223 tests pass with
  real PyYAML installed. Repeat complete CLI mock audits for JSON and YAML and
  confirm full database restoration.
- Build/install the 2.3.1 wheel and smoke-test its installed console entry point;
  refresh sample reports and record current verification separately from history.

## 2.3.0 (v2.3.0-final) - Configuration validation, authoritative identity rules, and release hardening

- **Authoritative Configuration Validator (`core/config_validator.py`)**:
  - Implemented offline semantic validation engine for `config.json` without external network requests.
  - Added `--validate-config` CLI flag for pre-flight validation (exit code 0 for valid, 2 for invalid), without target-network requests or state-changing target actions.
  - Normal CLI scanning automatically runs the authoritative preflight check, rejecting invalid configurations before creating the auditor or sending any HTTP requests.
  - Enforced single canonical format for operation keys (`<METHOD> /<path>` with strictly single space), consistent case handling, and spelling error suggestions (Levenshtein distance).
  - Implemented symmetric two-way path collision detection (`paths_collide`) between `ignore_readback_paths` and written/readback paths across both validator and transaction rollback.
  - Unified authentication header recognition rules between Validator and Auditor, standardizing `session`, `credential`, custom `auth_header_names`, and OpenAPI-declared security schemes.

- **Schema and Exemplary Assets**:
  - Added standard `config.schema.json` (JSON Schema Draft-07) for editor autocomplete, hover documentation, and structural validation.
  - Added comprehensive `config.example.json` with `$schema` linkage, sample identities, readbacks, and BOLA policies.

- **Security and Robustness Hardening**:
  - Bound recursion depth (`MAX_RECURSION_DEPTH = 15`) and explicitly reject non-standard JSON numeric values (`NaN`, `Infinity`).
  - Strict credential sanitization across all diagnostic outputs (`Actual`, `Expected`, errors) and stripped CR/LF/control characters to mitigate known log-injection paths.

- **Core Detection Behavior Compatibility**:
  - No intentional behavior changes were made to BOLA decisions, snapshot recovery, diff, generator, or parser logic in this release; all existing regression tests continue to pass.

- **Test Suite Expansion**:
  - Total automated tests expanded from 118 to 178 (all 178 passing, 0 failures, 0 errors).
  - Added 22 offline configuration validation tests (`tests/test_config_validation.py`).
  - Added 20 security and sanitization tests (`tests/test_rc2_security_hardening.py`).
  - Added 18 strict regression counterexample tests (`tests/test_rc3_hardening.py`).

- **Packaging Hygiene and Metadata**:
  - Standardized Python package version in `pyproject.toml` to PEP 440 compliant `2.3.0`, with GitHub / ZIP delivery tag designated as `v2.3.0-final`.
  - Purged all build artifacts, temporary test reports (`API_Security_Report.html`, `result.json`), and caches (`__pycache__`, `*.pyc`, `.pytest_cache`, `.git`) from the distribution archive.

## 2.2.0 - Regression-driven safety fixes

- Snapshot/recover complete written fields, objects and arrays using original
  business values; compare the full readback state, including derived changes.
- Recover after mutation/readback exceptions, guard recovery's own exceptions,
  and stop later writes on failed verification or asynchronous acceptance.
- Require configured strong readback consistency for unchanged-write SECURE.
- Do not mistake 403-with-data, historical denial text, anonymous private
  increments, or undeclared public access for access-control enforcement.
- Compare effective authentication headers; exclude request/trace echoes from
  identity evidence and support explicit trusted response resource_id_paths.
- Probe readOnly privilege fields while excluding them from ordinary baselines.
- Recursively validate samples, intersect allOf constraints and reject invalid
  baselines. Resolve 3.1 ref siblings in their original contexts; reject ambiguous
  3.0/Swagger structural siblings and missing pointers instead of losing fields.
- Propagate supported media types, rejecting unsupported JSON Patch arrays.
- Bound/redact bodies, URLs, known credentials, error text and result metadata.
- Add zero-check CI failure, coverage/suspicious gates, no-network dry-run and
  case-sensitive CLI allowlist replacement.

Migration: PUBLIC needs explicit policy; unchanged active checks need strong
readback consistency. Rewrite 3.0 structural ref siblings as allOf. Full-state
verification may require explicitly identifying harmless volatile fields. These
checks do not establish a universal rollback or privacy guarantee.

## 2.1.0 - Safety hardening

- Made read-only auditing the default and limited active mutations to explicitly
  allowlisted JSON `PATCH` operations.
- Added independent read-before/write/read-after/rollback verification, retrying
  readback and treating asynchronous or ambiguous outcomes as errors.
- Reworked BOLA decisions around owner, cross-visitor, anonymous, and distinct
  visitor-self baselines. Matching JSON structure alone is never confirmation.
- Added explicit `CONFIRMED`, `SECURE`, `PUBLIC`, `SUSPICIOUS`, `INCONCLUSIVE`,
  `SKIPPED`, and `ERROR` results with honest attempted/conclusive coverage.
- Enabled TLS verification by default, blocked redirects, capped response sizes,
  added global throttling, and restricted non-loopback clear-text HTTP.
- Added default evidence minimisation, secret/PII redaction, hashes, and HTML
  escaping.
- Expanded OpenAPI parsing to JSON/YAML, safe local external references,
  recursive schemas/compositions, and parameter override semantics.
- Added constraint-aware parameters, valid request baselines, and one-field
  nested mass-assignment mutations.
- Added packaging metadata, CI, an Apache-2.0 license, security guidance, and a
  standard-library regression suite.

The bundled mock remains intentionally vulnerable in one BOLA route and one
mass-assignment route so the end-to-end flow can be verified safely on loopback.
