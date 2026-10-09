# Authorization audit hardening for v2.5.2

## Baseline and review scope

This maintenance change starts from default branch `main` at
`2ba98ba0c8b4b816183d06dcf25d846372e1e3e7`. The published `v2.5.2` tag points to
`cab16fdce4a7771c8036ca4f0614e6384f7bec3d`. Their only differences are contributing,
verification and release-checklist documentation, including archived verification
history. Runtime code, CLI and package version are identical at this baseline.
The documentation cleanup is retained. No version change or publication is part
of this PR.

The two supplied crAPI summaries are background observations. This review did not
read real credentials or resource records, run crAPI, or reconstruct unavailable
original requests and responses. Synthetic regression fixtures reproduce the
response patterns; their results do not validate the reported crAPI findings.

## Root causes and repairs

| Problem | Root cause | Repair and location |
| --- | --- | --- |
| Clean JWT denials appear suspicious | `ResponseDiffEngine._denial_body_is_clean` accepted a fixed set of denial messages, missing `JWT Token required!` | `core/diff.py` recognizes bounded complete authentication/permission messages and rejects unrelated appended content, unknown containers and business fields; complete JSON-string denials cannot become valid resource baselines |
| GET can change state in read-only mode | Parser discarded descriptions; method selection had no semantic preflight; readback synthesized an identifier that hid declared operation semantics | `core/parser.py` preserves descriptions; `core/scan_safety.py` checks method, operation identifier, route, summary and description; `core/auditor.py` applies the guard to BOLA, dry-run, HTTP execution and PATCH readback before mutation |
| Strong resource comparisons are blocked or poorly explained | Unrecognized anonymous denial blocks existing BOLA confirmation gates; anonymous success exits before explaining object evidence | `ResponseDiffEngine.evaluate_bola` retains confirmation gates and records baseline validity, concrete object signals, denial conflicts, anonymous authentication violations and missing evidence separately |
| Invalid direct-use policy can send requests first | BOLA policy validation happened after the response collection | `APISentinelAuditor.audit_endpoint_bola` validates the selected business policy before HTTP |
| Coverage counts work that sent no request | Local preflight outcomes incremented audit counters; percentages counted result rows rather than distinct operations | `APISentinelAuditor._record_result` records transport attempts; `_audit_bola_task` preserves worker accounting on exceptions; `_finalise_coverage` counts distinct operations and excludes recovery records; `core/reporter.py` explains categories and both denominators |
| Trusted array paths fail policy validation | Configuration syntax validation used scalar field paths and rejected documented `items[].id` selectors | `ConfigValidator._validate_bola_section` accepts the existing evidence-engine wildcard syntax before runtime policy checks |

## Evidence and authorization policy

A normal HTTP 401/403 message is a usable rejection baseline only when its full
body is clean. Rejection status, matching response hashes and matching JSON keys
cannot independently confirm safety or a vulnerability. An error containing
business records or unknown complex content remains suspicious or inconclusive.
Error reasons do not copy arbitrary server error strings into decision metadata.

Tracing keys are not a blanket exemption: request/trace strings must be bounded
ASCII identifiers (letters, digits, underscore or hyphen), and timestamps must
use supported numeric, ISO-style or HTTP-date shapes. Credential prefixes,
assignments, encoded JSON and prose fail clean-body validation. Unusual legitimate
trace formats therefore remain conservative. A bare opaque credential or business
number that is indistinguishable from accepted tracing syntax cannot be identified
from its shape alone; reports remain sensitive artifacts.

For vehicle or report reads, confirmation still needs a valid Owner response, a
valid and different Visitor self-resource response, clean anonymous denial and
concrete matching business values or operator-approved resource identifier paths.
The configured identity/resource pair must reflect the actual authorization
policy. `expected_visitor_access: "allow"` covers a legitimate mechanic,
administrator or shared participant for that selected pair; it is not an
exemption for anonymous leakage or missing baselines.

An all-200 private-order pattern separately records the declared authentication
violation and anonymous object overlap. It remains `SUSPICIOUS` while privacy or
object authorization evidence is insufficient; it does not become a BOLA finding
solely because anonymous and authenticated bodies match. Explicitly public,
equivalent responses retain `PUBLIC`; authenticated sharing retains `AUTHORIZED`.
Trusted identifiers require human confirmation of their business meaning and
ownership. Request echoes and trace metadata do not certify ownership.

## Read-only safety boundary

Known state-changing reads such as `create_service_report` on
`GET /workshop/api/mechanic/receive_report` and
`GET /identity/api/v2/user/videos/convert_video` are blocked before requests.
Ordinary query operations remain eligible. A suspected unsafe GET readback blocks
the associated PATCH before any mutation. `--allow-write-tests` does not exempt
these reads and does not enable POST, PUT or DELETE detectors. No method is
substituted to bypass the guard.

Before consulting cached routes, the executor rejects ambiguous concrete read
paths: malformed or nested percent escapes, invalid UTF-8 escapes, dot segments
(including matrix suffixes), repeated slashes, encoded slashes at segment edges,
backslashes and control characters. Checks include the target base path. Nested
escapes are rejected after one decode rather than assuming a proxy's decode depth.
Raw and once-decoded paths are then checked against all declared operations,
including static routes overlapping a parameter template. Trailing-slash and
matrix-stripped aliases can add a known dangerous match; they cannot certify a
safe route, and the executor never rewrites the URL. BOLA and readback planning
apply the same concrete-route check before collecting baselines. Equivalent
readback templates retain declared metadata when placeholder names differ.

Ordinary Unicode, spaces, dots within identifiers, literal percent characters,
encoded question/hash characters and interior encoded slashes remain supported.
Query data is outside the path guard. Values that decode into another percent
escape, such as a literal `%2F` identifier, are conservatively blocked. Custom
proxy rewrites, Unicode compatibility normalization, query-triggered side effects
and undocumented operations still require operator review; this guard does not
prove that every GET is harmless. Every concrete URL is checked again before
transport, so warming the metadata cache cannot retain an earlier safe verdict.

Static English command/prose rules cannot discover every side effect, interpret
every language or prove a GET is harmless. Ambiguous descriptions can cause
conservative skips. Review operation semantics and the dry-run plan, keep unknown
or hazardous operations outside the selected test specification, and use an
isolated disposable target. Undeclared GET readbacks require the same manual
review. Dry-run and configuration validation remain offline, with zero network
requests; successful validation is not a side-effect or ownership guarantee.

## Coverage and report compatibility

| Field or category | Meaning |
| --- | --- |
| `total_endpoints` | Number of method/path operations in the selected specification |
| `total_checks` | Recorded result rows, including separate recovery results; not HTTP request count |
| `audited_count` | Primary check rows with at least one HTTP transport attempt, including network failure |
| `conclusive_count` | Attempted primary checks with `CONFIRMED`, `SECURE`, `PUBLIC` or `AUTHORIZED` |
| `attempted_endpoints`, `coverage_pct` | Distinct operations with an HTTP attempt, divided by all specification operations |
| `conclusive_endpoints`, `conclusive_coverage_pct` | Distinct operations with an attempted conclusive check, divided by all specification operations |
| `evidence.requests_attempted` | HTTP executor transport attempts for this check; zero for local preflight failure |
| `detector_unimplemented` | No supported detector or request format |
| `safety_policy` | Execution blocked by method, semantic risk, write allowlist or recovery safety |
| `missing_resource_id` | Owner baseline returned 404; verify existence and selector values |
| `missing_baseline` | Required identity/resource baseline absent, invalid or not distinct |
| `not_applicable` | Operation is not applicable to the current detector, for example no object selector |
| `invalid_input` | Policy or parameter preflight failed before execution |
| `insufficient_evidence` | Requests were attempted but evidence did not establish a conclusive result |
| `conclusive`, `error` | Completed conclusive check, or execution/program error |

`SUSPICIOUS` and `INCONCLUSIVE` never count as conclusive. Recovery records do not
inflate endpoint coverage. A confirmed-finding count is not a detection success
rate. Historical reports without new accounting fields retain their recorded
statistics and are explicitly labeled as lacking request accounting.

Package version, CLI flags, verdict enum, API signatures and
`report_schema_version: 2` remain unchanged. Existing JSON keys remain; evidence,
statistics and dry-run entries gain additive diagnostic fields. Consumers that
reject unknown keys need to allow these documented additions. Corrected attempt
accounting can lower attempted coverage for invalid-input scans; it does not
alter the conclusive-coverage threshold used by `--min-coverage`.
Malformed or unknown BOLA policy settings supplied directly to the auditor now
return zero-request `INCONCLUSIVE`, matching CLI configuration validation.
Direct calls to the diff engine retain its existing argument compatibility.

## Local crAPI retest

Use the updated source or a locally built installation; the existing v2.5.2
Windows executable does not acquire PR changes automatically. Keep the current
reduced specification, one worker and 0.5-second interval. First run
`--validate-config`, then `--dry-run --export-json plan.local.json`; review blocked
operations and both resource selectors before sending requests. Keep the two
known hazardous reads excluded even when confirming the new guard.

For actual read-only retesting, pass the reviewed specification, local
configuration and explicitly authorized loopback target, with `--workers 1`
and `--delay 0.5`.
Do not enable write tests. Check vehicle ownership and mechanic participation
from independent test-fixture records; configure allow/deny per pair. For orders,
verify that the intended policy is private and the resource identifiers refer to
different orders before reviewing anonymous disclosure evidence.

Compare categories, missing evidence and distinct-endpoint coverage, together
with findings. Preserve reports locally as sensitive artifacts. Share only
sanitized synthetic examples and aggregate counts. No conclusion about the live
crAPI vulnerabilities follows from the regression suite alone.

## Executed verification

This section records the authorization-hardening snapshot at `cf9656a`, before
the performance follow-up below. Its final counts refer to that snapshot.

Verification date: 2026-10-08 (Asia/Shanghai). Environment: Windows, Python
3.14.5, pytest 9.1.1 and PyYAML 6.0.3, using the existing local virtual environment.
All commands below use `.\.venv\Scripts\python.exe` as the interpreter. Repeated
iterations are grouped under the same command; counts are observations, not
production detection rates.

| Command arguments | Actual result |
| --- | --- |
| `-m pytest` | Baseline: 560 passed, 860 subtests. Initial repaired snapshot: 602 passed, 962 subtests. Final: **614 passed, 1009 subtests**, 0 failed, 0 skipped |
| `-m coverage run -m unittest discover -s tests` | Initial repaired snapshot: 602 OK. Final: **614 OK** |
| `-m coverage report` | Initial repaired snapshot: 86.15%; final: **86.26%** branch-aware coverage, above required 80% |
| `-m coverage json -o dist/authorization-coverage.json` | Passed; local coverage artifact written |
| `-m pytest tests/test_business_authorization.py tests/test_release_bola.py tests/test_auditor_integration.py tests/test_parameter_serialization.py` | 56 passed, 162 subtests |
| `-m unittest tests.test_authorization_evidence_hardening tests.test_diff tests.test_diff_hardening tests.test_business_authorization` | Early added regression run reproduced JWT denial failures; repaired iteration: 61 OK |
| `-m unittest tests.test_authorization_evidence_hardening tests.test_diff tests.test_diff_hardening tests.test_business_authorization tests.test_release_bola tests.test_auditor_integration` | Successive repair snapshots: 82, 85, then 87 OK |
| `-m unittest tests.test_read_only_safety tests.test_parameter_serialization tests.test_auditor_integration tests.test_release_transactions tests.test_v22_auditor_hardening tests.test_onboarding_cli -q` | Initial: 142 OK; later: 146 OK |
| `-m unittest tests.test_read_only_safety -q` | 17 OK before concrete-route regressions |
| `-m unittest tests.test_read_only_safety tests.test_parameter_serialization -q` | Final focused run: 51 OK, including 22 dedicated safety methods |
| `-m pytest tests/test_scan_accounting.py tests/test_report_usability.py tests/test_auditor_integration.py tests/test_curl_report.py tests/test_sarif.py tests/test_sarif_cli.py tests/test_cli_report_boundaries.py` | 109 passed, 124 subtests |
| `-m pytest tests/test_authorization_policy_preflight.py` | Initial three methods: 3 passed, 6 subtests |
| `-m pytest tests/test_authorization_policy_preflight.py tests/test_scan_accounting.py` | Worker-accounting snapshot: 10 passed, 27 subtests |
| `-m pytest tests/test_authorization_policy_preflight.py tests/test_config_validation.py tests/test_diff_hardening.py` | Array-policy repair: 50 passed, 9 subtests |
| `-m pytest tests/test_read_only_safety.py tests/test_authorization_evidence_hardening.py tests/test_authorization_policy_preflight.py tests/test_scan_accounting.py` | During metadata regression addition, the loaded pre-repair snapshot reproduced 24 failed subcases; 54 methods and 125 other subtests passed. All reproduced cases pass in the final full suite |
| `-m pytest tests/test_authorization_evidence_hardening.py tests/test_diff.py tests/test_diff_hardening.py tests/test_business_authorization.py tests/test_authorization_policy_preflight.py tests/test_scan_accounting.py` | After metadata repair: 78 passed, 145 subtests |
| `-m ruff check .` | Passed on repaired and final code |
| `-m ruff check core/auditor.py tests/test_authorization_policy_preflight.py` | Passed |
| `-m ruff check core/reporter.py tests/test_scan_accounting.py` | Passed |
| `-m mypy` | Passed: no issues in 19 source files |
| `-m mypy core/reporter.py` | Passed |
| `scripts/verify_business_scenarios.py` | Passed twice, including final code: six fixtures matched independent truth; zero false positives, false negatives or inconclusive cases within these fixtures |
| `scripts/verify_examples.py` | Passed twice, including final code: JSON read-only plus active JSON/YAML scans, full mock database restoration. Read-only conclusive coverage 60%; active 100%. Active fixture scan exit code 1 is the expected `--fail-on-vuln` result, not verification failure |
| `scripts/verify_install.py --wheelhouse dist/windows-wheelhouse --output dist/authorization-install-verification.json` | Passed twice, final wheel rebuilt from final source and installed in a fresh external venv without network dependency installation. Version 2.5.2, CLI/default reports, demo resources, offline plans, read-only zero PATCH, active restoration and shutdown passed |
| `api_sentinel.py --spec openapi.json --config config.example.json --validate-config` | Exit 0; offline configuration/spec validation passed |
| `api_sentinel.py --spec openapi.json --target http://127.0.0.1:8080 --config config.example.json --dry-run --export-json dist/authorization-plan.json` | Exit 0; requests_sent=0. Zero-network behavior also independently enforced by mocked transport regression tests |

Additional checks: `git diff --check` passed; all 18 top-level product Python
files parsed with Python 3.9 grammar. Final wheel source files were checked against
the checkout. No dependency or version change was introduced. No existing test
was deleted, skipped or weakened. The final change adds 54 test methods across
four focused modules.

Not executed locally: Python 3.9/3.12 runtime matrices, rebuilt Windows portable
executable, real crAPI retest, live production APIs or publication verification.
The PR-triggered CI must be reviewed separately; local success is not a claim
that remote CI or these external targets passed.

## Read-safety cache performance follow-up

The request preflight previously called `OpenAPIParser.get_endpoints()` for every
GET/HEAD, and PATCH readback metadata lookup called it again for every readback.
The parser already loads the source document once. These calls repeated parameter
merging, schema/reference normalization and operation construction across the
whole specification; preflight also reconstructed every GET/HEAD route pattern.
The reference and document caches did not eliminate that repeated work.

The auditor now builds one private safety snapshot during initialization. It
stores compiled GET/HEAD patterns, immutable risk signals and a readback metadata
index keyed by method and placeholder-normalized path. Ordinary reads traverse
the compiled patterns without normalizing the specification or reconstructing
patterns. Readback metadata lookup uses the index; returned default parameters
are deep copies and returned risks are fresh dictionaries.

Cache publication uses a frozen snapshot, tuples and read-only mappings. Normal
worker reads do not mutate it. The parser has no file-watching or reload API;
editing the source file or `raw_spec` in place is not a supported reload mechanism.
Construct a new auditor for a new specification, or replace its parser after
stopping an active scan. An explicit parser replacement invalidates the snapshot
by identity and rebuilds it under a lock on first use. Concurrent first readers
perform one rebuild. A rebuild failure raises before transport rather than
reusing the old snapshot.

Matching preserves the original route order, raw and once-decoded paths,
GET/HEAD cross-checks, static/dynamic overlaps, embedded placeholders and unknown
route fallback. A safe match does not stop the search for an overlapping unsafe
route. PATCH readback planning and execution continue to apply both metadata and
concrete-route guards before mutation. No authorization threshold, safety rule,
CLI parameter, report field, dependency or version changed in this follow-up.

`tests/test_read_safety_cache.py` adds nine methods covering exactly 100, 500 and
1000 synthetic operations, one and four workers, a frozen copy of the previous
preflight as the comparison oracle, deterministic work counts, real executor
entry points with stubbed transport, unsafe and safe PATCH readbacks, isolated
return values, parser replacement and zero-network CLI validation/dry-run.
Timing thresholds are deliberately excluded from test assertions.

The standalone benchmark uses temporary local OpenAPI documents with local
parameter/schema references and sends no HTTP requests. It compares identical
18-call batches (17 GET/HEAD checks plus one non-read check), with three timing
repetitions per size/thread pair. Instrumented work counts are collected
separately from elapsed times. Initialization cost is reported separately and
includes document loading, auditor setup and safety snapshot construction.
Measurements describe this helper workload on Windows/Python 3.14.5, not total
scan speed or network throughput. Safe-route matching remains linear in the
number of declared read routes.

Observed median times for each 18-call batch:

| Operations | Workers | Previous checks (ms) | Cached checks (ms) | One-time initialization (ms) |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 1 | 2214.650 | 0.363 | 165.091 |
| 100 | 4 | 2689.370 | 1.410 | 174.109 |
| 500 | 1 | 13306.721 | 2.141 | 1080.167 |
| 500 | 4 | 13882.458 | 3.279 | 732.389 |
| 1000 | 1 | 26153.816 | 2.994 | 1653.984 |
| 1000 | 4 | 27971.070 | 3.969 | 1486.441 |

Every previous batch performed 17 whole-specification normalization passes;
every cached batch performed zero after its one initialization pass. The previous
100/500/1000-operation batches normalized 1700/8500/17000 operations and built
1683/8483/16983 route patterns, respectively, in both worker configurations.
All cached batches performed zero repeated normalization and pattern builds.
All six comparisons matched expected safety results and sent zero requests.

Reproduce the measurements from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark_read_safety.py --sizes 100 500 1000 --workers 1 4 --requests-per-case 1 --repeats 3 --output dist/read-safety-performance.json
```

Final performance-follow-up verification (same environment and interpreter):

| Command arguments | Actual result |
| --- | --- |
| `-m pytest --junitxml=dist/read-safety-regression.xml` | **623 passed, 1023 subtests passed**, zero failures/skips |
| `-m coverage run -m unittest discover -s tests -q` | **623 OK** |
| `-m coverage report` | **86.41%** branch-aware coverage; required 80% |
| `-m coverage json -o dist/read-safety-coverage.json` | Passed |
| `-m ruff check .` | Passed |
| `-m mypy` | Passed: no issues in 19 source files |
| `-m pip_audit --strict --progress-spinner off --format json --output dist/read-safety-dependency-audit.json .` | Passed; resolved PyYAML 6.0.3, zero known vulnerabilities |
| `scripts/verify_business_scenarios.py` | All six local fixtures matched independent truth |
| `scripts/verify_examples.py` | Read-only JSON and active JSON/YAML mock scans passed; database restored |
| `scripts/verify_install.py --wheelhouse dist/windows-wheelhouse --output dist/read-safety-cache-install.json` | Final-source wheel in fresh external venv passed; 2.5.2, zero offline requests, zero read-only PATCH, active recovery verified |

The cache also passed an independent 1546-case comparison against the previous
route/readback behavior, including encoded and overlapping routes. Eight readers
rebuilt a replacement parser once; a failed replacement did not reuse old data.
All 18 product modules and both new verification modules parsed with Python 3.9
grammar. The 18 product files in the freshly built wheel matched the checkout
byte-for-byte. Protected authorization, safety rules, CLI, report, dependency,
version and workflow files were unchanged from `cf9656a`. Verification used only
local synthetic data and loopback mock targets. Remote CI results for the final
pushed commit are recorded on PR #33 separately; no merge or release is included.

## Concrete path guard maintenance patch

The earlier raw/once-decoded matcher could accept a safe parameter route while
a normalizing server resolved its value to a dangerous GET. The new path guard
runs before base-path removal and the immutable metadata cache on every read.
It is shared by BOLA preflight, execution plans, independent PATCH readbacks and
the final HTTP executor. It rejects ambiguity rather than canonicalizing and
sending a guessed route. An empty URL path or exact target prefix is checked as
the root operation. Authorization verdict thresholds, CLI/report formats,
dependencies and package version 2.5.2 remain unchanged.

`tests/test_read_only_path_guards.py` adds 11 regression methods. A local
normalizing server received eight dangerous GET/HEAD requests before the fix;
afterward socket/transport attempts, received requests and simulated effects are
zero. Seventeen ordinary loopback GET/HEAD requests remain successful. Regressions
also cover repeated/deep encoding, dot and matrix segments, separator/control
variants, invalid UTF-8, static/dynamic overlap, both BOLA identity paths, PATCH
readback preflight, mounted roots, warmed concurrent caches and offline CLI modes.

On Windows/Python 3.14.5, the focused safety/serialization/cache run passed 71
tests; the final full coverage-enabled unittest run passed 634 tests with 86.49%
branch-aware coverage. Ruff and Mypy passed. Wheel and sdist construction, strict
Twine checks, byte-for-byte product source checks and a fresh external offline
wheel installation passed, including mock rollback/restoration and zero read-only
PATCH. Exact-commit CI and Windows portable results are recorded on the patch PR.
No real crAPI proxy or production environment was tested, and no release was
published. The safety limitations and conservative exclusions above still apply.
