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

The executor checks raw and once-percent-decoded routes against declared
operations, including static routes overlapping a parameter template. BOLA and
readback planning apply the same concrete-route check before collecting baselines.
Equivalent readback templates retain declared metadata even when placeholder
names differ. This does not model arbitrary proxy rewrites or repeated decoding.

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
