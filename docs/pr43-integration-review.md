# PR #43 security integration and independent acceptance

This is an unpublished change. Neither PR is merged. No tag, GitHub Release,
PyPI upload, new external test API, or external active scan is part of acceptance.

## Reviewed baseline and branch strategy

GitHub was read again on 2026-10-26 (Asia/Shanghai): #42 was open/Draft at
`7f25de9df81798bd9f8d20ab15c45b87eb9c8dc2`; #43 was open at
`d0c184db66f7569e52325ee7758ec2b136fe57fd`. Their common ancestor and main base
was `80c7202fdfd203e298a924bf77e5c154671123ff`.

The [conflict analysis and plan](pr43-integration-plan.md) was committed before
implementation (`eccb5dc191b3fff5200131ca4a65f329eee5354c`). Integration retains
both histories, adds #42's security dependency to #43, and keeps both bases main.
#42's branch and Draft status are unchanged. This is a local branch integration,
not merging either GitHub PR. Only a normal fast-forward update of #43 is intended.
If #42 advances, its new safety changes need another review before merge.

Files shared by the two diffs are README, auditor, parser and transactions.
Text conflicts were in auditor selector dispatch and write transaction entry;
parser media selection/tags and transactions required semantic reconciliation.
The baseline conflict was the missing state-authority and recovery protection in
#43's older ancestry. HTTP-200 confirmation, inferred admin authority, Owner-ID
substring matching, partial PUT bodies and result accounting were behavior conflicts.

## Safety comparison to the pinned #42 HEAD

| Contract | Integrated result and independent check |
| --- | --- |
| No generic state authority means no active write | Ordinary external PATCH and PUT fail closed before read/write transport. Config flags and `strong` cannot unlock them. |
| HTTP/JSON/equality cannot prove state | `_authoritative_patch_state`, `_has_patch_state_authority`, `_verified_patch_document` and strict `_json_object` are unchanged from #42. |
| ACK is not restoration | `_rollback_and_verify` and `_execute_patch_case` are unchanged. Before, after and restored HTTP documents must match independently observed actual state. |
| Unverified recovery retains false and stops writes | Whole-transaction `RLock`, fail-closed halt and transport-adjacent authority recheck remain; new PUT tests cover waiting calls on another resource. |
| Original adversarial counterexamples remain | Both original test files and their verification script are unchanged relative to #42; normalized hashes and seven critical method hashes/ASTs are checked in CI. |
| Fixture observation stays internal | The ordinary auditor still returns no authority. Direct observations belong to owned disposable Demo/test stores only. No external adapter was added. |

`scripts/verify_pr43_integration.py` records normalized source hashes, method AST
identity, final source commit, dirty status and runtime/test hashes. Its pinned
baseline also works in shallow CI without fetching old history.

## Four detection capabilities

| Detection | Positive evidence | Counterexamples and boundaries |
| --- | --- | --- |
| Broken Authentication | Required effective OpenAPI authentication, valid Owner baseline, complete valid anonymous response, exact typed match of operator-verified Owner-private values. | Public equivalents, optional authentication, operation overrides, errors/denials, empty collections, missing/failed Owner, truncation and generic 200 cannot confirm. Error-body private matches remain suspicious. Clean anonymous denial can establish this check's secure result. |
| BFLA | Explicit required role, verified Owner has that role, Visitor lacks it, protected-value match and clean anonymous denial. Read-only data exposure is High; path keywords do not establish Critical privilege escalation. | Path/tag/operation/summary keywords only select a candidate. Missing roles, invalid privileged baseline, authorized same-role Visitor, public-policy conflict, mixed denial/data and empty results cannot confirm. |
| Collection BOLA | Valid Owner baseline, private-data paths, exact typed Owner-private values in Visitor, clean anonymous denial, no sharing authorization for this pair. Owner ID need not occur. | Owner-ID text or substrings are not proof. Different data or absent IDs do not prove safety. Invalid/empty baseline and incomplete comparison remain inconclusive. Clean Visitor denial is scoped secure; explicit permitted sharing requires positive evidence and is authorized. |
| PUT Mass Assignment | Internal direct actual-state authority, exact complete root document, full-document mutation and restore, actual post-write and post-restore verification. | Ordinary external PUT is blocked. Real replacement-server tests include nested objects, arrays, nulls and unmodeled sibling fields. Envelope/renaming/ignored-field/baseline overrides and Merge Patch media are rejected. PATCH partial-container behavior is retained. |

Configuration and operator assertion semantics are in [configuration.md](configuration.md).
New exact array paths use numeric indexes, not wildcards. Explicit private-data
policy also selects collections with pagination/query parameters. A legacy
`resource_id_paths`-only policy still selects the object detector, so without an
object selector its BOLA item remains skipped; separate authentication probes do
not relabel that missing object comparison as secure.

The original nine expanded-detection scenarios remain, with stronger fixtures and
additional boundaries. Changes to those new scenarios correct invalid assumptions:
real private/role policy is supplied for positives; the former different-200-data
SECURE expectation becomes INCONCLUSIVE and a separate clean-denial positive is
added; PUT uses actual replacement and direct store observation. Existing older
anonymous/sharing/accounting assertions and all #42 assertions are retained.

Relevant tests:

- `tests/test_expanded_detection.py`: real HTTP end-to-end cases, effective
  global/operation security, pagination, policy conflicts, evidence and counts.
- `tests/test_pr43_authorization_evidence.py`: positive, negative and boundary
  matrix for all three read-only evaluators, policy validation and wiring.
- `tests/test_pr43_put_safety.py`: replacement semantics, snapshots, ACK/no-op,
  opaque HTTP claims, authority loss, another resource and concurrent stop-write.
- `tests/test_pr43_evidence_paths.py`: readable array evidence paths without
  disabling credential, business-body or JSON redaction.
- `tests/test_expanded_report_boundaries.py`: cautious summaries, confirmed-only
  SARIF and refusal to generate unsafe partial PUT reproduction commands.

## Original cache counterexamples and actual-state observations

The unchanged original `opaque_cached_after` and `opaque_cached_restore` probes
run independently through `scripts/verify_pr42_adversarial.py`. Under ordinary
HTTP they are blocked before PATCH, return INCONCLUSIVE with
`rollback_verified=false`, and make no false restoration claim. This is prevention
by refusing an unprovable write, not proof of a generic cache-detection protocol.

The new PUT script records eight independent state machines: honest, opaque after,
opaque restore, no-op restore ACK, lost authority after write, plus ordinary-HTTP
honest/opaque-after/opaque-restore. It saves actual stores and complete write
journals separately from GET claims. No-op restore leaves the actual resource
modified, keeps rollback false and halts the next resource. Authority loss may
leave the actual resource restored, but proof remains unavailable and writes stay
halted. Ordinary HTTP performs zero PUTs even with an allowlist and strong label.

## Accounting and validation evidence

`total_endpoints` counts method/spec-path pairs. `total_checks` counts result
records including rollback records; `detection_items` counts unique endpoint/check
pairs. `audited_count` and `conclusive_count` count primary result records with
request observations. `confirmed` and per-type counters count confirmed detection
items/findings; `confirmed_endpoints` separately deduplicates affected endpoints.
`transport_attempts` counts actual opener attempts and is not multiplied by the
number of evaluations sharing a read observation group.

Attempted coverage deduplicates endpoints with transport evidence, including
connection failures. Conclusive endpoint coverage requires each selected check
to have an attempted conclusive result. A secure authentication check cannot hide
an inconclusive collection/BFLA check. Both denominators include all spec endpoints;
local preflight results do not count as attempts. Legacy repeated observations
of one check preserve the existing any-conclusive-observation rule for that check.

Original 36-scene truth set and all 25 vulnerable truths are unchanged. Direct
fixture-state mode remains 13/25 (52%); ordinary HTTP remains 6/25 (24%). Both have
zero confirmed false positives, zero safety/expectation failures and zero false
restoration claims. Two deliberately failed-restore resources remain modified in
the fixture-authority mode; their failures are recorded and later writes stop.
Those numbers are synthetic scenario results, not production detection rates.

Old CI run 40252995229 checked a synthetic merge ref and failed with Mypy
auditor.py:726, four unused imports, and nine assertion failures. The inferred
reason issue disappears with typed evaluator results and retained #42 dispatch;
unused imports are removed; product dispatch, anonymous evidence and accounting
are corrected without deleting old assertions. The integrated CI checks out the
exact PR HEAD and exports both original and new independent evidence.

Final local and CI evidence is produced from the committed tree:

```text
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m mypy --no-incremental
python -m ruff check .
python scripts/verify_pr42_adversarial.py --output dist/pr42-final.json
python scripts/verify_pr43_integration.py --output dist/pr43-final.json
python scripts/verify_authorization_coverage.py --output dist/authorization-final.json
python scripts/verify_authorization_coverage.py --generic-http --output dist/authorization-generic-final.json
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
```

Pre-commit runs are explicitly dirty candidate evidence. Clean final-HEAD reruns,
raw logs and JSON are in ignored `dist/` and GitHub verification artifacts; final
SHA and exact-SHA CI URLs are reported in the delivery, not inferred from an old
green workflow. Local wheel validation uses an offline wheelhouse and an external
temporary environment; no package is published. Windows CI remains automated
portable acceptance and does not replace manual desktop/browser/USB acceptance.

Local candidate validation before the integration commit: 769 full-suite tests
passed; Mypy passed all 20 product source files; Ruff passed. Coverage was
4765/5342 statements (89.20%), 2307/2768 branches (83.35%), and 7072/8110 combined
(87.20%). The combined measure is not mislabeled as pure branch coverage.
Original 28 adversarial tests, both 36-scene modes, JSON/YAML restoration checks,
business scenarios and source-external offline wheel installation passed. The
additional independent PR43 runner selects all 88 new/expanded tests, including
report/export boundaries, and separately observes eight actual PUT state machines.

## Remaining limitations and merge conclusion

PASS WITH CONDITIONS requires successful exact-final-SHA checks and a maintainer
decision accepting the external write restriction and explicit policy scope.
Neither PR is merged automatically.

Still unsafe or unsupported: ordinary external active PATCH/PUT; arbitrary POST
or DELETE mutation tests; non-root or ambiguous PUT representations; non-JSON PUT;
role inference from naming/security schemes; authentication mechanisms beyond
these anonymous read probes; confirmation without private-data/role evidence;
array reordering, transformed/redacted fields or unobserved pages; arbitrary
business workflow authorization and write-only administrative functions.

Operator-supplied privacy/role policy can be wrong and cause a false positive;
generic/public/reused values must not be marked Owner-private. Missing evidence
causes false negatives/inconclusive results. Read safety heuristics cannot prove
GET is side-effect free. Process death/power loss, other clients, other auditors
and other processes are outside finally/instance-lock recovery guarantees.
