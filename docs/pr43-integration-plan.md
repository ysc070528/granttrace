# PR #43 conflict analysis and implementation plan

Recorded before implementation, 2026-10-26 (Asia/Shanghai).

## Live baseline

- PR #42: open, Draft, `7f25de9df81798bd9f8d20ab15c45b87eb9c8dc2`.
- PR #43: open, `d0c184db66f7569e52325ee7758ec2b136fe57fd`.
- Both target main `80c7202fdfd203e298a924bf77e5c154671123ff`, also their merge base.
- #42 CI run 40251965507 passed. #43 run 40252995229 failed Mypy, Ruff and all three Python jobs; its checkout used the synthetic merge ref, not an exact HEAD checkout.

## Conflicts

Files changed by both branches: README.md, core/auditor.py, core/parser.py,
core/transactions.py. Merge preview reports textual conflicts in auditor's
selector dispatch and write transaction entry. Parser media selection and tags,
and transaction snapshot coverage versus PUT preparation, also need semantic review.

The baseline conflict is safety critical: #43 lacks #42's state authority gate,
whole-transaction lock, independently checked before/after/restored state,
strict readback response shape and structural coverage. These are missing
ancestors, not deliberate deletion commits; a direct replacement is unsafe.

Behavior conflicts: HTTP 200/valid JSON is not sensitive disclosure; admin words
are not role policy; absence of an Owner ID is not collection isolation; a GET
document is not necessarily a complete PUT representation. ACK is not restoration.

Test conflicts: #43's new positives rely on those unsupported assumptions and
simulate PUT using dict.update. Existing anonymous-leak, sharing and scan-accounting
assertions fail. Retain those assertions and both original opaque cache probes.

Actual failures: Mypy auditor.py:726 passes an inferred Collection[str] as reason;
Ruff reports four unused imports in test_expanded_detection.py. Python 3.12 reports
643 tests, nine failed assertions, including authentication, confirmed counts and
conclusive coverage. The other Python versions also failed.

## Ordered implementation

1. Integrate #42's exact current HEAD into a descendant of #43, retaining both
   histories. Keep both PR bases main and #42 unchanged. No force push, PR merge,
   version, tag, release, package publication or external active scan.
2. Use #42's auditor and transaction safety contracts as the implementation base.
   Preserve its original adversarial files byte for byte.
3. Add explicit per-operation private-data and role policy to the existing
   configuration. New read-only evaluators require real Owner baselines and typed
   private-value evidence. Heuristics produce candidates; missing proof remains
   SUSPICIOUS/INCONCLUSIVE. Respect public and authorized sharing policies.
4. Keep generic external PATCH/PUT blocked before transport. Permit PUT only in
   internal integrations with direct actual-state observation and an unambiguous
   full root-document replacement; test a server that really replaces resources.
5. Preserve old detector assertions and define endpoint, detection-result,
   confirmed-finding and conclusive coverage accounting separately. Fix product
   behavior instead of hardcoding expected statistics.
6. Run focused positive/negative/boundary tests, both original cache probes,
   full suite with coverage, Ruff, Mypy and existing verification scripts. Commit,
   repeat source-bound evidence at clean final HEAD, push without replacing newer
   commits, inspect exact-SHA CI and recheck both PRs remain unmerged.

## Acceptance boundaries

Fixture backing-store observation is an internal test capability, never a generic
external API adapter. Ordinary HTTP, JSON, value equality and consistency labels
cannot unlock writes or certify restoration. Unverified restoration retains false
and halts every subsequent active write in the same auditor. Explicit policies
are operator assertions whose correctness limits conclusions; GET side effects,
cross-process races and crash recovery remain outside these guarantees.
