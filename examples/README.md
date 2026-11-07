# Example reports

`sample_report.html` and `sample_result.json` are the reports of one run of the
built-in demo, `granttrace demo`. The demo starts a disposable loopback server
with fictional data, compares Owner, Visitor and Anonymous access, and runs its
PATCH checks against data it owns, so it can verify persistence and rollback
independently. The fixture intentionally contains one BOLA issue and one
mass-assignment issue.

Regenerate both files with:

```bash
python scripts/verify_examples.py --update-examples
```

The script first verifies the read-only and active JSON/YAML CLI scans of the
bundled mock, then copies the reports of a fresh demo run here.
`tests/test_committed_examples.py` fails when the committed reports no longer
match a fresh demo run.

These reports were generated with Python 3.14.6 and PyYAML 6.0.3 from `main`
after the 2.5.3 release. They declare version 2.5.3 but include the changes
listed under "Unreleased" in [CHANGELOG.md](../CHANGELOG.md), such as BOLA
reasons in English. The JSON records the UTC generation time; the demo chose the
loopback port for that run, so the target is not a fixed address.

Expected aggregate result:

- 5 operations checked: 3 BOLA and 2 mass-assignment checks
- 2 confirmed fixture vulnerabilities: BOLA on `GET /api/users/{user_id}/profile`
  and mass assignment of `role` on `PATCH /api/users/{user_id}/settings`
- 1 public and 2 secure results; no suspicious, inconclusive, skipped or error results
- 100% conclusive coverage
- 21 HTTP requests, GET and PATCH only; rollback verified and the demo database fully restored

A CLI scan of the same mock with `--allow-write-tests` gives a different result.
GrantTrace cannot observe the authoritative state of an external target, so it
stops PATCH checks before any write and reports them as `INCONCLUSIVE` with the
safety signal `unverified_state_authority`. That scan confirms only the BOLA
issue, with 60% conclusive coverage.

The HTML includes identity/resource and field/restoration summaries before raw
evidence, remediation/retest guidance, and offline endpoint search/status filters.
The JSON uses report_schema_version 2, including the optional AUTHORIZED result
for an explicitly permitted identity/resource pair (not present in this fixture).
See [VERIFICATION.md](../VERIFICATION.md) for the full test scope.

These numbers describe only the bundled fixture. They are not a claim about
coverage, false positives, or false negatives on another API.
