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

These reports were generated with Python 3.14.6 and PyYAML 6.0.3 during the
2.6.0 release preparation and declare version 2.6.0; see
[CHANGELOG.md](../CHANGELOG.md) for the changes since 2.5.3. The JSON records
the UTC generation time; the demo chose the loopback port for that run, so the
target is not a fixed address.

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

## VAmPI

`vampi/` holds the helper scripts for the
[VAmPI case study](../docs/case-studies/vampi.md): `run_vampi.py` starts a VAmPI
checkout on 127.0.0.1 without the Flask debugger, and `prepare_config.py`
creates two test accounts in it and fills a configuration drafted with
`--init-config`. Run them only against a VAmPI instance you started yourself.

## crAPI

`crapi/` holds the helper files for the
[crAPI case study](../docs/case-studies/crapi.md): `no-chatbot.compose.yml`
lets crAPI's gateway start without its LLM chatbot, and `prepare_config.py`
creates the test users and their objects and fills a configuration drafted with
`--init-config`. Run them only against a crAPI instance you started yourself.
