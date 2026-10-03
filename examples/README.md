# Verified loopback example

Regenerated with `python scripts/verify_examples.py --update-examples` on
2026-10-03 with Python 3.14.5 and PyYAML 6.0.3. Runtime and package metadata both
declare the unreleased development version **2.4.0.dev0**. The latest published
Release remains **v2.3.1**, whose historical assets do not contain the current
unreleased changes. The complete mock
database was compared before/after and was unchanged. With vulnerability gates
enabled the CLI exits 1, as expected for this deliberately vulnerable fixture.
See ../VERIFICATION.md for full test scope and historical runtime boundaries.

The HTML includes identity/resource and field/restoration summaries before raw
evidence, remediation/retest guidance, and offline endpoint search/status filters.
The JSON uses report_schema_version 2, including the optional AUTHORIZED result
for an explicitly permitted identity/resource pair (not present in this fixture).
Reproduce both artifacts with `python scripts/verify_examples.py --update-examples`.

`sample_report.html` and `sample_result.json` were generated against the bundled
loopback mock with active PATCH checks enabled. The fixture intentionally
contains one BOLA issue and one mass-assignment issue.

The verification harness chose an ephemeral loopback port; the report's target
port records that run and is not a fixed deployment address. JSON and YAML
specification scans produced the same aggregate conclusions and full restoration.

Expected aggregate result:

- 5 operations checked
- 2 confirmed fixture vulnerabilities
- 0 errors and 0 inconclusive results
- 100% conclusive fixture coverage
- mass-assignment rollback independently verified

These numbers describe only the bundled fixture. They are not a claim about
coverage, false positives, or false negatives on another API.
