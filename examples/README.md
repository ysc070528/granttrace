# Verified loopback example

Regenerated for v2.3.1-final on 2026-10-02 with Python 3.12.11 and PyYAML 6.0.3. The complete mock
database was compared before/after and was unchanged. With vulnerability gates
enabled the CLI exits 1, as expected for this deliberately vulnerable fixture.
See ../VERIFICATION.md for full test scope and historical runtime boundaries.

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
