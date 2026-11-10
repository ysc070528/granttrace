# Contributing to GrantTrace

Everyone taking part in this project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Report security problems in GrantTrace
privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

The command-line module is still `api_sentinel.py` and the auditor class
`APISentinelAuditor`, names from the project's earlier days. They stay as they
are: the `granttrace` command and existing imports depend on them.

Use Python 3.9 or newer. Create a branch from the latest `main`, then install
the development dependencies:

```bash
git switch -c your-change
python -m pip install -e ".[dev]" "setuptools>=77" wheel
```

Run the regression suite, the verification scripts CI runs and Ruff before
opening a PR:

```bash
python -m unittest discover -s tests
python scripts/verify_pr42_adversarial.py
python scripts/verify_pr43_integration.py
python scripts/verify_authorization_coverage.py
python scripts/verify_authorization_coverage.py --generic-http
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
python -m ruff check .
```

Measure coverage with the actual regression suite:

```bash
python -m coverage erase
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m coverage xml
python -m coverage json
```

Mypy is a blocking CI check and must report zero errors; coverage must be at least 80%:

```bash
python -m mypy
```

Keep PRs focused. Explain the problem, the resulting behavior and the checks you
actually ran. Preserve detection semantics and the write allowlist, independent
readback and recovery safeguards. Add useful regression cases for changed
behavior; do not add tests solely to raise the coverage percentage. Use only the
bundled loopback mock or isolated systems you are explicitly authorized to test.

Never commit real tokens, cookies, API keys, account credentials, production data,
or sensitive identity information. Redact examples and reports before sharing.
Report vulnerabilities through GitHub's
[Private Vulnerability Reporting](https://github.com/ysc070528/granttrace/security/advisories/new),
following [SECURITY.md](SECURITY.md), rather than a public issue.

## Output checks

Some checks compare GrantTrace's output or source with committed files, so a
change to what a scan reports fails them on purpose:

- `tests/test_output_snapshot.py` scans the bundled mock through the CLI and
  compares the JSON report, the HTML report and the console output with
  `tests/snapshots/`, after replacing run-specific values such as times and the
  loopback port. A refactor must leave the snapshots unchanged. When a change
  deliberately alters the output, regenerate them and review their diff as part
  of the change:

  ```bash
  GRANTTRACE_UPDATE_SNAPSHOTS=1 python -m pytest tests/test_output_snapshot.py
  ```

- `tests/test_committed_examples.py` compares `examples/sample_report.html` and
  `examples/sample_result.json` with a fresh `granttrace demo` run: version,
  verdicts, reasons, findings and statistics. Regenerate them after an output
  or version change, then update the generation details and numbers in
  `examples/README.md`:

  ```bash
  python scripts/verify_examples.py --update-examples
  ```

- `scripts/verify_pr43_integration.py` pins the source of seven write-safety
  methods in `core/auditor.py`, listed in its `PR42_METHOD_SHA256`; changing
  any of them fails CI. `tests/test_module_boundaries.py` fails when production
  code uses another module's private member: make the helper public instead.

## Branch naming

Use a prefix that describes the purpose of the change, followed by a short,
descriptive topic:

- `feat/<topic>` for features.
- `fix/<topic>` for bug fixes.
- `docs/<topic>` for documentation changes.
- `refactor/<topic>` for refactoring.
- `test/<topic>` for test changes.
- `chore/<topic>` for maintenance.
- `release/vX.Y.Z` for release preparation.

Examples: `fix/openapi-array-validation`, `docs/windows-installation`, and
`chore/release-metadata`.

Avoid tool-specific prefixes in new branches.
