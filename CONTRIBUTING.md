# Contributing to GrantTrace

Use Python 3.9 or newer. Create a branch from the latest `main`, then install
the development dependencies:

```bash
git switch -c your-change
python -m pip install -e ".[dev]" "setuptools>=77" wheel
```

Run the regression suite, local verification scripts and Ruff before opening a PR:

```bash
python -m unittest discover -s tests
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
