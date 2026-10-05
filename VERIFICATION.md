# GrantTrace Verification

Detailed historical release verification records are archived in
[release verification history](docs/history/release-verification-history.md).

## Current verified release

Current release: [v2.5.2](https://github.com/ysc070528/granttrace/releases/tag/v2.5.2)
([PyPI](https://pypi.org/project/granttrace/2.5.2/)).
Release source: [cab16fd](https://github.com/ysc070528/granttrace/commit/cab16fdce4a7771c8036ca4f0614e6384f7bec3d).
Evidence checked on 2026-10-05.

| Check | Result |
|---|---|
| Python | 3.9 / 3.12 / 3.14 passed |
| Full regression suite | 560 tests passed |
| Branch-aware coverage | 85.27% on Python 3.12; required minimum 80% |
| Mypy / Ruff | Passed |
| Business scenarios | 6/6 passed |
| JSON / YAML examples and fresh installation | Passed |
| Runtime dependency audit / CodeQL | Passed |
| Windows x64 portable | Built and smoke-tested |
| Wheel / sdist | Build and `twine check --strict` passed |

The built-in active Demo confirmed one BOLA / IDOR fixture and one Mass Assignment
fixture. Recovery was verified, the mock database was restored, and the local
server stopped. The read-only Demo sent no PATCH requests.

Evidence: [CI](https://github.com/ysc070528/granttrace/actions/runs/37286320226),
[CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37286320202),
[Windows portable](https://github.com/ysc070528/granttrace/actions/runs/37286320166),
and [distribution build / publishing](https://github.com/ysc070528/granttrace/actions/runs/37287898227).
CI results are associated with the commit recorded by each workflow run.

## Safety verification

- The default audit mode is read-only.
- Active PATCH tests require explicit opt-in and an operation allowlist.
- Active tests save the original state and use independent GET readback.
- Restoration is attempted when needed and the observed restored state is verified.
- Unverified recovery or asynchronous outcomes halt subsequent writes.

See [SECURITY.md](SECURITY.md) for authorization, network boundaries and report handling.

## Known limitations

- The Windows portable executable is unsigned and may trigger SmartScreen.
- Automated launcher validation covers process execution and exit status; manual
  UI behavior and every clean-machine Windows configuration are outside its scope.
- macOS / Linux standalone binaries are not currently distributed.
- Restoration does not provide transactional rollback or cover concurrent changes
  and state outside the configured readback.
- Results apply to the documented fixtures and environments; they do not guarantee
  behavior or authorization correctness for arbitrary third-party APIs.

## Reproducible checks

From a checkout with the development dependencies installed:

```bash
python -m unittest discover -s tests
python -m mypy
python -m ruff check .
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
```

For branch-aware coverage, use `python -m coverage run -m unittest discover -s tests`
followed by `python -m coverage report`. The configured minimum is 80%.
Windows build and smoke commands are documented in
[Windows portable](docs/windows-portable.md); release steps are in the
[release checklist](docs/release-checklist.md).
