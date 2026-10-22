# GrantTrace Verification

Detailed historical release verification records are archived in
[release verification history](docs/history/release-verification-history.md).

## v2.5.3 post-release verification

Evidence checked on **2026-10-22**. Current status: **v2.5.3 is published;
post-release installation, public-asset integrity and manual Windows acceptance
remain pending**.

The official [GitHub Release](https://github.com/ysc070528/granttrace/releases/tag/v2.5.3)
was published on **2026-10-15 at 05:36:07 UTC** and is neither a draft nor a
prerelease. The `v2.5.3` tag resolves to release commit
[7bedc423a1a83a0bc8cef06c81c59b5c4df88751](https://github.com/ysc070528/granttrace/commit/7bedc423a1a83a0bc8cef06c81c59b5c4df88751).
All four workflow runs below report that exact `head_sha`; results from the
earlier `8021ef2` baseline or local preparation are not substituted for them.

| Check | Verified result and evidence |
|---|---|
| Release-commit CI | [CI run 38422683309](https://github.com/ysc070528/granttrace/actions/runs/38422683309): completed / success on 2026-10-13; Python 3.9 / 3.12 / 3.14, Ruff, Mypy and runtime dependency audit jobs all passed. Each Python job logged 634 tests; Python 3.12 logged 86.49% branch-aware coverage against the 80% gate. |
| Release-commit CodeQL | [CodeQL run 38422683479](https://github.com/ysc070528/granttrace/actions/runs/38422683479): completed / success on 2026-10-13; the Analyze Python job passed. This records workflow completion, not an assertion about the repository's complete alert inventory. |
| Release-commit Windows portable | [Windows run 38422683196](https://github.com/ysc070528/granttrace/actions/runs/38422683196): completed / success on 2026-10-13; Windows x64 portable build and extracted-ZIP automated verification passed on windows-2025, with `source_tree_dirty: false`. |
| PyPI publication workflow | [Publish to PyPI run 38687665680](https://github.com/ysc070528/granttrace/actions/runs/38687665680): completed / success on 2026-10-15, triggered by the Release publication. Both Build and validate distributions and Publish distributions with OIDC passed; logs record wheel/sdist upload to PyPI for [2.5.3](https://pypi.org/project/granttrace/2.5.3/). |

CI includes business scenarios, JSON/YAML scans and restoration, and a fresh
external virtual environment installation of a wheel built from the checkout.
That pre-release local-wheel check does not verify a post-release installation
from PyPI. The publishing workflow validates distribution metadata, strict Twine
checks and hashes across its build/upload jobs; it does not install the published
package from PyPI.

Windows automation extracts its built ZIP outside the checkout into paths with
spaces and Chinese characters, clears Python environment/PATH dependencies and
checks CLI, demos, launcher execution and cleanup. Browser opening is suppressed
and the launcher pause is acknowledged via stdin. Its success covers that CI
artifact, not a later public Release download, human double-click, visual browser
inspection or a clean machine.

The public Release currently lists `GrantTrace-v2.5.3-Windows-x64.zip` and
`SHA256SUMS.txt`, both uploaded on 2026-10-20. This update checked their metadata;
it did not download those public assets or recompute their hashes. Local
preparation hashes and workflow-internal hash checks cannot certify the public
downloads.

### Remaining post-release acceptance

The following checks remain **pending** in this record. They were not performed
in this documentation update, and the evidence above does not establish them.

| Acceptance item | Evidence required before marking passed |
|---|---|
| Fresh PyPI installation | Create a new venv outside the source checkout, install `granttrace==2.5.3` from public PyPI and record installation, version, CLI and packaged demo/resource checks. |
| Public Release assets and SHA256 | Re-download the public assets and checksum file; calculate SHA256 and compare with that Release's checksum entries and GitHub asset digests where supplied, recording exact filenames and results. |
| Public PyPI wheel/sdist integrity | Download the published wheel/sdist and compare calculated SHA256 with the public PyPI JSON metadata. Publishing-job hashes alone are insufficient. |
| Manual Windows double-click and browser inspection | Record a human launch of the public portable package, launcher behavior, browser/report inspection and cleanup. |
| Clean-machine Windows acceptance | Record the public portable package's behavior on a clean Windows machine without an existing Python/development environment, including the tested OS and results. |

## v2.5.3 release preparation - 2026-10-13

Historical snapshot as of **2026-10-13**. The publication state and pending items
below describe that preparation date; the post-release section above records
the completed release gates and the acceptance work still outstanding.

Status: **local validation passed; v2.5.3 is not published**. The reviewed main
baseline is [8021ef208a9f5883894e8fb63e397c4eb9040070](https://github.com/ysc070528/granttrace/commit/8021ef208a9f5883894e8fb63e397c4eb9040070),
which includes merged [PR #33](https://github.com/ysc070528/granttrace/pull/33)
and [PR #34](https://github.com/ysc070528/granttrace/pull/34). Version and release
documentation changes are uncommitted. This preparation changes no detector,
core logic or API behavior.

Local environment: Windows 11 x64 `10.0.26200`, standard CPython **3.14.5**,
PyYAML **6.0.3**, pytest **9.1.1**, coverage **7.16.2**, Ruff **0.16.10**,
Mypy **2.4.0**, build **1.6.1**, Twine **7.0.0**, setuptools **84.0.0**,
wheel **0.48.0**. Portable builds use CPython **3.14.5** and PyInstaller
**6.22.3**, with the pins in `packaging/windows/requirements-build.txt`.

| Check | This preparation |
|---|---|
| Full regression suite | 634 passed, 1176 subtests passed on CPython 3.14.5; 142.51 seconds |
| Branch-aware coverage | 86.49% on CPython 3.14.5; required minimum 80% |
| Mypy / Ruff | Passed; no Mypy issues in 19 source files |
| Business scenarios | 6/6 passed; zero fixture false positives, false negatives or inconclusive results |
| JSON / YAML examples | Read-only JSON and active JSON/YAML passed; full mock database restored; conclusive coverage 60% / 100% |
| Generated examples | Regenerated against the bundled loopback mock with version 2.5.3 |
| Wheel / sdist | Build and `twine check --strict` passed; package metadata and contents checked |
| Fresh wheel installation | Passed in a new external venv using the local wheelhouse; package/runtime/CLI/HTML/JSON/User-Agent versions agree at 2.5.3 |
| Windows x64 portable | Built and extracted-ZIP smoke passed under space and Chinese paths; ZIP, checksum and build/smoke JSON hashes agree |
| README public links | All actual public links returned HTTP 200; main raw PNG validated; latest Release currently resolves to v2.5.2 |
| Final release-commit CI / CodeQL / Windows | Needs completion after commit / push / review |
| PyPI 2.5.3 installation | Needs completion after publication; PyPI currently exposes 2.5.2 and returns 404 for 2.5.3 |
| Manual Windows double-click / clean machine / browser inspection | Needs completion; automated smoke does not cover these checks |

Evidence for this run is saved locally under `dist/v2.5.3-release-prep/`,
`dist/v2.5.3-distributions/` and `dist/v2.5.3-windows/`. These ignored local
outputs are release candidates from the modified worktree, not final public
Release assets. Build JSON records `source_tree_dirty: true` for this preparation.

Fresh wheel installation verified packaged demo resources, active recovery,
full database restoration, local server shutdown, read-only zero PATCH and
JSON/YAML offline plans with zero requests. Windows validation used a reduced
PATH without Python, cleared Python environment variables and suppressed browser
opening; the launcher pause was acknowledged via stdin. These are automated
checks on the documented host, not clean-machine or manual desktop validation.

Local test commands used for this preparation:

```powershell
.\.venv\Scripts\python.exe -m coverage run --data-file=dist/v2.5.3-release-prep/.coverage -m pytest --junitxml=dist/v2.5.3-release-prep/regression.xml
.\.venv\Scripts\python.exe -m coverage report --data-file=dist/v2.5.3-release-prep/.coverage
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe scripts/verify_business_scenarios.py
.\.venv\Scripts\python.exe scripts/verify_examples.py --update-examples
.\.venv\Scripts\python.exe -m build --no-isolation --outdir dist/v2.5.3-distributions
.\.venv\Scripts\python.exe -m twine check --strict dist/v2.5.3-distributions/granttrace-2.5.3-py3-none-any.whl dist/v2.5.3-distributions/granttrace-2.5.3.tar.gz
.\.venv\Scripts\python.exe scripts/verify_install.py --wheel dist/v2.5.3-distributions/granttrace-2.5.3-py3-none-any.whl --wheelhouse dist/windows-wheelhouse --output dist/v2.5.3-release-prep/install-verification.json
```

Windows build/smoke commands are in [Windows portable](docs/windows-portable.md).
This preparation used `--output-dir dist/v2.5.3-windows` for the builder, with
the verifier's `--zip` and `--output` pointing to that same directory.

The merged baseline has successful [CI](https://github.com/ysc070528/granttrace/actions/runs/37877528925),
[CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37877528892)
and [Windows portable](https://github.com/ysc070528/granttrace/actions/runs/37877528884).
Its Python 3.9 / 3.12 / 3.14 jobs passed; the Python 3.12 log records **634 tests**
and **86.49%** branch-aware coverage. These results apply to `8021ef2`, whose
package version was 2.5.2, and do not verify the upcoming release commit.

The four Actions workflows were reviewed. CI retains the supported Python
matrix, the 80% coverage gate, Mypy, Ruff, runtime dependency auditing, business
fixtures, JSON/YAML scans and external fresh installation. Windows artifact
paths and the publishing workflow's version selection are synchronized to
v2.5.3. The publishing workflow was not dispatched. It publishes only from an
official stable Release and checks tag, source and distribution metadata, but
does not itself require successful CI: maintainers must check the final SHA
before creating a tag.

### SHA256 verification

Local distribution hashes are recorded in
`dist/v2.5.3-distributions/SHA256SUMS.txt`. The Windows builder separately writes
`dist/v2.5.3-windows/SHA256SUMS.txt`; its ZIP hash must match the build and smoke
JSON evidence. Verify the exact files intended for upload:

```powershell
Get-FileHash -Algorithm SHA256 dist/v2.5.3-distributions/granttrace-2.5.3-py3-none-any.whl
Get-FileHash -Algorithm SHA256 dist/v2.5.3-distributions/granttrace-2.5.3.tar.gz
Get-FileHash -Algorithm SHA256 dist/v2.5.3-windows/GrantTrace-v2.5.3-Windows-x64.zip
Get-Content dist/v2.5.3-distributions/SHA256SUMS.txt
Get-Content dist/v2.5.3-windows/SHA256SUMS.txt
```

After final CI builds and upload, download each public asset again and compare
its calculated SHA256 with that Release's checksum file and GitHub asset digest
when supplied. Verify PyPI wheel/sdist hashes against PyPI JSON metadata and
perform a fresh `pip install granttrace==2.5.3` outside the source checkout.
Those public-asset and PyPI installation checks remain pending until publication;
local candidate hashes cannot certify subsequently rebuilt assets.

## Historical v2.5.2 published release snapshot

Published snapshot: [v2.5.2](https://github.com/ysc070528/granttrace/releases/tag/v2.5.2)
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
