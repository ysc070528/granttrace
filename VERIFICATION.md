# GrantTrace Verification

Detailed historical release verification records are archived in
[release verification history](docs/history/release-verification-history.md).

## v2.7.1 post-release verification - 2026-11-13

Status: **v2.7.1 is published. The PyPI distributions and the official Windows
ZIP are verified; manual acceptance on a clean Windows machine is not done.**
The [pre-release acceptance](#v271-pre-release-acceptance---2026-11-11) below is
kept unchanged as the record of the candidate.

The [GitHub Release](https://github.com/ysc070528/granttrace/releases/tag/v2.7.1)
was published on **2026-11-12 at 02:14:34 UTC**; it is neither a draft nor a
prerelease and is the latest release. The `v2.7.1` tag (a lightweight tag, as
for v2.7.0) resolves to release commit
[a279309e3950d91603d6a94346a48eeaa4e9809b](https://github.com/ysc070528/granttrace/commit/a279309e3950d91603d6a94346a48eeaa4e9809b),
the merge of #93 and the head of `main`; its tree is identical to the reviewed
#93 head `2aaae81`. PyPI lists 2.7.1 as the latest version; 2.7.0 remains, and
neither is yanked. The `v2.7.0` tag still resolves to `7362098`.

Environment: Linux x86_64 container; CPython **3.9.25** (pip 23.0.1), **3.13.18**
(pip 26.2.2) and **3.14.6** (pip 26.1.2); PyInstaller **6.22.3**, used only to read
the Windows executable's archives. No Windows host was used.

| Check | Verified result and evidence |
|---|---|
| Release-commit CI | On `a279309`: GrantTrace CI [run 42983811098](https://github.com/ysc070528/granttrace/actions/runs/42983811098), CodeQL [run 42983811137](https://github.com/ysc070528/granttrace/actions/runs/42983811137) and Windows x64 portable [run 42983811160](https://github.com/ysc070528/granttrace/actions/runs/42983811160): all passed |
| PyPI publication workflow | [Run 43141489539](https://github.com/ysc070528/granttrace/actions/runs/43141489539): **manual `workflow_dispatch` from `main`** at 02:27:03 UTC, 12.5 minutes after the Release was published, not the `release` event. Both jobs passed: it validated the official v2.7.1 Release, checked out `a279309`, checked tag, project and runtime versions, built both distributions, passed `twine check --strict`, logged their SHA256s and published them with Trusted Publishing. No `release`-event run exists for v2.7.1, unlike 2.5.3, 2.6.0 and 2.7.0; the cause is not visible in the Actions data |
| PyPI distributions | `granttrace-2.7.1-py3-none-any.whl`, 199,423 bytes, SHA256 `85d0fa730beaf232ff9e9f9ead35f5044e929179e8fca440f30ca50982a253d5`; `granttrace-2.7.1.tar.gz`, 1,575,805 bytes, SHA256 `aeb55cd642f3645af477c514d11ee21a33608ccab6ff7b6e1030323b1033b846`; uploaded at 02:27:50 and 02:27:52 UTC. The downloaded files match PyPI's digests and the publishing run's log. All 37 source files in the wheel and all 173 non-generated files in the sdist are byte-identical to `v2.7.1`; the sdist contains the pre-release record, so it was built from the tag, not the candidate `37eef7b` |
| PyPI metadata | `Version: 2.7.1`, the unchanged `Summary`, `Requires-Python: >=3.9`, `Requires-Dist: PyYAML>=6.0`, `License-Expression: Apache-2.0`. The Markdown long description is the 2.7.1 README: it states that GrantTrace sends no PATCH, PUT or DELETE and describes the refusal; "never writes to your API" is gone |
| Fresh PyPI installations | `pip install granttrace==2.7.1` from public PyPI in new virtual environments on CPython 3.9.25, 3.13.18 and 3.14.6; pip's report shows the wheel with SHA256 `85d0fa73…`. Each install: `GrantTrace 2.7.1`; `core` from `site-packages`; the new `--help` text (no "mass-assignment auditor"); `granttrace demo` exits 0 with BOLA and mass assignment confirmed, rollback verified, the database restored and the server stopped |
| 2.7.1 refusal, installed from PyPI | A request recorder listened on the container's non-loopback address `192.0.2.2`. Scans of it without `--config`, with `{}` and with `--write-endpoint` but no configuration, and scans of `localhost.evil.com`, `127.0.0.1.nip.io` and `2130706433`, each exited 2 with the refusal and wrote no report; the recorder received **0 requests**. A configured scan of the same address was not refused, printed `Scan target`, and reached it (11 requests). A loopback scan of the bundled mock without identities ran with the mock-identity warning; the README development flow with `config.example.json` confirmed 1 finding; a remote dry run without identities sent 0 requests and pointed to `--init-config`. Same results on all three interpreters |
| Installed-wheel validation | `scripts/verify_install.py --wheel` with the PyPI wheel passed on 3.13.18 and 3.9.25: read-only scan passed with 0 PATCH, the external active scan blocked without state authority with 0 PATCH, the database restored, versions in HTML and JSON checked, 0 requests for the offline plan, the draft configuration blocked, run outside the source tree |
| Official Windows ZIP | Downloaded from the Release: `GrantTrace-v2.7.1-Windows-x64.zip`, 10,749,522 bytes, SHA256 `87865c576388330f19f9b943f2c35198dd522f57086c0cd23764712c491ff28d`. It matches the Release's `SHA256SUMS.txt` (`sha256sum -c`: OK; the file has Windows line endings and SHA256 `09305d899e9d854d5c6bdeb4c1036787cd099222140e050dbbbc9aeb2b874ad4`), GitHub's asset digest, and the `zip_sha256` recorded by Windows run 42983811160 on `a279309` (clean tree, Windows Server 2025, Python 3.14.5, PyInstaller 6.22.3), whose `verify_windows_portable.py` passed for these bytes |
| Windows ZIP contents | Integrity test OK; 88 entries under one top folder; no absolute or parent paths. `granttrace.exe`, `Start-Demo.bat`, `README.txt`, `LICENSE` and the three demo assets are present; README and launcher show v2.7.1 with no placeholder left. `granttrace.exe` is PE32+ x86-64, 3,137,603 bytes, SHA256 `577c02d67b9828112f5d2d4f5a8fafe6e7a0924d85505c82880e07e0251005d0`, as in the build record |
| Windows executable code | Read with PyInstaller's archive readers, without running anything: the entry script `api_sentinel` and all 33 bundled `core` and `mock_server` modules are bytecode-identical to the `v2.7.1` source compiled with CPython 3.14.6. The bundled version is 2.7.1, and `is_loopback_target`, the refusal text and the `Scan target` output are present |
| Release assets timeline | The ZIP was uploaded at 02:11:10 UTC, before publication; `SHA256SUMS.txt` at 02:50:32 UTC, 36 minutes after publication |
| Links and activity | The Release notes' CHANGELOG, verification-record and compare links, the PyPI project pages and the README images on `raw.githubusercontent.com` return HTTP 200. No workflow run failed after the release commit; no issue or pull request was opened since 2026-11-11 |

Not done:

- **Clean Windows machine:** nobody has extracted the official ZIP and
  double-clicked `Start-Demo.bat` on a clean Windows machine (including paths with
  spaces or Chinese characters, SmartScreen and the browser opening the report).
  The CI verification ran the same bytes on Windows Server 2025, but it does not
  exercise the 2.7.1 refusal; that the executable contains it is established from
  its bytecode, not by running it on Windows.
- **PyPI page rendering:** pypi.org served a JavaScript client challenge to this
  environment, so the rendered page was not seen; the published long description
  was read from PyPI's JSON API instead.
- VAmPI and crAPI were not re-run; the code scanning alert inventory was not read.

## v2.7.1 pre-release acceptance - 2026-11-11

Status: **accepted for release; v2.7.1 is not published.** Release candidate:
commit `37eef7b` (head of PR #93: main `61f7e05`, the merge of #92, plus the
version, the changelog date, the publishing workflow's manual choice, the
regenerated examples and release-specific documentation); the commit after it
adds only this record. PyPI's latest is 2.7.0; there is no `v2.7.1` tag or
Release.

Environment: Linux x86_64 container; CPython **3.13.18** for coverage, acceptance
scripts and the build, plus CPython **3.9.25**, **3.12.3** and **3.14.6**; PyYAML
**6.0.3**, pytest **9.2.0** (**8.4.2** on 3.9), coverage **7.17.2** (**7.10.7** on
3.9), Ruff **0.17.4**, Mypy **2.4.1**, build **1.6.1**, Twine **7.0.0**, setuptools
**84.2.1**, wheel **0.48.0**, pip-audit **2.10.1**. The Windows package was built
and checked by the GitHub-hosted `windows-2025` runner; no Windows host was used
locally.

| Check | Result |
|---|---|
| CI on main after #92 (`61f7e05`) | GrantTrace CI [run 42977306638](https://github.com/ysc070528/granttrace/actions/runs/42977306638), Windows x64 portable [run 42977306654](https://github.com/ysc070528/granttrace/actions/runs/42977306654) and CodeQL [run 42977306497](https://github.com/ysc070528/granttrace/actions/runs/42977306497): all passed |
| CI on the candidate (`37eef7b`) | 9 of 9 passed: Ruff, Mypy, tests on 3.9 / 3.12 / 3.14 and runtime dependency audit ([run 42978755482](https://github.com/ysc070528/granttrace/actions/runs/42978755482)), Windows x64 portable ([run 42978755524](https://github.com/ysc070528/granttrace/actions/runs/42978755524)), Analyze Python ([run 42978755518](https://github.com/ysc070528/granttrace/actions/runs/42978755518)) and CodeQL |
| Full regression suite | 1335 passed and 2478 subtests passed on CPython 3.12.3, 3.13.18 and 3.14.6; 1335 passed on 3.9.25; full unittest (1335 tests) passed on all four |
| Branch-aware coverage | 90.03% combined on 3.13.18 (statements 7324 / 7964, branches 3492 / 4050 = 86.22%); 89.94% on 3.9.25, 90.03% on 3.12.3 and 90.04% on 3.14.6; required minimum 80% |
| Mypy / Ruff | No Mypy issues in 32 source files; Ruff passed |
| Acceptance scripts | On each of the four interpreters: PR42 adversarial (28 tests); PR43 integration (89 tests, source `37eef7b`, clean tree); authorization coverage, authoritative and generic HTTP; business scenarios 6 / 6 (0 false positives, false negatives or inconclusive results); JSON / YAML examples (read-only exit 0, active exit 2 with external PATCH stopped before any write, 60% conclusive coverage, the mock database restored) |
| Runtime dependency audit | `pip-audit --strict` on the candidate: PyYAML 6.0.3, no known vulnerabilities |
| Generated examples | Regenerated with `scripts/verify_examples.py --update-examples`; they declare 2.7.1. Against the 2.7.0 files only the version, generation time, loopback port, result order and the User-Agent's version differ: 5 operations, 2 confirmed, 1 public and 2 secure results, 100% conclusive coverage, 21 requests |
| Wheel / sdist | Isolated `python -m build` from `git archive` of `37eef7b`; `twine check --strict` passed for both. Wheel: 43 files, no tests, caches or local configurations. Sdist: 196 entries (2.7.0: 195); against the 2.7.0 sdist built the same way, the only new file is `tests/test_cli_identity_guard.py` and none is missing. Metadata: `Version: 2.7.1`, the unchanged `Summary`, `Requires-Python: >=3.9`, `Requires-Dist: PyYAML>=6.0`, `License-Expression: Apache-2.0` |
| Clean installations | The wheel in new virtual environments on CPython 3.9.25, 3.13.18 and 3.14.6, and the sdist on 3.13.18, each outside the checkout: `granttrace --version` prints `GrantTrace 2.7.1` and `core` loads from `site-packages`; `granttrace demo` exits 0 with BOLA and mass assignment confirmed, rollback verified, the database restored and the server stopped; a scan of `https://api.example.test` without `--config` exits 2 with the refusal and writes no report. `scripts/verify_install.py --wheel` passed on the built wheel with 3.9.25 and 3.13.18: versions consistent, 0 PATCH in read-only and external active scans (the external active scan is blocked without state authority), 0 requests for the offline plan. Run from inside a virtual environment of uv's standalone CPython 3.9, the script's own venv creation fails before GrantTrace runs (the nested venv finds no standard library); it passed on 3.12.3, 3.13.18 and 3.14.6 that way |
| Version consistency | `pyproject.toml`, `core.__version__`, CLI, HTML and JSON reports and the HTTP User-Agent say 2.7.1. The Windows build and verification scripts, the Windows workflow's ZIP and artifact names (`GrantTrace-v2.7.1-Windows-x64`) and the packaged README and launcher derive it through `scripts/source_version.py`; the publishing workflow's manual choices include v2.7.1 |
| Windows x64 portable | Built from `37eef7b` (clean tree) in run 42978755524 on Windows Server 2025 with Python 3.14.5 and PyInstaller 6.22.3: `GrantTrace-v2.7.1-Windows-x64.zip`, 10,750,494 bytes, SHA256 `e69a28f35b2524ca8d53fa5dd8be43c34108bd2ce44667ced78711ed7691180b`. `scripts/verify_windows_portable.py` passed: extraction to paths with spaces and Chinese characters outside the checkout, no Python on the child PATH, `--version` and `--help`, active and read-only demos, an offline YAML plan with 0 requests, `Start-Demo.bat`, the loopback port closed and no package process left. The ZIP was not downloaded and rehashed here, and no one double-clicked it on a clean Windows machine |
| 2.7.1 changes | The refusal of a non-loopback scan without identities, the loopback parsing, the mock-identity warning and the dry-run guidance are covered by `tests/test_cli_identity_guard.py` (13 tests, 76 subtests), including a real scan of the loopback mock and the demo through `main()`. Detectors, evidence standards and report formats are unchanged: the JSON and HTML output snapshots are identical to 2.7.0, and the console snapshot gains only the `Scan target` line. VAmPI and crAPI were not re-run for this candidate |
| Secrets | A pattern scan of all 195 tracked files found no keys, tokens or JWTs; the only match is a dummy private-key marker in a redaction test. GitHub secret scanning is not enabled for the repository |
| Documentation | 27 Markdown files, 136 relative and same-repository links and anchors: 0 problems. `SECURITY.md`, the READMEs and the command-line reference describe the new requirement (#92); release-specific pages updated in #93 |

Local candidate hashes, built from `37eef7b` in the container:

```text
ca904dc0745f3d5c87d3293f8179564a3be545d56d3867812022e78d84a8a198  granttrace-2.7.1-py3-none-any.whl
78b09e95f05c823baa692c01e307c9145fc1e8cf20081ca3cd496659b2189155  granttrace-2.7.1.tar.gz
```

The publishing workflow builds the uploaded distributions from the tag. The
Release's Windows ZIP and `SHA256SUMS.txt` come from the Windows workflow run on
the release commit itself; their hashes differ from the builds above because the
build records its source commit.

Still to do: CI on the release commit, then the tag, the GitHub Release with the
Windows assets, PyPI publishing and the post-release checks in the
[release checklist](docs/release-checklist.md), including a clean Windows machine.

## v2.7.0 pre-release acceptance - 2026-11-11

Status: **accepted for release; v2.7.0 is not published.** Release candidate:
commit `750a801` (head of PR #90: main `9fc560c`, the merge of #84, plus the
release date, the publishing workflow's manual choice and release-specific
documentation); the commit after it adds only this record. PyPI's latest is
2.6.0; there is no `v2.7.0` tag or Release.

Environment: Linux x86_64 container; CPython **3.13.18** for coverage, linting,
acceptance scripts and the build, plus CPython **3.9.25** and **3.14.6**; PyYAML
**6.0.3**, pytest **9.2.0** (**8.4.2** on 3.9), coverage **7.17.2**, Ruff
**0.17.4**, Mypy **2.4.1**, build **1.6.1**, Twine **7.0.0**, setuptools
**84.2.1**, wheel **0.48.0**. The Windows package was built and checked by the
GitHub-hosted `windows-2025` runner; no Windows host was used locally.

| Check | Result |
|---|---|
| CI on main after #84 (`9fc560c`) | GrantTrace CI [run 42918318210](https://github.com/ysc070528/granttrace/actions/runs/42918318210) (Ruff, Mypy, tests on 3.9 / 3.12 / 3.14, runtime dependency audit), Windows x64 portable [run 42918318200](https://github.com/ysc070528/granttrace/actions/runs/42918318200) and CodeQL [run 42918318197](https://github.com/ysc070528/granttrace/actions/runs/42918318197): all passed |
| Full regression suite | 1322 passed and 2402 subtests passed on CPython 3.13.18 and 3.14.6; 1322 passed on 3.9.25; full unittest passed |
| Branch-aware coverage | 89.95% combined (statements 7281 / 7922, branches 3474 / 4034 = 86.12%); required minimum 80% |
| Acceptance scripts | PR42 adversarial; PR43 integration (89 tests, source `750a801`, clean tree); authorization coverage, authoritative and generic HTTP; business scenarios 6 / 6; JSON / YAML examples; installation |
| Wheel / sdist | Isolated `python -m build` from `git archive`; `twine check --strict` passed for both. Wheel: 43 files; sdist: 195 files; no caches, local configurations or build output. Metadata: `Version: 2.7.0`, the unchanged `Summary`, `Requires-Python: >=3.9`, `Requires-Dist: PyYAML>=6.0` |
| Clean installations | The wheel in new virtual environments on CPython 3.9.25, 3.13.18 and 3.14.6, and the sdist on 3.13.18, each outside the checkout: `granttrace --version` prints `GrantTrace 2.7.0` and `core` loads from `site-packages`; `granttrace demo` exits 0 with BOLA and mass assignment confirmed, rollback verified, the database restored and the server stopped. `scripts/verify_install.py --wheel` passed on the built wheel: versions consistent, 0 PATCH in read-only and external active scans (the external active scan is blocked without state authority), 0 requests for the offline plan |
| Version consistency | `pyproject.toml`, `core.__version__`, CLI, HTML and JSON reports and the HTTP User-Agent say 2.7.0. The Windows build and verification scripts, the Windows workflow's ZIP and artifact names and the packaged README and launcher derive it through `scripts/source_version.py`; the publishing workflow's manual choices include v2.7.0 |
| Windows x64 portable | Built from `9fc560c` (clean tree) in run 42918318200 on Windows Server 2025 with Python 3.14.5 and PyInstaller 6.22.3: `GrantTrace-v2.7.0-Windows-x64.zip`, 10,747,513 bytes, SHA256 `a05d6288b85577e6e4bee1a12c9910c8922e564cfa0cf475f96e180832bc1a90`. `scripts/verify_windows_portable.py` passed: extraction to paths with spaces and Chinese characters outside the checkout, no Python on the child PATH, `--version` and `--help`, active and read-only demos, an offline YAML plan with 0 requests, `Start-Demo.bat`, the loopback port closed and no package process left. The artifact host was not reachable from this environment, so the ZIP was not downloaded and rehashed here, and no one double-clicked it on a clean Windows machine |
| 2.7.0 detectors | Read-only POST, role matrix and sensitive-field checks are covered by `tests/test_v27_hardening.py`, including real HTTP to a loopback server. VAmPI and crAPI were not re-run for this candidate; the read-only GET/HEAD decisions are unchanged (a 200,000-endpoint differential against 2.6.0 found no difference) |
| Secrets | A pattern scan of all 194 tracked files found no keys, tokens or JWTs; the only match is a dummy private-key marker in a redaction test. GitHub secret scanning is not enabled for the repository |
| Documentation | Relative links, anchors and links to this repository: 0 problems. `SECURITY.md` describes when a read-only POST is sent; release-specific pages updated in #90 |

Local candidate hashes, built from `750a801` in the container:

```text
8efe69a82a953310156424bfb2451f6bee842d2e4655445f25daacddba9fe303  granttrace-2.7.0-py3-none-any.whl
2c72b227652da135275c17036f58232e051efa53f325aa24ca7ea60c7f183b92  granttrace-2.7.0.tar.gz
```

The publishing workflow builds the uploaded distributions from the tag. The
Release's Windows ZIP and `SHA256SUMS.txt` come from the Windows workflow run on
the release commit itself; their hashes differ from the build above because the
build records its source commit.

Still to do: CI on the release commit, then the tag, the GitHub Release with the
Windows assets, PyPI publishing and the post-release checks in the
[release checklist](docs/release-checklist.md), including a clean Windows machine.

## v2.6.0 pre-release acceptance - 2026-11-08

Status: **accepted for release; v2.6.0 is not published.** Release candidate:
commit `96255c3` (head of PR #87: main `2ce7093` plus documentation and package
metadata only); the commit after it adds only this record. PRs #78 to #87 merged
after the [first preparation round](#v260-release-preparation-first-round---2026-11-08).
PR #84 (2.7.0 features) is not part of this release.

Environment: Linux x86_64 container; CPython **3.13.18** for coverage, linting,
acceptance scripts and the build, plus CPython **3.9.25** and **3.14.6**; PyYAML
**6.0.3**, pytest **9.2.0** (**8.4.2** on 3.9), coverage **7.17.2**, Ruff
**0.17.4**, Mypy **2.4.1**, build **1.6.1**, Twine **7.0.0**, setuptools
**84.2.1**, wheel **0.48.0**; Docker **29.9.2** for crAPI. The Windows package was
built and checked by the GitHub-hosted `windows-2025` runner; no Windows host was
used locally.

| Check | Result |
|---|---|
| CI on the candidate | 9 of 9 passed: Ruff, Mypy, tests on 3.9 / 3.12 / 3.14, runtime dependency audit, Windows x64 portable, Analyze Python, CodeQL |
| Full regression suite | 1249 passed and 2336 subtests passed on CPython 3.13.18 and 3.14.6; 1249 passed on 3.9.25; full unittest passed |
| Branch-aware coverage | 89.77% combined (statements 6821 / 7436, branches 3219 / 3748 = 85.89%); required minimum 80% |
| Acceptance scripts | PR42 adversarial; PR43 integration (89 tests, pinned method hashes, source `96255c3`, clean tree); authorization coverage, authoritative and generic HTTP; business scenarios 6 / 6; JSON / YAML examples |
| Wheel / sdist | Isolated `python -m build`; `twine check --strict` passed for both. Wheel: 43 files, no caches or tests. Sdist: 191 files including `CODE_OF_CONDUCT.md`, `examples/` and the case-study helpers, and no local configurations, build output or caches. Metadata: `Version: 2.6.0`, the new `Summary`, `Requires-Python: >=3.9`, `Requires-Dist: PyYAML>=6.0` |
| Clean installations | The wheel in new virtual environments on CPython 3.9.25, 3.13.18 and 3.14.6, and the sdist on 3.13.18, each outside the checkout: `granttrace --version` prints `GrantTrace 2.6.0` and `core` loads from `site-packages`; `granttrace demo` exits 0 with BOLA and mass assignment confirmed, 100% conclusive coverage, 21 requests, rollback verified, the database restored and the server stopped. `scripts/verify_install.py --wheel` passed on the built wheel: versions consistent, 0 PATCH in read-only and external active scans, 0 requests for the offline plan |
| README development flow | `python mock_server/server.py` and a scan with `config.example.json`: exit 0, BOLA confirmed, 11 requests |
| Version consistency | `pyproject.toml`, `core.__version__`, CLI, HTML and JSON reports, the schema fetcher's User-Agent, the Windows launcher and README, the Windows build and verification scripts, and the publishing workflow's choices all say 2.6.0. PyPI's latest is 2.5.3; there is no `v2.6.0` tag or Release yet |
| Windows x64 portable | Built from `96255c3` (clean tree) in [run 42484093708](https://github.com/ysc070528/granttrace/actions/runs/42484093708) on Windows Server 2025 with Python 3.14.5 and PyInstaller 6.22.3: `GrantTrace-v2.6.0-Windows-x64.zip`, 10,722,272 bytes, SHA256 `1fd1b032f4c18ec8bf8ed7b72d1ae3c57f55d672d7201c0a972bcd4947bac8b2`. `scripts/verify_windows_portable.py` passed: extraction to paths with spaces and Chinese characters outside the checkout, no Python on the child PATH, `--version` and `--help`, active and read-only demos, an offline YAML plan with 0 requests, `Start-Demo.bat`, the loopback port closed and no package process left. The artifact host was not reachable from this environment, so the ZIP was not downloaded and rehashed here, and no one double-clicked it on a clean Windows machine |
| VAmPI regression | Vulnerable and secure modes, standard and field-rule scans: every verdict and SARIF result matches the [case study](docs/case-studies/vampi.md); 14 requests per scan |
| crAPI regression | Standard and field-rule scans: every verdict and SARIF result matches the [case study](docs/case-studies/crapi.md); 43 requests per scan; the gateway log shows GrantTrace sent only GET |
| Secrets | A pattern scan of all 190 tracked files found no keys, tokens or JWTs; the only match is a dummy private-key marker in a redaction test. Example configurations use placeholders; the crAPI helper contains crAPI's own published lab administrator login. GitHub secret scanning is not enabled for the repository |
| Documentation | Relative links, anchors and links to this repository: 0 problems. Capability statements corrected in #87 |

Local candidate hashes, built from `96255c3` in the container:

```text
29914dbab1236e2c40b8c2a96e5200178b02d12268c0ca70c5dbb612f657145a  granttrace-2.6.0-py3-none-any.whl
697cfb8872f5c98b2fef02d5ae7ac1ea5101df1fdf7f2f2d44c269dbe6fb3baa  granttrace-2.6.0.tar.gz
```

The publishing workflow builds the uploaded distributions from the tag. The
Release's Windows ZIP and `SHA256SUMS.txt` come from the Windows workflow run on
the release commit itself; their hashes differ from the candidate above because
the build records its source commit.

PR #87 merged as `4a37525`, identical to `c110ac4`. A later PR changed only the
Code of Conduct's reporting contact and this paragraph; no code, test or
package metadata changed after the acceptance.

Still to do: CI on the release commit, then the tag, the GitHub Release with the
Windows assets, PyPI publishing and the post-release checks in the
[release checklist](docs/release-checklist.md), including a clean Windows machine.

## v2.6.0 release preparation, first round - 2026-11-08

Status: **first round, superseded by the
[pre-release acceptance](#v260-pre-release-acceptance---2026-11-08) above.** On 2026-11-08 the
latest [GitHub Release](https://github.com/ysc070528/granttrace/releases/latest)
and the latest [PyPI](https://pypi.org/project/granttrace/) version were both
2.5.3. The checks below ran on release commit `c359eb1` (branch
`release/v2.6.0`, based on main `8090cc7`, which includes PRs #55 to #77); the
commit after it adds only this record. The release preparation changes versions,
documentation and the example reports, and makes the remote `$ref` fetcher's
User-Agent follow the runtime version instead of a hard-coded 2.5.3.

Local environment: Linux x86_64 container; CPython **3.13.18** for coverage,
linting, acceptance scripts and the build, plus CPython **3.9.25** and
**3.14.6**; PyYAML **6.0.3**, pytest **9.2.0**, coverage **7.17.2**, Ruff
**0.17.4**, Mypy **2.4.1**, build **1.6.1**, Twine **7.0.0**, setuptools
**84.2.1**, wheel **0.48.0**. No Windows host was used.

| Check | This preparation |
|---|---|
| Full regression suite | 1228 passed and 2294 subtests passed on CPython 3.13.18 and 3.14.6; 1228 passed on 3.9.25; full unittest passed |
| Branch-aware coverage | 89.66% combined (statements 91.66%, branches 3172 / 3702 = 85.68%) on CPython 3.13.18; required minimum 80% |
| Mypy / Ruff | Passed; no Mypy issues in 32 source files |
| Acceptance scripts | PR42 adversarial, PR43 integration (pinned method hashes) and authorization coverage (authoritative and generic HTTP) passed |
| Business scenarios | 6/6 matched; zero fixture false positives, false negatives or inconclusive results |
| JSON / YAML examples | Read-only JSON (exit 0) and active JSON/YAML (exit 2: external PATCH checks stay `INCONCLUSIVE` before any write) passed; full mock database restored; conclusive coverage 60% |
| Generated examples | Regenerated from the built-in demo with CPython 3.14.6; declare 2.6.0; 2 confirmed, 100% conclusive coverage, rollback verified |
| Wheel / sdist | `python -m build --no-isolation` and `twine check --strict` passed for both; the wheel has 43 files including the three demo assets and the `core/config_validation` package, and no caches, tests or `dist` files; metadata `Version: 2.6.0`, `Requires-Python: >=3.9`, `Requires-Dist: PyYAML>=6.0`; the sdist has 176 files including `examples/` |
| Fresh wheel installation | `scripts/verify_install.py --wheel` passed outside the checkout: package, runtime, CLI, HTML, JSON and User-Agent versions agree at 2.6.0; the installed demo confirmed BOLA and mass assignment with verified rollback and full restoration; read-only scans sent 0 PATCH; the external active scan was blocked without state authority |
| README public links | GitHub and PyPI links returned HTTP 200; the shields.io badges and the Actions badge could not be reached from this environment's network and were not checked |
| Windows x64 portable | Pending: built and smoke-tested by the release PR's Windows workflow; a manual double-click on a clean Windows machine is still needed |
| Release-commit CI / CodeQL | Pending on the release PR |
| Tag, GitHub Release, PyPI 2.6.0 installation | Pending after merge; maintainers create the tag and the Release, and publishing runs from it |

Local candidate hashes, built from `c359eb1` in the container:

```text
2ab9c9e2f9bae91afcdec858d3b753285a44d49f5447d9b89c465d8a72c18b07  granttrace-2.6.0-py3-none-any.whl
ee7393cc2c8eb445200b8c3471baaadf93b847400e3306633fae8139a4a8f885  granttrace-2.6.0.tar.gz
```

The publishing workflow builds the uploaded distributions from the tag, so
public PyPI files are verified against PyPI metadata and a fresh
`pip install granttrace==2.6.0` after publication, not against these local
candidates.

## v2.5.3 post-release verification

Evidence checked on **2026-10-22**. Current status: **v2.5.3 is published;
fresh PyPI installation, official Windows ZIP SHA256 verification, manual portable
launch and report checks, and PATH isolation have passed on the documented Windows
host. Clean-machine Windows acceptance and public PyPI wheel/sdist hash verification
remain pending**. See the [actual acceptance record](#v253-发布后验收记录2026-10-22)
for the completed checks and their limits.

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

The public Release lists [GrantTrace-v2.5.3-Windows-x64.zip](https://github.com/ysc070528/granttrace/releases/download/v2.5.3/GrantTrace-v2.5.3-Windows-x64.zip)
and [SHA256SUMS.txt](https://github.com/ysc070528/granttrace/releases/download/v2.5.3/SHA256SUMS.txt),
both uploaded on 2026-10-20. The initial post-release metadata check did not
download those public assets or recompute their hashes. The subsequent
[2026-10-22 acceptance record](#v253-发布后验收记录2026-10-22) confirms that the official
Windows ZIP's calculated SHA256 matched the official checksum. Local preparation
hashes and workflow-internal hash checks cannot certify public downloads.

### Post-release acceptance summary

The summary below reflects the existing 2026-10-22 actual acceptance record.
This documentation correction adds no new installation or runtime acceptance.

| Acceptance item | Status and evidence |
|---|---|
| Fresh PyPI installation | **Passed** in an independent new venv from public PyPI with `granttrace==2.5.3`; version, help, packaged Demo, HTML/JSON reports, rollback, database restoration and local service shutdown were recorded. |
| Official Windows ZIP SHA256 | **Passed**: the downloaded official ZIP's actual SHA256 matched the official checksum. The record does not separately establish comparison with GitHub asset digests. |
| Manual Windows portable launch and report inspection | **Passed** on the current Windows host: extracted the official ZIP, ran `Start-Demo.bat`, generated reports and opened the HTML report. The record does not specify a double-click in a path containing spaces or Chinese characters. |
| PATH isolation | **Passed** on Windows 10 Home China with the session PATH restricted to `%SystemRoot%\System32;%SystemRoot`: version, Demo, rollback, database restoration and local service shutdown succeeded. This is not clean-machine acceptance. |
| Public PyPI wheel/sdist integrity | **Pending**: download the published wheel/sdist and compare calculated SHA256 with the public PyPI JSON metadata. Publishing-job hashes and a successful PyPI installation do not establish this check. |
| Clean-machine Windows acceptance | **Pending**: test the public portable package on a fresh Windows device without an existing Python/development environment and record the tested OS and results. PATH isolation on the current host does not satisfy this requirement. |

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


## v2.5.3 发布后验收记录（2026-10-22）

### 已通过

- [x] 在独立 Python 虚拟环境中从 PyPI 安装 granttrace==2.5.3。
- [x] `granttrace --version` 正确显示 v2.5.3。
- [x] `granttrace --help` 正常显示帮助信息。
- [x] 内置 Demo 成功运行，生成 HTML 和 JSON 报告。
- [x] 内置 Demo 的回滚验证、模拟数据库恢复及本地服务关闭均返回成功。
- [x] 官方 Windows x64 ZIP 的实际 SHA256 与官方校验值一致。
- [x] 从官方 Windows ZIP 解压并运行 `Start-Demo.bat`。
- [x] 便携包 Demo 成功生成报告，HTML 报告可以正常打开。

### 验收边界

- 上述结果来自当前 Windows 环境的实际测试。
- 内置 Demo 的确认结果属于预设模拟场景。
- 全新 Windows 环境下的独立安装验收仍需单独确认。


### PATH 隔离测试

- [x] 在 Windows 10 Home China 环境中，将当前 PowerShell 会话的 PATH 临时限制为 `%SystemRoot%\System32;%SystemRoot` 后，便携版 `granttrace.exe --version` 正确输出 `GrantTrace 2.5.3`。
- [x] 在相同 PATH 限制下运行 `granttrace.exe demo`，Demo 成功完成。
- [x] 验证结果：`Rollback verified: yes`、`Mock database restored: yes`、`Local server stopped: yes`。

验收边界：本项为当前 Windows 环境下的 PATH 隔离测试，不等同于全新 Windows 设备上的独立安装验收。


### Windows USB cross-computer acceptance (2026-10-23)

#### Passed

- [x] Copied the Windows x64 portable package to a USB drive.
- [x] Ran `Start-Demo.bat` on a second Windows computer.
- [x] The built-in Demo completed successfully.
- [x] The HTML report was generated and opened automatically in the default browser.
- [x] The JSON report was generated successfully.
- [x] Both reports were saved to the USB drive.
- [x] No manual command-line input was required.

#### Scope and limitations

- This acceptance covers the built-in local Demo, not a real API security audit.
- Windows x64 portable execution was verified on a second computer.
- Other operating systems have not been verified by this test.
