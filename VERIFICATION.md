# GrantTrace Verification

Detailed historical release verification records are archived in
[release verification history](docs/history/release-verification-history.md).

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
