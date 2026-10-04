# v2.4.1 发布与发布后复核清单

**v2.4.1 已于 2026-10-04 正式发布**，当前稳定版本为 [v2.4.1](https://github.com/ysc070528/granttrace/releases/tag/v2.4.1)，[PyPI 2.4.1](https://pypi.org/project/granttrace/2.4.1/) 已可安装。本清单记录发布完成的事实与可重复执行的发布后复核步骤；此前开发版与历史版本的实际验收事实继续保留在 [验收记录](../VERIFICATION.md)。已有 v2.4.0 / v2.3.1 tag、Release 与资产保持原样。

## 已完成的发布记录

- [Release Prep PR #18](https://github.com/ysc070528/granttrace/pull/18) 已合并；发布时 final main commit 为 [`8ba6cb46c9bbd670449989a5bd54fb233543d81f`](https://github.com/ysc070528/granttrace/commit/8ba6cb46c9bbd670449989a5bd54fb233543d81f)。
- annotated tag `v2.4.1` 已创建，最终解析到上述 commit。
- [GitHub Release “GrantTrace v2.4.1”](https://github.com/ysc070528/granttrace/releases/tag/v2.4.1) 已正式发布，非 draft、非 prerelease，附带 `granttrace-2.4.1-py3-none-any.whl`、`granttrace-2.4.1.tar.gz` 和 `SHA256SUMS`。
- [Publish to PyPI 工作流](https://github.com/ysc070528/granttrace/actions/runs/37175522087) 成功；通过 OIDC Trusted Publishing 发布，owner 为 `ysc070528`、repository 为 `granttrace`、workflow 为 `release.yml`、environment 为 `pypi`，未使用 PyPI Token 或用户名/密码。
- 发布 commit 的 [main CI](https://github.com/ysc070528/granttrace/actions/runs/37137142692) 和 [CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37137142656) 均成功；Python 3.9 / 3.12 / 3.14、Mypy、Ruff、Runtime dependency audit 均通过。
- `main` 已受保护，required checks 包含正式 blocking 的 **Mypy**、三个 Python 测试、Ruff、Runtime dependency audit、Analyze Python 和 CodeQL。

## 已完成的发布验收

- `pyproject.toml`、`core.__version__`、wheel / sdist metadata 均为 `2.4.1`；安装后的 `granttrace --version` 输出 `GrantTrace 2.4.1`，User-Agent 为 `GrantTrace/2.4.1`，HTML 显示 `v2.4.1`，JSON `tool_version` 为 `2.4.1`。
- 不传 `-o` / `--output`，默认生成 `granttrace_report.html`。
- `granttrace demo --read-only` 发送 **0 PATCH**，得到 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED，确定性覆盖率 60%；demo JSON 的 `rollback_verified` 为 `null`，完整数据库状态不变。
- `granttrace demo` 得到 2 CONFIRMED、1 PUBLIC、2 SECURE，确定性覆盖率 100%；Mass Assignment 与 demo JSON 的 `rollback_verified` 均为 `true`，**full database restoration** 成功。
- 两种 demo 都只使用动态端口的 `127.0.0.1` 内置靶场，无外部 target 或用户凭据；运行后 `server_stopped = true`，HTML / JSON 报告正常生成。
- 304 项 unittest 全部通过，0 failures / errors / skipped；业务场景、JSON / YAML 示例、独立安装验证均通过。
- mypy 是正式阻塞 CI 门禁，必须为 0 errors；Ruff、Runtime dependency audit 和 CodeQL 均通过。
- 真实 unittest 总覆盖率（包含语句与分支）为 **80.83%–80.85%**，达到 **>=80%** 门槛；保留现有 `branch = true`、source 范围和 `fail_under = 80`，不通过排除代码提高结果。
- Python 3.9 / 3.12 / 3.14 远程 CI 均成功；`main` Branch Protection 的 required checks 包含 **Mypy**，名称以当前 GitHub Actions 返回为准。
- 构建 `granttrace-2.4.1-py3-none-any.whl` 和 `granttrace-2.4.1.tar.gz`，`twine check --strict` 通过；wheel 内有完整的 `core.demo_assets/*.json`，不含缓存、凭据、临时报告或 `.git`。
- 在源码目录外的全新虚拟环境安装本轮正式构建的 wheel，不依赖源码 checkout，验证 CLI、HTML / JSON、User-Agent 和通过 `importlib.resources` 加载的内置 demo 资源。
- 用户 API 扫描仍默认只读；主动 PATCH 测试仍要求显式允许、write allowlist、独立 GET readback、原始状态快照和 rollback verification。恢复失败继续阻断写入。
- 全部验收仅使用虚构数据与隔离本机靶场，**不使用真实生产凭据或生产 API**。
- Git 跟踪范围不包含凭据、本地配置、缓存、coverage、构建产物或临时报告。
- README 保留报告预览和指南，标识 `Stable: v2.4.1`，提供稳定版安装、版本确认与内置 demo 命令。

## 发布后复核

以下步骤用于复核已发布的 v2.4.1，不重新发布或改动历史资产：

- 核对 annotated tag `v2.4.1` 仍解析到发布 commit，正式 Release 仍为非 draft、非 prerelease，三个附件齐全；下载后重新计算 SHA-256，与 `SHA256SUMS` 比较。
- 核对发布 commit 的 main CI / CodeQL 成功，Mypy 仍为 required blocking check，coverage 门槛仍为 80%。
- 核对 PyPI 项目版本及发布工作流的成功记录；OIDC 发布者仍为 `ysc070528/granttrace`、`release.yml`、`pypi`。工作流继续核对 tag、源码 commit、项目与发行物版本，构建与上传分离。
- 在新环境安装 `python -m pip install --no-cache-dir granttrace==2.4.1`，核对版本与 demo 两模式；此步骤是安装复验，不是上传。
- README 应显示 `Stable: v2.4.1`；不创建未经开发与审查的下一版本号。
- 使用实际检查名称只读复核 main 保护、private vulnerability reporting、Topics 和剩余远程分支；查询本身不修改设置或删除分支。

## 本地复验

以下命令用于 v2.4.1 tag 的干净源码目录。先安装开发、构建和发行包检查依赖：

```bash
python -m pip install -e ".[dev]" build twine
python -m unittest discover -s tests
python -m mypy
python -m ruff check .
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
python -m coverage erase
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m coverage xml
python -m coverage json
python -m pip check
```

`verify_examples.py` 使用本机 HTTP 靶场核对 JSON / YAML、只读与写测试结果，并比较完整数据库的恢复状态，复验时不重新生成已发布示例。`verify_install.py` 在新虚拟环境安装源码构建的 wheel，检查源码目录外的入口、版本、配置预检、计划导出、已安装 demo 两种模式及其恢复和关闭；要验收下载的正式 Release wheel，应使用 `python scripts/verify_install.py --wheel /path/to/granttrace-2.4.1-py3-none-any.whl`，避免用重新构建的文件代替该资产。两个脚本的验收产物写入已忽略的 `dist/`。离线安装可使用 `python scripts/verify_install.py --wheelhouse <依赖 wheel 目录>`。

清理已核对范围内的旧 `dist/`、`build/` 与项目 egg-info 后，正式构建并检查：

```bash
python -m build
python -m twine check --strict dist/*
```

在仓库外新建并激活虚拟环境，用本轮构建 wheel 的实际路径安装，然后从该外部目录运行：

```bash
python -m pip install /path/to/granttrace-2.4.1-py3-none-any.whl
granttrace --version
python -c "import importlib.metadata as m; print(m.version('granttrace'))"
granttrace demo
granttrace demo --read-only
```

两个 demo 的 JSON 都应有 `tool_version = "2.4.1"`、`database_restored = true`、`target_bound_to_loopback = true`、`server_stopped = true`。只读运行的 `request_methods` 不含 `PATCH`，`rollback_verified` 为 `null`；主动运行的 `rollback_verified = true`，报告中的实际写检查也须恢复验证成功。输出目录应各自唯一，不覆盖已有报告。

```bash
git diff --check
git status --short
```

在 PowerShell 检查本地文件与 Git 跟踪范围：

```powershell
git ls-files -- config.json
git check-ignore -- config.json config.local.json config.local.checklist.json granttrace_report.html API_Security_Report.html report.html result.local.json plan.local.json
git ls-files -- config.example.json config.schema.json examples/sample_report.html examples/sample_result.json
```

第一条应无输出，第二条应列出每个本地产物，第三条应列出四个必须保留的示例 / schema 文件。不要用实际凭据测试这些规则。

## 仓库设置复验

具备维护权限的环境可用 GitHub CLI 只读查询发布、保护和仓库状态：

```bash
gh release view v2.4.0 --repo ysc070528/granttrace
gh release view v2.4.1 --repo ysc070528/granttrace
gh api repos/ysc070528/granttrace/private-vulnerability-reporting
gh api repos/ysc070528/granttrace/topics
gh api repos/ysc070528/granttrace/branches --paginate --jq '.[].name'
gh api repos/ysc070528/granttrace/branches/main --jq '{name, protected}'
gh api repos/ysc070528/granttrace/branches/main/protection/required_status_checks
```

v2.4.0 是历史已发布版本；v2.4.1 的正式 Release、annotated tag 和 PyPI 发布均已完成。私密报告开关应为 `enabled: true`，Topics 应包含 `mass-assignment`。`main` 的 `protected` 应为 `true`，required checks 应包含 Mypy、三个 Python 测试、Ruff、Runtime dependency audit 和当前 CodeQL 检查名称；权限不足时记录实际限制，交由维护者核实，不绕过保护。打开 README 检查可见报告图片与完整示例链接，并打开 [私密漏洞报告表单](https://github.com/ysc070528/granttrace/security/advisories/new) 确认入口可用。上述复核是只读查询，不修改仓库设置、历史 Release 或远程分支。
