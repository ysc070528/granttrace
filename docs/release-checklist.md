# 发布自检清单

本清单面向 **v2.4.1 发布准备**。本轮只提交开放的 Release Prep PR：不合并、不创建 tag / GitHub Release、不触发 PyPI 发布。源码版本号为 `2.4.1` 不代表已经发布；当前已发布稳定版本仍为 [v2.4.0](https://github.com/ysc070528/granttrace/releases/tag/v2.4.0)。`CHANGELOG.md` 记录准备发布的变更，此前开发版与历史版本的实际验收事实继续保留在 [验收记录](../VERIFICATION.md)。已有 v2.4.0 / v2.3.1 tag、Release 与资产保持原样。

## 发布前验收标准

- `pyproject.toml`、`core.__version__`、wheel / sdist metadata 均为 `2.4.1`；安装后的 `granttrace --version` 输出 `GrantTrace 2.4.1`，User-Agent 为 `GrantTrace/2.4.1`，HTML 显示 `v2.4.1`，JSON `tool_version` 为 `2.4.1`。
- 不传 `-o` / `--output`，默认生成 `granttrace_report.html`。
- `granttrace demo --read-only` 发送 **0 PATCH**，得到 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED，确定性覆盖率 60%；demo JSON 的 `rollback_verified` 为 `null`，完整数据库状态不变。
- `granttrace demo` 得到 2 CONFIRMED、1 PUBLIC、2 SECURE，确定性覆盖率 100%；Mass Assignment 与 demo JSON 的 `rollback_verified` 均为 `true`，**full database restoration** 成功。
- 两种 demo 都只使用动态端口的 `127.0.0.1` 内置靶场，无外部 target 或用户凭据；运行后 `server_stopped = true`，HTML / JSON 报告正常生成。
- 当前 304 项 unittest 全部通过，0 failures / errors / skipped；业务场景、JSON / YAML 示例、独立安装验证均通过，以实际执行数量为准。
- mypy 是正式阻塞 CI 门禁，必须为 0 errors；Ruff、Runtime dependency audit 和 CodeQL 均通过。
- 真实 unittest 总覆盖率（包含语句与分支）必须 **>=80%**，保留现有 `branch = true`、source 范围和 `fail_under = 80`，不通过排除代码提高结果。
- Python 3.9 / 3.12 / 3.14 远程 CI 均成功；`main` Branch Protection 的 required checks 包含 **Mypy**，名称以当前 GitHub Actions 返回为准。
- 构建 `granttrace-2.4.1-py3-none-any.whl` 和 `granttrace-2.4.1.tar.gz`，`twine check --strict` 通过；wheel 内有完整的 `core.demo_assets/*.json`，不含缓存、凭据、临时报告或 `.git`。
- 在源码目录外的全新虚拟环境安装本轮正式构建的 wheel，不依赖源码 checkout，验证 CLI、HTML / JSON、User-Agent 和通过 `importlib.resources` 加载的内置 demo 资源。
- 用户 API 扫描仍默认只读；主动 PATCH 测试仍要求显式允许、write allowlist、独立 GET readback、原始状态快照和 rollback verification。恢复失败继续阻断写入。
- 全部验收仅使用虚构数据与隔离本机靶场，**不使用真实生产凭据或生产 API**。
- Git 跟踪范围不包含凭据、本地配置、缓存、coverage、构建产物或临时报告。
- README 保留报告预览和指南，明确标识 v2.4.1 为 release prep；不声称尚未发生的 GitHub / PyPI 发布。

## 未来发布与仓库复核

以下是另行获得发布授权后的清单，**本轮不执行**：

- 合并已通过正式检查的 Release Prep PR 后，再确认最终 `main` 的 CI / CodeQL 成功。
- annotated tag `v2.4.1` 指向最终 `main` commit；正式 GitHub Release 附带 wheel、sdist 和 `SHA256SUMS`。
- 发布工作流必须核对 tag、源码 commit、项目版本及发行物 metadata 一致，构建与上传分离；只通过 `pypi` environment 的 OIDC Trusted Publishing 认证，不使用 Token 或明文凭据。
- PyPI 实际发布成功后，在新环境验证 `pip install --no-cache-dir granttrace==2.4.1`、版本与 demo；认证不可用时记录未发布原因。
- 只有实际发布与安装验证成功，才能将 README 改为 `Stable: v2.4.1` 并去掉 release prep 提示；不擅自创建下一开发版本。
- 使用实际检查名称复核 `main` 保护，要求 PR 与正式检查，包含 Mypy；本轮只读查询，不修改仓库设置。
- 复核 private vulnerability reporting、Topics 和剩余远程分支，以当前 GitHub API / 网页结果为准；本轮不删除远程分支。

## 本地复验

先安装开发、构建和发行包检查依赖：

```bash
python -m pip install -e ".[dev]" build twine
python -m unittest discover -s tests
python -m mypy
python -m ruff check .
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py --update-examples
python scripts/verify_install.py
python -m coverage erase
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m coverage xml
python -m coverage json
python -m pip check
```

`verify_examples.py --update-examples` 使用本机 HTTP 靶场核对 JSON / YAML、只读与写测试结果，并比较完整数据库的恢复状态；正式示例由该脚本生成，不手工替换报告内部版本。`verify_install.py` 在新虚拟环境安装本轮源码构建的 wheel，检查源码目录外的入口、版本、配置预检、计划导出、已安装 demo 两种模式及其恢复和关闭；它不代表已经验收历史 Release 的二进制文件。两个脚本的验收产物写入已忽略的 `dist/`。离线安装可使用 `python scripts/verify_install.py --wheelhouse <依赖 wheel 目录>`。

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

v2.4.0 是历史已发布版本；**本轮结束时 v2.4.1 应尚无 Release / tag / PyPI 上传**，Release Prep PR 保持开放。私密报告开关应为 `enabled: true`，Topics 应包含 `mass-assignment`。`main` 的 `protected` 应为 `true`，required checks 应包含 Mypy、三个 Python 测试、Ruff、Runtime dependency audit 和当前 CodeQL 检查名称；权限不足时记录实际限制，交由维护者核实，不绕过保护。打开 README 检查可见报告图片与完整示例链接，并打开 [私密漏洞报告表单](https://github.com/ysc070528/granttrace/security/advisories/new) 确认入口可用。本轮不执行任何仓库设置或分支清理操作。
