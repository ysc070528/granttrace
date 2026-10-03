# 发布自检清单

本清单面向 **2.4.0** 正式发行。`CHANGELOG.md` 记录该版本变更；此前开发版与历史版本的实际验收事实继续保留在 [验收记录](../VERIFICATION.md)。已有 Release 标签与资产（包括 [v2.3.1](https://github.com/ysc070528/granttrace/releases/tag/v2.3.1)）保持原样。源码版本号不代表已经发布：只有 release PR 合并后的 `main` CI 与 CodeQL 均成功，才创建正式 tag / Release。

## 发布前验收标准

- `granttrace --version` 输出 `GrantTrace 2.4.0`，与包 metadata、运行时、User-Agent、HTML / JSON 报告一致。
- 不传 `-o` / `--output`，默认生成 `granttrace_report.html`。
- README 五分钟体验的只读结果为 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED，确定性覆盖率 60%。
- README 五分钟体验加 `--allow-write-tests` 后为 2 CONFIRMED、1 PUBLIC、2 SECURE，确定性覆盖率 100%，Mass Assignment 的 `rollback_verified` 为 `true`，完整数据库状态恢复。
- 268 项 unittest 全部通过，无失败、错误或跳过；业务场景、JSON / YAML 示例、独立安装验证均通过。
- Ruff 通过，真实 coverage 无明显回退，pip-audit 和 CodeQL 通过；mypy 历史问题继续作为 advisory。
- 构建 `granttrace-2.4.0-py3-none-any.whl` 和 sdist，并在源码目录外的全新环境安装、执行 CLI 和真实 loopback 扫描。
- Git 跟踪范围不包含凭据、本地配置、缓存、coverage、构建产物或临时报告。
- README 首屏显示 `Stable: v2.4.0`，保留报告图、完整示例与私密漏洞报告入口。

## 发布与仓库复核

- Release PR 的正式 CI 检查通过后合并，再确认最终 `main` 的 CI / CodeQL 成功。
- annotated tag `v2.4.0` 指向最终 `main` commit；正式 GitHub Release 附带 wheel、sdist 和 `SHA256SUMS`。
- 只有安全发布认证可用时发布 PyPI，并在新环境验证 `pip install granttrace==2.4.0`；认证不可用时记录未发布原因。
- 用实际返回的检查名称配置 `main` 保护，要求 PR 与正式检查，不把 mypy advisory 设为门禁；权限不足时明确记录人工事项。
- 逐个证明旧分支 HEAD 是 `main` 祖先或其 PR 已完全合并，再删除对应远程分支；保留 `main` 与仍在开发的分支。
- 复核 private vulnerability reporting、Topics 和剩余远程分支，以当前 GitHub API / 网页结果为准。

## 本地复验

先安装构建和运行依赖，然后检查安装后的入口：

```bash
python -m pip install . "setuptools>=77" wheel
granttrace --version
python -m unittest discover -s tests
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
python -m pip install -e ".[dev]"
python -m ruff check .
python -m coverage erase
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m coverage xml
python -m coverage json
python -m pip check
python -m mypy
```

`verify_examples.py` 使用本机 HTTP 靶场核对 JSON / YAML、只读与写测试结果，并比较完整数据库的恢复状态。`verify_install.py` 在新虚拟环境安装本轮源码构建的 wheel，检查源码目录外的入口、版本、配置预检和计划导出；它不代表已经验收历史 Release 的二进制文件。两个脚本的验收产物写入已忽略的 `dist/`。离线安装可使用 `python scripts/verify_install.py --wheelhouse <依赖 wheel 目录>`。

再严格按 [README 五分钟体验](../README.md#五分钟体验) 启动靶场，执行没有 `-o` 的两个扫描命令。每次都确认新生成的 `granttrace_report.html`、`result.local.json`，并比对清单中的状态计数、覆盖率和恢复标记。

在 PowerShell 检查本地文件与 Git 跟踪范围：

```powershell
git ls-files -- config.json
git check-ignore -- config.json config.local.json config.local.checklist.json granttrace_report.html API_Security_Report.html report.html result.local.json plan.local.json
git ls-files -- config.example.json config.schema.json examples/sample_report.html examples/sample_result.json
```

第一条应无输出，第二条应列出每个本地产物，第三条应列出四个必须保留的示例 / schema 文件。不要用实际凭据测试这些规则。

## 仓库设置复验

具备维护权限的环境可用 GitHub CLI 查询已发布版本、私密报告开关、Topics 和分支：

```bash
gh release view v2.4.0 --repo ysc070528/granttrace
gh api repos/ysc070528/granttrace/private-vulnerability-reporting
gh api repos/ysc070528/granttrace/topics
gh api repos/ysc070528/granttrace/branches --paginate --jq '.[].name'
gh api repos/ysc070528/granttrace/branches/main --jq '{name, protected}'
```

发布前 `gh release view v2.4.0` 应尚无结果；正式发布后应能查到非 draft、非 prerelease 的 Release。私密报告开关应为 `enabled: true`，Topics 应包含 `mass-assignment`。`main` 的 `protected` 应为 `true`，必要检查名称必须来自当前 Actions 结果；如果账号权限或 GitHub 计划不允许设置，记录实际限制并交由维护者处理。旧分支必须先确认已合并，再执行清理。打开 README 检查可见报告图片与完整示例链接，并打开 [私密漏洞报告表单](https://github.com/ysc070528/granttrace/security/advisories/new) 确认入口可用。权限不足时，在仓库网页查看对应设置并记录实际结果。
