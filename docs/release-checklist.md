# 发布自检清单

当前包版本与运行时版本统一为开发版本 **2.4.0.dev0**。最新正式发布仍为 [GitHub Release v2.3.1](https://github.com/ysc070528/granttrace/releases/tag/v2.3.1)。`CHANGELOG.md` 的 `Unreleased` 记录当前尚未发布的变更；已有 Release 标签与资产保持原样，不包含这些变更。版本身份、完整回归、业务场景、示例和独立安装已在本修订重新验收；其他勾选保留此前自检结果，实际执行环境和结果见 [验收记录](../VERIFICATION.md)。

- [x] `granttrace --version` 输出 `GrantTrace 2.4.0.dev0`，与 `pyproject.toml`、运行时、报告和 CHANGELOG 的 `Unreleased` 开发版本一致；最新正式 Release 保持 `v2.3.1`。
- [x] 不传 `-o` / `--output`，默认生成 `granttrace_report.html`。
- [x] README 五分钟体验的只读结果为 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED，确定性覆盖率 60%。
- [x] README 五分钟体验加 `--allow-write-tests` 后为 2 CONFIRMED、1 PUBLIC、2 SECURE，确定性覆盖率 100%，Mass Assignment 的 `rollback_verified` 为 `true`。
- [x] `python -m unittest discover -s tests` 全部通过，依赖齐全时无跳过。
- [x] `python scripts/verify_business_scenarios.py` 通过，合法共享 / 管理员场景与跨租户拒绝符合预先声明的真值。
- [x] `python scripts/verify_install.py` 通过，新环境安装本修订的 `granttrace-2.4.0.dev0-py3-none-any.whl`，并从源码目录外验证命令入口、开发版本、JSON / YAML 预检与只读计划导出。
- [x] `SECURITY.md` 有可点击的私密报告入口，仓库的 private vulnerability reporting 设置已实际确认。
- [x] Git 跟踪列表不含 `config.json`；`.gitignore` 覆盖本地配置、草稿 checklist、HTML / JSON 报告和计划，保留示例与 schema。
- [x] GitHub Topics 包含 `mass-assignment`。
- [x] README 首屏有英文一句话和无需展开即可看到的报告图，完整示例报告链接可访问。
- [ ] 远程 Branches 仅保留 `main`。现有七个旧分支均已合入 `main`，尚未删除，删除需维护者明确授权；本轮 PR 的临时分支也在审查期间保留，合并后由已启用的自动删除设置清理。全部清理后再复核此项。

## 本地复验

先安装构建和运行依赖，然后检查安装后的入口：

```bash
python -m pip install . setuptools wheel
granttrace --version
python -m unittest discover -s tests
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
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
gh release view v2.3.1 --repo ysc070528/granttrace
gh api repos/ysc070528/granttrace/private-vulnerability-reporting
gh api repos/ysc070528/granttrace/topics
gh api repos/ysc070528/granttrace/branches --paginate --jq '.[].name'
```

私密报告开关应为 `enabled: true`，Topics 应包含 `mass-assignment`。七个已合并旧分支仍需维护者明确授权删除；本轮临时分支在 PR 合并后自动删除。全部清理后再确认仅有 `main`。打开 README 检查可见报告图片与完整示例链接，并打开 [私密漏洞报告表单](https://github.com/ysc070528/granttrace/security/advisories/new) 确认入口可用。GitHub CLI 权限不足时，在仓库网页查看对应设置并记录实际结果。
