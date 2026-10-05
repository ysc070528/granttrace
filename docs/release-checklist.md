# v2.5.1 Ready for release 收尾清单

最新 main 为
[`c913f19a7331dbd291332f9c7dfb7244f45fb2d3`](https://github.com/ysc070528/granttrace/commit/c913f19a7331dbd291332f9c7dfb7244f45fb2d3)，
[Release Prep PR #27](https://github.com/ysc070528/granttrace/pull/27) 已合并。
源码保持 `2.5.1`；实际已发布 stable 仍为 v2.5.0，尚无 v2.5.1 tag / Release / PyPI。
本轮不执行发布操作，不改变版本或增加接口能力。

- [x] README 真实扫描和 SARIF 示例显式提供 target；SARIF 使用已授权的 loopback mock。
- [x] README Stable / PyPI 指向实际已发布 v2.5.0，源码 2.5.1 状态单独说明。
- [x] PR #27 已合并，等待 review / merge 的过时状态已纠正。
- [x] Swagger 2.0 参数 schema 保留 `uniqueItems`；8 项定向回归通过，重复数组请求前拒绝，有效值正例保留。
- [x] 收尾变更后的完整 pytest **560 passed / 860 subtests passed**；新增 8 个回归方法。
- [x] 定向回归 **218 passed / 522 subtests passed**；mypy 18 个源码文件 0 issues，仓库根目录 Ruff 通过。
- [x] 业务场景 **6/6** 符合本机 fixture，三个 JSON / YAML example 模式完整恢复数据库。
- [x] coverage 下 **560 tests OK / branch-aware 85.27%**，XML / JSON 已生成，80% 门槛与原 source / branch 配置保留。
- [x] 现有构建依赖满足要求，`build --no-isolation` 生成本轮 2.5.1 wheel / sdist；两者 twine strict PASS，未上传。
- [x] 本轮 wheel 与 PyYAML 6.0.3 在源码外 fresh virtual environment 安装通过；版本链为 2.5.1。
- [x] installed read-only demo 0 PATCH；active demo 1 BOLA / 1 Mass Assignment，rollback / database restored / server stopped 均为 true；JSON / YAML plan 等价且 0 请求。

**Ready for release（未发布）：本轮本地发布前验收已完成。**

PR #27 发布准备验收的 **552 passed / 6/6** 仅作为基线。
main 的 CI 37220855716 / CodeQL 37220855877 仅验证合并基线；
本轮本地收尾没有创建新提交 / PR 或运行新的远程 CI，不将基线绿灯代用。
正式发布的最终源码须包含本轮修复，再核实 exact commit、远程门禁及最终资产。
准确结果与范围见 [Ready for release 收尾验收](../VERIFICATION.md#2026-10-05-v251-ready-for-release-收尾验收)。

---

# v2.5.1 发布准备与发布前验收清单

这是 **release preparation**：正式源码版本为 `2.5.1`，
尚未创建 v2.5.1 tag / GitHub Release，尚未上传或发布 PyPI。
当前已发布 stable 仍为 [v2.5.0](https://github.com/ysc070528/granttrace/releases/tag/v2.5.0)。

Release Prep 阶段曾前置展示 README 的 `Stable: v2.5.1` 及发布链接；当前 README 已改为实际已发布的 stable v2.5.0，源码 2.5.1 与正式发布状态分别说明。
本轮准备发布已合并 maintenance 修复，不新增功能；历史 release、tag 和资产保持不变。

## v2.5.1 Release source

- Base main：[`c950432c2696c9fcd442591db82ed2cb0393351a`](https://github.com/ysc070528/granttrace/commit/c950432c2696c9fcd442591db82ed2cb0393351a)。
- Release Prep branch：`codex/v2.5.1-release`。
- 已合并的修复：[maintenance PR #26](https://github.com/ysc070528/granttrace/pull/26)。
- 版本：`2.5.1`，不保留 `.dev0`，不添加 rc / post-release 后缀。
- 实际执行证据与限制见 [v2.5.1 发布前验收](../VERIFICATION.md#2026-10-05-v251-发布前验收)。

## v2.5.1 本轮本地已完成

### 版本链、构建和独立安装

- [x] project / runtime / wheel / installed metadata / JSON 均为 `2.5.1`。
- [x] CLI 为 `GrantTrace 2.5.1`；HTML 为 `v2.5.1`，实际 User-Agent 为 `GrantTrace/2.5.1`。
- [x] 隔离 `python -m build` 产生 2.5.1 wheel 与 sdist；两种 distribution 均通过 `twine check --strict`，没有上传。
- [x] wheel / sdist 的 Name、Version、Python>=3.9、Apache-2.0、PyYAML>=6.0 与 Markdown README long description 正确；wheel RECORD size / hash 核对通过，所需 runtime / demo / docs / scripts / tests / examples 内容齐全。
- [x] 在本轮包内文件名与内容检查范围内未发现私有配置、缓存、日志、临时报告、venv / .git / coverage / 嵌套构建产物或真实主机路径；公开 synthetic 隐私 fixture 经过上下文核对，此项不代表通用秘密扫描保证。
- [x] 本轮实际构建 wheel 在源码目录外的 fresh virtual environment 安装，imports、CLI / help、metadata、默认报告与 packaged demo resources 可用。
- [x] 安装环境 `pip check` 无依赖冲突，实际为 granttrace 2.5.1、PyYAML 6.0.3。
- [x] 安装后的 JSON / YAML plan 等价，`requests_sent = 0`，配置草稿继续阻断。
- [x] 官方 HTML / JSON 示例由 `verify_examples.py --update-examples` 更新，再不带更新参数复验通过。
- [x] 报告截图保留；固定 v2.5.0 raw 图片 URL 实测 200 / image/png，PNG signature 正确。

### 质量与本机模型

- [x] 本轮 unittest **552 项通过**，0 failures / errors / skipped。
- [x] coverage 下同为 552 项通过；branch-aware 总覆盖率 **84.91%**，XML / JSON 生成。
- [x] 保留 coverage source、`branch = true`、`fail_under = 80`，没有降低门槛。
- [x] blocking mypy **0 errors**（18 个源码文件），Ruff 通过。
- [x] strict runtime dependency audit：实际解析的 PyYAML 6.0.3 没有已知漏洞，没有 ignore。
- [x] 业务场景 **6/6** 符合本机 fixture 真值。
- [x] JSON / YAML examples 的只读及主动结果符合预期，三个模式完整恢复 mock 数据库。

### Installed demo 与现有安全边界

- [x] read-only demo **0 PATCH**；rollback 不适用，数据库恢复与 server stopped 通过。
- [x] active demo 1 BOLA / 1 Mass Assignment CONFIRMED；rollback verified、database restored、server stopped 均为 true。
- [x] 安装后默认用户扫描 0 PATCH；主动扫描独立读回、rollback 及完整数据库恢复通过。
- [x] Merge Patch 恢复安全、数组记录比较、credential redaction、报告/输入 alias、conditional / local `$ref`、参数兼容与 operation/spec 交叉检查的维护回归通过完整 unittest。
- [x] SARIF、cURL、HTML / JavaScript 和 onboarding 的现有单元回归通过；不冒称本轮独立安装后执行官方 SARIF schema 或浏览器验收。
- [x] 默认只读、显式 PATCH 开关与 allowlist、独立 GET readback、snapshot / rollback verification 和恢复失败停写保持。
- [x] 只使用虚构凭据和隔离本机模型；未增加主动 POST / PUT、自动登录 / OAuth 或其他检测能力。

### 发布工作流

- [x] `release.yml` 仅更改 manual default / choices / allowlist / 对应说明，保留历史版本。
- [x] 4 段内嵌 Python AST 解析；3 段下游校验 AST 与 base 一致。
- [x] 43 组完全离线校验通过：28 组 event / tag / release，15 组 source / distribution / hash。
- [x] 稳定 published 与已有正式 Release 的 main/manual 正例通过；draft / prerelease / edited / dev tag / 版本或资产不一致等负例阻断。
- [x] 未执行 `workflow_dispatch`，没有实际上传或取得 OIDC 发布身份；上述结果仅为静态与 mock 验收。

## v2.5.1 远程门禁与后续动作

[Release Prep PR #27](https://github.com/ysc070528/granttrace/pull/27) 的首次 HEAD
`ec440b58939ed99153138c39755551282cf14ff3` 已实际通过
[CI 37219626327](https://github.com/ysc070528/granttrace/actions/runs/37219626327) 和
[CodeQL 37219626326](https://github.com/ysc070528/granttrace/actions/runs/37219626326)。
三个 Python job 各 552 项通过，branch-aware coverage 为 3.9：84.90%，
3.12 / 3.14：84.91%；Mypy、Ruff、runtime audit 成功，审计没有已知漏洞。
CodeQL analysis `1889266959` 实际分析 PR merge commit
`428cce1caaef4f64cdaddab18baf7e036a3282af`，error / warning 为 0、结果为空。
这是首次提交的证据；最终文档 HEAD 须独立通过全部门禁，
最新状态以 [PR #27 Checks](https://github.com/ysc070528/granttrace/pull/27/checks) 为准。
最终 HEAD 的 exact SHA 与对应运行记录见 PR 正文；首次提交成功不能代替该验证。

- [x] 创建 [Release Prep PR #27](https://github.com/ysc070528/granttrace/pull/27)，现已合并。
- [x] 首次 HEAD 的 Python 3.9 / 3.12 / 3.14、Mypy、Ruff、Runtime dependency audit、CodeQL 全部通过。
- [x] Release Prep PR #27 已合并；main 为 `c913f19a7331dbd291332f9c7dfb7244f45fb2d3`。
- [x] 核对 PR #27 合并后的 main `c913f19a7331dbd291332f9c7dfb7244f45fb2d3`，以及 [CI 37220855716](https://github.com/ysc070528/granttrace/actions/runs/37220855716) / [CodeQL 37220855877](https://github.com/ysc070528/granttrace/actions/runs/37220855877)；它们只验证本轮收尾修复前的合并基线。
- [ ] 基于最终 main / tagged source 核实正式 wheel / sdist / SHA256SUMS；本轮分支构建 hash 不能当作最终 Release hash。
- [ ] 经明确授权创建 annotated tag `v2.5.1`，确认精确指向最终 main。
- [ ] 经明确授权创建正式 GitHub Release 并附加三个正式资产。
- [ ] 经明确授权执行 PyPI 发布；核对 OIDC 与发布工作流真实结果。
- [ ] PyPI 可见后，fresh install / metadata / 两种 demo 及恢复、server shutdown 复核。

发布前构建仅属于 **PR branch pre-release build**，不证明 v2.5.1 已正式发布。
已发布 PyPI 2.5.0 long description 保持不可变；README 源修复没有回写它。
本轮验收只覆盖所列本机 fixture 与安装流程，不代表生产 API 零误报、完整授权覆盖或完全安全。

## v2.5.1 Release Notes 草稿

GrantTrace v2.5.1 prepares the maintenance fixes merged in PR #26: safer Merge Patch
recovery checks, array record comparison corrections, known-credential redaction,
report/input overwrite protection, local and conditional schema handling, and
configuration/spec and parameter validation with canonical legacy scalar compatibility.
The final cleanup also preserves Swagger 2.0 `uniqueItems` constraints so duplicate
configured arrays are rejected before any request is sent.
Default read-only auditing and explicit PATCH opt-in, independent readback and rollback
verification remain in place. No new detection capabilities are added.
This is release preparation; no v2.5.1 tag, GitHub Release or PyPI release has been created.

---

下方 v2.5.0 与更早清单按原文保留，只记录对应历史版本；
其中“当前”“本轮”“已发布”“未发布”不表示 v2.5.1 发布准备的状态。

# v2.5.0 发布完成与发布后验收清单

**v2.5.0 已于 2026-10-04 正式发布**，当前稳定版本为 [v2.5.0](https://github.com/ysc070528/granttrace/releases/tag/v2.5.0)，[PyPI 2.5.0](https://pypi.org/project/granttrace/2.5.0/) 已可安装。本轮只同步发布完成与安装验收文档；v2.4.1 / v2.4.0 / v2.3.1 的 tag、Release、PyPI 与资产历史保持不变，不新增功能、修改检测逻辑或版本，也不执行新的 tag / 发布操作。

## Release source

- Release Prep 的 base main commit：[`7e40de4d5c2b1ff7e2d8e01b7a36c0366a1d3bec`](https://github.com/ysc070528/granttrace/commit/7e40de4d5c2b1ff7e2d8e01b7a36c0366a1d3bec)。
- Release Prep branch：`codex/v2.5.0-release`。
- Release Prep：[PR #23](https://github.com/ysc070528/granttrace/pull/23)，已人工审查并合并。
- 版本：`2.5.0`，不使用 `.dev0`、`rc1` 或 `-final`。
- 已合并功能：[SARIF PR #20](https://github.com/ysc070528/granttrace/pull/20)、[安全 cURL PR #21](https://github.com/ysc070528/granttrace/pull/21)、[配置引导 PR #22](https://github.com/ysc070528/granttrace/pull/22)。
- Final main commit：[`151bab4a613edee1b3ff8c86b68575038f769b00`](https://github.com/ysc070528/granttrace/commit/151bab4a613edee1b3ff8c86b68575038f769b00)，annotated tag `v2.5.0` 精确解析到该 commit。
- 正式发布与 PyPI 安装验收见 [VERIFICATION.md](../VERIFICATION.md#2026-10-04-v250-正式发布验收)。以下[发布前验收](../VERIFICATION.md#2026-10-04-v250-发布前验收)保留实际执行记录；此前功能 PR 的结果不能代替该轮验收。

## 发布前验收（历史）

本节保留 Release Prep 阶段已完成的验收；“本轮”指发布前阶段，不表示本次文档 PR 重新执行了这些检查。

### 版本一致性

- [x] `pyproject.toml = 2.5.0`。
- [x] `core.__version__ = 2.5.0`。
- [x] 源码与独立安装后的 `granttrace --version = GrantTrace 2.5.0`。
- [x] wheel metadata 的 `Name = granttrace`、`Version = 2.5.0`。
- [x] sdist metadata 的 `Name = granttrace`、`Version = 2.5.0`。
- [x] 正式生成的 HTML 显示 `v2.5.0`。
- [x] 正式生成的 JSON `tool_version = 2.5.0`。
- [x] 本机 fixture 实际请求的 User-Agent 为 `GrantTrace/2.5.0`。

### SARIF

- [x] SARIF 2.1.0 仅包含 CONFIRMED；SUSPICIOUS / INCONCLUSIVE 等不升级为漏洞。
- [x] BOLA / IDOR 为 `GT-BOLA-001` / `CWE-639`。
- [x] Mass Assignment 为 `GT-MASS-001` / `CWE-915`。
- [x] workspace 内的真实 OpenAPI spec 使用安全相对 artifact location，不伪造源码行号；外部 spec 不泄漏本机绝对路径。
- [x] 不泄漏 credential、原始敏感响应或未脱敏 headers；dry-run 不导出 SARIF。
- [x] 官方 OASIS SARIF 2.1.0 schema 与 HTML / JSON / SARIF 同时输出通过。

### cURL 复现模板

- [x] 仅支持可安全表达的 CONFIRMED BOLA / IDOR、Mass Assignment。
- [x] Visitor 的 Bearer / Basic / API Key / Cookie / 自定义认证头使用占位符。
- [x] 即使 `--include-sensitive-evidence`，模板仍不导出真实 credential。
- [x] 实际 URL / 已确认 injected payload / Content-Type 在安全范围内保留，POSIX quoting 与 `curl --globoff` 保持。
- [x] Clipboard API、离线 fallback、手工复制与 HTML / JS injection 防护测试通过。

本轮独立安装验收还执行实际生成的 clipboard JavaScript，3 种 Node DOM fallback 模式通过；这不是浏览器 UI 实测，不扩大为所有浏览器兼容性保证。

### 配置引导与离线计划

- [x] `init → manual review → validate → dry-run → read-only first scan` 流程正确；草稿与占位符继续阻断运行。
- [x] config-only 与 spec-aware 区分准确；validator 原有接受与拒绝语义不变。
- [x] validate 离线、不创建网络连接；dry-run `requests_sent = 0`，不做 DNS、登录、GET 或 PATCH。
- [x] 首次真实扫描建议不含 `--allow-write-tests`；配置 allowlist 不等于启用 PATCH。
- [x] POSIX / PowerShell 显示命令的引用与路径、日志注入防护通过；引导不输出 credentials / resource IDs。

### 核心 safety

- [x] 用户 API 扫描默认只读，发送 0 PATCH。
- [x] 主动 PATCH 仍需显式 `--allow-write-tests` 与明确 write allowlist。
- [x] 独立 GET readback、原始状态 snapshot 与 rollback 保持。
- [x] rollback verification 保持；recovery 失败仍阻断后续写入。
- [x] BOLA / IDOR / Mass Assignment verdict 及 TLS / HTTP / redirect / proxy 边界不变。
- [x] 所有验收只用虚构数据和隔离本机 fixture，不使用真实生产凭据或生产 API。

### 质量与远程门禁

本轮本地实测为 **486 项通过、coverage 82.78%、mypy 0 errors、Ruff 与 runtime dependency audit 通过**。远程 PR 检查与最终合并后 main 检查须分别确认，不能用旧功能 PR 的绿灯替代。

- [x] 本轮 unittest 486 项，0 failures / errors / skipped。
- [x] Python 3.9 远程测试通过：486 项，coverage 82.77%。
- [x] Python 3.12 远程测试通过：486 项，coverage 82.78%。
- [x] Python 3.14 远程测试通过：486 项，coverage 82.78%。
- [x] blocking Mypy 为 0 errors；没有降低配置或增加 suppressions。
- [x] Ruff 通过。
- [x] Runtime dependency audit 通过。
- [x] Release Prep PR 的 Mypy / Ruff / Runtime dependency audit 远程正式门禁均通过。
- [x] Analyze Python / CodeQL 通过。
- [x] branch-aware coverage >=80%，保留现有 source、`branch = true`、`fail_under = 80`。
- [x] 业务场景 6/6 匹配本机 fixture 真值。
- [x] JSON / YAML examples、只读与主动扫描结果及完整数据库恢复通过。
- [x] 通过源码目录外的全新虚拟环境安装本轮 wheel，CLI / help / metadata 与内置资源可用。

### Installed demo

- [x] `granttrace demo --read-only` 发送 0 PATCH。
- [x] 主动 demo 的 BOLA 与 Mass Assignment 结果符合内置 fixture。
- [x] 主动 demo `rollback_verified = true`。
- [x] 两种模式 `database_restored = true`、`server_stopped = true`。
- [x] demo 仅使用动态 `127.0.0.1`，不接受外部 target 或用户凭据，输出目录唯一。

### 构建与仓库卫生

- [x] 清理已核对的旧构建范围后执行 `python -m build`。
- [x] 构建 `granttrace-2.5.0-py3-none-any.whl`。
- [x] 构建 `granttrace-2.5.0.tar.gz`。
- [x] `python -m twine check --strict dist/*` 通过。
- [x] 包内保留 demo assets、SARIF / cURL / onboarding 模块；wheel / sdist 不含秘密、缓存、本机路径、`.git` 或临时报告。
- [x] release workflow YAML 与 diff 校验通过；保留 tag / commit / 版本 / metadata / SHA256 校验、构建上传分离与 OIDC。
- [x] `git diff --check`、本地 Markdown 链接和历史版本保留检查通过。
- [x] 只提交预期发布准备文件；不跟踪 dist / build / egg-info / coverage / 虚拟环境或临时报告。

## 本轮发布前复验命令（历史）

本节保留发布前复验命令与当时的待办状态；当前正式完成情况见下方“合并与发布后动作”。

上述首次远程记录来自 release-prep commit `ce84a0b11a5e1450aea7fb6698a5cdaa46e6e86f`
的 [CI](https://github.com/ysc070528/granttrace/actions/runs/37192301259) 与
[CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37192301260)。
三个 Python job 的 business scenarios、examples、installed-wheel 验证也均成功。
补入这些记录后，最终 PR HEAD 仍须重新通过全部门禁；最新结果以 PR #23 的 Checks 为准。
合并后的 main / tag / Release / PyPI 尚未执行，下面对应项目继续保持 unchecked。

```bash
python -m unittest discover -s tests
python -m mypy
python -m ruff check .
python -m coverage erase
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m coverage xml
python -m coverage json
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py --update-examples
python scripts/verify_examples.py
python scripts/verify_install.py
python -m pip check
python -m build
python -m twine check --strict dist/*
git diff --check
git status --short
```

构建前先确认待清理目录都属于当前 checkout。正式示例只能由 `verify_examples.py --update-examples` 生成。独立安装验收必须使用本次实际构建 wheel；构建后的本地 SHA-256 仅标记 **PR branch pre-release build hashes**，不能当作最终 Release 资产 hash。

发布工作流本轮完成 YAML 解析、4 段内嵌 Python 的编译和 35 项隔离模拟验收。未安装 actionlint，也未为本任务下载 binary；这属于静态与隔离校验，没有触发 publish job 或取得 OIDC 发布身份。

## 合并与发布后动作

以下记录已完成的正式发布与用户提供的 fresh PyPI install 验收，不重新执行发布动作：

- [x] 人工审查并合并 [Release Prep PR #23](https://github.com/ysc070528/granttrace/pull/23)。
- [x] 最终 main 的 [CI](https://github.com/ysc070528/granttrace/actions/runs/37193226878) / [CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37193226876) 全部成功。
- [x] 记录最终 main 的 exact 40-char SHA：`151bab4a613edee1b3ff8c86b68575038f769b00`。
- [x] 已创建 annotated tag `v2.5.0`。
- [x] 远程 tag 精确指向上述 final main commit。
- [x] 已核实最终 merged / tagged source 的正式 wheel / sdist 资产。
- [x] [GitHub Release “GrantTrace v2.5.0”](https://github.com/ysc070528/granttrace/releases/tag/v2.5.0) 已发布。
- [x] Release 已附加 wheel、sdist 与 `SHA256SUMS`。
- [x] Release ID `402957160`，非 draft、非 prerelease，发布于 `2026-10-04T10:30:40Z`。
- [x] `release: published` 自动触发 [Publish to PyPI 37195596802](https://github.com/ysc070528/granttrace/actions/runs/37195596802)，Build / OIDC publish jobs 与 Trusted Publishing 成功；head SHA 为 final main commit，发布者仍为 `ysc070528/granttrace`、`release.yml`、`pypi`。
- [x] [PyPI `2.5.0`](https://pypi.org/project/granttrace/2.5.0/) 可见。
- [x] fresh Windows virtual environment 从 PyPI 安装 `granttrace==2.5.0` 成功，安装 `PyYAML-6.0.3 granttrace-2.5.0`。
- [x] CLI 为 `GrantTrace 2.5.0`，`importlib.metadata` 为 `2.5.0`。
- [x] read-only demo：BOLA / IDOR 1 confirmed、Mass Assignment 0 confirmed、PATCH disabled；database restored、server stopped，成功完成。
- [x] active demo：BOLA / IDOR 1 confirmed、Mass Assignment 1 confirmed、rollback verified、database restored、server stopped，成功完成。
- [x] 临时隔离虚拟环境已清理，存在性检查为 `False`。
- [x] 本次 PR 已完成最小发布后文档同步，等待人工 review；PR 保持开放、未合并。

Final main SHA：`151bab4a613edee1b3ff8c86b68575038f769b00`

正式 GitHub Release wheel：`granttrace-2.5.0-py3-none-any.whl`，109901 bytes。

Final wheel SHA256：`8cd2fb7715727503585cefa9f83147dc81e1a19941bf454836b379a400f64805`

正式 GitHub Release sdist：`granttrace-2.5.0.tar.gz`，342818 bytes。

Final sdist SHA256：`d05d08b3f66e05741867b587781510d93da312778676fca11a07adc29e7b24e2`

`SHA256SUMS`：190 bytes，GitHub digest 为 `sha256:f03073a8800790cd53d72a4aba1412fcbf28dc0f788cff512cfce13118950f9b`。

这些 hash 仅标识 GitHub Release 资产；PyPI 工作流独立构建发行物。安装与 demo 结果为用户提供的 bundled local demo / isolated local acceptance，不证明生产 API 零误报、完整授权覆盖或完全安全。本次文档 PR 未重新执行安装、demo 或发布。

## 发布前 Release Notes 草稿（历史）

以下保留发布前草稿原文；末尾的未发布说明仅指草稿编写时的状态。当前正式发布事实见上方完成记录。

GrantTrace v2.5.0 introduces CONFIRMED-only SARIF 2.1.0 export with safe OpenAPI
artifact locations, safe cURL reproduction templates with Visitor credential
placeholders, and clearer configuration onboarding and offline dry-run guidance.
Default read-only auditing, independent GET readback and rollback verification
remain in place. Active PATCH still requires explicit opt-in and an allowlist;
active POST / PUT and automated login / OAuth are not included. Quality checks
retain Python 3.9 / 3.12 / 3.14, blocking Mypy, Ruff, dependency audit, CodeQL and
the minimum 80% branch-aware coverage gate. This is a notes draft, not a published
Release or a claim that PyPI 2.5.0 is available.

## Previous stable release

以下保留 v2.4.1 的完整历史发布与复核记录，仅适用于该历史 release/tag；其中当时 README 和版本要求不代表本轮 v2.5.0 源码状态。

### v2.4.1 发布与发布后复核清单

**v2.4.1 已于 2026-10-04 正式发布**，当前稳定版本为 [v2.4.1](https://github.com/ysc070528/granttrace/releases/tag/v2.4.1)，[PyPI 2.4.1](https://pypi.org/project/granttrace/2.4.1/) 已可安装。本清单记录发布完成的事实与可重复执行的发布后复核步骤；此前开发版与历史版本的实际验收事实继续保留在 [验收记录](../VERIFICATION.md)。已有 v2.4.0 / v2.3.1 tag、Release 与资产保持原样。

#### 已完成的发布记录

- [Release Prep PR #18](https://github.com/ysc070528/granttrace/pull/18) 已合并；发布时 final main commit 为 [`8ba6cb46c9bbd670449989a5bd54fb233543d81f`](https://github.com/ysc070528/granttrace/commit/8ba6cb46c9bbd670449989a5bd54fb233543d81f)。
- annotated tag `v2.4.1` 已创建，最终解析到上述 commit。
- [GitHub Release “GrantTrace v2.4.1”](https://github.com/ysc070528/granttrace/releases/tag/v2.4.1) 已正式发布，非 draft、非 prerelease，附带 `granttrace-2.4.1-py3-none-any.whl`、`granttrace-2.4.1.tar.gz` 和 `SHA256SUMS`。
- [Publish to PyPI 工作流](https://github.com/ysc070528/granttrace/actions/runs/37175522087) 成功；通过 OIDC Trusted Publishing 发布，owner 为 `ysc070528`、repository 为 `granttrace`、workflow 为 `release.yml`、environment 为 `pypi`，未使用 PyPI Token 或用户名/密码。
- 发布 commit 的 [main CI](https://github.com/ysc070528/granttrace/actions/runs/37137142692) 和 [CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37137142656) 均成功；Python 3.9 / 3.12 / 3.14、Mypy、Ruff、Runtime dependency audit 均通过。
- `main` 已受保护，required checks 包含正式 blocking 的 **Mypy**、三个 Python 测试、Ruff、Runtime dependency audit、Analyze Python 和 CodeQL。

#### 已完成的发布验收

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

#### 发布后复核

以下步骤用于复核已发布的 v2.4.1，不重新发布或改动历史资产：

- 核对 annotated tag `v2.4.1` 仍解析到发布 commit，正式 Release 仍为非 draft、非 prerelease，三个附件齐全；下载后重新计算 SHA-256，与 `SHA256SUMS` 比较。
- 核对发布 commit 的 main CI / CodeQL 成功，Mypy 仍为 required blocking check，coverage 门槛仍为 80%。
- 核对 PyPI 项目版本及发布工作流的成功记录；OIDC 发布者仍为 `ysc070528/granttrace`、`release.yml`、`pypi`。工作流继续核对 tag、源码 commit、项目与发行物版本，构建与上传分离。
- 在新环境安装 `python -m pip install --no-cache-dir granttrace==2.4.1`，核对版本与 demo 两模式；此步骤是安装复验，不是上传。
- README 应显示 `Stable: v2.4.1`；不创建未经开发与审查的下一版本号。
- 使用实际检查名称只读复核 main 保护、private vulnerability reporting、Topics 和剩余远程分支；查询本身不修改设置或删除分支。

#### 本地复验

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

#### 仓库设置复验

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
