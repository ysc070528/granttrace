# GrantTrace 验收记录

## 2026-10-03 v2.4.0 发布前验收

本轮在已合并 PR #11 的最新 `main`（`4b65e54`）基础上创建
`codex/v2.4.0-release`，将统一版本来源从 **2.4.0.dev0** 切换为
**2.4.0**。保留 `api_sentinel.py`、`APISentinelAuditor` 兼容入口，未改变
BOLA / IDOR / Mass Assignment 判断标准，未降低 allowlist、独立读回或恢复
限制，未新增 POST / PUT 主动测试或自动认证功能。验证仅使用本机 loopback
靶场、离线测试与公开包索引 / 漏洞服务，未使用真实凭据或生产 API。

### 本地实际结果

环境：Windows，Python **3.14.5**，PyYAML **6.0.3**。

| 检查 | 实际结果 |
|---|---|
| `python -m unittest discover -s tests` | **268/268 通过**；0 失败、0 错误、0 跳过 |
| `python scripts/verify_business_scenarios.py` | 六个业务模型全部匹配预先声明的真值；本地样本误报、漏报、不确定均为 0 |
| `python scripts/verify_examples.py --update-examples` | 只读 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED，确定性覆盖率 60%；主动 JSON / YAML 均 2 CONFIRMED、1 PUBLIC、2 SECURE，确定性覆盖率 100%；完整数据库恢复成功，示例重生成为 2.4.0 |
| `python scripts/verify_install.py` | 在全新虚拟环境安装本轮构建的 **granttrace-2.4.0-py3-none-any.whl**，从源码目录外执行安装后的 CLI；版本、预检、计划和真实只读 / 主动扫描均通过 |
| `python -m ruff check .` | 全部通过 |
| `python -m coverage erase` / `run -m unittest discover -s tests` / `report` / `xml` / `json` | 真实执行 268 项测试并生成结果；总覆盖率 **79.66%**，语句 **3071/3715 = 82.66%**，分支 **1467/1982 = 74.02%**，无排除行，与此前参考一致 |
| `python -m pip check` | 无依赖冲突 |
| `python -m pip_audit --strict --progress-spinner off .` | 本轮解析的项目运行依赖无已知漏洞；严格模式通过 |
| `python -m mypy` | **20 个问题 / 6 个文件**，检查 13 个源码文件；与此前状态一致，继续作为 advisory |
| actionlint 检查工作流 | 通过 |
| `python -m build` / `python -m twine check --strict` | wheel / sdist 均成功构建且 metadata / README 检查通过；Apache-2.0 使用标准 SPDX metadata |
| `python scripts/verify_install.py --wheel dist/granttrace-2.4.0-py3-none-any.whl` | 指定正式构建的 wheel，源码目录外的新虚拟环境中全部安装与真实 mock 扫描验收通过 |
| sdist 解压后的源码目录外复验 | 268 项测试、业务场景、JSON / YAML 示例全部通过；公开配置、指南、兼容入口和验收脚本完整 |

独立安装验证实际记录只读模式发送 **0 次 PATCH**，主动模式发送 **3 次 PATCH**。
该次数包含探测与恢复请求，不代表三个独立漏洞。安装后的 metadata、
`core.__version__`、CLI `--version` / Banner、HTML 报告、JSON `tool_version`
均为 **2.4.0**，实际请求 User-Agent 为 **`GrantTrace/2.4.0`**。
主动 Mass Assignment 的 `rollback_verified` 为 `true`，完整数据库与扫描前
一致；JSON / YAML 只读计划等价且未发送目标请求，未完成配置草稿仍被阻止。

coverage 只测量单元测试父进程中的产品代码 `api_sentinel.py` 与 `core/`，
包含未执行代码，不包含测试、mock、验收脚本或另行启动的 Python 子进程。
端点确定性覆盖率 60% / 100% 与这里的代码覆盖率是不同指标。业务场景
误报 / 漏报数据仅描述六个已知真值模型，不代表其他 API 的检测效果。

### CodeQL、发行认证与尚待完成的验证

- 既有 CodeQL alert #1 指向 `tests/test_report_usability.py:137` 的合成
  literal。针对该路径的离线测试实际 **1/1 通过**：生成 HTML 不含测试中的
  假秘密值，包含 `REDACTED`。人工核对支持其为自定义 sanitizer 未被抽象
  数据流模型识别的误报判断；该告警继续保留 open，未 dismiss。此局部证据
  不替代本轮远端 CodeQL；发布前仍须确认无新增阻断性告警。
- PyPI `granttrace` JSON 查询返回 404，仅表示当时未查询到公开项目，
  不保证名称可以注册。当前未发现可安全使用的 PyPI 发布认证，按授权边界
  跳过 PyPI 上传，不要求聊天提供明文 token。
- 本段记录发布前已实际完成的本地验收。正式 wheel / sdist 与指定 wheel
  独立安装已验收；Release PR、远端 Python
  3.9 / 3.12 / 3.14 CI、合并后 `main` CI / CodeQL、tag / GitHub Release、
  分支清理及保护设置仍需分别记录实际结果；本段不宣称这些操作已完成。

下方所有历史版本与开发版验收保留原文，各段“当前”均指该轮记录时的状态。

---

## 2026-10-03 工程化收尾：2.4.0.dev0

本轮从最新 `main`（`9732a68`）创建 `codex/repository-hardening`，开发版本仍为 **2.4.0.dev0**。GitHub 只读查询确认最新正式 Release 为 **v2.3.1**，`main` 的 `protected` 为 `false`。未修改检测标准、身份规则、写允许清单、独立读回或恢复限制；未访问生产 API、使用真实凭据、修改仓库设置、删除远程分支、合并、建 tag 或发布 Release。

### 本地实际结果

环境：Windows，Python **3.14.5**，PyYAML **6.0.3**，Node 可用；工具版本为 Ruff **0.16.10**、coverage.py **7.16.2**、mypy **2.4.0**、pip-audit **2.10.1**、actionlint **1.7.12**。

| 检查 | 实际结果 |
|---|---|
| `python -m unittest discover -s tests` | 修改前后均 **268/268 通过**；0 失败、0 错误、0 跳过 |
| `python -m coverage run -m unittest discover -s tests` | 同一正式测试入口，**268/268 通过**，0 跳过 |
| `python -m coverage report` / `xml` / `json` | 总覆盖率 **79.66%**；语句 **3071/3715 = 82.66%**，分支 **1467/1982 = 74.02%**，无排除行 |
| `python scripts/verify_business_scenarios.py` | 六个业务模型全部符合预先声明的真值，样本误报/漏报/不确定均为 0 |
| `python scripts/verify_examples.py` | 只读 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED；主动 JSON/YAML 均 2 CONFIRMED、1 PUBLIC、2 SECURE；三次整份数据库恢复成功 |
| `python scripts/verify_install.py` | fresh build 的 **granttrace-2.4.0.dev0-py3-none-any.whl** 在新虚拟环境由 pip 解析安装依赖；源码目录外 CLI、真实只读 HTML/JSON、预检、JSON/YAML 等价计划、草稿阻断均通过 |
| `python -m ruff check .` | 全部通过；显式检查 `E4/E7/E9/F`，无新增 `noqa` 或 `type: ignore` |
| `python -m mypy` | **20 个问题 / 6 个文件**，共检查 13 个源码文件；非阻断，保留全部诊断 |
| `python -m pip_audit --strict --progress-spinner off --format json --output dist/pip-audit.json .` | 本次解析运行依赖 **PyYAML 6.0.3**，无已知漏洞；未审计开发 extra 或所有历史可选版本 |
| `python -m pip check` | 无依赖冲突 |
| actionlint 检查两个 workflow | 通过；工具下载后核对官方 SHA256，未启用本机未安装的 ShellCheck/Pyflakes |
| Python 3.9 语法模式解析 | 38 个 Python 文件通过；此项不代表 Python 3.9 运行时已在本机验证 |
| 文档链接和展示 | 10 个 Markdown 文件中的 22 条本地文档/图片链接有效；现有截图和示例品牌/版本保持正确 |

coverage 只测量单元测试父进程中的产品代码 `api_sentinel.py` 与 `core/`，包含未执行代码；不包含 tests、mock、验收脚本或另行启动的 Python 子进程。子进程版本回归仍真实执行。这里的代码覆盖率与报告中的端点确定性覆盖率（只读 60%、主动 100%）是不同指标；本轮没有新增凑覆盖率的测试，也没有设置任意百分比门槛。

### CI 状态与保留问题

- 保留 Python **3.9 / 3.12 / 3.14** 矩阵、unittest、业务/示例/独立安装验收。固定 Node 环境防止报告交互测试因缺 Node 跳过；`coverage[toml]` 支持 Python 3.9 读取本仓库配置。每个解释器生成 text/XML/JSON，显示 missing lines 和分支，并上传 14 天证据与 Actions 摘要。GitHub 日志发现旧 Actions 的 Node 20 运行时弃用警告后，改用已核实为 Node 24 的官方 checkout/setup-python/setup-node/upload-artifact v7，并关闭 checkout 的凭据持久化。
- Ruff 为正式门禁；修复限未使用导入/变量、等价局部函数和验收脚本导入位置。mypy 现有问题涉及动态 JSON/Optional 推断、集合类型和返回类型；本轮不批量改变核心实现或加忽略，CI 明确显示 advisory outcome 与诊断。后续可分模块处理再升级门禁。
- pip-audit 独立用 Python 3.12，避免其 Python >=3.10 要求影响产品的 Python 3.9 支持；直接读取项目运行依赖，`--strict`，不忽略漏洞、不自动修复、服务失败也不会被当作通过。只访问包索引和公开漏洞服务。[工具范围与限制](https://github.com/pypa/pip-audit/blob/main/README.md)
- CodeQL 独立 workflow 使用 Python 静态分析、`build-mode: none`、默认查询集和最小权限；触发为 PR/main push/每周/手动，不运行扫描器或访问目标 API。[官方配置说明](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning) CodeQL 及跨解释器的实际远端结果以本轮 PR checks 为准，本地 actionlint 通过不能替代它们。
- 版本静态链及真实回归/独立安装均一致：项目与 wheel metadata、`core.__version__`、CLI、User-Agent、HTML、JSON `tool_version` 全为 **2.4.0.dev0**；历史 Release 未变。
- A 类展示已使用 GrantTrace，本轮修正 README 版本状态及 PyYAML 已是声明依赖的提示措辞。B 类保留兼容模块 `api_sentinel.py`、`APISentinelAuditor`、entry point/import 引用与旧报告 ignore 规则；直接重命名存在外部调用兼容风险。旧 CLI/包/ZIP 名在历史记录中按原事实保留。
- 本文件已有多个版本与轮次的验收，适合未来拆至 `docs/verification/`、根文件保留索引；本轮新增独立记录，保留所有既有历史原文。
- 合并前由维护者手动启用/复核 **main Branch Protection**，选择必要测试、Ruff、运行依赖审计和 CodeQL 检查；mypy 暂不作为必需检查。已合并旧远程分支可在确认合并状态后按需手动删除。本轮不执行这两项。若已启用 CodeQL Default setup，需维护者在网页确认 Advanced setup 与本工作流的配置一致。

复现新增检查（正式测试与验收命令见上表）：

```bash
python -m pip install ".[dev]" setuptools wheel
python -m ruff check .
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m coverage xml
python -m coverage json
python -m mypy
# 以下依赖审计在 Python 3.12+ 的独立环境执行。
python -m pip install "pip-audit>=2.10,<3"
python -m pip_audit --strict --progress-spinner off --format json --output dist/pip-audit.json .
```

生成的证据、wheel、缓存均在 ignore 范围，不作为源码提交。工作区的 CRLF 历史文件以 `git -c core.whitespace=cr-at-eol diff --check` 检查；没有修改仓库 Git 配置。

远端首次真实执行（PR #11，提交 `a3afd17`）：[GrantTrace CI](https://github.com/ysc070528/granttrace/actions/runs/37109356278) 与 [CodeQL](https://github.com/ysc070528/granttrace/actions/runs/37109356295) 均成功。Python 3.9/3.12/3.14 各 268 项无跳过，coverage 各为 79.66%，三份完整业务/示例/独立安装证据已上传；Ruff 与运行依赖审计通过。mypy 仍为 20 个问题，step 实际退出 1、Actions 摘要为 `advisory: failure`，job 按设计非阻断；CodeQL 已完成真实分析和结果上传，此结果不等同于通用安全保证。Actions 运行时升级后的最终提交须另看 PR 最新 checks。

---

## 2026-10-03 当前 PR：2.4.0.dev0 开发版本身份

当前 PR #10 的开发版本身份统一为 **2.4.0.dev0**，适用于运行时、CLI、HTTP User-Agent、HTML、JSON、项目和 wheel 元数据。最新正式 Release 仍为 **v2.3.1**，其标签与历史资产保持原样，尚未包含当前 `Unreleased` 变更。本次仅修正开发版本身份，不合并 PR、不发布 Release、不删除分支。

本次版本身份修正后，在 Windows Python **3.14.5**、PyYAML **6.0.3** 下重新执行：

- `python -m unittest discover -s tests`：**268/268 通过，0 失败、0 错误、0 跳过**。现有真实 HTTP 版本回归同时核对 Banner、User-Agent、HTML 和 JSON 均读取 `core.__version__`。
- `python scripts/verify_business_scenarios.py`：六个业务真值场景全部通过，样本误报、漏报、不确定各为 0。
- `python scripts/verify_examples.py --update-examples`：重新生成示例 HTML/JSON；只读与主动 JSON/YAML 的状态计数、60%/100% 覆盖率和完整数据库恢复均符合原有预期。
- `python scripts/verify_install.py`：本轮构建 **`granttrace-2.4.0.dev0-py3-none-any.whl`**，在全新虚拟环境由 pip 解析并安装声明依赖，从源码目录外验证已安装 CLI、实际默认 HTML/JSON、JSON/YAML 预检和计划导出、未完成草稿阻断，全部通过。首次运行因沙箱禁止访问 PyPI 失败，允许网络访问后原命令重跑通过。
- 版本一致性：`pyproject.toml`、`core.__version__`、`granttrace --version`、User-Agent（`GrantTrace/2.4.0.dev0`）、HTML（`v2.4.0.dev0`）、JSON `tool_version`、wheel 及已安装 metadata 全部对应 **2.4.0.dev0**。
- 用现有截图脚本从重新生成的示例报告导出两张 PNG，Edge 页面版本为 `v2.4.0.dev0`。仓库内剩余 `2.3.1` 仅用于历史事实、正式 Release 链接和既有配置 schema 标识；schema 语义未改变，沿用原 `$id`。

下方 268 项、265 项测试与 2.3.1 wheel 等结果均是此前修订的真实历史记录，与本段当前开发构建的重新验收分别记录。

---

## 2026-10-03 发布自检修订（版本身份修正前的历史记录）

本段记录此前发布自检修订，当时开发代码仍标为 **2.3.1**；运行时、CLI、HTTP User-Agent、HTML、JSON、项目和 wheel 元数据使用该版本。这一历史标识已在当前修订改为 **2.4.0.dev0**。以下保留当时实际验收结果，没有修改历史 `v2.3.1` 标签或重新发布其 ZIP，历史 Release 资产不包含这些开发变更。

- **完整回归：268/268 通过，0 失败、0 错误、0 跳过**，分别在 Windows Python 3.12.11 和 3.14.5、真实 PyYAML 6.0.3 下执行。新增三项回归验证项目版本、实际 CLI 默认报告以及直接 Reporter 默认输出。
- 实际不传 `-o` 的扫描生成 **`granttrace_report.html`**。只读结果为 1 CONFIRMED、1 PUBLIC、1 SECURE、2 SKIPPED，确定性覆盖率 60%；JSON/YAML 主动结果均为 2 CONFIRMED、1 PUBLIC、2 SECURE，确定性覆盖率 100%。三个模式的完整数据库均与运行前一致，主动 Mass Assignment 的恢复核验成功。
- `scripts/verify_business_scenarios.py` 六个场景全部符合独立真值，样本误报、漏报、不确定各为 0；范围限本地模型。
- `scripts/verify_install.py` 在本次独立临时目录构建 wheel，新环境安装后核对文件名及 metadata、运行时和 CLI 版本；从源码目录外运行真实只读扫描，不传 `-o` 生成默认报告并核对 HTML/JSON 版本。JSON/YAML 预检、只读计划和草稿阻断均通过。离线依赖来自当前平台的 PyYAML wheelhouse。另放入无效旧版本 wheel 后复验通过，证明旧 `dist/` 产物不会被误选。
- Git 跟踪列表无 `config.json`。实际验证 11 个本地配置/报告/计划产物被忽略，6 个示例/schema/源码配置路径不被忽略。源码配置规则仅作用于仓库根，专用 `*.local.json` 与草稿清单规则仍适用于各目录。
- GitHub 仓库实时设置核验：Topics 保留原列表并添加 `mass-assignment`；private vulnerability reporting 为 `enabled: true`；`delete_branch_on_merge: true`。SECURITY 已提供私密表单链接，提交报告需要登录 GitHub。
- README 首屏补英文一句话和无需展开的报告图；示例 HTML/JSON、完整截图和紧凑预览均重新生成。Edge 实际页面版本显示 `v2.3.1`，搜索/状态筛选正常，本地文档链接与图片路径检查通过。

尚未完成的清单项是“远程分支仅保留 main”。七个旧功能分支已验证为 `main` 的祖先，但自动审批拒绝删除远程分支，理由是截图请求没有明确授权这项删除。旧分支继续保留；本轮新 PR 分支在审查期间也需保留，合并后由已启用的自动删除设置清理。需要维护者明确批准旧分支删除后再核验并勾选此项。

本轮没有访问生产 API、发布新的 Release 或合并本轮 PR。CI 的实际运行结果以本轮 PR 检查为准。

---

## 2026-10-03 开发分支：首次体验、报告与参数编码（此前修订的历史记录）

本段对应此前首次体验、报告与参数编码修订；当时包元数据为 GrantTrace **2.3.1**，未发布新的版本。以下 265 项测试和 `granttrace-2.3.1-py3-none-any.whl` 等结果保留原始执行事实，当前开发版本为 **2.4.0.dev0**。更早的发布验收在下方独立保留。

- **完整回归：265/265 通过，0 失败、0 错误、0 跳过**。Windows 下分别运行 Python 3.12.11 与 3.14.5，真实 PyYAML 6.0.3 已安装。新增 42 项覆盖配置草稿、参数序列化、报告交互及业务授权；测试无需未追踪的 `config.json`。
- 产品、验收脚本和测试共 34 个 Python 文件通过 Python 3.9 语法模式解析；本机未实际运行 Python 3.9。CI 配置覆盖 3.9、3.12、3.14，远程执行结果以本次 PR 检查为准。
- `scripts/verify_examples.py` 经真实 HTTP 靶场验证：只读模式确认 1 个故意漏洞，确定性覆盖率 60%；JSON/YAML 主动模式均确认 2 个故意漏洞，确定性覆盖率 100%，无错误或不确定结果。每次整份数据库与运行前完全一致，Mass Assignment 的恢复独立核验为成功；主动漏洞门槛预期返回 1。
- `scripts/verify_business_scenarios.py` 的六个本地场景均符合预先声明的真值：共享/管理员读取为 `AUTHORIZED`；同租户未共享/跨租户隔离为 `SECURE`；两个故意泄露为 `CONFIRMED`。本地样本误报 0、漏报 0、不确定 0。额外回归保留匿名泄露、无效 Visitor 自有基线、允许访问却拒绝等不确定边界。
- wheel **`granttrace-2.3.1-py3-none-any.whl`** 构建成功。在全新 Python 3.14 虚拟环境中，从预下载的 wheelhouse 安装本地 wheel 及声明的 PyYAML 依赖；从源码目录外执行安装后的 **`granttrace`**。检查导入来源为新环境，版本、JSON/YAML 配置预检、等价只读计划（`requests_sent: 0`）、草稿生成和未完成草稿阻断均通过。本次验证的是此分支构建的 wheel，没有验收 GitHub 历史 Release 的二进制产物。
- 重新生成示例 HTML/JSON 与 README 预览。在 Edge 实际渲染中执行搜索、状态组合筛选及无结果状态；1440px 桌面和 390px 手机宽度检查通过，端点表格可横向滚动。High/Critical 标签高度约 23px；无 JavaScript 错误、无外部请求。已有凭据回显与 HTML 注入反例回归通过。

可复现命令：

```bash
python -m pip install . setuptools wheel
python -m unittest discover -s tests
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
```

`verify_install.py --wheelhouse <目录>` 可使用含当前平台 PyYAML wheel 的目录执行离线依赖安装。默认模式让 pip 正常解析声明依赖。验收结果写入 `dist/`，CI 上传对应证据；示例更新需显式使用 `verify_examples.py --update-examples`。

本次未连接真实业务 API、未使用生产身份、未部署或发布。`expected_visitor_access: allow` 必须来自业务方对当前身份/资源关系的确认；它不自动推断权限，也不是通用端点豁免。本地六个模型的误报/漏报数字不能代表真实业务效果。

---

## v2.3.1-final 修复版验收记录

日期：2026-10-02。环境：Windows、Python 3.12.11、PyYAML 6.0.3。

### 实际完成的验证

- **完整测试：223/223 通过，0 失败、0 错误、0 跳过，约 5.51 秒。** 原有 178 项加发布回归 45 项；四个新模块分别为 BOLA 8 项、配置 17 项、证据 13 项、事务 7 项。真实 YAML 成功加载和模拟缺依赖错误均已覆盖。
- 所有产品 Python 源码通过 Python 3.9 语法模式解析；本次没有运行 Python 3.9 解释器。
- `config.json`、`config.example.json` 及真实 YAML 规范的配置预检返回 0；dry-run 导出计划中的 `requests_sent` 为 0。
- 完整 CLI 只读扫描：1 个 CONFIRMED、1 个 PUBLIC、1 个 SECURE、2 个 SKIPPED；确定性覆盖率 60%。
- 完整 CLI 主动扫描分别使用 JSON/YAML 规范：两次均检出靶场预设的 2 个漏洞；1 个 PUBLIC、2 个 SECURE；0 错误、0 不确定、0 可疑；确定性覆盖率 100%。
- 每次扫描后，对整份模拟数据库与写前快照做比较，结果一致；批量赋值发现的独立恢复核验为成功。
- 同时开启漏洞、错误、可疑及 100% 覆盖率门槛时，主动扫描因靶场预设漏洞返回 1。
- wheel 构建成功：`api_sentinel-2.3.1-py3-none-any.whl`。在单独新建的虚拟环境执行 `pip install --no-index --no-deps` 安装本地 wheel，并从源码目录外运行安装后的 `api-sentinel`：版本、JSON 配置预检、dry-run 均返回 0；导入位置确认来自安装环境，运行时版本为 `2.3.1-final`，包版本为 `2.3.1`。这项测试验证本地 wheel 内容与入口，不声称在该新环境完成网络依赖解析；真实 PyYAML 验证在另一个独立验证环境完成。

### 修复反例

- 访客正常拒绝、匿名 404/500 正文带私有业务数据：SUSPICIOUS，不再计入安全或确定性覆盖。
- 非有限数或浮点溢出的读回：在主动写入前拒绝，PATCH 请求数为 0；写后出现非法读回仍执行恢复。
- Cookie 分量、特殊 Cookie 名称、编码值及数字凭据回显：默认 JSON/HTML 证据不保留已知凭据；显式敏感证据开关保持原有行为。
- 错误读回参数形状：配置预检返回 2，尚未创建审计器或建立连接。
- OpenAPI 自定义认证头：JSON/YAML 在配置预检与 dry-run 两种入口都返回 0。

### 交付范围

历史版本归档记录：原 v2.3.1 迁移前 ZIP 为 `API-Sentinel-Hardened-v2.3.1-final.zip`，历史根目录为 `API-Sentinel-Hardened/`，正式文件 44 个。归档排除构建目录、egg-info、Python 缓存、虚拟环境和临时扫描输出；保留重新生成的两个参考报告。原始 v2.3.0-final ZIP 与审查副本保持不变。

未访问真实业务 API，未执行线上部署，未运行 GitHub Actions；本地靶场的 100% 覆盖率只属于这 5 个示例端点。应用层恢复不能通用撤销并发业务修改、异步任务或读回未暴露的外部副作用。

---

## v2.3.0-final 最终验收记录

日期：2026-10-02。环境：Windows，Python 3.12.11。

### 1. 自动化回归测试（178 / 178 PASS）
- **完整测试矩阵**：运行 `python test_suite.py`，全量 **178/178 项全部通过**（0 失败，0 错误，耗时约 5.3s）。
- **测试分布与覆盖（共 10 个测试模块，总计 178 项全部 PASS）**：
  1. `tests/test_auditor_integration.py`: 12 项
  2. `tests/test_config_validation.py`: 22 项
  3. `tests/test_diff.py`: 16 项
  4. `tests/test_diff_hardening.py`: 18 项
  5. `tests/test_evidence.py`: 15 项
  6. `tests/test_parser_generator_hardening.py`: 6 项
  7. `tests/test_rc2_security_hardening.py`: 20 项
  8. `tests/test_rc3_hardening.py`: 18 项
  9. `tests/test_schema_regressions.py`: 18 项
  10. `tests/test_v22_auditor_hardening.py`: 33 项

### 2. 离线配置语义校验验收
- 执行 `python api_sentinel.py --spec openapi.json --config config.json --validate-config`：返回码 0，完全无网络请求，耗时约 0.05s。
- 执行 `python api_sentinel.py --spec openapi.json --config config.example.json --validate-config`：返回码 0。
- 执行非法配置（如读写路径碰撞、操作键空格不规范、小写 HTTP 方法、未映射字段）：正常扫描入口与 `--validate-config` 均在发起网络连接前以退出码 2 退出，并精准输出定位信息。

### 3. 本地靶场端到端回归验收
- 启动 `mock_server/server.py`，执行只读扫描：3 个 GET 端点正常检查，2 个写接口按预期标记为 `SKIPPED`。
- 执行带写测试扫描 `--allow-write-tests`：
  - 准确检出故意保留的 2 个漏洞（CWE-639 BOLA 越权，CWE-915 Mass Assignment 特权篡改）；
  - 1 个 PUBLIC 端点、2 个 SECURE 端点；0 错误、0 不确定，确定性覆盖率 100%；
  - 事务回滚机制生效，测试结束后靶场数据库快照与测试前比对一致。

### 4. Python Wheel 构建验收
- 执行构建命令：`pip wheel . --no-deps`。
- 规范性核查：`pyproject.toml` 中 `version = "2.3.0"` 符合 PEP 440；wheel 构建成功，生成 `api_sentinel-2.3.0-py3-none-any.whl`（大小约 79.2 KB）。
- 构建环境清理：构建完成后已清理 `build/`、`temp_dist/`、`*.egg-info` 等中间产物，未混入交付包。

### 5. 交付 ZIP 清洁检查验收
- 历史交付归档名称：`API-Sentinel-Hardened-v2.3.0-final.zip`。
- 归档文件构成：**严格 40 个正式文件**，历史归档顶层目录为 `API-Sentinel-Hardened/`。
- 清洁度核验结果：
  - 确认**零** `__pycache__`、**零** `*.pyc`、**零** `.pytest_cache`、**零** `.git` 目录；
  - 确认**零**临时扫描输出物（无 `result.json`、`report.html`、`scan.log`、`API_Security_Report.html`）；
  - 保留标准离线参考示例：`examples/sample_report.html` 与 `examples/sample_result.json`；
  - 确认 `config.json` 与 `config.example.json` 仅包含本地测试专用的 Mock 占位符（`TOKEN_ALICE_OWNER_1001`、`TOKEN_BOB_VISITOR_1002`、RFC 4122 示例 UUID），无真实敏感凭据；
  - 自动化模式扫描未发现真实密钥、个人用户名或本机绝对路径（文本与字节扫描 0 命中）。

---

## v2.2.0 本地验收记录（历史归档）

> [!NOTE]
> 以下为 **v2.2.0 历史验收记录**，保留作为历史实现追溯参考。

日期：2026-10-01。环境：Windows，Python 3.12.11。

## 已执行的验证

- 完整回归：118 / 118 通过（v2.1 原有 34 项，新增 84 项）。
- 所有 Python 源文件通过 Python 3.9 语法模式解析；这不等于在 Python 3.9 运行过。
- 本地 HTTP 靶场：5 个端点，确认 2 个故意保留的漏洞（CWE-639 和 CWE-915）；1 个 PUBLIC、2 个 SECURE；0 错误、0 不确定，确定性覆盖率 100%。
- 开启错误、漏洞、可疑结果、100% 覆盖率门槛后，CLI 正确以退出码 1 报告靶场漏洞。
- 主动扫描结束后，整份模拟数据库与扫描前快照完全一致，不只检查 role。
- 示例 HTML / JSON 重新生成；报告中的已知凭据、姓名、工资已作脱敏。检查 HTML 转义和离线内容，不声称已完成浏览器视觉验收。
- 新增单元反例包括恢复函数自身异常、回滚失败后停写、异步请求停写、完整数组恢复、派生权限残留检测和真实 readOnly 字段攻击链。

## 复查问题与处理

| 原问题 | 本版处理 |
|---|---|
| R01 普通字段/数组被改坏却声称回滚成功 | 实际业务值来自快照，完整容器恢复，默认核验整份读回状态 |
| R02 提交后解码/读回异常绕过回滚 | 异常进入请求错误，finally 恢复；恢复自身异常也停写 |
| R03 恢复失败后继续发写请求 | 保留全局停写状态，后续写操作 SKIPPED |
| R04 403 含数据或历史拒绝文字误判安全 | 错误正文与实际业务数据分开判断，冲突保持可疑/不确定 |
| R05 80% 相似度吞掉私有增量，忽略鉴权要求 | 显式公开策略 + 完整 JSON 一致才可 PUBLIC；鉴权冲突保留可疑 |
| R06 同凭据不同配置绕过身份检查 | 比较最终生效认证头，普通 trace 差异不算身份差异 |
| R07 请求回显 ID 造成确认证据 | 排除请求/追踪元数据；可信资源 ID 路径需明确配置 |
| R08 readOnly 特权字段漏测 | 普通基线排除，攻击候选保留；配置字段未覆盖不能声称全部安全 |
| R09 明文/截断 JSON/驼峰密钥/URL 等泄露 | 统一结果出口清理；不可解析正文默认只保留摘要，证据规模受限 |
| R10 窄数值区间/allOf/非法 example 生成错误 | 数值可行区间、组合交集及递归验证；无法合成时显式拒绝 |
| R11 声明媒体类型与实际发送不一致 | 传播 application/json / merge-patch+json；不支持的格式跳过 |
| R12 外部 ref 与 sibling 来源混乱、缺失属性 | 3.1 分来源解析后交集；3.0 结构性 sibling 拒绝并要求 allOf；缺失 pointer 报错 |
| R13 空扫描/全不支持项目错误通过 CI | 零确定性检查不能通过错误门槛，另有覆盖率和可疑门槛 |

## 迁移注意事项

请阅读 README 的“v2.2 配置与迁移说明”，特别是：

- 显式公开策略、可信资源 ID 路径、强一致读回约定。
- CLI 允许清单替换配置清单，路径区分大小写。
- 默认全读回核验可能因时间戳变化失败；只可显式忽略已确认无安全影响的波动字段，不能忽略写入字段。
- 使用 --dry-run 预览范围；它不是一次扫描，也不证明目标安全。

## 未验证或不能保证的部分

没有访问真实业务 API，没有使用真实账号或凭据，没有执行线上部署。
本机未安装 PyYAML，因此只验证了 YAML 缺依赖提示/模拟路径，未验证真实 YAML 加载；
没有运行 pip 安装、wheel 构建、GitHub Actions 或 Python 3.9 运行时。

这是 Beta 工具，生成器并非完整 JSON Schema 求解器，脱敏也并非通用隐私识别器。
无法通用撤销进程强杀、并发写、迟到异步任务、邮件/通知/审计日志或读回未暴露的状态。
本地靶场的 100% 覆盖率只属于这 5 个示例端点，不代表真实系统的检出率。

原始桌面 ZIP 和 v2.1.0 交付包保持不变。
