# GrantTrace

![CI](https://github.com/ysc070528/granttrace/actions/workflows/test.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/granttrace.svg)](https://pypi.org/project/granttrace/)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

**当前发布版本：2.5.3** · [GitHub Releases](https://github.com/ysc070528/granttrace/releases/latest) · [PyPI](https://pypi.org/project/granttrace/)

Windows 便携版已正式提供；已发布版本与下载资产以官方 GitHub Release / PyPI 页面实际列出的版本为准。下方下载入口和 `pip install` 均可获取当前已发布版本。

An OpenAPI authorization auditor that compares identity responses and reports explicitly scoped authorization evidence.

安全优先、证据驱动的 OpenAPI 权限与授权审计工具。提供 BOLA / IDOR 只读身份对照，并在配置明确的业务证据后检查匿名私有数据暴露、角色边界和集合接口私有数据泄漏。输出 HTML / JSON 和可选 SARIF。当前分支的新增能力尚未发布；检测范围受身份、资源与配置证据限制，不表示完整覆盖 OWASP API Top 10。

默认扫描会在请求前跳过具有明显状态变更语义的 GET，包括独立读回；静态规则无法保证发现所有副作用，仍需人工核对规范和计划。拒绝响应、授权证据及覆盖率的具体边界见 [授权审计加固说明](docs/authorization-audit-hardening.md)。

仅对明确获得授权的系统进行测试；主动写测试仅应在可丢弃、隔离的测试资源上启用。

**PR #42 / #43 的未发布安全收紧：普通 CLI 对外部 API 的主动 PATCH / PUT 均阻断。** 即使显式开启写入、配置 allowlist、field_map 和 `consistency: strong`，缺少可运行的权威状态核验能力仍会在写入前报告 `INCONCLUSIVE`；dry-run 同样显示阻断原因。现有参数和配置继续解析，不能用配置解除这项保护。PUT 完整替换与恢复调用链仅在持有独立实际存储的内部测试夹具中验收，不能据此宣称通用外部 PUT 可安全执行。
内置 `granttrace demo` 通过直接核对它自己持有的可丢弃数据库保留主动演示；普通 HTTP 200、缓存请求头、重复 GET 或一致性声明不能证明新鲜度与恢复成功。
[原独立复核](docs/pr42-independent-review.md) 的风险记录保留；[本次 fail-closed 复核](docs/pr42-state-authority-review.md) 给出两个原始反例、修复证据和兼容性影响。

## Windows 用户：解压后双击体验

**推荐 Windows 10 / 11（64 位），便携包无需安装 Python。** 从官方 [GitHub Release](https://github.com/ysc070528/granttrace/releases/latest) 选择对应版本下载：

1. 下载 Release 中实际提供的 Windows x64 ZIP，将整个 ZIP 解压到一个普通文件夹。v2.5.3 发布后的文件名为 **`GrantTrace-v2.5.3-Windows-x64.zip`**。
2. 打开解压后的文件夹，双击 **`Start-Demo.bat`**；保留旁边的程序和依赖文件。
3. 查看自动打开的 HTML 报告；若未打开，按启动器打印的 HTML 路径手动打开。HTML / JSON 保存在解压目录的 `granttrace-demo/session-*/run-*/`。Demo 只使用内置、可丢弃的 `127.0.0.1` 靶场，结束时关闭靶场并核验数据恢复。

不要直接在 ZIP 内运行启动器。便携包版本以包内 `README.txt` 和 `.\granttrace.exe --version` 为准；程序、启动器和报告在解压目录内使用，不需要修改系统 PATH。维护者的构建与验收步骤见 [Windows 便携包说明](docs/windows-portable.md)。

Windows 便携程序尚未进行代码签名，部分系统可能显示 Microsoft Defender SmartScreen 或“发布者未知”提示。请只从官方 GitHub Release 下载，并使用同一 Release 的 **`SHA256SUMS.txt`** 核对完整性。

## macOS / Linux 用户：使用 Python 安装

需要 **Python 3.9+**；当前不提供 macOS / Linux standalone binary，Windows ZIP 仅适用于 Windows。
已有 Python 的 Windows 用户也可沿用此方式：

```bash
python -m pip install --upgrade granttrace
granttrace --version
granttrace demo
```

[Python 五分钟体验](#五分钟体验) · [完整示例报告](https://github.com/ysc070528/granttrace/blob/main/examples/sample_report.html) · [配置指南](https://github.com/ysc070528/granttrace/blob/main/docs/configuration.md) · [命令行与迁移](https://github.com/ysc070528/granttrace/blob/main/docs/advanced.md) · [验收记录](https://github.com/ysc070528/granttrace/blob/main/VERIFICATION.md) · [发布自检](https://github.com/ysc070528/granttrace/blob/main/docs/release-checklist.md)

## 为什么是 GrantTrace / Why GrantTrace

- **Compare identities**：比较 Owner / Visitor / Anonymous 等身份访问同一资源的结果。
- **Verify real side effects**：内部演示将读回与自己持有的实际数据库核对；普通 GET、HTTP 200 或一致性声明不构成权威实际状态证据。
- **Restore safely**：内部主动测试使用显式 allowlist、完整原始快照及权威恢复核验；恢复失败或无法核验时停止该 auditor 后续写入。

## 10 秒看懂 GrantTrace

```mermaid
flowchart TD
    A["OpenAPI Spec + Owner / Visitor / Anonymous"] --> B["GrantTrace"]
    B --> C["只读身份差异比较（默认）"]
    C --> R["HTML / JSON（可选 SARIF）"]
    B -->|内部可丢弃存储具备权威核验| W["主动写测试"]
    W --> D["读回与独立实际存储核对"]
    D --> E["恢复与权威核验"]
    E --> R
```

<img src="https://raw.githubusercontent.com/ysc070528/granttrace/main/docs/assets/report-preview.png" alt="GrantTrace 报告：身份访问摘要、修复建议和端点筛选" width="900">

## 五分钟体验

使用上方 Windows 启动器或 Python 安装命令，即可体验内置 `granttrace demo`。

安装后可在任意目录运行，无需 clone、准备配置、另开终端或访问外部 API。Demo 自动启动动态端口的 `127.0.0.1` 靶场，比较身份访问、演示 BOLA / IDOR 与 Mass Assignment，并通过独立读回与恢复核验展示 PATCH 测试证据。**主动写操作仅发生在内置、可丢弃的本机靶场**；demo 不接受外部 target 或用户凭据，结束时关闭靶场。

HTML / JSON 报告保留在当前目录的 `granttrace-demo/` 唯一子目录，终端会输出绝对路径，不覆盖已有报告。可选用 `granttrace demo --output-dir PATH` 指定报告父目录，或 `granttrace demo --read-only` 仅体验只读身份访问，发送 **0 PATCH**。

完整离线示例：[HTML 报告](https://github.com/ysc070528/granttrace/blob/main/examples/sample_report.html)（下载后用浏览器打开）与 [JSON 结果](https://github.com/ysc070528/granttrace/blob/main/examples/sample_result.json)。

## 接入自己的 API

推荐按以下顺序首次接入；前四步只处理本地文件：

1. **生成草稿和清单**：

```bash
granttrace --spec your-openapi.yaml --init-config config.local.json
```

2. **人工填写并核对**：打开配置和 checklist，填写不同的 Owner / Visitor 测试账户、可丢弃资源与业务授权预期。候选 PATCH 字段和 GET 路径只是接口合同提示；确认所需读回映射，删除不用的读回草稿，替换全部 `__GRANTTRACE_INPUT__:` 占位值，最后移除 `_granttrace_draft`。草稿未完成时会阻止验证、计划与扫描；`write_allowlist` 默认为空。

3. **离线验证配置与规范**，检查终端中的 scope、模式、警告和下一步：

```bash
granttrace --spec your-openapi.yaml --config config.local.json --validate-config
```

4. **生成并人工检查本地计划**；dry-run 发送 **0 请求**：

```bash
granttrace --spec your-openapi.yaml --config config.local.json --dry-run --export-json plan.local.json
```

5. **第一次真实扫描保持只读**：确认计划后，将下例地址替换为已授权的测试目标；这一步会发送读取请求，默认 **0 PATCH**。

```bash
granttrace --spec your-openapi.yaml --target https://authorized-test.example \
  --config config.local.json --export-json result.local.json
```

6. **当前外部 API 保持只读**：普通 CLI 没有通用权威状态核验能力。添加 `--allow-write-tests`、`write_allowlist` 或独立 GET readback 均不能解除外部 PATCH / PUT 的写前阻断。需要主动演示时使用自己持有可丢弃存储的内置 `granttrace demo`。

OpenAPI 和离线验证不能证明资源归属、业务授权策略、合法测试权限、生产读回一致性或实际恢复能力；检查通过只代表配置结构及支持的语义通过当前检查。账户、API Key / Cookie、合法共享和管理员访问见 [配置指南](https://github.com/ysc070528/granttrace/blob/main/docs/configuration.md)，输出与自动化兼容性见 [命令行说明](https://github.com/ysc070528/granttrace/blob/main/docs/advanced.md)。支持的数组、布尔值及 `style` / `explode` 编码见 [参数规则](https://github.com/ysc070528/granttrace/blob/main/docs/parameter-serialization.md)。接入实测前请核对 [安全边界](https://github.com/ysc070528/granttrace/blob/main/SECURITY.md)。

当前分支新增的只读证据配置位于原有 `bola` 按操作配置中。例如：

```json
{
  "bola": {
    "GET /admin/settings": {
      "private_data_paths": ["settings.secret_name"],
      "required_role": "administrator",
      "owner_role": "administrator",
      "visitor_role": "reader"
    },
    "GET /orders": {"private_data_paths": ["[0].private_note"]}
  }
}
```

`private_data_paths` 是操作员对所选 Owner 实际值的私有性声明，须先人工核对，不从字段名或 Owner ID 自动推断。路径须指向非空字符串或有限数值；布尔值、null、空值不能作为 Owner 私有数据证据。配置后还须取得有效 Owner 基线并在未授权响应中精确匹配对应私有值，才可确认泄漏。匿名检测遵循 OpenAPI 全局 `security`、操作级覆盖和匿名访问备选项。BFLA 另需明确所需角色、有效特权基线及不含业务数据的匿名拒绝；Owner 不自动表示管理员，管理路径关键词只产生候选线索。集合响应缺少 Owner ID、仅返回不同数据或未匹配某个私有路径，都不能单独证明隔离，证据不足时为 `INCONCLUSIVE`。

一个端点可产生多个检测项和多个确认漏洞。请求尝试覆盖率按唯一操作计数；确定性覆盖率要求该操作每种已选主检查均有确定结论，不能用一次匿名拒绝掩盖同一端点的集合 BOLA 证据不足。确认数量按确认检测项计数；这些比例不是系统总体安全率。

## SARIF 导出

`--export-sarif PATH` 可与 HTML / JSON 同时使用。启动下方仓库 mock 后，在明确授权、可丢弃的本机靶场执行；此命令会发送读取请求，默认 **0 PATCH**：

```bash
granttrace --spec openapi.json --target http://127.0.0.1:8080 --config config.example.json \
  --export-json result.local.json --export-sarif granttrace.sarif -o report.html
```

SARIF 2.1.0 **只包含 CONFIRMED 的 BOLA / IDOR、Broken Authentication、BFLA 与 Mass Assignment**；SUSPICIOUS / INCONCLUSIVE 不升级为漏洞，完整状态仍见 HTML / JSON。SARIF 始终脱敏且不导出原始响应或 headers，不能与 `--dry-run` 同用；各输出路径须独立。当前工作目录内的真实 OpenAPI spec 会作为相对 artifact location，不伪造源码行号，API endpoint 仍放在 message / properties。在 GitHub Actions 中从 checkout 的仓库根目录运行，再用 `upload-sarif` 上传；workspace 外的 spec 省略 location，绝不导出本机绝对路径，其结果无法展示为 GitHub Code Scanning alert。详见 [兼容说明](https://github.com/ysc070528/granttrace/blob/main/docs/advanced.md#sarif-导出)。

## cURL 复现模板

HTML 确认漏洞卡片可提供安全的 POSIX shell cURL 模板和“复制 cURL”按钮。认证值均为 Visitor 占位符；匿名访问模板省略凭据，即使使用 `--include-sensitive-evidence` 也不会放入真实认证值。PUT 暂不生成复现模板：仅包含注入字段的局部请求会删除完整替换资源中的其余字段。请只在明确授权的测试环境中填入自己的测试凭据；脱敏值需人工补全，信息不足时不提供按钮。离线报告支持复制 fallback，也可直接选择命令文本。详见 [复现说明](https://github.com/ysc070528/granttrace/blob/main/docs/advanced.md#curl-复现模板)。

## 从源码开发 / 运行仓库 mock

需要查看源码或手工运行仓库靶场时：

```bash
git clone https://github.com/ysc070528/granttrace.git
cd granttrace
python -m pip install -e .
python mock_server/server.py
```

另开终端，进入同一目录执行首次只读扫描：

```bash
granttrace --spec openapi.json --target http://127.0.0.1:8080 --config config.example.json --export-json result.local.json
```

用浏览器打开默认生成的 **`granttrace_report.html`**：先查看发现与修复建议，再按状态筛选检查项、展开证据。两个 PATCH 因默认只读而跳过；检测项数量与覆盖率取决于本分支所选证据策略，以实际 HTML / JSON 为准。JSON 结果写入 `result.local.json`；两个本地产物均由 `.gitignore` 忽略。

即使对手工启动的本机 mock 添加写入开关，普通 CLI 仍缺少权威状态核验能力：

```bash
granttrace --spec openapi.json --target http://127.0.0.1:8080 --config config.example.json --allow-write-tests --export-json result.local.json
```

再次打开 **`granttrace_report.html`**，允许清单内的主动检查应在写前被阻断为 `INCONCLUSIVE`，不能取得已验证恢复的声明。本次扫描更新同名 HTML / JSON 文件。需要包含实际存储核验的主动 PATCH 演示时运行 `granttrace demo`。

## 验证与边界

当前能力、未检测场景、覆盖率口径与维护验收对比见 [2.5.x 检测能力审计](docs/authorization-coverage-audit.md)。
该记录区分确认漏洞、可疑线索和安全阻断，并评估尚未实现的相邻授权能力。

```bash
python -m unittest discover -s tests
python scripts/verify_business_scenarios.py
python scripts/verify_install.py
```

测试直接使用仓库中的 `config.example.json`，无需创建本地凭据文件。[业务场景验收](https://github.com/ysc070528/granttrace/blob/main/docs/business-scenarios.md) 单独记录团队共享、管理员读取、跨租户拒绝和故意越权的真值、误报与漏报；[验收记录](https://github.com/ysc070528/granttrace/blob/main/VERIFICATION.md) 标明实际测试环境和范围。

“没有确认漏洞”不等于系统安全。检查覆盖率、错误、可疑和不确定项；显式授权预期只适用于本次身份与资源组合。当前普通外部 PATCH / PUT 主动测试保持阻断，内部夹具的权威观察能力不能泛化到外部 API。远程 `$ref`、GraphQL、gRPC、自动 OAuth / mTLS 登录和 POST 主动测试尚未实现；缺少明确私有值或角色边界的匿名 / BFLA 确认、无充分 Owner 基线的集合隔离结论也不支持。更多规则与迁移说明见 [操作指南](https://github.com/ysc070528/granttrace/blob/main/docs/advanced.md)。

Apache License 2.0。
