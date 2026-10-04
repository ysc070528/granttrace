# 命令行、结果与迁移

[返回项目首页](../README.md)

## 常用参数

| 参数 | 含义 |
|---|---|
| `--init-config FILE` | 离线生成待填写配置和相邻 checklist；未完成草稿不能扫描 |
| `--validate-config` | 离线检查配置并退出（检查通过含 warning 返回 0，错误返回 2），不发送网络请求 |
| `--allow-write-tests` | 开启允许清单内的 PATCH 写入、读回和回滚检查 |
| `--write-endpoint "PATCH /path"` | 将主动检查限制到指定 PATCH 端点，可重复使用 |
| `--insecure` | 关闭 TLS 证书校验，仅用于隔离测试环境 |
| `--allow-http` | 允许访问非本机的明文 HTTP 目标 |
| `--delay` | 所有线程共享的最小请求间隔 |
| `--max-response-bytes` | 单个响应允许读取的最大字节数 |
| `--fail-on-vuln` | 确认漏洞时返回退出码 1 |
| `--fail-on-error` | 存在错误、不确定结果或零确定性检查时返回退出码 2 |
| `--fail-on-suspicious` | 存在可疑结果时返回退出码 2 |
| `--min-coverage 80` | 确定性端点覆盖率低于指定百分比时返回退出码 2 |
| `--dry-run` | 只展示本地计划，不向目标发送请求；可用 `--export-json` 导出 |
| `--export-sarif PATH` | 导出 SARIF 2.1.0，仅包含 CONFIRMED 漏洞；不能与 dry-run 同用 |
| `--include-sensitive-evidence` | 在报告中保留敏感字段；默认关闭 |

## 首次接入与终端引导

沿用现有 `--init-config`、`--validate-config`、`--dry-run`，完整填写流程见 [配置指南](configuration.md#推荐首次接入流程)。生成草稿后，终端保留配置与 checklist 成功路径，并补充人工核对、默认空允许清单和离线下一步提示。草稿仍有 `_granttrace_draft` 或 `__GRANTTRACE_INPUT__:` 时不能用于验证、计划或扫描。以下节选展示 POSIX 平台的引导输出；路径随实际输入变化：

```text
[SAFE DEFAULT] write_allowlist is empty. No active PATCH test has been authorized.
[NOTE] Local-only preparation: no requests were sent.
[NEXT] Validate offline:
       granttrace --spec your-openapi.yaml --config config.local.json --validate-config # POSIX shell
[NEXT] After validation, inspect the local plan:
       granttrace --spec your-openapi.yaml --config config.local.json --dry-run --export-json plan.local.json # POSIX shell
```

OpenAPI 中的候选 PATCH 字段与 GET 路径只是合同提示。工具不推断身份、资源归属、允许访问策略、readback 一致性或写入权限；验证成功也不能证明这些业务事实或目标上的恢复能力。

### 离线验证的两种范围

显式指定 `--spec` 时，检查配置与选定 OpenAPI 规范；指定文件无法加载则失败。未指定 `--spec` 而当前目录有默认 `openapi.json` 时，仍使用该默认规范。只有未选择规范且不存在默认文件时，才保留 config-only validation：

```bash
# Spec-aware：同时检查配置与规范
granttrace --spec your-openapi.yaml --config config.local.json --validate-config

# Config-only：在没有默认 openapi.json 的目录中运行
granttrace --config config.local.json --validate-config
```

spec-aware 成功提示说明配置和选定规范共同参与检查；config-only 成功提示明确没有执行 operation/spec 交叉检查，下一步只要求显式提供 `--spec` 重新验证，不直接推荐扫描。两者都不发送请求。成功输出仍保留 Identities、Write allowlist、Readbacks、Parameter values、BOLA policies 的原有数量；新增 scope 和模式说明只描述当前检查范围与配置状态。

```text
[OK] Offline configuration validation passed.
[SCOPE] Configuration + selected OpenAPI specification were checked together: your-openapi.yaml

[OK] Configuration-only validation passed.
[NOTE] No OpenAPI specification was selected; operation/spec cross-checking was not performed.
```

`write_allowlist` 为空时，模式提示推荐只读首次接入；非空时显示允许清单和读回数量，明确主动 PATCH 配置仍不生效，直到真实扫描单独提供 `--allow-write-tests`。离线检查不证明资源归属、预期授权策略、合法测试权限、生产 readback 一致性或真实回滚安全。

warning 仍逐项显示；没有 error 时，即使有 warning 也返回 0，并提示 warning 数量。失败时继续显示具体 `Path`、`Reason`、`Expected`、`Actual`、`Tip`，随后汇总 error / warning 数量，下一步只建议修复并重新验证，不推荐直接扫描。

### 本地计划与首次真实扫描

```bash
granttrace --spec your-openapi.yaml --config config.local.json --dry-run --export-json plan.local.json
```

dry-run 根据本地规范和配置生成现有计划 JSON，发送 **0 请求**；不会进行 DNS/连接探测、登录、凭据刷新、GET 或 PATCH。新增 stderr 摘要由 `operations` 统计，示意如下：

```text
[PLAN] Local-only dry run complete.
[PLAN] Requests sent: 0 (no GET, PATCH, login, DNS or connectivity probe).
[PLAN] Operations: 5
[PLAN] BOLA checks: 3
[PLAN] Mass Assignment checks: 2
[PLAN] Write-enabled operations in this plan: 0
[MODE] Read-only plan: no active PATCH testing is enabled.
```

同时存在允许清单与 `--allow-write-tests`，且计划条目的 `writes_enabled` 为 true 时，stderr 显示 `[CAUTION]`：dry-run 本身仍发送 0 请求，但对应 PATCH 在真实扫描中会获得主动测试资格。必须继续人工核对专用可丢弃资源、独立 GET readback、`field_map`、一致性和恢复预期；计划不证明运行时条件满足。

无论允许清单是否为空、当前 dry-run 是否带写开关，下一步始终推荐不带 `--allow-write-tests` 的首次只读真实扫描：

```bash
granttrace --spec your-openapi.yaml --target https://authorized-test.example \
  --config config.local.json --export-json result.local.json
```

终端使用 `<AUTHORIZED_TARGET_URL>` 提醒人工填入已授权目标，不从配置猜测地址。真实扫描会发送读取请求；写模式仍是之后需要显式选择的独立决定。

### 输出与自动化兼容性

原有 flag 和退出码保持不变，不新增 onboarding 子命令。新增 NEXT / NOTE / SAFETY / CAUTION / PLAN 引导优先写入 **stderr**；原有 banner、成功结果与 dry-run stdout 行为保留，stdout 并非保证只有 JSON。自动化读取计划应继续使用 `--export-json`，导出文件只含原有计划 JSON，不混入终端提示，不改变 JSON 结构。

| 结果 | 退出码 |
|---|---|
| 配置检查通过，含只有 warning 的情况 | `0` |
| 配置检查失败 | `2` |
| dry-run 计划生成成功 | `0` |
| CLI 参数使用无效 | `2` |

成功退出码只说明当前离线检查或计划生成完成。现有扫描自动化仍可组合 `--fail-on-error`、`--fail-on-vuln`、`--fail-on-suspicious`、`--min-coverage`，其含义不变。

引导只展示数量、状态、固定提示和文件路径，不展示 token、Cookie、API key、自定义认证值、资源 ID、payload 或原始 readback 对象。NEXT 命令用于显示，POSIX 使用 `shlex.join`；Windows 使用 **PowerShell 7** 的 `&` 调用运算符和单引号字面量，重复转义 ASCII 单引号及智能单引号，不使用 cmd.exe 格式。每条可复制命令末尾的 `# POSIX shell` / `# PowerShell 7` 是 shell 注释，标明对应终端。例如 Windows 输出：

```powershell
& 'granttrace' '--spec' 'API specs/中文.yaml' '--config' 'config.local.json' '--validate-config' # PowerShell 7
```

路径显示继续脱敏并转义控制字符，避免文件名伪造日志行。NEXT 命令遇到控制字符时用 `<PATH_WITH_CONTROL_CHARACTERS>` 替代该参数；路径包含被识别为凭据、需要脱敏的片段时，用 `<PATH_REQUIRING_MANUAL_INPUT>` 替代。占位路径和 `<AUTHORIZED_TARGET_URL>` 都需先按实际位置与授权范围手工补全；不能直接当作真实路径或目标执行。

## SARIF 导出

该功能用于源码开发版本，尚未包含在已发布的 v2.4.1 包中；本说明不表示 v2.5 已发布。完成审计后可同时输出 HTML、JSON 与 SARIF：

```bash
granttrace --spec openapi.json --config config.local.json \
  --export-json result.local.json --export-sarif granttrace.sarif -o report.html
```

- 仅精确为 `CONFIRMED` 的现有 BOLA / IDOR 与 Mass Assignment 结果进入 SARIF；SECURE、PUBLIC、AUTHORIZED、SKIPPED、SUSPICIOUS、INCONCLUSIVE、ERROR 不生成漏洞 result，也不改变原判定。
- BOLA / IDOR 映射为 `GT-BOLA-001` / `CWE-639`，Mass Assignment 映射为 `GT-MASS-001` / `CWE-915`，当前确认漏洞的 SARIF level 均为 `error`。没有确认漏洞时仍生成合法的 `results=[]`。
- 始终使用现有脱敏能力清理已知凭据，与 `--include-sensitive-evidence` 无关。只保留固定规则信息、可安全表达的 API endpoint 和 HTTP(S) target origin；不复制原始响应、headers、请求 payload 或任意 evidence。无法证明安全的动态字段直接省略。
- 使用 `core.models.parse_operation_key` 验证 canonical OpenAPI operation key，再用现有脱敏函数处理已知凭据。`GET /users/{id}`、`GET /sessions/{id}`、`POST /api/token/introspect`、`GET /api/credentials/{id}` 等合法路由均保留，不按路由名称猜测本机路径或凭据；query / fragment 等非法 operation key 不导出。
- 当前工作目录作为 artifact workspace。真实 OpenAPI spec 经路径解析后仍位于 workspace 内时，CONFIRMED result 增加 `locations[].physicalLocation.artifactLocation.uri`，例如 `openapi.yaml` 或 `specs/api.yaml`；URI 使用相对路径和必要的百分号编码，不添加虚假的 `startLine` / `startColumn`，也不把 API endpoint 当成源码文件。指向 workspace 外的符号链接同样不导出 location。
- 在 GitHub Actions 中从 checkout 的仓库根目录运行 GrantTrace，再用 `github/codeql-action/upload-sarif` 上传结果，spec 应是已提交到仓库的文件。[GitHub Code Scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) 可使用该 artifact location 关联真实 spec。workspace 外部、缺失或无法安全表示的 spec 省略 location，不泄漏绝对本机路径；该类结果仍保留在 SARIF 中，但无法展示为 GitHub Code Scanning alert。
- `--dry-run --export-sarif` 返回退出码 2，不生成 SARIF，也不发送请求。配置草稿生成与离线配置校验同样不能导出 SARIF。
- SARIF 输出路径不得为空、纯空白或包含 NUL 等控制字符，以上情况在创建 auditor 或发送请求前返回退出码 2。路径也不得与 HTML / JSON 输出或 spec / config 输入重合。缺失的输出父目录沿用现有逻辑创建；写入失败返回退出码 2、不打印 traceback 或成功提示，已完成的 HTML / JSON 输出保留。

## cURL 复现模板

当前源码开发功能，尚未包含在已发布的 v2.4.1 包中，不表示 v2.5 已发布。HTML 的确认漏洞卡片可提供 **cURL 复现模板（请填入授权测试凭据）**，只用于明确授权的测试环境：

- 只为能够安全表达的 CONFIRMED BOLA / IDOR 和 Mass Assignment 生成；普通端点结果行及其他 verdict 不添加按钮。模板使用实际测试 URL 和 canonical operation，不猜测资源 ID 或请求参数。
- 认证来自 Visitor 的有效 header 形状，全部转换为占位符，例如 `Authorization: Bearer <VISITOR_TOKEN>`、`Authorization: Basic <VISITOR_CREDENTIAL>`、`X-API-Key: <VISITOR_X_API_KEY>`、`Cookie: <VISITOR_COOKIE>`。自定义 header 的值同样是占位符；原值不会作为模板元数据传给报告层，`--include-sensitive-evidence` 不能解除这个边界。
- PATCH 只使用重新脱敏的已确认注入字段和实际请求 Content-Type，保留 `application/merge-patch+json`。模板不复制 snapshot、rollback payload、恢复数据或响应；无法可靠表达的嵌套/数组字段、缺失或不安全元数据会省略模板。
- URL 凭据、query 值、fragment 和已知 secrets 按现有规则处理；部分值脱敏时会提示人工补全测试值。模板针对 POSIX shell，对参数使用 shell quoting，并关闭 cURL URL glob；不适合作为 PowerShell 命令直接粘贴。
- 命令以 escaped HTML 文本保存在 `<pre>`，按钮通过 `textContent` 读取。优先用浏览器 Clipboard API；在 `file://` 等不可用或失败场景尝试临时 textarea 复制。失败时显示“复制失败，请手动选择”，搜索/筛选继续工作；无 JavaScript 时仍可手动选择模板。
- 主动 PATCH 复现前应自行保存原状态并准备独立 readback、恢复与恢复验证；单条 cURL 模板不会自动执行 GrantTrace 的完整恢复流程。

## 结果解释

本次 JSON 报告 `report_schema_version` 为 2，新增 `AUTHORIZED` 状态及业务授权预期证据。处理状态枚举的外部程序需同时支持该值。

- `CONFIRMED`：证据满足确认条件。
- `SECURE`：本次读取检查得到可信拒绝，或全部配置写字段在强一致读回中均未持久化；不是整个系统安全的保证。
- `PUBLIC`：明确声明公开、不要求鉴权，且三种身份的完整 JSON 数据一致。
- `AUTHORIZED`：当前身份与所选资源按显式业务授权预期获得访问；结论只适用于本次配置组合。
- `SUSPICIOUS`：观察到异常，但不足以确认漏洞。
- `INCONCLUSIVE`：缺少有效资源、读回、凭证或其他必要证据。
- `SKIPPED`：当前模式未执行该检查。
- `ERROR`：网络、服务端、配置、回滚或程序错误。

“没有确认漏洞”不等于目标系统安全。报告中的尝试覆盖率、确定性覆盖率、错误和不确定项必须一起查看。

## v2.2 配置与迁移说明

先用只读模式或本地计划核对范围：

```bash
granttrace --spec openapi.json --config config.json --dry-run --export-json plan.json
```

- 显式 CLI `--write-endpoint` **替换**配置允许清单，不会扩大它；操作路径区分大小写。干跑退出码 0 只代表本地计划生成成功，不是扫描通过。
- CI 可同时使用 `--fail-on-error --fail-on-vuln --fail-on-suspicious --min-coverage 80`；阈值按期望检查范围设置。错误门槛优先返回 2，漏洞门槛返回 1。空规范、全部不支持的检查不能通过错误门槛。
- 身份比较基于最终发送的认证头，头名称忽略大小写；token 覆盖 Authorization。trace 头不算认证。自定义认证头需用 `auth_header_names: ["X-Session"]`，或在规范 header API Key 安全方案中声明。
- `consistency: "strong"` 是操作者对读回接口的约定，不是工具自动证明的属性；确认读回绕过缓存并反映已提交状态后才能设置。未设置时，未观察到修改归为 INCONCLUSIVE，不能为了通过 CI 随意声明。
- baseline_payload 只选择额外字段，其业务值取自写前读快照，不再发送生成器的示例值。无法快照的字段不会写入。
- 嵌套字段支持 `members[0].role`。工具发送和恢复完整的 members 容器；读回包装不一致时，可配置 `snapshot_path: "data"` 或 `snapshot_field_map: {"members": "data.team"}` 映射请求根字段。
- 恢复核验默认比较**完整读回文档**，会发现请求字段以外的派生权限变化。对已知无安全影响的时间戳可配置 `ignore_readback_paths: ["updatedAt"]`；禁止忽略任何实际写入字段/容器。不要忽略权限、派生权限或业务状态；无法恢复的变动会停写并要求人工处置。
- 公开接口需显式 `security: []`，或在 bola 策略中设置 expected_public: true；这不能覆盖规范已声明的鉴权要求。403 正文含业务数据、历史日志中的拒绝词、匿名公开投影之外的私有增量，均不被误当作安全。
- 默认不把任意 *_id 视为资源归属证据。仅在确认业务含义后配置 `{"bola": {"GET /records/{id}": {"resource_id_paths": ["data.id"]}}}`；支持 items[].id，已知请求回显/metadata/trace 路径始终排除。
- OpenAPI 3.1 schema $ref siblings 分别按来源解析、按约束交集处理；3.0/Swagger 结构性 siblings 明确拒绝，请改写为 allOf。缺失引用不再静默转成空 schema。
- readOnly 特权字段仍属于攻击候选，但普通基线不包含 readOnly。生成器递归验证样本，无法合成的复杂 schema 显式失败，不以非法样本证明安全。
- 默认省略非 JSON、损坏/截断的正文，仅保留摘要；URL 查询值、错误文本、camelCase 密钥、已知凭据也会清理。任意业务自由文本无法保证完全脱敏，报告仍是敏感资料。
- 本工具不是数据库事务：强制终止进程、并发业务修改、迟到异步任务、通知/邮件/审计日志，以及读回未暴露的状态无法通用撤销。必须使用专用、可丢弃且隔离的测试资源。
