# 命令行、结果与迁移

[返回项目首页](../README.md)

## 常用参数

| 参数 | 含义 |
|---|---|
| `--init-config FILE` | 离线生成待填写配置和相邻 checklist；未完成草稿不能扫描 |
| `--validate-config` | 离线执行配置语义校验并退出（合法退出码 0，非法退出码 2），不发送网络请求 |
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

## SARIF 导出

该功能用于源码开发版本，尚未包含在已发布的 v2.4.1 包中；本说明不表示 v2.5 已发布。完成审计后可同时输出 HTML、JSON 与 SARIF：

```bash
granttrace --spec openapi.json --config config.local.json \
  --export-json result.local.json --export-sarif granttrace.sarif -o report.html
```

- 仅精确为 `CONFIRMED` 的现有 BOLA / IDOR 与 Mass Assignment 结果进入 SARIF；SECURE、PUBLIC、AUTHORIZED、SKIPPED、SUSPICIOUS、INCONCLUSIVE、ERROR 不生成漏洞 result，也不改变原判定。
- BOLA / IDOR 映射为 `GT-BOLA-001` / `CWE-639`，Mass Assignment 映射为 `GT-MASS-001` / `CWE-915`，当前确认漏洞的 SARIF level 均为 `error`。没有确认漏洞时仍生成合法的 `results=[]`。
- 始终使用现有脱敏能力清理已知凭据，与 `--include-sensitive-evidence` 无关。只保留固定规则信息、可安全表达的 API endpoint 和 HTTP(S) target origin；不复制原始响应、headers、请求 payload 或任意 evidence。无法证明安全的动态字段直接省略。
- 不构造源码文件、行号或 `physicalLocation`。SARIF-compatible tooling 可读取此格式；[GitHub Code Scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) 要展示告警需要位置，本轮不提供源码映射，不能保证 API 结果上传后显示为源码告警。
- `--dry-run --export-sarif` 返回退出码 2，不生成 SARIF，也不发送请求。配置草稿生成与离线配置校验同样不能导出 SARIF。
- SARIF 路径不得与 HTML / JSON 输出或 spec / config 输入重合。缺失的输出父目录沿用现有逻辑创建；写入失败返回退出码 2、不打印 traceback 或成功提示，已完成的 HTML / JSON 输出保留。

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
