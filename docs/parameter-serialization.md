# 参数编码

[返回项目首页](../README.md)

配置参数值保留 JSON 类型。`[10, 20]` 使用规范声明的数组格式，`true` / `false` 使用小写，不会发送 Python 列表或布尔文本。业务路径、参数名与值分别编码，值中的 `&`、`/`、逗号等不应改变所选参数或资源。

| 规范 | 位置 | 支持格式 |
|---|---|---|
| OpenAPI 3.x | path | `simple`、`label`、`matrix`，标量、数组及平面对象，按 `explode` 处理 |
| OpenAPI 3.x | query | `form`；数组的 `spaceDelimited`、`pipeDelimited`；平面对象的 `deepObject` |
| OpenAPI 3.x | header | 标量（RFC 7230 token 名称，`simple` 样式，严格防范 CRLF 与非法字符） |
| OpenAPI 3.x | cookie | 标量（RFC 6265 token 名称，`form` 样式，严格防范 CRLF、分号与控制字符） |
| Swagger 2.0 | path / query | 标量；数组的 `csv`、`ssv`、`tsv`、`pipes`；`multi` 仅 query |
| Swagger 2.0 | header | 标量（RFC 7230 token 名称，严格防范 CRLF 与非法字符） |

示例：query `form` 数组 `[10,20]` 在 `explode: true` 时为 `ids=10&ids=20`，在 `explode: false` 时为 `ids=10,20`（线上可见编码后的分隔符）。标量布尔值为 `enabled=true`。Header 参数如 `X-Request-ID: req-123`；Cookie 参数如 `session_track=xyz789`。

安全隔离与合规限制：
- Header / Cookie 业务参数绝不允许覆盖 `Authorization` 等身份认证凭据。若参数与身份 Header 冲突，或与身份 Cookie 名称冲突，检测器会明确阻断（`ParameterSerializationError`），绝不静默覆盖。
- 认证 Header 仅从请求者身份的 `headers` 取得；认证 Cookie 仅从该身份的 `Cookie` Header 或明确的身份参数配置取得，禁止回退到 `common`、平铺共享值或默认值。Owner 与 Visitor 的认证 Cookie 按实际序列化值检查隔离。匿名探测会省略认证 Header / Cookie，即使规范将它们标为 `required: true`；必填普通业务参数缺失仍会在任何请求前记录 `INCONCLUSIVE`，包括 BOPLA 共享读取流程。
- 业务 Header 不得改写 `Host`、`Content-Length`、`Transfer-Encoding`、`Connection`、`User-Agent` 等传输管理字段，冲突按大小写不敏感检查。OpenAPI 3.x 中 `Authorization`、`Accept`、`Content-Type` Parameter Object 的既有忽略规则保持不变。
- 业务 Cookie 与身份 Cookie 安全合并为一条 `Cookie: <auth>; <business>` 请求头。
- 严禁 CRLF 注入（值含 `\r`、`\n`、`\0`）及控制字符；Cookie 值仅接受 RFC 6265 cookie-octet，拒绝空格、双引号、逗号、分号和反斜杠。
- 新增业务 Header / Cookie 参数支持仅限 GET 操作及 GET 读回，不启用新的 PATCH / PUT 写入路径。
- 暂不支持参数 `content` 编码、嵌套或空容器、Header/Cookie 复杂数组或对象、分隔符歧义、`allowReserved: true` 以及 Swagger 2.0 cookie 参数。这些在发起端点请求前明确记录 `INCONCLUSIVE` 和具体原因，不猜测、不静默转成列表文本或遗漏必需参数。缺少必需参数时 0 请求发送。
- `deepObject` 必须显式声明 `explode: true`。账户的 `headers` 仍可提供 Authorization、API Key、Cookie；它们与已声明业务 Header / Cookie 参数的自动序列化受各自的安全隔离保护。

独立读回与被测操作使用相同编码器。读回可在 `readbacks.<operation>.parameters` 中明确提供 GET 参数元数据；请确认所选资源和参数映射的业务含义。

规则来源：[OpenAPI 3.0.3 Parameter Object](https://spec.openapis.org/oas/v3.0.3#parameter-object)、[Swagger 2.0 Parameter Object](https://spec.openapis.org/oas/v2.0#parameter-object)。实现与测试覆盖的是上表列出的子集。
