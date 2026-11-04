# 参数编码

[返回项目首页](../README.md)

配置参数值保留 JSON 类型。`[10, 20]` 使用规范声明的数组格式，`true` / `false` 使用小写，不会发送 Python 列表或布尔文本。业务路径、参数名与值分别编码，值中的 `&`、`/`、逗号等不应改变所选参数或资源。

| 规范 | 位置 | 支持格式 |
|---|---|---|
| OpenAPI 3.x | path | `simple`、`label`、`matrix`，标量、数组及平面对象，按 `explode` 处理 |
| OpenAPI 3.x | query | `form`；数组的 `spaceDelimited`、`pipeDelimited`；平面对象的 `deepObject` |
| OpenAPI 3.x | header | 标量、数组及平面对象（RFC 7230 token 名称，`simple` 样式；数组无论 `explode` 均为逗号分隔；对象 `explode: false` 为 `k1,v1,k2,v2`，`explode: true` 为 `k1=v1,k2=v2`；严格防范 CRLF、分隔符歧义与非法字符） |
| OpenAPI 3.x | cookie | 仅支持标量（RFC 6265 token 名称，`form` 样式；数组及对象因 RFC 6265 语法限制与歧义明确拒绝；严格防范 CRLF、控制字符、分号与分隔符注入） |
| Swagger 2.0 | path / query | 标量；数组的 `csv`、`ssv`、`tsv`、`pipes`；`multi` 仅 query |
| Swagger 2.0 | header | 标量；数组的 `csv`（RFC 7230 token 名称，仅支持 `collectionFormat: csv`，严格防范 CRLF 与非法字符；不支持非 body 对象） |

示例：query `form` 数组 `[10,20]` 在 `explode: true` 时为 `ids=10&ids=20`，在 `explode: false` 时为 `ids=10,20`（线上可见编码后的分隔符）。标量布尔值为 `enabled=true`。
Header 参数支持标量（如 `X-Request-ID: req-123`）、数组（`simple` 样式，无论 `explode` 均为逗号分隔，如 `X-Roles: admin,reader`）以及平面对象（`explode: false` 时为 `X-Ctx: env,prod,region,us`，`explode: true` 时为 `X-Ctx: env=prod,region=us`）。Swagger 2.0 header 数组仅支持 `collectionFormat: csv`，不支持非 body 对象。
Cookie 参数目前仅支持标量（`form` 样式，如 `session_track=xyz789`）。根据 RFC 6265，Cookie 请求头中的 cookie-value 不允许未转义的逗号（`%x2C`），且 OpenAPI 规范与主流 HTTP 客户端对 Cookie 数组及对象的序列化存在严重分歧与解析歧义：`explode: false` 生成逗号分隔值（如 `ui_features=new_nav,compact`）不符合 RFC 6265 规范语法；`explode: true` 则会生成同名重复 cookie（如 `tags=a; tags=b`）或丢失参数命名前缀导致未命名空间污染与认证 Cookie 冲突。此外，当前尚未实现 OpenAPI 3.2 的 `style: cookie`。因此，所有 Cookie 数组与对象参数（无论 `explode` 为 `true` 还是 `false`）均明确拒绝并记录 `INCONCLUSIVE`，保证零请求发送，绝不静默降级或发送不合规的 HTTP 请求。

安全隔离与合规限制：
- Header / Cookie 业务参数绝不允许覆盖 `Authorization` 等身份认证凭据。若参数与身份 Header 冲突，或与身份 Cookie 名称冲突，检测器会明确阻断（`ParameterSerializationError`），绝不静默覆盖。
- 认证 Header 仅从请求者身份的 `headers` 取得；认证 Cookie 仅从该身份的 `Cookie` Header 或明确的身份参数配置取得，禁止回退到 `common`、平铺共享值或默认值。Owner 与 Visitor 的认证 Cookie 按实际序列化值检查隔离。匿名探测会省略认证 Header / Cookie，即使规范将它们标为 `required: true`；必填普通业务参数缺失仍会在任何请求前记录 `INCONCLUSIVE`，包括 BOPLA 共享读取流程。
- 业务 Header 不得改写 `Host`、`Content-Length`、`Transfer-Encoding`、`Connection`、`User-Agent` 等传输管理字段，冲突按大小写不敏感检查。OpenAPI 3.x 和 Swagger 2.0 中作为普通 Header 参数声明的 `Authorization`、`Accept`、`Content-Type` 均按大小写不敏感忽略；真实认证凭据仍来自各请求者的身份配置。OpenAPI 3.x 明文要求忽略这些声明；Swagger 2.0 的[官方指南](https://swagger.io/docs/specification/v2_0/describing-parameters/#header-parameters)将它们交由 `consumes` / `produces` 和 `securityDefinitions` / `security` 描述。
- 业务 Cookie 与身份 Cookie 安全合并为一条 `Cookie: <auth>; <business>` 请求头。
- 严禁 CRLF 注入（值含 `\r`、`\n`、`\0`）及控制字符；Cookie 值仅接受 RFC 6265 cookie-octet，拒绝空格、双引号、逗号、分号和反斜杠。
- 新增业务 Header / Cookie 参数支持仅限 GET 操作及 GET 读回，不启用新的 PATCH / PUT 写入路径。
- 暂不支持参数 `content` 编码、嵌套或空容器（如 `[]`、`{}`）、包含自身分隔符的数据（如 header 数组项含逗号）、所有 Cookie 数组与对象参数、OpenAPI 3.2 的 `style: cookie`、`allowReserved: true` 以及 Swagger 2.0 cookie 参数或非 body 对象。这些在发起端点请求前明确记录 `INCONCLUSIVE` 和具体原因，不猜测、不静默转成列表文本或遗漏必需参数。缺少必需参数或校验失败时 0 请求发送。不得笼统宣称所有 OpenAPI 3.x 参数组合均已支持。
- `deepObject` 必须显式声明 `explode: true`。账户的 `headers` 仍可提供 Authorization、API Key、Cookie；它们与已声明业务 Header / Cookie 参数的自动序列化受各自的安全隔离保护。

独立读回与被测操作使用相同编码器。读回可在 `readbacks.<operation>.parameters` 中明确提供 GET 参数元数据；请确认所选资源和参数映射的业务含义。

规则来源：[OpenAPI 3.0.3 Parameter Object](https://spec.openapis.org/oas/v3.0.3#parameter-object)、[Swagger 2.0 Parameter Object](https://spec.openapis.org/oas/v2.0#parameter-object)。实现与测试覆盖的是上表列出的子集。
