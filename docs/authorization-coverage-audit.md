# GrantTrace 2.5.x 检测能力审计与维护验收

> 后续维护更新：本文件保留当时的风险与原始统计，不代表最新验收。两个无标记缓存反例已在后续修改中采用发送 PATCH 前阻断的方式处理；普通 CLI 外部写测试因此暂停。详见 [本次状态权威性复核](pr42-state-authority-review.md)。

审计日期：2026-10-26。后续独立复核、统计口径纠正及未解决反例见 [PR #42 独立复核](pr42-independent-review.md)。基线为 `80c7202fdfd203e298a924bf77e5c154671123ff`。
本轮检查真实源码、现有测试、离线计划、报告边界，并执行本机可丢弃 HTTP 测试。
未连接生产 API、未执行 crAPI 扫描、未重新验收 Windows 实机便携包；本报告不外推生产检出率。
版本号维持 2.5.3，当前变更供下一次 2.5.x 维护发布评审，不代表已发布。

## 1. 结论与优先级

最紧急的问题是 PATCH 状态证据可靠性：非权威的成功响应曾可用于建立快照、跳过恢复或宣称恢复成功。
真实 HTTP 反例复现了资源仍为修改状态、结果却是 `SECURE` / `rollback_verified=true`。
其余已修复项是错误正文中的资源泄露线索丢失、普通名称的显式 readOnly 字段漏选、Swagger 2 JSON 格式错选，以及计划解释不足。

| 优先级 | 项目 | 本轮处理 | 依据 |
|---|---|---|---|
| P0 | 写前、写后、恢复后读回不能接受任意 2xx / Content-Range | 已修复；不可信写前快照不发 PATCH；恢复不可证则停止后续写测试 | [auditor.py:723 `_json_object`][a-object]、[927 `_rollback_and_verify`][a-rollback]、[952 `_execute_patch_case`][a-execute] |
| P1 | 400/404/500 等正文中的明确 Owner 资源线索被压为不确定 | 已修复；仅 `SUSPICIOUS`，保留确认门槛 | [diff.py:768 `evaluate_bola`][d-evaluate] |
| P1 | 非权限命名但显式 readOnly 字段未成为候选 | 已修复，含嵌套和数组字段；实际执行仍须选入 field_map | [generator.py:920 `_iter_privilege_fields`][g-fields] |
| P1 | Swagger 2 consumes 第一项为 XML，后面 JSON 未选用 | 已修复，优先已声明的 JSON；不会新增任何端点或方法 | [parser.py:397/408 内容格式选择][p-body] |
| P1 | 离线计划未解释部分必然不执行的 GET / 未实现方法 | 已补充已有 reason / reason_category，不改变结果状态或覆盖率定义 | [auditor.py:1251 `build_plan`][a-plan] |
| P2 | 缺少 self 基线时提供更有用、仍不能确认的线索 | 待决，需证明 Owner 特异性及排除永远返回当前账户的接口 | [diff.py:608 `_build_evidence`][d-evidence] |
| P2 | 更多 header/cookie 编码、分页、版本完整校验、路由性能、配置复用 | 待决，需要独立合同、样例和基准；不得取消安全限制 | [auditor.py:404 `_build_url`][a-url]、[parser.py:70 `_detect_version`][p-version]、[307 `_read_request_risk`][a-risk] |
| 待评估 | BFLA、字段读取策略、多角色矩阵 | 仅评估；本轮未加入这些检测器 | 第 8 节 |

## 2. 检测覆盖能力矩阵

以下位置均链接到基线的准确代码；维护变更见 PR diff。每项区分“解析得到接口”和“实际检测接口”，两者不等价。

| 能力 | 当前支持 | 边界、盲区与可能误判 | 真实代码证据 |
|---|---|---|---|
| Swagger 2.0 | body parameter、consumes、securityDefinitions、路径/查询 collectionFormat | 不支持非 body 对象参数、formData；本轮修复 JSON 格式错选 | [parser `_extract_request_body_details`:408][p-body]；[parameters `_settings`:122][param-settings] |
| OpenAPI 3.0.x | 路径级与操作级参数覆盖、requestBody、security、JSON/YAML、本地引用 | 使用扫描所需子集，没有完整 OAS 合同验证 | [parser `get_endpoints`:468][p-endpoints]、[`_merge_parameters`:373][p-params] |
| OpenAPI 3.1.x | schema `$ref` siblings、组合、条件、prefixItems 等递归解析路径 | 解析不等于支持全部 JSON Schema；生成/验证仍会拒绝无法处理的语义 | [parser `_deep_resolve_schema`:232][p-schema]；[generator `_validate_schema_value`:278][g-validate] |
| 版本识别 | `_detect_version` 读取版本标签 | 未严格限定已验证版本；不能据其接受文档就宣称完整支持 3.2 或未知版本 | [parser `_detect_version`:70][p-version] |
| `$ref` | 文档内及规范目录内 JSON/YAML、JSON Pointer；循环/深度保护 | 远程、绝对路径、越目录引用被拒绝；不应为扩大覆盖而开放 | [parser `_reference_target`:104][p-refs]、[`_deep_resolve_schema`:232][p-schema] |
| GET | 带路径或任意查询参数的 GET 进入 BOLA 流程 | 无选择器的 `/me`、纯列表、功能接口会跳过；任何查询参数并不必然是对象选择器，可能得到相同 self URL 而不能确认 | [auditor `audit_endpoint_bola`:591][a-bola] |
| PATCH | 显式开启、allowlist、独立 GET、字段映射和可恢复快照 | 只支持对象 application/json / application/merge-patch+json；不是 JSON Patch 操作数组、任意 vendor 格式或任意写 API | [auditor `audit_endpoint_mass_assignment`:1013][a-mass] |
| POST / PUT / DELETE | parser 能列出并在报告中记录 | `run` 不执行检测；均 SKIPPED / detector_unimplemented；不构造补偿事务 | [parser `get_endpoints`:468][p-endpoints]；[auditor `run`:1297][a-run] |
| HEAD / OPTIONS / TRACE | parser 能列出；底层对 HEAD 有读安全保护 | 不进入 GET 对象检测器，run 中仍记录未实现 | [auditor `run`:1297][a-run]、[`_read_request_risk`:307][a-risk] |
| 身份认证 | 独立 Owner、Visitor 的静态 token / headers，以及无凭据 Anonymous；校验有效认证材料不同 | 可以存额外身份，但检测流程固定选择这三者，不自动枚举角色；无 OAuth 登录/刷新、mTLS 客户端证书或 HMAC 签名流程 | [auditor `_validate_identities`:216][a-identities]、[`_http_request`:341][a-http]、[`audit_endpoint_bola`:591][a-bola] |
| 跨用户 / 跨租户 | Owner 资源 URL 分别以 Owner、Visitor、Anonymous 请求；Visitor 请求自己的不同 URL 作对照 | tenant/project/resource 关系来自人工参数、业务预期，无法从 OpenAPI 自动证明；不是自动租户拓扑发现 | [auditor `audit_endpoint_bola`:591][a-bola]、[`_operation_parameter_values`:386][a-values] |
| 共享 / 管理员 | 显式 `expected_visitor_access: allow` 对该账户和所选资源转换为 AUTHORIZED；允许但被拒绝转不确定 | 默认 deny；真实共享误配为 deny 可能误报。allow 不能消除匿名泄露或缺失基线 | [auditor `audit_endpoint_bola`:677][a-policy]；[tests/test_business_authorization.py:73][t-business] |
| BOLA 确认 | Owner/self 有效且不同；跨访问获得具体业务值或显式可信 ID；匿名被可信拒绝 | 不凭 HTTP 200 或结构相似度确认；没有独立 self、匿名基线异常、字段不对应等可能漏报，但不能直接判安全 | [diff `_build_evidence`:608][d-evidence]、[`_object_access_signals`:699][d-signals]、[`evaluate_bola`:768][d-evaluate] |
| 拒绝与软错误 | 干净 401/403、部分 HTTP 200 JSON 鉴权拒绝；拒绝正文含业务内容时给可疑 | 404 未配置为可信鉴权拒绝；HTTP 200 HTML 登录页、空 JSON 无法建立基线；异常状态不直接确认 | [diff `_assess_response`:227][d-assess]、[`_denial_body_is_clean`:384][d-denial] |
| 路径 / 查询 | OAS simple/label/matrix、form、flat deepObject、分隔数组/对象；Swagger collectionFormat；严格值编码 | 不支持嵌套参数容器、content 参数、allowReserved=true、歧义分隔符等；不安全或无合同的数据不猜编码 | [parameters `serialize_path_parameter`:210][param-path]、[`serialize_query_parameter`:231][param-query]、[`_settings`:122][param-settings] |
| Header / Cookie | 身份上下文可提供认证头，识别部分规范中的认证头 | 一般业务 header/cookie 参数编码不支持，即使参数可选也可能阻止该端点；本轮未删去此检查 | [auditor `_build_url`:404][a-url] |
| 请求体 / 保护字段 | JSON 对象中权限名称候选；本轮补显式 readOnly 候选，支持嵌套与数组第 0 项 | 未声明 readOnly、又非已知名称的保护字段仍可能漏选；不会任意猜测隐藏字段；field_map 不是由 OpenAPI 自动证明的授权策略 | [generator `_iter_privilege_fields`:920][g-fields]、[`build_mass_assignment_cases`:1054][g-cases] |
| 响应体 | 实际响应的 JSON 对象、数组、嵌套记录、可信字段路径 | `get_endpoints` 未提取 response schema 供字段授权判断；XML/HTML/protobuf 无比较器；JSON 可解析不代表业务完整 | [parser `get_endpoints`:468][p-endpoints]、[diff `_assess_response`:227][d-assess] |
| 数组 / 分页 | 数组记录整体规范化、排序及重复计数保护；单次分页响应可以比对；支持 items[].id | 不自动跟随 next/cursor，不遍历全部对象；跨页面差异可能使值匹配不足；当前数组关联保护应保留 | [diff `_meaningful_record_value`:472][d-records]、[`_meaningful_leaf_pairs`:497][d-values]、[`_resource_identifier_pairs`:546][d-ids]；[数组关联回归测试][t-array] |
| 持久化与恢复 | 独立读回、完整写入容器快照、全读回文档比对（可显式忽略易变路径）、finally 恢复和失败停写 | 无原值、映射冲突、不可逆 Merge Patch、不可信读回均不能安全完成；HTTP 200 也无法单独证明“最新且权威” | [transactions `prepare_patch`:126][tx-prepare]、[`ensure_reversible_merge_patch`:105][tx-merge]；[auditor `_execute_patch_case`:952][a-execute] |
| 扫描目标 | 操作 URL 在显式 target 下构建；不自动发现外部目标，禁止跟随重定向 | 静态 GET 规则不能证明无副作用；仍需审阅目标、规范和资源 | [auditor `_build_url`:404][a-url]、[`_NoRedirectHandler`:38][a-redirect]、[scan_safety `read_only_risk`:88][s-risk] |
| 报告 / 脱敏 | 内部用原始响应判定，输出边界脱敏；HTML 统一转义；JSON 保留完整状态；SARIF 仅确认项 | 脱敏后人手复核需看匹配路径/计数或本地安全保存的原始证据；不能用默认公开隐私提升可读性 | [evidence.py 模块][evidence]、[reporter `generate`:208][reporter]、[SARIF `generate`:140][sarif] |

## 3. 实际未检测的端点与根因

仓库内 `openapi.json` 和 `core/demo_assets/openapi.json` 当前均有相同的五个操作。
本轮离线计划及 `verify_examples.py` 的真实本机扫描核对如下，不代表用户外部 API 的清单：

| 操作 | 默认只读行为 | 显式允许写测试后的本机示例行为 |
|---|---|---|
| GET /api/public/articles/{article_id} | PUBLIC | PUBLIC |
| GET /api/documents/{doc_uuid} | CONFIRMED | CONFIRMED |
| GET /api/users/{user_id}/profile | SECURE | SECURE |
| PATCH /api/users/{user_id}/settings | SKIPPED，未发送写入 | CONFIRMED，并恢复 |
| PATCH /api/users/{user_id}/nickname | SKIPPED，未发送写入 | SECURE，未持久化权限字段 |

来源：[openapi.json][sample-spec]、[config.example.json][sample-config]、[scripts/verify_examples.py][example-script]；
实际输出见 [验收证据 JSON](authorization-coverage-results.json) 的 `verification.examples` 与 `spec_inventory`。
默认示例确定性覆盖率仍为 60%；主动隔离示例仍为 100%。它们只覆盖五个演示操作。

所有扫描在 [run:1297][a-run] 逐项处理：未实现方法记录 SKIPPED；GET 无选择器/读安全规则命中时在 [audit_endpoint_bola:591][a-bola] 零请求退出；
参数不支持/策略无效成为 INCONCLUSIVE；PATCH 关闭、未列入 allowlist、无 schema/格式未实现成为跳过；缺映射、无可恢复原值、字段无候选等成为不确定。
具体根因不是单一“检测器太少”：

1. **业务真值不可推断。** OpenAPI 没有可供工具直接相信的资源归属、共享关系、管理员权限和字段写权限；草稿故意保留待填标记（[config_scaffold.py:116][scaffold]）。
2. **证据需要成链。** Owner、Visitor self、匿名拒绝、具体值/可信 ID 任一环不满足都会限制确认；这是精确性保护，也形成真实漏报边界（[diff.py:768][d-evaluate]）。
3. **写事务必须可恢复。** 有效状态和恢复路径不足时，覆盖率不能优先于资源安全（[transactions.py:126][tx-prepare]、[auditor.py:952][a-execute]）。
4. **编码/结构受限。** 一般 header/cookie/formData、非 JSON、自动分页等没有完整合同与执行器（[auditor.py:404][a-url]）。
5. **已确认的维护缺陷。** 本轮四类证据/候选/格式问题及计划解释已修复，见第 1 节和固定场景反例。

可确认的误报保护包括：永远返回当前用户、自身与 Owner 未区分、仅字段结构相似、反射请求/trace 标识、数组记录重关联、匿名公开摘要等。
依据：[tests/test_diff_hardening.py:118][t-echo]、[177 数组关联][t-array]、[tests/test_release_bola.py:36][t-bola]。
业务预期或可信 ID 路径配错仍会产生错误结论；本轮未把这些配置假设改成自动推断。

## 4. 结果状态与覆盖率口径

状态产生和计数来源：[auditor `_map_bola_verdict`:577][a-map]、[`_record_result`:491][a-record]、[`_finalise_coverage`:1235][a-coverage]。

| 状态 | 含义与限制 |
|---|---|
| CONFIRMED | BOLA 的完整确认条件，或 PATCH 后独立读回证明目标字段持久化。恢复失败仍可保留已证实漏洞，但必须同时记录恢复 ERROR、停止后续写测试。 |
| SECURE | 本次配置的身份、所选资源/字段满足可信拒绝或无持久化条件；不代表整个 API 没有漏洞。 |
| AUTHORIZED | 明确配置允许的这一组身份和资源访问与证据相符，不代表自动识别了所有管理员/共享关系。 |
| PUBLIC | 明确公开策略且 Owner、Visitor、Anonymous 完整数据等价等条件满足。 |
| SUSPICIOUS | 存在冲突或资源泄露线索，需要人工复核；本轮错误正文升级只到此状态。 |
| INCONCLUSIVE | 缺少可靠基线、选择器区分、完整响应、映射或足够证据；不能当安全。 |
| SKIPPED | 方法未实现、不适用、写门未开启、读安全策略阻止等；并不表示做完检测。 |
| ERROR | 网络、运行错误或无法保证恢复等，需要处理；不是可靠拒绝。 |

统计维持原定义：

- 分母为规范解析得到的全部不同方法/路径操作；`max(1, total_endpoints)` 避免零除。
- 尝试覆盖率为至少尝试一次 HTTP 的不同端点 / 全部规范操作，**包含失败的连接尝试**，不代表成功取得响应。
- 确定性覆盖率只计实际尝试后为 CONFIRMED、SECURE、PUBLIC、AUTHORIZED 的不同端点。
- SUSPICIOUS、INCONCLUSIVE、ERROR、零请求阻断不计确定性覆盖；ROLLBACK 附加记录不重复计端点。
- `total_checks` 是结果记录数，可包含恢复记录，不能当成扫描端点数；`raw_filtered_count` 的旧命名仍保留兼容性。
- HTML 展示上述口径；JSON 顶层仍是 `report_schema_version: 2` 和 stats/results/findings 等字段；SARIF 只收确认漏洞，没有完整覆盖率分母，不能用 SARIF 结果数推算覆盖率。

报告来源：[reporter.py:208][reporter]、[api_sentinel.py:581 JSON 写出][json-report]、[sarif.py:140][sarif]。

## 5. 实际修改及兼容性

产品代码修改范围仅四个模块：

- `core/auditor.py`：状态读回要求无传输错误、HTTP 200、未截断、无 Content-Range、非空且有效的业务 JSON 对象；三个状态阶段复用同一检查。没有更改通用 HTTPResult.ok，PATCH 204 ACK 仍可通过独立 GET 完成确认/恢复。补计划说明，并复用选择器判断。
- `core/diff.py`：对含 Owner 特异值或可信 ID 的 4xx/5xx 正文，只有 self 基线有效且不同、匿名拒绝可信时才给可疑；`confirmation_signals` 仍为空。
- `core/generator.py`：普通命名的显式 readOnly 字段可成为候选，保留已有嵌套候选顺序和普通请求基线不带 readOnly 字段的行为。
- `core/parser.py`：Swagger consumes 复用 JSON 优先选择；媒体类型匹配处理大小写/分号前空白，保留发送时的原格式。

兼容性和安全影响：

1. 无新增 CLI 参数、结果状态、JSON 顶层字段、SARIF 规则；默认只读、目标构造、重定向保护、allowlist、完整恢复比较均保留。
2. 非 200 / partial 读回以前可能产生 SECURE/CONFIRMED，现在可能不确定、零 PATCH 或恢复 ERROR。这是有意收紧证据；依赖旧错误状态的自动化需要接受更保守结果。
3. 部分错误正文由 INCONCLUSIVE 变为 SUSPICIOUS。现有 `--fail-on-suspicious` 因此可能触发；不会增加 SARIF 确认项。
4. 显式允许写入且 field_map 已列出自定义 readOnly 字段的配置，现在可能真正测试该字段；这就是维护修复的目标。仍需操作者确认该字段对 Visitor 不可写、资源可丢弃。
5. 计划沿用 reason/reason_category，但它们会出现在更多条目中；严格逐键比较整个条目的外部脚本可能需要放宽可选字段断言。writes_enabled 仍只表达启用与允许条件，计划不构成成功恢复保证。
6. HTTP 200 不能替代最新性/一致性/归属保证。配置 strong 是操作者声明；工具无法识别所有以 200 返回的陈旧缓存。后端异步事务、未观测的副作用仍需独立策略，本轮未承诺支持。
7. Windows 打包入口、启动器和 Demo API 未改动。Linux 新 wheel 的安装和内置 Demo 已验证；这些本地测量不包含 Windows 实机、Python 3.9/3.14；提交后的当前 CI 补充见 PR 描述，不能以历史验收冒充当前验收。

## 6. 测试真值、原始口径与真实前后对比

固定定义位于 [scripts/verify_authorization_coverage.py](../scripts/verify_authorization_coverage.py) 的 `SCENARIOS`。
预期结果、漏洞真值、恢复/停写不变量先于扫描声明；本机服务器直接维护可检查状态，不用工具结论给自己定真值。
新增 [tests/test_authorization_maintenance.py](../tests/test_authorization_maintenance.py) 的 16 个测试方法，含 36 场景子测试、读回状态矩阵、错误正文误报保护、204 写 ACK、嵌套 readOnly、Swagger 格式和零网络计划验证。
原有 634 项测试保留，无删除或放宽断言。

36 个场景均实际运行。固定集合中 29 个具备进入完整目标请求流程的条件；另 7 个是无选择器、危险读、两个写门关闭、三个不可信初始快照的保护对照。
这 7 个仍保留在总场景和全部已知漏洞的分母中。HTTP 主检查执行数包含只尝试初始 GET、没有发送 PATCH 的场景；它与完整目标检测数分开。

| 指标 | 修改前 | 修改后 |
|---|---:|---:|
| 固定验收场景，全部实际运行 | 36 | 36 |
| 预先声明可进入完整目标流程的场景 | 29 | 29 |
| 上述集合中实际执行目标请求 | 26 | 29 |
| 全部场景中主检查至少尝试一次 HTTP | 29 | 32 |
| 主检查 SKIPPED | 5 | 4 |
| 主检查 INCONCLUSIVE | 9 | 11 |
| 主检查 SUSPICIOUS | 1 | 3 |
| 主检查 ERROR | 0 | 0 |
| 主检查 CONFIRMED | 13 | 13 |
| 主检查 SECURE | 6 | 3 |
| 主检查 AUTHORIZED | 2 | 2 |
| 所有独立声明的已知漏洞场景 | 25 | 25 |
| 严格确认检出率（CONFIRMED / 25） | 13/25 = 52.00% | 13/25 = 52.00% |
| 已知无漏洞场景误报为 CONFIRMED | 0 | 0 |
| 已知漏洞未获 CONFIRMED，含可疑/安全阻断 | 12 | 12 |
| 违反预期状态或恢复不变量的场景 | 12 | 0 |
| 资源未恢复却声称恢复成功 | 4 | 0 |
| 扫描结束资源仍变化，含故意恢复失败对照 | 5 | 2 |
| 整体 unittest 测试方法数，通过 | 634 | 650 |
| coverage.py 语句＋分支综合覆盖率 | 86.49% | 86.74% |

新增三个有效确认：普通 readOnly、嵌套 readOnly、Swagger JSON 备选格式。
同时撤销三个以不可信写前快照为基础的确认，因此严格检出率没有被“做高”。错误正文的两个新增线索仍按未确认漏报计。
修改后的两个未恢复资源来自故意设置的 `patch_restore_failure` / `patch_restore_202`：程序记录恢复失败/不可信、`rollback_verified=false` 并阻止后续写入；测试服务器随后关闭并丢弃数据。

修改后仍未确认的 12 个已知漏洞场景：

- `error_500_owner_data`、`error_404_owner_data`：异常状态，只提供可疑线索。
- `truncated_owner_response`：响应截断，不接受不完整证据。
- `patch_initial_202`、`patch_initial_206`、`patch_initial_content_range`：不能建立可靠写前快照，禁止写入。
- `patch_stale_202`、`patch_stale_203`、`patch_stale_206`、`patch_invalid_after`：恢复已核验，但修改后的观察不足，不能确认持久化。
- `patch_default_readonly`、`patch_not_allowlisted`：明确未获本次写入许可。

完整的逐场景预期、前后状态、PATCH 数量、恢复状态、失败原因及实际源码指纹，见 [authorization-coverage-results.json](authorization-coverage-results.json)。
测量时修改后工作树尚未提交，`source_commit` 仍为基线；因此同时记录 `source_tree_dirty`、运行时代码 SHA256 及相同的 fixture 脚本 SHA256，避免冒充已提交版本。

## 7. 复现与验收范围

在隔离的源码目录安装项目和开发检查工具后：

```bash
python -m unittest discover -s tests
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m ruff check .
python -m mypy
python scripts/verify_authorization_coverage.py --output dist/authorization-coverage.json
python scripts/verify_business_scenarios.py
python scripts/verify_examples.py
python scripts/verify_install.py
```

对比基线使用**同一份**新 fixture 脚本运行旧源码：

```bash
git worktree add --detach ../granttrace-baseline 80c7202fdfd203e298a924bf77e5c154671123ff
python scripts/verify_authorization_coverage.py --source-root ../granttrace-baseline --output dist/before.json
python scripts/verify_authorization_coverage.py --output dist/after.json
```

旧源码测量退出 1 是固定新验收标准发现 12 个未满足场景的预期表现；JSON 仍完整写出，不应把此退出码抹成成功。
新源码返回 0。该脚本不接受目标 URL，所有 HTTP 服务只绑定 127.0.0.1、随机端口，并在 finally 关闭。

此处记录首次本地测量：Linux / CPython 3.12.14，Node 可用。Ruff、Mypy、650 项 unittest、原六业务场景、JSON/YAML 示例和源码外的新 wheel 安装均通过。
安装验收确认：HTML/JSON 版本一致、默认只读 0 PATCH、内置 Demo BOLA/MA 各 1 项、恢复成功、数据库恢复、服务关闭、配置草稿阻断、dry-run 0 请求。
示例主动扫描的子进程退出 1 来自 `--fail-on-vuln`，由 verify_examples 按预期验证；验收脚本本身通过。
没有声称执行 Windows 新构建、Windows USB 跨机、浏览器真实打开、Python 3.9/3.14 或外部真实业务扫描。

## 8. 相邻授权能力评估（本轮均未实现）

依据是当前固定身份对比、策略字段、选择器要求、只有两类检查的报告规则：[auditor.py:591][a-bola]、[diff.py:768][d-evaluate]、[config_validator.py:1530][config-bola]、[sarif.py:140][sarif]。
下表是基于这些代码边界的设计评估，不是已验证功能或实现承诺。

| 维度 | BFLA 功能级授权 | 敏感字段越权读取 | BOPLA 对象属性授权 | 多角色权限边界 |
|---|---|---|---|---|
| 定位 | 符合授权审计，但需表达操作级预期，不能套用对象选择器 | 符合，且属于 BOPLA 读取面的一个子集 | 符合；现有 MA 仅覆盖部分写入面，不是完整 BOPLA | 符合，需要超出现有单一 Owner/Visitor 对照 |
| 只读可靠性 | 限经审查的无副作用 GET；写功能不能默认探测 | 可用 GET，但仅凭字段名称或“管理员比用户多字段”不能确认 | 读取部分可只读；写入仍需事务和独立读回 | 经审查的 GET 可只读；角色身份真实性仍需业务验证 |
| 额外配置 | 角色-操作允许/拒绝矩阵、拒绝语义、GET 无副作用确认 | 哪些响应字段对哪个角色/对象禁止、公开投影策略 | 对象、字段、角色、读写动作的显式授权预期 | 多组独立凭据、角色、资源归属、继承与共享规则 |
| 误报风险 | 高：HTTP 200 可能是公开帮助或空壳页面 | 高：字段存在不等于敏感或不合法；脱敏占位与公共字段需排除 | 高：字段正常可写和越权写必须区分；缺字段不等于拒绝 | 高：管理员、团队共享、角色继承容易误判 |
| 复杂度 | 中：需要新的适用性/策略判定，不能取消当前无选择器跳过 | 中到高：字段路径、缺失/null/脱敏/数组投影及策略比较 | 高：读写策略、恢复与不同表示映射组合较多 | 中到高：身份组合增长、限速、基线复用及资源配对 |
| 必要测试 | 管理 GET 普通角色拒绝/泄露、公开 GET、软拒绝、危险 GET 零请求 | 真敏感泄露、合法公开字段、按角色隐藏、null/脱敏、分页/嵌套 | 合法字段更新、只读字段写入、受限字段读出、更新未持久化、恢复失败 | 管理员合法、租户管理员仅本租户、共享、继承、凭据无效、跨租户 |
| 架构兼容性 | 可复用传输/脱敏，但需新的操作级策略、检查分类及报告审查 | 可复用 JSON 路径/证据，需字段级授权配置与报告语义 | 可复用 MA 事务，完整能力需业务策略和新结果解释 | 可复用每次两身份比较；完整矩阵需要调度与配置接口设计 |

建议未来首先评审有明确字段策略的只读检查或少量人工指定的角色-操作对照。
任何增加新检查分类、角色矩阵、字段策略接口、SARIF 规则或主动方法，均应另立评审，不混入本轮维护补丁。

[p-version]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parser.py#L70
[p-refs]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parser.py#L104
[p-schema]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parser.py#L232
[p-params]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parser.py#L373
[p-body]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parser.py#L397
[p-endpoints]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parser.py#L468
[a-identities]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L216
[a-http]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L341
[a-values]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L386
[a-url]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L404
[a-record]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L491
[a-map]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L577
[a-bola]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L591
[a-policy]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L677
[a-object]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L723
[a-rollback]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L927
[a-execute]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L952
[a-mass]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L1013
[a-coverage]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L1235
[a-plan]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L1251
[a-run]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L1297
[a-risk]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L307
[a-redirect]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/auditor.py#L38
[d-assess]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L227
[d-denial]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L384
[d-records]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L472
[d-values]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L497
[d-ids]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L546
[d-evidence]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L608
[d-signals]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L699
[d-evaluate]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/diff.py#L768
[g-fields]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/generator.py#L920
[g-cases]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/generator.py#L1054
[g-validate]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/generator.py#L278
[param-settings]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parameters.py#L122
[param-path]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parameters.py#L210
[param-query]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/parameters.py#L231
[tx-prepare]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/transactions.py#L126
[tx-merge]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/transactions.py#L105
[s-risk]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/scan_safety.py#L88
[scaffold]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/config_scaffold.py#L116
[config-bola]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/config_validator.py#L1530
[reporter]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/reporter.py#L208
[sarif]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/sarif.py#L140
[json-report]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/api_sentinel.py#L581
[evidence]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/core/evidence.py#L1
[t-business]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/tests/test_business_authorization.py#L73
[t-echo]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/tests/test_diff_hardening.py#L118
[t-array]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/tests/test_diff_hardening.py#L177
[t-bola]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/tests/test_release_bola.py#L36
[sample-spec]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/openapi.json#L1
[sample-config]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/config.example.json#L1
[example-script]: https://github.com/ysc070528/granttrace/blob/80c7202fdfd203e298a924bf77e5c154671123ff/scripts/verify_examples.py#L1
