# PR #42：无标记旧状态与恢复 ACK 的 fail-closed 复核

日期：2026-10-26。重新核对 GitHub 的 PR HEAD 为 `e677f54b36611208f6300950b51877cb4d5f5b3c`，读取完整 PR 差异、两个历史审计文档、原始 JSON 及测试后开始修改。没有覆盖其他提交。没有使用生产服务器或真实用户数据。

## 结论与适用范围

**PASS WITH CONDITIONS：两个已知错误恢复声明路径已通过阻断无权威状态核验的外部写入解决。条件是维护者接受这一兼容性收紧、核对本次 HEAD 的 CI，并完成所需的 Windows 人工验收。PR 保持 Draft。**

普通 CLI 对外部 API 的主动 PATCH 现在暂停：即使配置写开关、allowlist、field_map、可恢复快照及 `consistency: strong`，仍缺少可执行的权威状态核验实现，返回 `INCONCLUSIVE`，发送 **0 个 PATCH**。这项阻断不能用现有配置解除。
内置 Demo 直接核对其自有的、同步更新的可丢弃内存数据库，保留主动流程。没有增加通用 HTTP 版本协议、缓存探测器、新配置开关或漏洞检测类型。

此修改没有解决从普通 HTTP 响应普遍识别无标记缓存这一不可能的问题，也没有把模拟服务器通过外推成生产恢复保证。历史风险披露和 JSON 原始记录保留，旧报告上增加本报告的链接。

## 修复前重新复现的事实

在隔离 loopback 服务器上独立维护真实资源与 GET 返回内容。写入日志独立记录实际状态变化，GET 返回完整、合法的 HTTP 200 JSON，不含 Age、Warning、Content-Range。

| 原始反例 | 初始真实状态 | 写入与读回 | e677f54 的实际结束状态 | 工具错误输出 |
|---|---|---|---|---|
| `opaque_cached_after` | role=user | 第一次 PATCH 实际改成 admin；GET 始终回初始状态 | role=admin；仅 1 次 PATCH，没有恢复请求 | SECURE，rollback_verified=true |
| `opaque_cached_restore` | role=user | PATCH 实际改成 admin；恢复 ACK 200 但未应用；GET 伪装成原状态 | role=admin；2 次 PATCH，其中恢复无副作用 | CONFIRMED，rollback_verified=true |

原始复现脚本本轮重新运行：20 个旧测试通过，但两个独立探针仍失败，退出码 **3**。另外把本轮同一套 28 个对抗测试运行在 e677f54 上，得到 8 次失败断言；失败轨迹保留于 [原始结果](pr42-state-authority-results.json)。没有用旧 CI 代替复现。
原始位置：[e677f54 core/auditor.py:947 `_rollback_and_verify`](https://github.com/ysc070528/granttrace/blob/e677f54b36611208f6300950b51877cb4d5f5b3c/core/auditor.py#L947)、[971 `_execute_patch_case`](https://github.com/ysc070528/granttrace/blob/e677f54b36611208f6300950b51877cb4d5f5b3c/core/auditor.py#L971)。

根因：`_json_object()` 只校验 HTTP/JSON 外形；`PatchSnapshot.matches()` 只比较值；`strong` 只是配置声明。原逻辑将这些组合成真实状态证明，既可跳过恢复，又可误信虚假的恢复读回。

## 最小安全方案与代码位置

| 位置 | 行为与证据含义 |
|---|---|
| `core/auditor.py:724 _authoritative_patch_state` | 默认没有权威状态实现，返回 None；不从 HTTP 200、ETag 外形或配置声明推断权威性。私有方法只给内置受控 Demo 和隔离夹具连接实际 backing store，不构成通用恢复协议或对外配置接口。 |
| `core/auditor.py:739 _verified_patch_document` | 先保留 200、有限 JSON、无部分/陈旧标记等旧门槛，再把整个 HTTP 文档与独立观察到的实际资源文档作严格 JSON 值比较。无法观察、观察报错或内容不一致都不可用于确认。 |
| `core/auditor.py:1156 _audit_endpoint_mass_assignment` | 无实现时在任何写入前阻断；已有默认只读、allowlist、field_map、方法/媒体类型、读路径安全检查继续存在。初始文档和发送前复核也必须与权威状态相符。 |
| `core/auditor.py:1003 _execute_patch_case` | 写后匹配只能使用通过权威核验的文档；无标记旧状态不再绕过恢复；ACK 不证明持久化。 |
| `core/auditor.py:977 _rollback_and_verify` | 恢复 ACK 加普通 GET 不足以通过；恢复读回必须与实际状态相符，并通过整个快照比较。失败保留 finally 预先设置的停写原因，提示检查实际测试资源。 |
| `core/auditor.py:1066 audit_endpoint_mass_assignment` | 原有全事务 RLock 保留；等待调用取得锁后检查停写标记，包括其他资源。 |
| `core/auditor.py:1326 build_plan` | 零请求计划对普通 CLI 同样给出 `writes_enabled=false` 与 `unverified_state_authority`，不声称配置已满足运行时证明。 |
| `core/transactions.py:97 matches / 105 covers_document` | 保留全快照/结构比较与恢复规则；明确它们只比较值或结构，不证明权威性、新鲜度或初始文档完整性。 |
| `core/demo.py:120 _LocalDemoAuditor._authoritative_patch_state` | 仅接受持有的、仍运行的相同 DemoServer 对象和相同 origin、已有 settings/nickname 资源路径；直接复制该 server 的实际用户记录。没有把 loopback 地址本身当作证明。 |

三个概念严格分开：HTTP ACK 表示请求得到了响应；文档相等表示观察值相等；只有本轮受控本地场景的直接 backing-store 观察才能在其限定范围内核验持久化或恢复。外部 CLI 没有第三项能力，因此不执行主动写入。
配置 `consistency` 字段继续保留兼容，并作为原先更保守的额外约束；它没有提供权威观察能力。没有增加 GET 次数、缓存请求头或“信任我”的布尔配置。

## 新的独立对抗验证

新增 `tests/test_pr42_state_authority.py`，其中 `CachedAfterServer` 与 `NoopRestoreServer` 是两种独立服务器状态机，分别启动隔离端口、数据库和写入日志。保留原有 20 个对抗测试的全部安全断言；测试夹具增加的是直接实际状态观察，没有将 HTTP 回显用作第二份证明。

| 场景 | 真实副作用 | 修复后的预期与实测 |
|---|---|---|
| 两个原始反例，普通 HTTP 入口 | 主资源和其他资源均 0 PATCH；状态未改变 | INCONCLUSIVE；rollback_verified=false；没有恢复成功声明；计划零请求且同样阻断 |
| 旧写后 GET，但直接状态可观察 | admin 写入真实发生；执行真正恢复，实际回 user | 旧读回与实际 store 不一致，不能 SECURE 或 CONFIRMED；INCONCLUSIVE；只有真实恢复经核验才 rollback_verified=true |
| 虚假恢复 ACK，实际 store 可观察 | admin 写入真实发生；恢复 ACK 无副作用，真实状态仍 admin | 已证实的写入仍 CONFIRMED；rollback_verified=false，单独 ROLLBACK ERROR；全局停写；其他资源 0 PATCH |
| 初始 200 与实际 store 不一致 | 0 PATCH | INCONCLUSIVE，不建立可用于写入的快照 |
| 准备快照期间丢失权威观察 | 0 PATCH | 发送前再次检查，INCONCLUSIVE |
| 写入之后丢失权威观察 | 尝试恢复，实际资源可已回原值 | 仍不能宣称恢复已验证；保留停写，后续资源 0 PATCH |
| 恢复被暂停时第二线程真实等待写锁 | 第一资源恢复无副作用 | 等待者明确观察到锁被占用；失败释放锁后，第二资源仍 0 PATCH |
| 真正持久化且真正恢复的对照 | 2 PATCH 均实际应用，整个记录回原值 | CONFIRMED，rollback_verified=true，无停写 |

写入日志包含 mutation/restore 的请求体、应用前后状态和 `applied`；观测 JSON 记录初始快照、GET 声称的内容、直接状态观察、实际状态、verdict、恢复证据与停写原因。
保留并实际执行 202/203/206、Content-Range、Age/Warning、204 ACK、部分 JSON、未持久化、恢复失败、额外字段变化、嵌套 readOnly、权限门和可捕获退出等旧反例。
新增真实 subprocess CLI 测试验证写开关不能解除阻断，且 SARIF 仅导出实际 CONFIRMED 的 BOLA。原主动 HTML/JSON/SARIF 集成断言在连接自有数据库的受控夹具上保留。

`verify_pr42_adversarial.py` 仍运行两个原始探针。它们现在通过“发送前阻断、无虚假恢复声明”被处理，不能解释为识别了任意缓存。脚本保留退出码 3：将来仍有未解决探针时必须非零退出；当前实测为 0。

## 统计口径与兼容性

原来的 36 个场景、25 个漏洞真值均保留，并执行两次：

| 模式 | 全部场景 | 执行过主检查 | 严格确认 / 完整漏洞分母 | 未确认漏洞 | SUSPICIOUS / INCONCLUSIVE / SKIPPED |
|---|---:|---:|---:|---:|---|
| 直接实际状态观察的受控夹具 | 36 | 32 | 13/25 = 52% | 12 | 3 / 11 / 4 |
| 普通 HTTP，无权威状态实现 | 36 | 17 | 6/25 = 24% | 19 | 3 / 19 / 4 |

两种模式均无 CONFIRMED 误报、无虚假恢复成功声明。受控夹具故意设计的两种恢复失败仍保持失败和停写，不从统计中删除。SUSPICIOUS、SKIPPED、INCONCLUSIVE 没有计入确认。
历史操作条件分母 20 的 13/20=65% 仅适用于有直接实际状态观察的夹具；普通 HTTP 只读 BOLA 子集为 6/9=66.67%，三个未确认 BOLA 仍计入分母。这些子集数不能替代完整的 25 场景统计，也不能宣传成生产检出率。
原历史 86.74% 是语句与分支合计，82.68% 才是纯分支覆盖；本轮仍分别报告语句、分支、综合分子分母，见原始 JSON。

兼容性收紧是有意且必要的：既有写开关/配置仍可解析，但普通外部主动 PATCH 不再执行，结果从过去的可确认/安全变为不确定。只读默认、CLI 参数、配置 schema、报告 schema 2、状态枚举、SARIF 确认过滤、恢复负载和 allowlist 未改变。`_LocalDemoAuditor` 的私有构造参数用于绑定实际 DemoServer，不是新的用户开关。未实现外部版本/数据库适配器。

## 验收证据与合并条件

本地测试记录以 Python 源文件 SHA256、测试文件 SHA256、父提交和脏工作树标记关联实际修改内容，详见 [pr42-state-authority-results.json](pr42-state-authority-results.json)。避免把尚未提交的运行谎报成父提交本身的结果。提交后的 CI 必须在该 HEAD 上重新执行；工作流新增独立反例、两套 36 场景与原始 JSON artifact 上传，维护者可核对 artifact 中的 `source_commit`。

本地最终结果：681 项全量测试、28 项独立对抗测试全部通过；36＋36 场景无安全断言失败。Ruff、Mypy（19 个产品源文件）、运行时依赖审计（PyYAML 6.0.3，无已知漏洞）、JSON/YAML、源码外 wheel 安装及主动/只读 Demo 均通过。语句覆盖 4491/5049=88.95%，纯分支 2155/2602=82.82%，综合 6646/7651=86.86%。

本地全量、对抗、Ruff、Mypy、依赖审计、JSON/YAML、源码外 wheel 安装及主动/只读 Demo 的最终结果见 JSON。GitHub Actions 的最终 HEAD、运行链接、各 job 结论记录于 PR 正文，不能以旧 e677f54 的绿色 CI 替代。若任何必需检查未完成或失败，不能按本报告的有条件结论合并。

仍需人工：Windows 真桌面双击 Start-Demo.bat、默认浏览器打开 HTML、U 盘跨机运行，以及维护者接受外部写测试暂停。Windows CI 的浏览器打开被 smoke 验证抑制，不能代替这些操作。

剩余风险：

- P0/P1：本轮范围内两个已知错误恢复成功路径不再可从普通外部 CLI 触发；没有宣称所有服务端行为都可证明。CI 未通过时仍是合并阻断。
- P1 适用边界：SIGKILL、断电、解释器崩溃不能由 finally 保障恢复；不得把 Demo/受控夹具或私有观察方法扩展到生产恢复保证。外部 CLI 阻断使其不再暴露该主动写风险。
- P2：同一 auditor 的停写和串行锁不协调多个进程、多个 auditor 或其他客户端；内置受控 Demo 应独占其可丢弃资源。任何未来外部权威适配器都需要独立设计、授权与真实契约验证，本轮未实现。
- P2：Windows 桌面、浏览器及 U 盘人工验收仍未执行；代码签名状态和既有便携包边界不变。

若维护者要求维持通用外部主动 PATCH，同时接受普通 GET 作恢复证明，应判 **BLOCK**。本补丁只建议以明确的 fail-closed 行为合并，不建议放开该限制。
