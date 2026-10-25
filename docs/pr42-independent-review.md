# PR #42 合并前独立复核

复核对象：`863b0a87572a14b6203cc6115184666cd18bddae`，日期 2026-10-26。
本次重新读取产品代码、测试、审计文档及测量数据；没有把此前的总结当作验证结果。
“独立”指新的测试服务器、独立维护的实际状态和新断言，不代表另一个人工审查者。
没有使用生产服务器或真实用户数据。PR 保持 Draft，不升级版本、不合并、不发布。

## 1. 总体结论

**PASS WITH CONDITIONS：在人工审查本次补丁、接受下述读回前提及完成人工验收后，可考虑合并。**

已复现并最小修复三个 P1 问题：已知缓存的 200 读回被信任、已知不完整的写后业务对象被用来确认持久化，以及并发调用绕过失败停写检查。
新增 20 个独立回归测试方法；对原提交运行有 10 次失败断言，对修复后运行全部通过。
原 36 场景仍满足各自预期，原 25 个已知漏洞的统计完整保留。

**条件不能省略：**主动 PATCH 仅限明确授权、可丢弃的测试资源，且必须从服务端实现、独立数据库/权威读路径或受控夹具验证读回真实、新鲜、完整。
配置 `consistency: strong` 只是操作者声明，不会让缓存接口变成权威数据源；无法满足这些条件时保持只读。
两个无缓存标记、故意违反 strong 约定的旧数据探针仍能触发错误恢复声明，未宣称解决，详见第 4 节。
若要求工具对这种不可观察的新鲜度违约也给出保证，当前实现不满足该要求，不能在这一适用范围内批准合并。

## 2. 已确认发现及修复

以下原始位置固定指向被审提交；当前修复可在同一 PR diff 中审查。

| 编号/级别 | 原始位置 | 复现条件与影响 | 最小修复及测试 |
|---|---|---|---|
| F1 / P1 | [core/auditor.py:724 `_json_object`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/auditor.py#L724)、[933 `_rollback_and_verify`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/auditor.py#L933) | HTTP 200 旧状态带 Age:120 或 Warning:110，仍作为快照/写后/恢复证据；可跳过恢复或错误标记 rollback_verified=true。 | 大小写无关地拒绝非零/无效 Age、过期 Warning 110/111；保留 200/无截断/无 Content-Range 等旧门槛。`test_known_cached_*`、`test_known_stale_initial_snapshot_sends_zero_patches`、缓存头矩阵。 |
| F2 / P1 | [core/auditor.py:958 `_execute_patch_case`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/auditor.py#L958)、[1019 `audit_endpoint_mass_assignment`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/auditor.py#L1019) | 写入实际未持久化，写后 GET 只回显 role=admin，却遗漏初始快照中的 id/profile/counter 等；仍可 CONFIRMED。 | `PatchSnapshot.covers_document` 要求已观察的非易变业务结构继续存在；选中字段单独做目标值比较。缺已知字段、嵌套字段或数组记录时不能确认。`test_partial_200_echo_cannot_confirm_persistence`、`test_nested_or_array_omissions_cannot_confirm_persistence`。 |
| F3 / P1 | [core/auditor.py:1019 `audit_endpoint_mass_assignment`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/auditor.py#L1019) | 第二个线程在失败标记建立前通过入口检查，等待后仍向另一个资源发出两个 PATCH；序列扫描本来正确，并发直接调用存在竞态。 | 整个公共写审计入口置于同一 RLock 中，等待者取得锁后才检查停写标记；默认 run 的串行原则不变。事件屏障测试 `test_waiting_concurrent_call_rechecks_halt_before_writing`，真实 HTTP 记录 /other PATCH 数 2→0。 |
| F4 / P2 | [旧审计第 6 节](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/docs/authorization-coverage-audit.md) | 把 coverage.py 综合百分比称为“分支覆盖率”，易误导。 | 更正文案，分别列语句、分支和综合口径；原 JSON 数值不篡改。 |
| F5 / P2 | [core/auditor.py:1257 `build_plan`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/auditor.py#L1257) | 直接调用库时，错误 BOLA 策略的计划未解释 invalid_input，而执行零请求返回不确定。CLI 会在计划前做配置验证，因此没有绕过写保护。 | 保留为诊断改进项，本轮不扩展计划/配置接口。证据 JSON 包含直接库调用的计划和执行结果。 |

代码修改仅涉及 `core/auditor.py` 和 `core/transactions.py`，其他变更为测试、复现脚本及审计说明。
不改变 write_allowlist、默认只读、参数或报告 schema；已知不完整响应和显式过期缓存会更保守地变为不确定/恢复错误。
RLock 使同一个 auditor 的直接并发写调用遵守原有串行政策；不协调不同进程、不同 auditor 或外部业务客户端。

## 3. 十个审查重点的验收结论

| 重点 | 结论与边界 |
|---|---|
| 写前快照 | 映射/可恢复原值检查保留；已知部分/过期证据阻止 PATCH。初始 200 已隐藏的字段无法由一个响应发现。 |
| 写后持久化 | 目标字段值需独立读回匹配，且相对初始文档不得缺已知业务结构；不以 ACK 确认。 |
| 恢复验证 | 继续比较整个已观察文档，不只比较被测字段；恢复 ACK 成功但值未恢复、其他字段变化均失败停写。 |
| 恢复失败停写 | 串行和同 auditor 并发入口均阻止后续写入；原先并发竞态已修复。 |
| 202/203/206/Content-Range | 状态证据仍拒绝；原场景和相关状态矩阵重新通过。 |
| 204 ACK | 实际 HTTP 测试仍 CONFIRMED 且真实恢复；ACK 本身不是持久化证据。 |
| 4xx/5xx 线索 | 反射 request_id/params 不会确认；显式可信 id 可能仅为 SUSPICIOUS，仍需排查反射。 |
| readOnly 候选 | 写开关、allowlist、field_map 三类保护实测；嵌套只读字段被正确拒绝或确认，普通可写兄弟字段保持原值。 |
| Swagger 2 格式 | XML 在前、JSON 在后以及大小写/参数化媒体类型选择保留；不新增 XML、vendor JSON 或 JSON Patch 写支持。 |
| 离线计划 | 原先四类说明与执行的零请求结果回归通过；不是完整运行担保，直接库调用的策略校验说明仍有 F5 差距。 |

原逻辑证据：[core/transactions.py:126 `prepare_patch`](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/transactions.py#L126)、[core/diff.py:921 错误正文分支](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/diff.py#L921)、[core/generator.py:920 候选选择](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/generator.py#L920)、[core/parser.py:397 内容类型选择](https://github.com/ysc070528/granttrace/blob/863b0a87572a14b6203cc6115184666cd18bddae/core/parser.py#L397)。

## 4. 两组未解决的新鲜度探针

`verify_pr42_adversarial.py` 除运行回归，还单独记录下面两组探针，**不计入通过测试数量**：

| 探针 | 夹具实际状态 | 工具仍可能输出 | 为什么不能视作已解决 |
|---|---|---|---|
| opaque_cached_after | PATCH 已改变数据，GET 无 Age/Warning 地回旧状态 | SECURE、rollback_verified=true，实际未恢复 | 后端故意违背已声明 strong，响应中没有可检测的新鲜度反证。 |
| opaque_cached_restore | 恢复 ACK 成功但没应用，GET 无标记回原状态 | CONFIRMED、rollback_verified=true，实际未恢复 | 与真正已恢复的网络观察相同；仅增加重复 GET 也不能证明服务端真实状态。 |

两组都在修改前后复现，证据 JSON 的 `unsupported_contract_probes` 明确 `solved:false`。
复现脚本在回归通过但这些风险仍存在时退出 **3**，表示有条件验收；原提交存在回归失败时退出 1。没有以退出 0 包装所有反例通过。
没有以“没有缓存头”作为新鲜度证明，也没有把这些风险隐去。当前保证限于已观察文档和真实独立读回前提。
若要在不具备此保证的后端主动写入，需要可核验版本/ETag、服务端权威读、数据库对照或业务事务协议；这涉及额外合同与配置，本轮未擅自设计实现。
SIGKILL、进程崩溃、断电也不能依靠 Python finally 兑现恢复；测试覆盖的是可捕获 KeyboardInterrupt/SystemExit，以及恢复不可证后停写。

## 5. 原剩余十二场景逐项分类

分类规则先于统计：A=安全保护正确，不应放开；B=证据不足必须不确定；C=有泄露线索只能可疑；D=可安全修的实际检测缺陷；E=真值/口径调整。
原定义和服务器行为来源为 [scripts/verify_authorization_coverage.py 的 SCENARIOS 与 Handler](../scripts/verify_authorization_coverage.py)，原始逐项结果来源 [authorization-coverage-results.json](authorization-coverage-results.json)。

| 场景 | 当前状态 | 分类 | 原因与处理 |
|---|---|---|---|
| error_500_owner_data | SUSPICIOUS | C | 500 正文含 Owner 数据；不是成功访问基线，不能升级确认。 |
| error_404_owner_data | SUSPICIOUS | C | 404 正文含 Owner 数据；不等于可信拒绝，也不能直接确认。 |
| truncated_owner_response | INCONCLUSIVE | B | Owner 证据被截断，比对不完整。 |
| patch_initial_202 | INCONCLUSIVE | A | 初始状态尚未形成权威快照，不发 PATCH。 |
| patch_initial_206 | INCONCLUSIVE | A | 初始表示为部分内容，不发 PATCH。 |
| patch_initial_content_range | INCONCLUSIVE | A | 即便状态 200，Content-Range 仍表明部分表示，不发 PATCH。 |
| patch_stale_202 | INCONCLUSIVE | B | 写后 pending 表示不能证明持久化；恢复已核验。 |
| patch_stale_203 | INCONCLUSIVE | B | 写后非权威表示不能证明持久化；恢复已核验。 |
| patch_stale_206 | INCONCLUSIVE | B | 写后部分内容不能证明持久化；恢复已核验。 |
| patch_invalid_after | INCONCLUSIVE | B | 写后无效 JSON；不能凭成功 ACK 确认。 |
| patch_default_readonly | SKIPPED | A | 没有开启主动写入。 |
| patch_not_allowlisted | SKIPPED | A | 未授权本端点的写测试。 |

合计 A=5、B=5、C=2、D=0。**本次三个新缺陷位于原十二场景以外，不能倒改原十二场景来美化检出率。**
E 是跨场景口径问题：原 `false_negatives=12` 实际指全部已知漏洞未确认，包含安全阻断与刻意破坏证据的对照，不能解释成十二个可修复检测器缺陷；场景的“服务器有漏洞”真值仍保留。

## 6. 正确统计

本地完整复跑原提交 650 项测试通过；最终修复后完整复跑 670 项通过；Ruff/Mypy、原 36 场景、六业务场景、JSON/YAML 示例和源码外安装/Demo 重新通过。
详细原始计数、覆盖分子/分母、源码及测试指纹、对抗失败轨迹都在 [pr42-independent-results.json](pr42-independent-results.json)。

| 指标（同一原始 36 场景） | 被审提交 | 修复后 |
|---|---:|---:|
| 已知漏洞完整分母 | 25 | 25 |
| CONFIRMED | 13 | 13 |
| 全分母确认率 | 13/25=52% | 13/25=52% |
| 未确认的已知漏洞（含保护对照） | 12 | 12 |
| 先验可开展检测的漏洞分母 | 20 | 20 |
| 该分母内确认率 | 13/20=65% | 13/20=65% |
| 原场景中无漏洞却确认 | 0 | 0 |

65% 的分母只排除上表 A 中五个**事先设计为无写权限或无初始快照**的控制场景；不排除运行后的失败、不完整响应或错误状态。
B 的五个和 C 的两个全部仍在 20 的分母内。不把可疑算成检出，不另造“排除一切失败后 100%”作为性能数字。
该条件确认率只描述这组人为夹具，不代表真实 API 的检出率。

原提交覆盖率澄清：

- 语句：4427 / 4984 = **88.82%**。
- 分支：2125 / 2570 = **82.68%**。
- coverage.py 综合： (4427 + 2125) / (4984 + 2570) = **86.74%**。

此前把最后一项叫作“分支覆盖率”不准确，现已更正。`num_partial_branches` 也不是未覆盖分支总数，应使用 `covered_branches / num_branches`。
修复后：语句 4457/5011=**88.94%**，分支 2141/2586=**82.79%**，综合 6598/7597=**86.85%**。
三个分子/分母单独保存在新证据 JSON，避免依赖不同机器测试时间或百分比尾数。

## 7. 当前兼容性验收与人工余项

| 项目 | 本地新执行 | 当前提交 CI / 人工边界 |
|---|---|---|
| Python 3.12 | 670 测试、覆盖率、安装、Demo、报告、示例通过 | 当前 PR HEAD 的 Actions 为平台补充证据，见 PR 描述中的对应 run。 |
| Python 3.9 / 3.14 | 当前容器不可执行这些解释器，标为本地未验证 | 必须核实新提交的 CI，不能借用 863b0a8 的旧成功记录。 |
| Windows 便携包 | Linux 容器不能运行，标为本地未验证 | 新 HEAD Windows CI 要求重新构建 ZIP/SHA256、解压后源码外及 PATH 隔离验收。 |
| Start-Demo.bat | Linux 未执行 | Windows 验证脚本会用 cmd /c call 实际运行批处理；CI 通过仍不代表真实桌面双击和默认浏览器打开。 |
| HTML / JSON / SARIF | 原回归和源码外安装复跑通过；可疑错误正文不导出为 SARIF 确认项 | schema 2、CLI 参数及配置格式未改。 |
| 默认只读 / dry-run | 新回归、旧 CLI/配置回归和安装验证重新通过；0 PATCH / 0 请求 | 保留保护，不为了提高 52% 放开。 |
| 恢复失败停写 | 新串行、并发、异常退出测试通过 | 只协调当前进程当前 auditor；强制终止和外部并发另见限制。 |

Windows 剩余人工验收：从本次 CI 产物完整解压，在目标 Windows 机器上双击 Start-Demo.bat，确认默认浏览器实际打开 HTML、JSON 保存、终端恢复/服务关闭结果；再按需执行 U 盘跨机、中文/空格目录及系统拦截提示检查。
没有以历史 U 盘验收代替本次结果。CI 的 `launcher_browser_open_suppressed_for_smoke` 会刻意抑制打开浏览器，不能据此宣称真实浏览器体验已验证。

## 8. 尚存风险与合并条件

- 已复现的 F1/F2/F3 已修复；在声明的独立权威读回合同成立时，本轮未发现其他未修复的阻断性 P0/P1。
- 高影响前提风险：无标记陈旧 200、初始读回自身隐藏字段、服务端未观测副作用，仍可能让状态判断不真实。两组危险反例仍存在，必须保持披露并限制写测试适用环境。
- P2：完整库级计划诊断、跨进程/外部更新协调、硬终止后的人工恢复，以及一般业务授权/共享/可信 ID 配置正确性。本轮未新增检测器或恢复协议。
- 人工合并条件：审阅 F1/F2/F3 的最小 diff；核对当前 HEAD 的所有 CI；接受并保留读回前提与未解决反例披露；完成需要交付的目标 Windows 桌面/浏览器人工验收。

当前仅提交到 PR #42 原分支，等待维护者决定。没有自动合并或发布。
