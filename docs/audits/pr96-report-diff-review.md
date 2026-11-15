# PR #96 合并前独立复核：`granttrace diff`

复核对象：PR #96（`feat/report-diff`），两轮审计，日期 2026-11-13 至 2026-11-14。
第一轮审计提交 `7393226`，第二轮（本文件主体）审计提交 `c8a2b7b`；修复提交位于同一分支，可在 PR diff 中审查。
复核由实现这段代码的同一方执行。结论依据是可重复运行的反例和测试，不代表另一位人工审查者的判断。
全部反例使用合成账号和本机回环地址上的测试服务；没有使用真实凭据、真实目标或真实扫描数据。
PR 保持 Draft，不合并、不发布、不创建 Tag。

## 1. 结论

第二轮复核的三个问题中，两个是缺陷，已修复：

- **问题一**：没有可核对的 `comparison_context` 时，`--assume-same-identities` 实际上同时担保了规范和配置。
- **问题二**：没有实际请求支撑的确定判定，可以把 CONFIRMED 变成 `resolved`。

第三个是过时的文档说明，已改正。修复后所有已知反例都不再产生 `resolved`，合法场景的兼容性保持不变。

**安全不变量：** 只有在两份报告被证明针对同一目标、同一组测试身份，且该操作的规范、策略和资源都未变化时，才给出 `new`、`persisting` 或 `resolved`。证明不了的每一项，只能由使用者用对应的参数逐项声明为假设；每个假设只覆盖它所说的那一项，不覆盖任何已检测到的变化，并记录在比较结果和每一条依赖它的结论上。参与结论的判定必须有实际发出的请求作支撑。

## 2. 第二轮：复核的三个问题（`c8a2b7b`）

### 问题一（P0，已修复）：账号假设被扩大为整个配置一致

位置：[`compare_reports`](https://github.com/ysc070528/granttrace/blob/c8a2b7baf504463cf6f9d0ccaed15897c40e52f7/core/report_diff.py#L692) 中身份判断之后没有任何配置条件；[`scope_reasons`](https://github.com/ysc070528/granttrace/blob/c8a2b7baf504463cf6f9d0ccaed15897c40e52f7/core/report_diff.py#L784) 在没有上下文时只比较证据中的请求路径、查询参数和三项判定依据。

**复现**：真实扫描器对本机测试服务扫描两次。服务在第二次扫描时**漏洞仍然存在**，目标端口和账号都相同，只改变下面一处：

- A：OpenAPI 规范新增一个可选 header 参数，其默认值让请求走到做了正确授权的边缘节点，配置不变；
- B：规范不变，`parameter_values.common` 设置同一个 header。

两次扫描的判定分别为 CONFIRMED 和 SECURE，证据中的 `target_url`、`visitor_self_url` 完全相同；header 值不在证据中，证据比较无从发现差异。

| | 不设密钥，`--assume-same-identities` | 不设密钥，三项假设 | 设密钥，任意假设 |
|---|---|---|---|
| `c8a2b7b` | **`resolved`**（只记录 `same_identities`） | 不支持该参数 | A：`spec_changed`；B：`resources_changed` |
| 修复后 | `not_comparable`（`configuration_unverified`） | `resolved`，记录 `same_identities`、`same_configuration` | 同左，假设不能覆盖 |

**影响**：使用者只声明「账号相同」，工具却把一个仍然存在的漏洞报告为已修复。

**修复**：没有匹配的带密钥上下文时，新增全局阻断原因 `configuration_unverified`，只能由新参数 `--assume-same-configuration` 解除，并以 `same_configuration` 记录。三个假设各自独立，证据中可见的变化仍然阻断。

**回归测试**：
- `test_an_assumption_covers_only_its_own_condition`（单元）
- `test_an_assumption_about_accounts_never_covers_the_configuration`（真实扫描，A、B 各在有密钥和无密钥下）
- 随机化差分测试的规则实现同步更新
- Windows 便携版验证脚本新增「账号假设不能覆盖配置」一步

### 问题二（P1，已修复）：没有请求支撑的确定判定支持结论

位置：[`_Entry.conclusive_negative`](https://github.com/ysc070528/granttrace/blob/c8a2b7baf504463cf6f9d0ccaed15897c40e52f7/core/report_diff.py#L444) 只看判定字符串；对照测试 [`test_one_sided_evidence_does_not_outrank_agreeing_fingerprints`](https://github.com/ysc070528/granttrace/blob/c8a2b7baf504463cf6f9d0ccaed15897c40e52f7/tests/test_report_diff.py#L689) 用一条没有任何证据的 SECURE 记录得出了 `resolved`。

扫描器自己计算确定覆盖率时，要求记录的 `requests_attempted > 0`（[`core/results.py`](https://github.com/ysc070528/granttrace/blob/c8a2b7baf504463cf6f9d0ccaed15897c40e52f7/core/results.py#L272)），且有专门测试 `test_local_errors_and_zero_request_conclusive_records_are_not_coverage`。`diff` 没有采用同一规则。

| 当前 SECURE 记录 | `c8a2b7b`（同一密钥上下文） | 修复后 |
|---|---|---|
| `requests_attempted: 0` | **`resolved`**，`fully_comparable=true` | `not_comparable`（`current_unverified`） |
| 没有任何证据，报告版本 2.8.0 | **`resolved`**，`fully_comparable=true` | `not_comparable`（`current_unverified`） |
| `requests_attempted: true` | **`resolved`**，`fully_comparable=true` | `not_comparable`（`current_unverified`） |

**必需证据与辅助证据的界线**：

- **必需**：每条参与结论的确定判定都要有 `requests_attempted` ≥ 1 的整数。
  - 2.5.3 起所有扫描结果都记录该字段；2.4.1 至 2.5.2 写的 schema 2 报告从不记录，缺失时视为未知而不是零，予以豁免。
  - 字段存在而为 0 或类型错误时，任何版本都不豁免；版本号无法读取时也不豁免。
- **辅助（可缺失）**：请求 URL、判定细节等。
  - 字段策略（BOPLA）会把整份报告所有记录的 `target_url` 置空，包括其他操作的记录。
  - 有同一密钥的指纹覆盖资源时，单侧缺少 URL 不阻断；没有指纹时仍按 `scope_unknown` 阻断。
- **方向**：没有请求支撑的 CONFIRMED 仍会列出（不会让漏洞从比较结果中消失），但不能支持 `new`、`persisting`、`resolved`；没有请求支撑的判定也不算确定覆盖。

**兼容性证据**：

| 场景 | `c8a2b7b` | 修复后 |
|---|---|---|
| 两份 2.5.2 报告（无请求计数）+ 假设 | `resolved` | `resolved` |
| 真实扫描：第二次为另一个操作增加字段策略，订单记录失去 URL 但保留请求计数 | `resolved` | `resolved` |
| 真实 RBAC 扫描（内置 HTTP 执行器） | 确定判定的请求计数为 2–3 | 不受影响 |

在 `c8a2b7b` 的全部测试运行期间，扫描器共记录 768 条确定判定，其中没有请求计数的 13 条都来自替换了 HTTP 执行器的单元测试，或上面那条「零请求不算覆盖」的专门测试。

**回归测试**：
- `ObservationTests`（6 项，含 8 种无效计数 × 8 种转换、版本豁免边界、Mass Assignment 汇总记录、覆盖率）
- `test_request_urls_missing_on_one_side_are_covered_by_agreeing_fingerprints_only`
- `test_a_field_policy_elsewhere_removes_request_urls_without_blocking_a_fix`（真实扫描）
- 随机化差分测试加入无请求记录

### 问题三（文档，已改正）

[`core/report_diff.py` 模块说明](https://github.com/ysc070528/granttrace/blob/c8a2b7baf504463cf6f9d0ccaed15897c40e52f7/core/report_diff.py#L36) 仍写着 “credentials are never fingerprinted”。实际实现是：

- 凭据不写入报告，也不单独计算指纹。
- 身份指纹在计算前遮盖凭据，所以轮换凭据不被当成换了身份。
- 所有已识别的凭据合并计算一个 `credentials` 指纹，任一凭据变化都会被发现；轮换与换号无法区分，所以凭据变化后账号视为未验证。

现已改写，并补充两项限制：
1. 同时持有比较密钥且知道其余所有凭据的人，可以用合并指纹验证对剩余一个凭据的猜测。
2. 没有被识别为凭据的值不会被遮盖，会和所在配置项一起计算指纹。

`docs/advanced.md` 同步补充。

## 3. 离线最小反例

两份报告除判定外完全相同，正是问题一中真实扫描写出的形态（账号号码、地址均为合成值）：

```json
{"tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000", "stats": {},
 "results": [{"endpoint": "GET /orders/{orderId}", "check": "BOLA", "verdict": "CONFIRMED",
              "evidence": {"requests_attempted": 4,
                           "target_url": "http://127.0.0.1:8000/orders/11",
                           "visitor_self_url": "http://127.0.0.1:8000/orders/22"}}]}
```

当前报告把 `verdict` 改为 `SECURE`；问题二的变体再把 `requests_attempted` 改为 `0`。

| 命令 | `c8a2b7b` | 修复后 |
|---|---|---|
| `granttrace diff baseline.json current.json --assume-same-identities` | `resolved` | `not_comparable`（`configuration_unverified`） |
| 同上，再加 `--assume-same-configuration` | 参数不存在 | `resolved`，记录两项假设 |
| 问题二变体，加修复后所需的全部假设 | `resolved`（旧版只需 `--assume-same-identities`） | `not_comparable`（`current_unverified`） |

## 4. 第一轮摘要（`7393226`）

第一轮确认 18 个问题（7 个 P0、6 个 P1、5 个 P2），已在 `3365c25` 等提交中修复。主要包括：

- 规范修改、非凭据身份 header、换成另一账号的凭据、无密钥或无账号 `id` 的扫描，都能把仍存在的漏洞报告为 `resolved`，其中多数还标为 `fully_comparable`；
- 截断或类型错误的上下文被当作「未变化」；
- 读不出主体的记录跨主体匹配；
- 无法解析的 CONFIRMED 记录被丢弃；
- 16 位弱密钥可被离线恢复；
- 报告中的任意文本进入输出；
- 重复 JSON 键被接受。

修复方式见 PR 描述及提交说明。

## 5. 验证

- `tests/test_report_diff.py`：85 项测试，约 5,500 个子测试。新增测试在 `c8a2b7b` 上运行时失败：
  - 行为断言失败：问题二的单元测试得到 `resolved`、`new` 或 `persisting`；问题一的单元测试缺少 `configuration_unverified`。
  - 因旧版没有新参数而以退出码 2 结束：端到端测试；它们的行为证据见第 2 节探针结果。
  - 修复后全部通过。
- 全量测试 1420 项通过，输出快照与 `main` 一致；Ruff、Mypy 通过。
- 四个 Python 版本的矩阵、GitHub CI（含 CodeQL 和 Windows 便携版）的结果以 PR #96 描述中的验证表为准。

## 6. 残余限制

- 报告没有签名；能修改报告的人可以修改判定或复制上下文（每次比较都会在 `comparability.not_verified` 中列出）。
- 两次扫描之间服务端测试数据的变化无法得知；`resolved` 只表示「相同配置下不再复现」。
- 不设密钥时，三项假设都是使用者的声明，工具只核对证据中可见的部分；凡依赖假设的结论都会标注。
- 人为选择的比较密钥仍可能被离线猜出；应使用随机密钥。
- 扫描时的命令行开关（例如只读模式、超时、响应大小上限）不在指纹中。按代码审查，它们只会让检查变为 SKIPPED、INCONCLUSIVE 或 ERROR，没有发现能把 CONFIRMED 变成确定安全结论的开关；这一点没有逐项做端到端验证。
