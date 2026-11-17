# CI 安全回归门禁

[English](ci-gate.md)

`granttrace diff` 离线比较两份 JSON 扫描报告（见[对比两次扫描](advanced.md#对比两次扫描granttrace-diff)）。
加上一个或多个 `--fail-on-*` 参数后，它还会决定流水线能否继续：按你的选择，在出现新增确认漏洞、
确定性覆盖率下降或无法比较的漏洞时阻断。

不加这些参数时，`granttrace diff` 的行为与以前完全相同：终端输出和 JSON 不变，比较完成时退出码为 `0`，
输入无效时为 `2`。

门禁是 **fail-closed** 的：不可比较的结果、没有证据支撑的判定、你声明的假设，都不会被当作通过。
通过只表示启用的条件没有出现，**不表示 API 是安全的**。

## 快速开始

```bash
granttrace diff baseline.json current.json --fail-on-new --fail-on-coverage-decrease
```

两次扫描应设置同一个 `GRANTTRACE_COMPARISON_KEY`、针对同一个目标，并给每个测试身份填写账号 `id`。
这样报告带有密钥指纹，门禁可以核实目标、测试账号和配置没有变化。不设密钥时门禁无法通过（退出码 `3`），
见[假设](#假设)。

## 参数

| 参数 | 作用 |
|---|---|
| `--fail-on-new` | 出现新增确认漏洞时退出码 `1`。当前报告中的确认漏洞无法证明已在基线中存在，或基线已核实不受影响的检查现在无法核实时，退出码 `3` |
| `--fail-on-coverage-decrease` | 确定性覆盖率下降时退出码 `1` |
| `--fail-on-not-comparable` | 任一份报告中有确认漏洞无法比较时退出码 `3` |
| `--gate-allow-assumptions` | 允许依赖 `--assume-*` 声明的结论参与门禁判断；必须同时使用至少一个 `--fail-on-*` |
| `--github-actions` | 输出 GitHub Actions 注解和步骤摘要，见 [GitHub Actions](#github-actions) |

参数必须完整拼写，不能缩写。

## 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 每个启用的条件都已证明成立。不加 `--fail-on-*` 时：比较已完成 |
| `1` | **发现回归**：启用的条件被违反，且两份报告已证明可比 |
| `2` | 输入或参数无效，或输出无法写入；没有门禁结论 |
| `3` | **无法核实**：启用的条件既不能证明成立，也不能证明被违反 |

同时满足多种情况时，`2` 优先于 `1`，`1` 优先于 `3`，已证实的回归不会被降级为「无法核实」。

任何非零退出码都会让 CI 步骤失败。如果只想在已证实的回归时阻断、把 `3` 当作警告，需要在流水线中明确写出，
例如在 shell 步骤中：

```bash
set +e
granttrace diff baseline.json current.json --fail-on-new --github-actions
code=$?
if [ "$code" -eq 3 ]; then echo "::warning::GrantTrace 无法核实门禁"; exit 0; fi
exit "$code"
```

## 各条件检查什么

漏洞和检查的标识方式与 `granttrace diff` 相同：检查类型、操作模板和主体。JSON 中每一项都带有下列原因代码之一。

### `--fail-on-new`

| 结果 | 情况 | 原因代码 |
|---|---|---|
| 回归（1） | 基线已核实该检查不受影响，当前确认存在漏洞 | `new_finding` |
| 无法核实（3） | 当前报告中的确认漏洞既不是新增也不是持续存在：首次发现、新操作、规范/策略/资源变化、基线未核实、判定没有实际请求、主体无法识别 | `confirmed_not_comparable` |
| 无法核实（3） | 基线已核实不受影响的检查，当前没有确定结论：ERROR、SKIPPED、INCONCLUSIVE、判定没有实际请求、检查缺失或操作被移除 | `no_longer_verified` |
| 无法核实（3） | 基线已核实不受影响的检查，当前变为 PUBLIC 或 AUTHORIZED，同时该操作的规范、策略或资源发生了变化或无法证明未变化（与 `diff` 判断确认漏洞时的规则相同；请求路径有任何差异也算变化） | `accepted_after_declaration_change` |

后两行很重要：仅仅「当前没有新增确认漏洞」是不够的。漏洞可能藏在一个不再得出结论的检查后面，
也可能藏在一次同时修改了判定依据的改动后面，例如在规范中去掉该操作的 `security`，或在策略中允许 Visitor 访问。

持续存在的漏洞不会让 `--fail-on-new` 失败：这个条件回答的是「是否变差」。如果要在存在任何确认漏洞时阻断，
请在扫描时使用 `--fail-on-vuln`。

### `--fail-on-coverage-decrease`

| 结果 | 情况 | 原因代码 |
|---|---|---|
| 回归（1） | 基线中有确定结论的检查，当前没有（包括被移除操作的检查） | `conclusive_check_lost` |
| 回归（1） | 报告统计中的确定性覆盖率百分比下降，例如新增了无法得出确定结论的操作 | `coverage_pct_decreased` |

与比较结果中 `coverage.decreased` 的定义相同。

### `--fail-on-not-comparable`

| 结果 | 情况 | 原因代码 |
|---|---|---|
| 无法核实（3） | 任一份报告中的确认漏洞无法比较；同时列出比较给出的原因代码 | `finding_not_comparable` |

## 门禁无法通过的情况

无论启用哪个条件，出现以下情况时结果至多为「无法核实」（退出码 `3`）：

| 原因代码 | 情况 |
|---|---|
| `comparison_blocked` | 比较存在阻断原因：目标、测试账号或配置无法核对或已变化，或存在可能是确认漏洞但无法解析的记录 |
| `assumptions_not_allowed` | 比较依赖 `--assume-*` 声明，但没有使用 `--gate-allow-assumptions` |
| `no_conclusive_results` | 当前报告没有任何确定结论，例如目标无法访问 |

在未证明可比的报告之间看到的覆盖率下降，记为「无法核实」，不记为回归。

## 假设

没有匹配的密钥指纹时（未设密钥、两次密钥不同，或 2.7.1 及更早版本的报告），需要
`--assume-same-identities` 和 `--assume-same-configuration`，目标不同时还需要 `--assume-same-target`。
这些是你的声明，不是报告能证明的事实。默认情况下门禁不让它们决定结果：退出码 `3`，原因 `assumptions_not_allowed`。

`--gate-allow-assumptions` 允许它们参与判断，此时结果会标明依赖假设：JSON 中 `verified` 为 `false`，
`relies_on_assumptions` 列出这些假设，终端、注解和步骤摘要也会写明。依赖假设发现的回归仍然返回 `1`。
假设永远不能覆盖报告中可见的变化。

优先使用比较密钥；在 CI 中把它保存为 secret。

## GitHub Actions

GitHub Actions 的 runner 会读取步骤打印的每一行（stdout 和 stderr），执行行首的 `::命令::` 和行内任意位置的旧格式
`##[命令]`。报告中的角色名、字段名是自由文本，所以无论是否使用 `--github-actions`，`granttrace diff` 的终端输出都会转义
这两种标记：`##[` 输出为 `##\u005b`，行首 `::` 的第一个冒号输出为 `\u003a`。这是对输出文字的唯一改动，只影响含有这些
标记的文字；JSON、步骤摘要和注解保持原值。

`--github-actions` 在正常输出之外增加：

- **日志的第二道防护**：所有来自报告的内容都打印在 `::stop-commands::` 与其随机令牌之间，即使将来某处漏掉了转义，
  runner 也不会执行其中的命令。
- **注解**：每个回归一条 error，每个无法核实的条目一条 warning，各最多 9 条；最后一条给出结果：失败或无法核实为
  error，依赖假设的通过为 warning，已核实的通过为 notice。
- **步骤摘要**：向 `$GITHUB_STEP_SUMMARY` 追加 Markdown 摘要：结果、各条件、最多 100 个条目。来自报告的文字经过编码，
  无法形成链接、图片、HTML 或表格单元格。变量未设置时只在 stderr 提示，其他行为不变；文件无法写入时退出码为 `2`。

不加 `--fail-on-*` 也可以使用 `--github-actions`：此时把比较结果写入步骤摘要并保护日志，不输出注解。

### 示例工作流

[`examples/github-actions/granttrace-security-gate.yml`](../examples/github-actions/granttrace-security-gate.yml)
分别扫描基线分支和 Pull Request（被测服务由工作流在 127.0.0.1 上启动），然后运行门禁。使用前：

1. 添加仓库 secret `GRANTTRACE_COMPARISON_KEY`：`python -c "import secrets; print(secrets.token_hex(32))"`。
   来自 fork 的 Pull Request 拿不到 secret，门禁会返回 `3`。
2. GrantTrace 配置保存在基线分支，两次扫描都从基线分支读取，Pull Request 无法修改用来评判它的身份、策略和资源参数。
   OpenAPI 规范取自各自的分支：被修改的操作会变为不可比较，以退出码 `3` 交给人工审查。
3. Pull Request 的代码与门禁运行在同一个 runner 上，可能修改那里的文件。请把被测服务运行在不挂载工作区的容器中，
   只把密钥交给扫描步骤，并要求外部贡献者的工作流经审批后运行。
4. Pull Request 可以修改工作流本身。请把该 job 设为必需的状态检查，并通过 code owner 审查保护 `.github/`。
5. 保持 `pull_request` 触发器。`pull_request_target` 会让 Pull Request 的代码能够访问你的 secret。
6. 只扫描工作流自己启动的服务。GrantTrace 的安全规则与普通扫描相同：不向外部目标发送 PATCH、PUT、DELETE。

基线必须来自 Pull Request 无法影响的来源。伪造的基线如果把某个漏洞列为已确认，它就成了「持续存在」，
而 `--fail-on-new` 不会因持续存在的漏洞而失败。

## 输出

终端在比较摘要之后输出门禁：结果和退出码、各条件、最多 50 个条目，以及退出码说明。

使用 `--export-json` 时，比较结果增加 `gate` 对象（仅在使用 `--fail-on-*` 时出现；`comparison_schema_version` 仍为 1）：

| 字段 | 内容 |
|---|---|
| `gate_schema_version` | 1 |
| `result` | `passed`、`failed` 或 `unverified` |
| `exit_code` | 0、1 或 3 |
| `verified` | 结果不依赖任何假设时为 `true`；`unverified` 时始终为 `false` |
| `allow_assumptions` | 是否使用了 `--gate-allow-assumptions` |
| `relies_on_assumptions` | 结果所依赖的假设 |
| `prerequisites` | 未满足的前提，每项含 `reason` 以及阻断代码或假设 |
| `conditions` | 每个启用条件的 `condition`、`flag`、`result`、`regressions`、`unverified` |

条目包含原因代码、Finding ID、检查类型、操作模板、主体、基线和当前的判定，漏洞条目还包含比较给出的原因代码。
与比较结果一样，门禁输出不包含证据、URL、凭据或报告中的自由文本。

## 门禁不能证明的事

- API 是安全的。持续存在的漏洞，以及两次扫描都没有核实的检查，都不在比较范围内。
- 报告是真实的。报告没有签名，见 `comparability.not_verified`。
- 两次扫描之间服务端的测试数据没有变化。

兼容性：不新增依赖；支持 Python 3.9 及以上版本；Windows 便携版包含门禁功能。
