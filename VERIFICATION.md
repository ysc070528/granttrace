# API-Sentinel 验收记录

## v2.3.1-final 修复版验收记录

日期：2026-10-02。环境：Windows、Python 3.12.11、PyYAML 6.0.3。

### 实际完成的验证

- **完整测试：223/223 通过，0 失败、0 错误、0 跳过，约 5.51 秒。** 原有 178 项加发布回归 45 项；四个新模块分别为 BOLA 8 项、配置 17 项、证据 13 项、事务 7 项。真实 YAML 成功加载和模拟缺依赖错误均已覆盖。
- 所有产品 Python 源码通过 Python 3.9 语法模式解析；本次没有运行 Python 3.9 解释器。
- `config.json`、`config.example.json` 及真实 YAML 规范的配置预检返回 0；dry-run 导出计划中的 `requests_sent` 为 0。
- 完整 CLI 只读扫描：1 个 CONFIRMED、1 个 PUBLIC、1 个 SECURE、2 个 SKIPPED；确定性覆盖率 60%。
- 完整 CLI 主动扫描分别使用 JSON/YAML 规范：两次均检出靶场预设的 2 个漏洞；1 个 PUBLIC、2 个 SECURE；0 错误、0 不确定、0 可疑；确定性覆盖率 100%。
- 每次扫描后，对整份模拟数据库与写前快照做比较，结果一致；批量赋值发现的独立恢复核验为成功。
- 同时开启漏洞、错误、可疑及 100% 覆盖率门槛时，主动扫描因靶场预设漏洞返回 1。
- wheel 构建成功：`api_sentinel-2.3.1-py3-none-any.whl`。在单独新建的虚拟环境执行 `pip install --no-index --no-deps` 安装本地 wheel，并从源码目录外运行安装后的 `api-sentinel`：版本、JSON 配置预检、dry-run 均返回 0；导入位置确认来自安装环境，运行时版本为 `2.3.1-final`，包版本为 `2.3.1`。这项测试验证本地 wheel 内容与入口，不声称在该新环境完成网络依赖解析；真实 PyYAML 验证在另一个独立验证环境完成。

### 修复反例

- 访客正常拒绝、匿名 404/500 正文带私有业务数据：SUSPICIOUS，不再计入安全或确定性覆盖。
- 非有限数或浮点溢出的读回：在主动写入前拒绝，PATCH 请求数为 0；写后出现非法读回仍执行恢复。
- Cookie 分量、特殊 Cookie 名称、编码值及数字凭据回显：默认 JSON/HTML 证据不保留已知凭据；显式敏感证据开关保持原有行为。
- 错误读回参数形状：配置预检返回 2，尚未创建审计器或建立连接。
- OpenAPI 自定义认证头：JSON/YAML 在配置预检与 dry-run 两种入口都返回 0。

### 交付范围

ZIP 为 `API-Sentinel-Hardened-v2.3.1-final.zip`，根目录为 `API-Sentinel-Hardened/`，正式文件 44 个。归档排除构建目录、egg-info、Python 缓存、虚拟环境和临时扫描输出；保留重新生成的两个参考报告。原始 v2.3.0-final ZIP 与审查副本保持不变。

未访问真实业务 API，未执行线上部署，未运行 GitHub Actions；本地靶场的 100% 覆盖率只属于这 5 个示例端点。应用层恢复不能通用撤销并发业务修改、异步任务或读回未暴露的外部副作用。

---

## v2.3.0-final 最终验收记录

日期：2026-10-02。环境：Windows，Python 3.12.11。

### 1. 自动化回归测试（178 / 178 PASS）
- **完整测试矩阵**：运行 `python test_suite.py`，全量 **178/178 项全部通过**（0 失败，0 错误，耗时约 5.3s）。
- **测试分布与覆盖（共 10 个测试模块，总计 178 项全部 PASS）**：
  1. `tests/test_auditor_integration.py`: 12 项
  2. `tests/test_config_validation.py`: 22 项
  3. `tests/test_diff.py`: 16 项
  4. `tests/test_diff_hardening.py`: 18 项
  5. `tests/test_evidence.py`: 15 项
  6. `tests/test_parser_generator_hardening.py`: 6 项
  7. `tests/test_rc2_security_hardening.py`: 20 项
  8. `tests/test_rc3_hardening.py`: 18 项
  9. `tests/test_schema_regressions.py`: 18 项
  10. `tests/test_v22_auditor_hardening.py`: 33 项

### 2. 离线配置语义校验验收
- 执行 `python api_sentinel.py --spec openapi.json --config config.json --validate-config`：返回码 0，完全无网络请求，耗时约 0.05s。
- 执行 `python api_sentinel.py --spec openapi.json --config config.example.json --validate-config`：返回码 0。
- 执行非法配置（如读写路径碰撞、操作键空格不规范、小写 HTTP 方法、未映射字段）：正常扫描入口与 `--validate-config` 均在发起网络连接前以退出码 2 退出，并精准输出定位信息。

### 3. 本地靶场端到端回归验收
- 启动 `mock_server/server.py`，执行只读扫描：3 个 GET 端点正常检查，2 个写接口按预期标记为 `SKIPPED`。
- 执行带写测试扫描 `--allow-write-tests`：
  - 准确检出故意保留的 2 个漏洞（CWE-639 BOLA 越权，CWE-915 Mass Assignment 特权篡改）；
  - 1 个 PUBLIC 端点、2 个 SECURE 端点；0 错误、0 不确定，确定性覆盖率 100%；
  - 事务回滚机制生效，测试结束后靶场数据库快照与测试前比对一致。

### 4. Python Wheel 构建验收
- 执行构建命令：`pip wheel . --no-deps`。
- 规范性核查：`pyproject.toml` 中 `version = "2.3.0"` 符合 PEP 440；wheel 构建成功，生成 `api_sentinel-2.3.0-py3-none-any.whl`（大小约 79.2 KB）。
- 构建环境清理：构建完成后已清理 `build/`、`temp_dist/`、`*.egg-info` 等中间产物，未混入交付包。

### 5. 交付 ZIP 清洁检查验收
- 交付归档名称：`API-Sentinel-Hardened-v2.3.0-final.zip`。
- 归档文件构成：**严格 40 个正式文件**，顶层目录统一定义为 `API-Sentinel-Hardened/`。
- 清洁度核验结果：
  - 确认**零** `__pycache__`、**零** `*.pyc`、**零** `.pytest_cache`、**零** `.git` 目录；
  - 确认**零**临时扫描输出物（无 `result.json`、`report.html`、`scan.log`、`API_Security_Report.html`）；
  - 保留标准离线参考示例：`examples/sample_report.html` 与 `examples/sample_result.json`；
  - 确认 `config.json` 与 `config.example.json` 仅包含本地测试专用的 Mock 占位符（`TOKEN_ALICE_OWNER_1001`、`TOKEN_BOB_VISITOR_1002`、RFC 4122 示例 UUID），无真实敏感凭据；
  - 自动化模式扫描未发现真实密钥、个人用户名或本机绝对路径（文本与字节扫描 0 命中）。

---

## v2.2.0 本地验收记录（历史归档）

> [!NOTE]
> 以下为 **v2.2.0 历史验收记录**，保留作为历史实现追溯参考。

日期：2026-10-01。环境：Windows，Python 3.12.11。

## 已执行的验证

- 完整回归：118 / 118 通过（v2.1 原有 34 项，新增 84 项）。
- 所有 Python 源文件通过 Python 3.9 语法模式解析；这不等于在 Python 3.9 运行过。
- 本地 HTTP 靶场：5 个端点，确认 2 个故意保留的漏洞（CWE-639 和 CWE-915）；1 个 PUBLIC、2 个 SECURE；0 错误、0 不确定，确定性覆盖率 100%。
- 开启错误、漏洞、可疑结果、100% 覆盖率门槛后，CLI 正确以退出码 1 报告靶场漏洞。
- 主动扫描结束后，整份模拟数据库与扫描前快照完全一致，不只检查 role。
- 示例 HTML / JSON 重新生成；报告中的已知凭据、姓名、工资已作脱敏。检查 HTML 转义和离线内容，不声称已完成浏览器视觉验收。
- 新增单元反例包括恢复函数自身异常、回滚失败后停写、异步请求停写、完整数组恢复、派生权限残留检测和真实 readOnly 字段攻击链。

## 复查问题与处理

| 原问题 | 本版处理 |
|---|---|
| R01 普通字段/数组被改坏却声称回滚成功 | 实际业务值来自快照，完整容器恢复，默认核验整份读回状态 |
| R02 提交后解码/读回异常绕过回滚 | 异常进入请求错误，finally 恢复；恢复自身异常也停写 |
| R03 恢复失败后继续发写请求 | 保留全局停写状态，后续写操作 SKIPPED |
| R04 403 含数据或历史拒绝文字误判安全 | 错误正文与实际业务数据分开判断，冲突保持可疑/不确定 |
| R05 80% 相似度吞掉私有增量，忽略鉴权要求 | 显式公开策略 + 完整 JSON 一致才可 PUBLIC；鉴权冲突保留可疑 |
| R06 同凭据不同配置绕过身份检查 | 比较最终生效认证头，普通 trace 差异不算身份差异 |
| R07 请求回显 ID 造成确认证据 | 排除请求/追踪元数据；可信资源 ID 路径需明确配置 |
| R08 readOnly 特权字段漏测 | 普通基线排除，攻击候选保留；配置字段未覆盖不能声称全部安全 |
| R09 明文/截断 JSON/驼峰密钥/URL 等泄露 | 统一结果出口清理；不可解析正文默认只保留摘要，证据规模受限 |
| R10 窄数值区间/allOf/非法 example 生成错误 | 数值可行区间、组合交集及递归验证；无法合成时显式拒绝 |
| R11 声明媒体类型与实际发送不一致 | 传播 application/json / merge-patch+json；不支持的格式跳过 |
| R12 外部 ref 与 sibling 来源混乱、缺失属性 | 3.1 分来源解析后交集；3.0 结构性 sibling 拒绝并要求 allOf；缺失 pointer 报错 |
| R13 空扫描/全不支持项目错误通过 CI | 零确定性检查不能通过错误门槛，另有覆盖率和可疑门槛 |

## 迁移注意事项

请阅读 README 的“v2.2 配置与迁移说明”，特别是：

- 显式公开策略、可信资源 ID 路径、强一致读回约定。
- CLI 允许清单替换配置清单，路径区分大小写。
- 默认全读回核验可能因时间戳变化失败；只可显式忽略已确认无安全影响的波动字段，不能忽略写入字段。
- 使用 --dry-run 预览范围；它不是一次扫描，也不证明目标安全。

## 未验证或不能保证的部分

没有访问真实业务 API，没有使用真实账号或凭据，没有执行线上部署。
本机未安装 PyYAML，因此只验证了 YAML 缺依赖提示/模拟路径，未验证真实 YAML 加载；
没有运行 pip 安装、wheel 构建、GitHub Actions 或 Python 3.9 运行时。

这是 Beta 工具，生成器并非完整 JSON Schema 求解器，脱敏也并非通用隐私识别器。
无法通用撤销进程强杀、并发写、迟到异步任务、邮件/通知/审计日志或读回未暴露的状态。
本地靶场的 100% 覆盖率只属于这 5 个示例端点，不代表真实系统的检出率。

原始桌面 ZIP 和 v2.1.0 交付包保持不变。
