# 配置指南

[返回项目首页](../README.md)

## 推荐首次接入流程

`OpenAPI → --init-config → 人工填写与核对 → --validate-config → --dry-run → 人工确认 → 首次只读扫描 → 可选主动 PATCH`

1. **离线生成草稿**：

```bash
granttrace --spec openapi.json --init-config config.local.json
```

生成 `config.local.json` 与 `config.local.checklist.json`，列出账户、资源参数和 PATCH 独立读回待填项。已有文件不会被覆盖，不复制规范里的示例凭据或资源值，不发送请求。`write_allowlist` 默认为空，没有授权任何主动 PATCH。

2. **人工核对配置和 checklist**：填写不同的有效 Owner / Visitor 测试凭据、各自可丢弃资源和业务授权预期；工具不会推断资源归属、管理员或团队共享权限、`expected_visitor_access`、`expected_public`。候选写字段和 GET 路径只是 OpenAPI 合同提示，须自行确认读回独立性、`field_map`、一致性与恢复路径。首次只读接入可移除未填写且不用的 `readbacks`，保持 `write_allowlist: []`。替换全部 `__GRANTTRACE_INPUT__:` 占位值，完成审核后才移除 `_granttrace_draft`；未完成的草稿仍会阻止验证、计划与扫描。

3. **离线验证配置与选定规范**，不发送请求：

```bash
granttrace --spec your-openapi.yaml --config config.local.json --validate-config
```

检查成功输出中的数量、scope、模式和警告。允许清单有条目时，只表示主动 PATCH 配置存在；这一步没有启用写测试。没有选定规范的 config-only 检查不执行 operation/spec 交叉检查，须再显式提供 `--spec`，详见 [验证模式](advanced.md#离线验证的两种范围)。

指定规范后，检查配置操作是否声明于规范，以及实际生效的显式 path / query 参数值是否满足支持的 schema 约束。不存在的允许清单、BOLA、operation-level 参数或 readback 关联 PATCH 操作会报错。独立 GET readback 不在规范中时保留支持并给出 warning，须人工确认其路径与参数；这项 warning 不能证明接口存在或可恢复。

4. **生成并审阅本地计划**：

```bash
granttrace --spec your-openapi.yaml --config config.local.json --dry-run --export-json plan.local.json
```

dry-run 发送 **0 请求**，不登录、不刷新凭据、不做 DNS/连接探测，不发送 GET 或 PATCH。stderr 摘要显示检查数量与计划中的写入资格；`plan.local.json` 仍只包含计划 JSON。即使在 dry-run 加入 `--allow-write-tests`，也只是展示真实扫描时可能获得写入资格的操作，没有执行请求。

5. **人工确认后，第一次真实扫描保持只读**：将示例地址替换为已授权的测试目标。

```bash
granttrace --spec your-openapi.yaml --target https://authorized-test.example \
  --config config.local.json --export-json result.local.json
```

真实扫描会发送读取请求；上例没有 `--allow-write-tests`，因此发送 **0 PATCH**，即使配置中已有允许清单。终端推荐的首次真实扫描同样保持只读。

6. **以后有需要才显式开启主动 PATCH**：同时需要明确的 `write_allowlist`、合法独立 GET readback 映射、真实扫描中的 `--allow-write-tests`，以及运行时的快照、写入与恢复条件。先人工确认专用可丢弃资源、字段映射、读回一致性及恢复预期，再单独选择写模式；配置条目存在或计划显示 `writes_enabled` 都不证明实际目标可恢复。

OpenAPI 描述接口合同；validator 检查配置结构及支持的语义。二者不能证明资源归属、预期授权策略、合法测试权限、生产 readback 一致性或真实 PATCH 恢复能力。尤其 `consistency: "strong"` 是操作者经核实后的约定，不是离线工具验证出来的保证。

## 合法团队共享和管理员访问

```json
{"bola": {"GET /documents/{id}": {"expected_visitor_access": "allow", "resource_id_paths": ["id"]}}}
```

`expected_visitor_access` 默认是 `deny`。只有业务方确认当前 Visitor 有权读取所选 Owner 资源时才使用 `allow`。有效且不同的 Visitor 自有资源、可信匿名拒绝及具体跨资源数据证据满足时输出 `AUTHORIZED`，不生成漏洞发现。配置允许却实际拒绝归为 `INCONCLUSIVE`。匿名泄露或无效基线不会被 `allow` 豁免。

该配置仅适用于本次身份与资源组合。相同操作检查不获授权的用户或另一租户时，要更换测试配置并设为 `deny`。工具不会由团队名或角色名自动推断权限。真值与统计见 [业务场景验收](business-scenarios.md)。

## 参数值与编码

保留参数的 JSON 类型；数组和布尔值统一按规范序列化，独立读回使用同一编码器。支持范围与明确拒绝的格式见 [参数规则](parameter-serialization.md)。

显式参数不会通过类型转换绕过 schema 检查：`integer` 参数使用 `1001`，不能填写字符串 `"1001"` 或布尔值。检查还包括支持的 enum、数值范围、字符串及容器约束；复杂或不支持的 schema 不能建立参数有效性。身份的 `id` 是身份标识，不代替 `parameters` 中参数自身的类型约定。

## 配置结构

`config.json` 支持以下信息：

- `identities`：Owner、Visitor 和 Anonymous 的 ID、令牌、请求头及身份参数。
- `parameter_values`：按 `METHOD /path` 为非身份参数提供确定的有效资源值。
- `write_allowlist`：允许主动检查的 PATCH 操作；未配置时不会发送写请求。
- `readbacks`：写接口对应的独立 GET 路径、字段映射及一致性约定。
- `bola`（可选）：按操作配置 `expected_public`、`resource_id_paths`。

简化示例：

```json
{
  "identities": {
    "owner": {
      "id": "1001",
      "token": "Bearer OWNER_TOKEN",
      "parameters": {"user_id": 1001}
    },
    "visitor": {
      "id": "1002",
      "token": "Bearer VISITOR_TOKEN",
      "parameters": {"user_id": 1002}
    },
    "anonymous": {"id": null, "token": null, "parameters": {}}
  },
  "write_allowlist": [
    "PATCH /api/users/{user_id}/settings"
  ],
  "readbacks": {
    "PATCH /api/users/{user_id}/settings": {
      "method": "GET",
      "path": "/api/users/{user_id}/profile",
      "consistency": "strong",
      "field_map": {"role": "role"}
    }
  }
}
```

凭证也可以通过 `headers` 配置 API Key、Cookie 或自定义鉴权头。实际配置文件应放入密钥管理系统或加入 `.gitignore`，不要提交真实凭证。

## 配置语义校验与 IDE Schema 支持

从 v2.3.0 起，项目内置了权威的离线配置语义校验引擎（`core/config_validator.py`）以及标准的 JSON Schema 规范文件（`config.schema.json`）：

1. **Schema 关联与 IDE 提示**：
   在配置文件（如 `config.example.json`）首行加入：
   ```json
   {
     "$schema": "./config.schema.json",
     "description": "..."
   }
   ```
   即可在 VS Code、PyCharm 等现代编辑器中获得字段自动补全、类型提示与悬停说明。

2. **离线配置语义校验 (`--validate-config`)**：
   无需目标服务在线或建立任何网络连接，检查配置结构及支持的语义：
   - 校验 HTTP 操作键格式（严格规范为单空格 `<METHOD> /<path>`，方法必须大写）；
   - 检查 `write_allowlist` 与 `readbacks` 的完整映射及声明的一致性值（`consistency: "strong"`），不证明实际服务满足该声明；
   - 执行 `ignore_readback_paths` 与写入路径/读回路径的全维度对称碰撞检测；
   - 校验身份凭证、自定义认证头提取一致性，并对未知/拼错字段提供相似度提示（Levenshtein 智能建议）。

   基本用法：
   ```bash
   # 同时检查配置和规范（返回码 0 为当前检查通过）
   granttrace --spec openapi.json --config config.json --validate-config

   # 校验示例配置
   granttrace --spec openapi.json --config config.example.json --validate-config
   ```

   - **退出码 0**：当前配置检查通过；有 warning 也保留此成功退出码，应人工阅读警告；
   - **退出码 2**：配置存在非法字段或语义冲突，一次性输出所有违规字段路径、预期值与实际值。
   > **注意**：正常扫描加载配置时，CLI 也会在初始化阶段调用同款校验逻辑；配置非法则拒绝启动（退出码 2）。离线检查成功不能证明业务授权策略正确，也不授权写测试。原有字段含义、草稿阻断和验证判定保持不变。
