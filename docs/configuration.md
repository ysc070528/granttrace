# 配置指南

[返回项目首页](../README.md)

## 根据 OpenAPI 生成草稿

```bash
granttrace --spec openapi.json --init-config config.local.json
```

离线生成 `config.local.json` 与 `config.local.checklist.json`，列出账户、资源参数和 PATCH 独立读回待填项。已有文件不会被覆盖。规范不能证明账户权限、资源归属或读回强一致性；候选 GET 仅供人工确认。草稿不启用写测试，也不直接联系目标。

逐项填写不同的有效 Owner / Visitor 凭据与真实资源，替换全部占位值，再按清单移除草稿标记。未完成的草稿会阻止预检、计划与扫描。仅接入只读检查时，可移除未填写的 `readbacks`，保持 `write_allowlist: []`。

## 合法团队共享和管理员访问

```json
{"bola": {"GET /documents/{id}": {"expected_visitor_access": "allow", "resource_id_paths": ["id"]}}}
```

`expected_visitor_access` 默认是 `deny`。只有业务方确认当前 Visitor 有权读取所选 Owner 资源时才使用 `allow`。有效且不同的 Visitor 自有资源、可信匿名拒绝及具体跨资源数据证据满足时输出 `AUTHORIZED`，不生成漏洞发现。配置允许却实际拒绝归为 `INCONCLUSIVE`。匿名泄露或无效基线不会被 `allow` 豁免。

该配置仅适用于本次身份与资源组合。相同操作检查不获授权的用户或另一租户时，要更换测试配置并设为 `deny`。工具不会由团队名或角色名自动推断权限。真值与统计见 [业务场景验收](business-scenarios.md)。

## 参数值与编码

保留参数的 JSON 类型；数组和布尔值统一按规范序列化，独立读回使用同一编码器。支持范围与明确拒绝的格式见 [参数规则](parameter-serialization.md)。

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
      "parameters": {"user_id": "1001"}
    },
    "visitor": {
      "id": "1002",
      "token": "Bearer VISITOR_TOKEN",
      "parameters": {"user_id": "1002"}
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
   无需目标服务在线或建立任何网络连接，离线预检配置结构与安全语义：
   - 校验 HTTP 操作键格式（严格规范为单空格 `<METHOD> /<path>`，方法必须大写）；
   - 检查 `write_allowlist` 与 `readbacks` 的完整映射与读回一致性（`consistency: "strong"`）；
   - 执行 `ignore_readback_paths` 与写入路径/读回路径的全维度对称碰撞检测；
   - 校验身份凭证、自定义认证头提取一致性，并对未知/拼错字段提供相似度提示（Levenshtein 智能建议）。

   基本用法：
   ```bash
   # 校验项目默认配置（返回码 0 为合法）
   granttrace --spec openapi.json --config config.json --validate-config

   # 校验示例配置
   granttrace --spec openapi.json --config config.example.json --validate-config
   ```

   - **退出码 0**：配置语义完全合法，无任何违规；
   - **退出码 2**：配置存在非法字段或语义冲突，一次性输出所有违规字段路径、预期值与实际值。
   > **注意**：正常执行安全扫描时，CLI 也会在初始化阶段强制调用同款预检逻辑，若配置非法将拒绝启动并安全退出（退出码 2），防止无效扫描。
