# GrantTrace Hardened v2.3.1-final 交付说明

本版基于用户提供的 v2.3.0-final 修复独立审查中复现的 5 个问题，保留只读默认模式、显式写允许清单、独立读回和恢复核验。

## 本版修复

1. **匿名响应参与完整安全判定。** 访客跨资源访问被拒绝时，匿名响应也必须提供可信、干净的拒绝证据，端点才能标为 SECURE。匿名成功或错误响应带业务数据归为 SUSPICIOUS；其他不可靠匿名基线归为 INCONCLUSIVE，不计入确定性覆盖率。
2. **主动写入前拒绝无法核验的快照。** 严格响应 JSON 解码拒绝 NaN、Infinity 和浮点溢出；原始快照和请求载荷必须是有限、可序列化的 JSON，快照必须先与写前状态一致。写后读回无效仍执行恢复。
3. **补齐凭据回显脱敏。** 默认净化覆盖完整 Cookie 内各凭据值及常用编码形式，也覆盖与已知凭据相等的 JSON 数字叶子；显式敏感证据开关继续保留原值。
4. **统一读回参数的数据形状。** `readbacks.parameters` 要求参数对象数组，每项具备有效 `name`、`in` 和 `schema`，仅支持 `path`/`query`。`parameter_values` 必须为映射。IDE Schema、语义校验和运行时一致。
5. **统一规范感知预检。** `--validate-config` 和扫描入口共用 JSON/YAML 规范加载，读取 OpenAPI 声明的自定义认证头。显式选择的缺失、空路径或损坏规范返回 2；缺少默认规范时仍支持配置单独校验。

CLI `--write-endpoint` 替换配置中的写范围后，所选端点同样必须通过独立读回映射检查。

## 运行

要求 Python 3.9 或以上。安装项目会安装 YAML 解析依赖 PyYAML。

```bash
python -m pip install .
python -m unittest discover -s tests
python api_sentinel.py --spec openapi.json --config config.json --validate-config
python api_sentinel.py --spec openapi.json --config config.json --dry-run
```

启动本地靶场：

```bash
python mock_server/server.py
```

另开终端执行只读审计：

```bash
python api_sentinel.py --spec openapi.json --config config.json --target http://127.0.0.1:8080 --export-json result.json
```

在专用本地靶场中检查写入与恢复：

```bash
python api_sentinel.py --spec openapi.json --config config.json --target http://127.0.0.1:8080 --allow-write-tests --fail-on-error --export-json result.json
```

## 验收与版本

本次实际测试结果、环境、wheel 安装验证与归档检查记录见 `VERIFICATION.md`。本版新增四个发布回归模块，原测试保留；只对旧允许清单测试的配置补充了合法读回映射。

运行时版本为 `2.3.1-final`；Python 包元数据版本为 `2.3.1`；ZIP 根目录保持 `GrantTrace/`。示例报告已从本版本地靶场重新生成。

恢复核验是应用层尽力恢复，不是数据库原子事务。本版不增加 GraphQL、gRPC、自动登录、任意参数序列化或通用业务权限推断；更多能力边界见 `README.md` 与 `SECURITY.md`。
