# Auth/RBAC Security Development Plan

## 背景与目标

当前已发布 `v1.2.1`，下一阶段聚焦鉴权链路的高优先级安全与正确性问题。目标是在不做大重构的前提下，逐步完成：

1. 密钥治理（移除硬编码开发密钥回退路径）
2. Token 存储加固（明文改哈希）
3. RBAC 中间件一致性修复
4. 密钥轮换接口降敏（不再返回明文 secret）
5. 权限判断与错误语义收敛
6. 高风险路径补测与回归

## 执行范围与优先级

### P0: 密钥治理
- 影响文件：`src/config.rs`, `src/startup.rs`, `src/main.rs`
- 目标：禁止默认内置 PEM 作为隐式回退，启动阶段对密钥配置 fail-fast。
- 验收：未配置密钥时按策略明确失败，不再使用硬编码开发密钥。

### P0: Token 存储哈希化
- 影响文件：`migrations/*`, `src/db/mod.rs`, `src/handlers/auth.rs`, `src/middleware/auth.rs`, `src/handlers/service.rs`
- 目标：`sessions/refresh_tokens/blacklisted_tokens` 查询与写入基于 `token_hash`。
- 验收：核心流程（登录、刷新、登出、introspect）不依赖明文 token 查库。

### P1: RBAC claims 类型修复
- 影响文件：`src/middleware/rbac.rs`
- 目标：与 `auth_middleware` 注入的 `Claims` 一致，修复 `String` 读取错误。
- 验收：401/403/200 权限矩阵行为正确。

### P1: 轮换接口降敏
- 影响文件：`src/handlers/auth.rs`, `src/handlers/service.rs`, `src/models/*`
- 目标：移除轮换接口中的 `new_secret` 明文返回。
- 验收：响应体与日志不暴露新密钥。

### P2: 权限判断与错误码收敛
- 影响文件：`src/handlers/auth.rs`, `src/handlers/service.rs`, `src/errors/*`
- 目标：减少分散 `scope.contains("admin")`，将冲突类错误映射为 `409`。
- 验收：关键管理端接口状态码语义一致。

### P2: 补测与回归
- 影响文件：`tests/integration_test.rs`, `tests/rbac_integration_test.rs`, `tests/database_integration_test.rs`
- 目标：补齐 refresh rotation/replay、blacklist 联动、RBAC 矩阵等测试。
- 验收：新增测试稳定通过，无回归。

## 建议执行顺序

1. 密钥治理
2. Token 哈希化（含 migration）
3. RBAC 修复
4. 轮换接口降敏
5. 权限/错误语义收敛
6. 补测与整体回归

## 回滚点

- 每一阶段独立提交，出现生产风险时按阶段回滚。
- Token 哈希化阶段保留平滑迁移窗口，避免一次性删除旧字段。

## 测试与发布验证

- 基础：`cargo fmt`、`cargo check`、`cargo test`
- 定向：
  - `/v1/auth/refresh`, `/v1/auth/logout`, `/v1/auth/introspect`
  - `/api/rbac/*` 权限矩阵
  - `/v1/admin/*/rotate-secret` 响应脱敏验证
- 发布前：确认 API 响应与日志中无明文 secret/token。
