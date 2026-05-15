# Keylo 1.4.0 发布说明

发布日期：2026年5月16日

## 版本定位

Keylo 1.4.0 是一次面向第三方服务集成体验的功能版本。这个版本不追求完整 OIDC Provider 兼容，而是把 Keylo 明确推进为轻量、可扩展、标准友好的统一鉴权与授权中心。

核心目标：

- 服务可以通过轻量发现接口了解 Keylo 的接入端点。
- 第三方资源服务可以优先使用 JWKS 本地验签。
- 服务客户端注册模型能表达接入类型、内省权限、单服务 token TTL 和运维归属。
- 接入方可以直接参考 Spring、Node、Go、Rust 模板完成集成。

---

## 主要改进

### 轻量发现配置

新增公开接口：

```text
GET /.well-known/keylo-configuration
```

返回内容包括：

- `issuer`
- `jwks_uri`
- `introspection_endpoint`
- `service_token_endpoint`
- `service_introspection_endpoint`
- `supported_token_types`
- `supported_claims`
- `supported_audiences`
- `documentation_uri`

说明：该接口不是 OIDC discovery 文档，而是 Keylo 自己的轻量集成契约。

### 动态 Access Token Audience

新增配置：

```env
JWT_AUDIENCES=admin-backend,crawler
```

用户/管理 access token 的 JWT audience 校验不再硬编码在代码中，而是由 `JWT_AUDIENCES` 控制。默认值保持兼容：`admin-backend,crawler`。

### 服务客户端集成元数据

`service_clients` 表新增：

- `integration_type`
- `introspection_allowed`
- `token_ttl_seconds`
- `owner`
- `contact`

服务注册和更新接口支持这些字段。`token_ttl_seconds` 允许给单个服务配置独立 token TTL；未配置时继续使用全局 `SERVICE_TOKEN_EXPIRY_SECONDS`。

`introspection_allowed=false` 时，该服务的 `service_access` token 不能调用 `/v1/auth/introspect` 和 `/v1/service/introspect`。

### 服务注册输入校验

服务注册与更新会规范化 `allowed_scopes` 和 `allowed_audiences`：

- trim
- 去重
- 排序
- 拒绝空字符串
- 拒绝单项中包含空白字符
- `allowed_audiences` 允许 `*`
- `allowed_scopes` 不允许 `*`

新增错误码：

```json
{
  "error": "invalid_request"
}
```

用于表达明确的请求参数错误。

### 第三方接入模板

新增模板目录：

```text
docs/integrations/
```

包含：

- Spring Security
- Node Express
- Go net/http
- Rust Axum

这些模板围绕 discovery-lite、JWKS、本地验签、`iss/aud/token_type/scope` 校验和内省补强展开。

### 文档补强

更新：

- `README.md`
- `docs/API_REFERENCE.md`
- `docs/THIRD_PARTY_INTEGRATION.md`
- `docs/END_TO_END_QUICKSTART.md`

---

## 数据库迁移

新增迁移：

```text
migrations/20260515160000_extend_service_clients_integration_metadata.sql
```

该迁移向 `service_clients` 追加列和索引，默认值保持兼容：

- `integration_type` 默认 `internal`
- `introspection_allowed` 默认 `true`
- `token_ttl_seconds` 默认为空，表示使用全局配置

---

## 升级指南

### 从 1.3.1 升级到 1.4.0

1. 更新镜像/二进制到 `v1.4.0`。
2. 启动服务并确认数据库迁移执行成功。
3. 检查轻量发现接口：

```bash
curl -s http://127.0.0.1:2345/.well-known/keylo-configuration
```

4. 如需新增资源服务 audience，配置：

```env
JWT_AUDIENCES=admin-backend,crawler,inventory-svc
```

5. 重新注册或更新服务客户端，为新接入服务补充：

```json
{
  "integration_type": "internal",
  "introspection_allowed": true,
  "token_ttl_seconds": 900,
  "owner": "Platform Team",
  "contact": "platform@example.com"
}
```

6. 按 `docs/integrations/README.md` 调整第三方资源服务的 JWKS 验签和 claims 校验逻辑。

---

## 兼容性说明

- HTTP API 保持向后兼容。
- 旧服务客户端会在迁移后自动获得默认元数据。
- `JWT_AUDIENCES` 未配置时仍使用 `admin-backend,crawler`。
- `service_access` token 默认 TTL 行为不变，除非服务客户端显式配置 `token_ttl_seconds`。
- 关闭 `introspection_allowed` 会影响该服务调用内省接口，但不影响它申请服务 token 或本地验签使用。

---

## 验证结果摘要

本版本发布前已完成：

```bash
cargo fmt --check
cargo test --lib
cargo test --test integration_test
```

验证结果：

- `cargo fmt --check` 通过。
- `cargo test --lib` 通过，35 个单元测试全部通过。
- `cargo test --test integration_test` 通过，30 个集成测试全部通过。
