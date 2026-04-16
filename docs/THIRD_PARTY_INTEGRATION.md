# Keylo 第三方系统与服务对接指南

本文档用于指导第三方系统把 Keylo 作为统一认证中心接入，覆盖：

- 后台管理系统（如 AgileBoot）
- API 网关 / BFF
- 内部微服务（Service-to-Service）
- 外部 OAuth 提供商接入

> 版本基线：Keylo v1.0.x（当前代码行为）

---

## 1. 角色边界与职责拆分

### 1.1 Keylo 负责

- 统一认证（用户/客户端/服务）
- JWT 签发（RS256）
- JWKS 公钥发布
- 用户 Token 与服务 Token 内省
- 服务账号白名单策略（`allowed_scopes` + `allowed_audiences`）
- 审计日志与黑名单吊销

### 1.2 第三方系统负责

- 本地业务数据
- 本地 RBAC（角色、菜单、数据权限）
- 本地会话策略（如页面态）

推荐原则：**认证集中在 Keylo，授权保留在业务系统本地**。

---

## 2. Token 模型与字段约定

Keylo 当前主要使用三类 JWT：

1. 用户/客户端访问令牌：`token_type=access`
2. 客户端刷新令牌：`token_type=refresh`
3. 服务访问令牌：`token_type=service_access`

### 2.1 用户/客户端 Access Token（示例）

```json
{
  "sub": "user:alice",
  "iss": "keylo",
  "aud": "admin-backend",
  "scope": ["read", "write"],
  "token_type": "access",
  "exp": 1710000000,
  "iat": 1709990000,
  "jti": "uuid"
}
```

### 2.2 服务 Access Token（示例）

```json
{
  "sub": "service:agileboot-admin",
  "iss": "keylo",
  "aud": "admin-backend",
  "scope": ["user.read"],
  "token_type": "service_access",
  "exp": 1710000000,
  "iat": 1709990000,
  "jti": "uuid"
}
```

### 2.3 实现注意点

- 用户名密码登录时（用户身份）通常仅返回 `access_token`。
- 客户端身份登录时（client 身份）会返回 `access_token` 与 `refresh_token`。
- 受保护业务接口只接受 `token_type=access`。
- 服务内省接口与用户内省接口都要求调用方携带合法 `service_access` Token。

---

## 3. 推荐接入架构

### 3.1 管理后台接入（典型）

1. 前端向业务后端提交账号密码。
2. 业务后端转发到 Keylo：`POST /v1/auth/token`。
3. Keylo 返回 Access Token。
4. 业务后端基于 `sub` 做本地用户映射。
5. 业务后端继续使用本地 RBAC 完成授权。

### 3.2 纯后端服务接入

1. 在 Keylo 注册服务账号。
2. 使用 `POST /v1/service/token` 获取 `service_access` Token。
3. 收到用户 Token 时，调用 `POST /v1/auth/introspect` 做统一内省。
4. 按 `sub`、`scope`、`aud` 生成本地安全上下文。

### 3.3 网关/BFF 接入

推荐策略：

- 常规流量：JWKS 本地验签（低延迟）
- 高敏接口：本地验签 + 内省双检
- 网关仅做认证前置，细粒度授权下沉至业务服务

---

## 4. 服务间调用白名单模型

Keylo 1.0 采用“服务账号白名单”而非独立拓扑图。

每个服务账号维护两类边界：

- `allowed_scopes`：最多可申请哪些权限
- `allowed_audiences`：最多可访问哪些目标服务

签发服务 Token 时，请求值必须是白名单子集，否则拒绝。

### 4.1 管理入口

- `POST /v1/admin/services`
- `GET /v1/admin/services`
- `GET /v1/admin/services/{service_id}`
- `PUT /v1/admin/services/{service_id}`
- `POST /v1/admin/services/{service_id}/rotate-secret`

---

## 5. 对接接口矩阵（按阶段）

### 阶段 A：基础认证

#### A-1 获取用户/客户端 Token

```http
POST /v1/auth/token
Content-Type: application/json

{
  "client_id": "alice",
  "client_secret": "user-password"
}
```

响应示例（用户身份）：

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

响应示例（客户端身份）：

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### A-2 刷新 Token（客户端模式）

```http
POST /v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "<refresh-token>"
}
```

#### A-3 获取 JWKS

```http
GET /.well-known/jwks.json
```

### 阶段 B：服务集成

#### B-1 注册服务账号（管理员）

```http
POST /v1/admin/services
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "service_id": "agileboot-admin",
  "service_secret": "replace-with-strong-secret",
  "name": "AgileBoot Admin",
  "description": "AgileBoot 管理平台服务账号",
  "allowed_scopes": ["user.read", "user.write"],
  "allowed_audiences": ["admin-backend"]
}
```

#### B-2 获取服务 Token

```http
POST /v1/service/token
Content-Type: application/json

{
  "service_id": "agileboot-admin",
  "service_secret": "replace-with-strong-secret",
  "audience": "admin-backend",
  "scope": "user.read"
}
```

响应：

```json
{
  "access_token": "<service-jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "user.read"
}
```

#### B-3 内省用户 Token（服务令牌保护）

```http
POST /v1/auth/introspect
Authorization: Bearer <service_access_token>
Content-Type: application/json

{
  "token": "<user-access-token>"
}
```

有效响应：

```json
{
  "active": true,
  "sub": "user:alice",
  "scope": "read write",
  "aud": "admin-backend",
  "iss": "keylo",
  "exp": 1710000000,
  "iat": 1709990000,
  "jti": "uuid",
  "token_type": "access"
}
```

无效响应：

```json
{
  "active": false
}
```

#### B-4 内省服务 Token（服务令牌保护）

```http
POST /v1/service/introspect
Authorization: Bearer <service_access_token>
Content-Type: application/json

{
  "token": "<service-access-token>"
}
```

### 阶段 C：会话与审计（可选）

- `POST /v1/auth/logout`：注销并拉黑当前 Access Token
- `GET /v1/auth/me`：查看当前 Claims 摘要
- `GET /v1/admin/audit-logs`：审计查询（admin scope）

---

## 6. OAuth 外部身份源接入（可选）

如果你希望 Keylo 充当 OAuth 聚合入口（如 GitHub 登录）：

### 6.1 公开登录入口

- `GET /v1/auth/oauth/login/{provider}`
- `GET /v1/auth/oauth/callback/{provider}`

### 6.2 管理配置入口（admin scope）

- `GET /api/oauth/providers`
- `POST /api/oauth/providers`
- `PUT /api/oauth/providers/{provider_id}`
- `DELETE /api/oauth/providers/{provider_id}`

建议：第三方业务系统只对接 Keylo 的统一 Token，不直接耦合各 OAuth Provider 的细节。

---

## 7. 第三方系统校验策略（强烈建议）

对用户访问 Token 至少校验：

- `iss`：必须匹配部署值（默认 `keylo`）
- `token_type`：必须为 `access`
- `exp`：未过期
- `aud`：必须匹配当前系统标识（如 `admin-backend`）

对内省结果还应校验：

- `active=true`

推荐顺序：

1. JWKS 本地验签
2. 高敏接口补内省
3. `sub` 映射本地用户并加载本地授权

---

## 8. 常见错误与处理建议

### 8.1 `401 Unauthorized`

常见原因：

- Token 缺失或格式错误
- 签名无效/过期
- 黑名单吊销
- 调用内省接口时未携带 `service_access` Token

### 8.2 `403 Forbidden`

常见原因：

- 调用管理员接口但无 `admin` scope
- 服务申请了未授权 `scope` 或 `audience`

### 8.3 `429 Too Many Requests`

常见于登录接口频繁失败触发限流或锁定，建议客户端退避重试并记录审计。

---

## 9. 上线前检查清单

- [ ] 生产环境使用专用 RSA 密钥（禁止默认开发密钥）
- [ ] 所有服务账号仅配置最小 `allowed_scopes` / `allowed_audiences`
- [ ] 管理接口仅对 `admin` scope 开放
- [ ] 网关与服务已完成 `iss`/`aud`/`exp`/`token_type` 校验
- [ ] 高敏接口已增加内省
- [ ] 密钥轮换流程已演练（JWKS 缓存策略已验证）
- [ ] 审计日志与告警阈值已配置

---

## 10. 参考文档

- AgileBoot 对接： [AGILEBOOT_INTEGRATION.md](AGILEBOOT_INTEGRATION.md)
- 生产部署： [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)
- 密钥轮换： [KEY_ROTATION.md](KEY_ROTATION.md)
- 版本边界： [RELEASE_1_0.md](RELEASE_1_0.md)

