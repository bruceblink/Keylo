# Keylo 第三方系统集成指南

本文档说明第三方系统如何将 Keylo 作为统一认证中心接入，适用于后端管理系统、内部业务服务和 API 网关。

## 集成目标

Keylo 负责：

- 用户认证
- Access Token / Refresh Token 签发
- 服务到服务鉴权
- OAuth 第三方登录
- 审计日志

第三方系统负责：

- 本地业务用户资料
- 菜单、角色、数据权限
- 页面与运营后台

推荐模式是：第三方系统信任 Keylo 的身份认证结果，但保留自己的授权模型。

## Token 类型

Keylo 当前提供两类 Token：

- 用户访问 Token：`token_type=access`
- 服务访问 Token：`token_type=service_access`

用户访问 Token 的典型 Claims：

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

服务访问 Token 的典型 Claims：

```json
{
  "sub": "service:agileboot-admin",
  "iss": "keylo",
  "aud": "admin-backend",
  "scope": ["read"],
  "token_type": "service_access",
  "exp": 1710000000,
  "iat": 1709990000,
  "jti": "uuid"
}
```

## 推荐接入架构

### 场景一：后台管理系统接入

例如 AgileBoot 这类带 UI 的后台系统。

1. 前端登录页提交用户名密码到 AgileBoot。
2. AgileBoot 后端将认证请求转发给 Keylo 的 `/v1/auth/token`。
3. Keylo 返回用户 Access Token。
4. AgileBoot 按 `sub` 将 Keylo 身份映射到本地用户。
5. AgileBoot 根据本地角色、菜单、数据权限完成授权。
6. 前端后续请求继续携带 Keylo 的 Access Token。

### 场景二：后端服务接入

适用于不直接承接用户登录页面的业务服务。

1. 在 Keylo 注册服务账号。
2. 服务使用 `/v1/service/token` 获取自己的 `service_access` Token。
3. 服务收到用户 Access Token 后，通过 `/v1/auth/introspect` 内省用户 Token。
4. Keylo 返回 Token 是否有效以及标准 Claims。
5. 服务根据 `sub`、`scope`、`aud` 建立本地安全上下文。

## 接口清单

### 1. 用户登录

请求：

```http
POST /v1/auth/token
Content-Type: application/json

{
  "client_id": "alice",
  "client_secret": "user-password"
}
```

响应：

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

说明：

- 对用户身份，`client_id` 实际上等于用户名。
- 当前实现中，用户登录返回 Access Token；客户端凭证模式会额外返回 Refresh Token。

### 2. 注册第三方服务

请求：

```http
POST /v1/admin/services
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "service_id": "agileboot-admin",
  "service_secret": "replace-with-strong-secret",
  "name": "AgileBoot Admin",
  "description": "AgileBoot 管理后台",
  "allowed_scopes": ["read"],
  "allowed_audiences": ["admin-backend"]
}
```

### 3. 获取服务 Token

请求：

```http
POST /v1/service/token
Content-Type: application/json

{
  "service_id": "agileboot-admin",
  "service_secret": "replace-with-strong-secret",
  "audience": "admin-backend",
  "scope": "read"
}
```

响应：

```json
{
  "access_token": "<service-jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

### 4. 内省用户 Access Token

请求：

```http
POST /v1/auth/introspect
Authorization: Bearer <service_access_token>
Content-Type: application/json

{
  "token": "<user-access-token>"
}
```

响应：

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

无效或过期 Token：

```json
{
  "active": false
}
```

### 5. 内省服务 Token

请求：

```http
POST /v1/service/introspect
Authorization: Bearer <service_access_token>
Content-Type: application/json

{
  "token": "<service-access-token>"
}
```

## 第三方系统的校验策略

第三方系统推荐校验以下字段：

- `iss` 必须等于 `keylo`
- `token_type` 必须是 `access`
- `aud` 必须匹配当前系统标识，例如 `admin-backend`
- `exp` 必须晚于当前时间
- `active` 必须为 `true`

若系统自身保留本地授权模型，还应执行：

- 通过 `sub` 找到本地用户映射
- 加载本地角色、菜单、数据权限
- 将 Keylo 的认证身份与本地业务授权解耦

## AgileBoot 集成建议

对于 AgileBoot 这类管理系统，建议职责划分如下：

- Keylo：统一认证中心
- AgileBoot：管理 UI、本地 RBAC、菜单权限、数据权限

推荐实现：

1. AgileBoot 登录接口代理 Keylo 的 `/v1/auth/token`。
2. AgileBoot 将 Keylo 的 `sub` 映射为本地用户外部身份。
3. AgileBoot 后续请求直接信任 Keylo Access Token。
4. AgileBoot 内部服务或网关使用 `/v1/auth/introspect` 做用户 Token 内省。

## 安全建议

- 不要让第三方系统直接共享 Keylo 的 JWT 签名密钥。
- 第三方系统优先通过服务 Token 调用 Keylo 内省接口。
- 后台系统只把 UI 和本地授权留在自己侧，不要复制 Keylo 的认证逻辑。
- 所有服务账号都应限制 `allowed_scopes` 与 `allowed_audiences`。
- 管理接口只允许带有 `admin` scope 的用户 Token 访问。