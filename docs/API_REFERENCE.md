<!-- markdownlint-disable MD060 -->

# Keylo API 接口文档（完整）

> 基于当前代码路由整理，覆盖认证、用户、RBAC、OAuth、服务间认证与系统健康检查。

> 从初始化到用户/RBAC/服务客户端的完整实操流程，请参考：[END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md)

> 多客户端统一用户池与权限模型落地步骤请参考：[MULTI_CLIENT_RBAC_INTEGRATION.md](MULTI_CLIENT_RBAC_INTEGRATION.md)

## 1. 鉴权约定

### 1.1 Token 类型

- 用户/管理接口：`Authorization: Bearer <access_token>`
- 服务接口：`Authorization: Bearer <service_access_token>`

### 1.2 受保护接口中间件规则

- 管理接口：`role` 包含 `admin`，`scope` 包含 `admin`，`aud=admin-backend`
- 用户自助接口：`role` 包含 `user`，`scope` 包含 `write`，`aud=admin-backend`
- 服务内省接口：`role=service`，`scope` 包含 `read`
- 授权中心集成内省：`role=service`，`scope` 包含 `read`，`aud=admin-backend`

### 1.3 错误码（机读）

常见错误：

- `wrong_credentials`
- `missing_credentials`
- `invalid_token`
- `expired_token`
- `insufficient_scope`
- `insufficient_role`
- `invalid_audience`
- `token_type_invalid`
- `permission_not_bound`
- `role_not_bound`
- `service_client_not_authorized`
- `too_many_requests`

---

## 2. 系统与公开接口

### 2.1 系统状态

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 否 | 欢迎页 |
| GET | `/healthz` | 否 | 存活检查 |
| GET | `/readyz` | 否 | 就绪检查 |
| GET | `/protected` | 是（access） | 受保护示例接口 |

### 2.2 JWT 公钥

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/.well-known/jwks.json` | 否 | JWKS 公钥文档 |

---

## 3. 认证与令牌接口

### 3.1 获取用户 Token

- **POST** `/v1/auth/token`
- 鉴权：否
- 请求体：

```json
{
  "client_id": "alice",
  "client_secret": "Alice#12345"
}
```

- 响应体：

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### 3.2 获取管理 Token

- **POST** `/v1/admin/token`
- 鉴权：否（仅受信任管理客户端凭证可通过）
- 请求体同 `/v1/auth/token`
- 响应体包含 `access_token` 与 `refresh_token`

### 3.3 刷新 Token

- **POST** `/v1/auth/refresh`
- 鉴权：否
- 请求体：

```json
{
  "refresh_token": "..."
}
```

- `POST /v1/auth/refresh` 的 `refresh_token` 来源说明：
  - 通过 `POST /v1/admin/token` 获取（该接口会返回 `refresh_token`）
  - `POST /v1/auth/token` 当前仅返回 `access_token`，不返回 `refresh_token`
- 刷新时旧 `refresh_token` 会被数据库原子消费；并发或重复使用同一个 refresh token 只允许一个请求成功。

### 3.4 当前用户信息

- **GET** `/v1/auth/me`
- 鉴权：是（access）
- 响应字段：`sub`、`uid`、`scope[]`、`role[]`、`aud`、`exp`、`iss`、`jti`
- 字段说明：`uid` 为 `users` 表主键（稳定用户 ID），`sub` 为主体标识字符串。

### 3.5 退出登录

- **POST** `/v1/auth/logout`
- 鉴权：是（access）
- 作用：将当前 access token 拉黑

### 3.6 用户注册

- **POST** `/v1/auth/register`
- 鉴权：否
- 请求体：

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Alice#12345"
}
```

### 3.7 第三方 JIT 迁移注册

- **POST** `/v1/auth/migrations/jit-register`
- 鉴权：否
- 请求体：`provider`、`external_user_id`、`username`、`email`、`password?`、`active?`、`roles?`、`metadata?`

### 3.8 Token 内省（授权中心集成）

- **POST** `/v1/auth/introspect`
- 鉴权：是（service_access + `read` + `aud=admin-backend`）
- 请求体：

```json
{
  "token": "..."
}
```

---

## 4. 管理接口（Auth 管理）

> 统一要求：admin access token

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/admin/blacklist` | 拉黑 token |
| GET | `/v1/admin/blacklisted-tokens` | 查询黑名单 token |
| GET | `/v1/admin/audit-logs` | 查询审计日志（`limit/offset`） |
| POST | `/v1/admin/audit-logs/cleanup` | 清理审计日志（按保留天数） |
| GET | `/v1/admin/clients` | 查询管理客户端 |
| POST | `/v1/admin/clients` | 创建管理客户端 |
| PUT | `/v1/admin/clients/{client_id}` | 更新管理客户端 |
| POST | `/v1/admin/clients/{client_id}/rotate-secret` | 轮换管理客户端密钥 |

`POST /v1/admin/clients/{client_id}/rotate-secret`：

- 请求体可选 `new_secret`。传入时服务端只保存 bcrypt hash，响应不会回显明文。
- 省略 `new_secret` 时服务端会生成新密钥，并在响应的 `new_secret` 字段中一次性返回；调用方必须立即保存。
- 响应包含 `secret_generated`，用于区分是否由服务端生成。

---

## 5. 用户管理接口

> 路径前缀：`/v1/admin/users`，统一要求：admin access token

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/users?limit=&offset=` | 用户分页列表 |
| POST | `/v1/admin/users` | 创建用户 |
| POST | `/v1/admin/users/provision` | 原子创建用户并绑定角色模板 |
| GET | `/v1/admin/users/{user_id}` | 获取用户详情 |
| PUT | `/v1/admin/users/{user_id}` | 更新用户 |
| DELETE | `/v1/admin/users/{user_id}` | 删除用户 |
| GET | `/v1/admin/users/{user_id}/effective-permissions` | 用户最终权限并集 |
| POST | `/v1/admin/users/{user_id}/reset-password` | 重置密码 |
| POST | `/v1/admin/users/migrations/import` | 同步执行第三方用户导入 |
| POST | `/v1/admin/users/migrations/jobs` | 提交异步导入任务 |
| GET | `/v1/admin/users/migrations/jobs/{job_id}` | 查询异步导入任务状态 |

### 5.1 Provision 请求体

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Alice#12345",
  "role_ids": ["role-id-1"],
  "role_names": ["ssc_dispatcher"]
}
```

### 5.2 用户自助接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/v1/user/change-password` | user access token | 修改当前用户密码 |

---

## 6. RBAC 接口

> 路径前缀：`/api/rbac`，统一要求：admin access token

### 6.1 角色管理

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/roles` |
| POST | `/api/rbac/roles` |
| GET | `/api/rbac/roles/{role_id}` |
| PUT | `/api/rbac/roles/{role_id}` |
| DELETE | `/api/rbac/roles/{role_id}` |

### 6.2 权限管理

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/permissions` |
| POST | `/api/rbac/permissions` |
| GET | `/api/rbac/permissions/{permission_id}` |
| PUT | `/api/rbac/permissions/{permission_id}` |
| DELETE | `/api/rbac/permissions/{permission_id}` |

说明：`GET /api/rbac/permissions` 支持 `prefix` 查询参数，如：`?prefix=ssc.`

### 6.3 用户角色管理

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/users/{user_id}/roles` |
| POST | `/api/rbac/users/{user_id}/roles` |
| POST | `/api/rbac/users/{user_id}/roles/batch` |
| DELETE | `/api/rbac/users/{user_id}/roles/{role_id}` |

### 6.4 角色权限管理

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/roles/{role_id}/permissions` |
| POST | `/api/rbac/roles/{role_id}/permissions` |
| POST | `/api/rbac/roles/{role_id}/permissions/batch` |
| DELETE | `/api/rbac/roles/{role_id}/permissions/{permission_id}` |

### 6.5 用户权限查询

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/users/{user_id}/permissions` |
| GET | `/api/rbac/users/{user_id}/check-permission/{permission_name}` |

### 6.6 批量接口请求体

- 用户批量绑定角色：

```json
{
  "role_ids": ["role-id-1", "role-id-2"]
}
```

- 角色批量绑定权限：

```json
{
  "permission_ids": ["perm-id-1", "perm-id-2"]
}
```

---

## 7. OAuth 接口

### 7.1 公开 OAuth 登录流程

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/auth/oauth/login/{provider}` | 否 | 跳转到 OAuth 提供方 |
| GET | `/v1/auth/oauth/callback/{provider}` | 否 | OAuth 回调并签发系统 token |

### 7.2 OAuth 管理接口（admin）

> 路径前缀：`/api/oauth`

| 方法 | 路径 |
|---|---|
| GET | `/api/oauth/providers` |
| POST | `/api/oauth/providers` |
| GET | `/api/oauth/providers/{provider_id}` |
| PUT | `/api/oauth/providers/{provider_id}` |
| DELETE | `/api/oauth/providers/{provider_id}` |
| GET | `/api/oauth/accounts` |
| POST | `/api/oauth/link` |
| DELETE | `/api/oauth/unlink/{provider}` |

---

## 8. 服务间认证接口

### 8.1 公开接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/v1/service/token` | 否 | 服务凭证换取 `service_access` token |

请求体：

```json
{
  "service_id": "order-svc",
  "service_secret": "secret",
  "audience": "inventory-svc",
  "scope": "read write"
}
```

### 8.2 服务受保护接口

| 方法 | 路径 | 鉴权 |
|---|---|---|
| POST | `/v1/service/introspect` | service_access + `read` |

请求体：

```json
{
  "token": "..."
}
```

### 8.3 服务管理接口（admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/services` | 服务列表 |
| POST | `/v1/admin/services` | 注册服务 |
| GET | `/v1/admin/services/{service_id}` | 服务详情 |
| PUT | `/v1/admin/services/{service_id}` | 更新服务 |
| POST | `/v1/admin/services/{service_id}/rotate-secret` | 轮换服务密钥 |

`POST /v1/admin/services/{service_id}/rotate-secret`：

- 请求体可选 `new_secret`。传入时响应不会回显明文。
- 省略 `new_secret` 时服务端生成新密钥，并在响应的 `new_secret` 字段中一次性返回。
- 响应包含 `secret_generated`。

## 8.4 运行时安全约定

- 登录和内省接口按客户端 IP 限流。默认使用 TCP peer IP；只有 `TRUST_PROXY_HEADERS=true` 时才信任 `X-Forwarded-For` / `X-Real-IP`。
- `/readyz` 默认要求数据库可用；无数据库路由只应在非生产环境显式设置 `ALLOW_IN_MEMORY_FALLBACK=true` 时使用。

---

## 9. 通用响应格式

### 9.1 业务接口（多数）

成功：

```json
{
  "success": true,
  "data": {}
}
```

失败：

```json
{
  "success": false,
  "error": "...",
  "message": "..."
}
```

### 9.2 认证错误（`AuthError`）

```json
{
  "code": 1012,
  "error": "insufficient_scope",
  "message": "Insufficient scope"
}
```

---

## 10. Claims 参考

Access token 关键字段：

- `sub`：主体标识（Subject）。通常为 `user:<username>`、`client:<client_id>` 或特定主体 ID，用于后端识别请求发起方，不建议作为用户表主键使用。
- `uid`：用户主键 ID（`users.id`）。当 token 代表用户主体时应优先使用 `uid` 进行用户关联与数据查询。
- `iss`：签发方（Issuer）。用于校验 token 来源是否可信，需与服务端配置的发行者一致。
- `aud`：受众（Audience）。标识 token 目标服务（如 `admin-backend`）；后端应校验是否匹配当前资源服务。
- `token_type`：令牌类型。当前常见为 `access`（访问令牌）或 `refresh`（刷新令牌）；受保护接口只接受 `access`。
- `scope`（数组）：权限点集合。用于接口级授权判断，建议采用能力点命名（如 `ssc.camera.write`）。
- `role`（数组，兼容历史字符串）：角色集合。用于粗粒度角色判断（如 `admin`、`user`）；当前输出为数组，兼容历史单字符串。
- `exp`：过期时间（Unix 时间戳，秒）。当前时间超过该值后 token 无效。
- `iat`：签发时间（Unix 时间戳，秒）。可用于排查时钟漂移、审计与会话时序分析。
- `jti`：令牌唯一 ID（JWT ID）。用于黑名单吊销、幂等追踪与审计定位。

## 11. 后端校验建议顺序（推荐）

为保证安全性与可观测性，建议后端按以下顺序做统一校验：

1. 验证 `Authorization` 头存在且格式正确（Bearer）。
2. 验签并校验基础声明：`iss`、`exp`、`iat`。
3. 校验 `token_type=access`（否则返回 `token_type_invalid`）。
4. 校验 `aud` 是否匹配当前资源服务（否则返回 `invalid_audience`）。
5. 按接口策略校验 `scope`（否则返回 `insufficient_scope`）。
6. 按接口策略校验 `role`（否则返回 `insufficient_role`）。
7. 如启用吊销机制，校验 `jti` / token 是否在黑名单。
8. 通过后再进入业务处理。

说明：高敏接口可叠加内省（introspect）作为防御纵深。

## 12. 前端使用建议（非安全边界）

- 前端可使用 `scope` 与 `role` 做导航、按钮、页面块的显示控制。
- 前端隐藏仅用于体验优化，**不作为安全边界**。
- 真正访问控制必须由后端再次校验 token claims。
- 当权限变更后，应引导前端刷新 token，以拿到最新 claims。

## 13. 权限变更生效策略

- 角色/权限变更后，对“新签发 token”立即生效。
- 已签发旧 token 在过期前仍可能保留旧权限。
- 若需立即失效，建议结合黑名单或缩短 access token 生命周期。

<!-- markdownlint-enable MD060 -->
