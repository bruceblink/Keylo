<!-- markdownlint-disable MD060 -->

# Keylo API 接口文档（完整）

> 基于当前代码路由整理，覆盖认证、用户、RBAC、OAuth、服务间认证与系统健康检查。

> 从初始化到用户/RBAC/服务客户端的完整实操流程，请参考：[端到端快速开始](../guides/END_TO_END_QUICKSTART.md)

> 多客户端统一用户池与权限模型落地步骤请参考：[多客户端 RBAC 集成](../integrations/MULTI_CLIENT_RBAC_INTEGRATION.md)

> Keylo 2.0 Keystone 迁移与客户端 refresh/session 保存策略请参考：[Keystone 迁移方案](../integrations/keystone.md) 和 [客户端 Token 指南](KEYLO_2_0_CLIENT_GUIDE.md)

## 1. 鉴权约定

### 1.1 Token 类型

- 用户/管理接口：`Authorization: Bearer <access_token>`
- 服务接口：`Authorization: Bearer <service_access_token>`

### 1.2 受保护接口中间件规则

- 管理接口：`role` 包含 `admin`，`scope` 包含 `admin`，`aud=admin-backend`，且服务端实时确认 user Principal 仍是 active 的 `internal_employee` 并拥有 platform-scoped `admin`/`super_admin` 角色；active admin client 也会实时复核。旧的或手工构造的 admin JWT 不会绕过该检查。
- 平台组织管理接口：除管理 Token 条件外，人类主体必须实时为 `internal_employee`；client 主体必须仍是 active admin client。人类非 GET 请求继续适用近期 MFA 规则。
- 用户自助接口：`role` 包含 `user`，`scope` 包含 `write`，`aud=admin-backend`
- 服务内省接口：`role=service`，`scope` 包含 `read`
- 授权中心集成内省：`role=service`，`scope` 包含 `read`，`aud=admin-backend`

### 1.3 错误码（机读）

常见错误：

- `wrong_credentials`
- `missing_credentials`
- `invalid_token`
- `expired_token`
- `not_found`
- `forbidden`
- `conflict`
- `invalid_request`
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
| GET | `/metrics` | 否 | Prometheus 运行时指标 |
| GET | `/protected` | 是（access） | 受保护示例接口 |

### 2.2 发现配置与 JWT 公钥

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/.well-known/keylo-configuration` | 否 | Keylo 轻量发现配置 |
| GET | `/.well-known/jwks.json` | 否 | JWKS 公钥文档 |

平台管理员密钥管理接口（要求 `admin-backend` audience、platform `admin`/`super_admin` 权限；写操作遵循部署的近期 MFA 策略）：

| 方法 | 路径 | 作用 |
|---|---|---|
| POST | `/v1/admin/security/jwt-keys/rotate` | 生成并启用新的 active RSA key，保留旧 key 为 passive |
| POST | `/v1/admin/security/jwt-keys/rollback` | 将 live passive key 恢复为 active |
| POST | `/v1/admin/security/jwt-keys/retire` | 提前下线 passive key |

轮换请求体为 `{ "key_id": "keylo-rs256-2", "overlap_seconds": 900 }`，两个字段都可选；回滚和下线请求体为 `{ "key_id": "..." }`。响应会返回 `active_key_id`、`passive_key_ids` 和有效 overlap，不会返回任何私钥。轮换期间 `/.well-known/jwks.json` 同时发布 active 与仍在 overlap 窗口内的 passive 公钥；新 Token 只使用 active `kid`。每次轮换、回滚和下线都会写入对应的 `jwt_signing_key.*` 审计事件。

`/.well-known/keylo-configuration` 用于第三方服务发现 Keylo 的核心接入端点。它不是完整 OIDC discovery 文档，而是 Keylo 面向轻量统一鉴权场景提供的稳定集成契约。

配置中的 `issuer` 仍是 JWT 的 `JWT_ISSUER`；当设置 `OIDC_PUBLIC_ISSUER` 时，JWKS、Token、内省和文档 URL 使用该公开 origin，避免把容器监听地址暴露给接入方。

`/.well-known/openid-configuration` 是标准 OIDC Discovery 地址，当前公布 Authorization Code + PKCE（S256）、query response mode、RS256 JWKS 与 `openid`、`profile`、`email` scope。Discovery 同时声明可返回的 `sub`、`name`、`email`、`email_verified`、`organization_id` claims，客户端应只依赖所请求 scope 可获得的字段。OIDC issuer 由 `OIDC_PUBLIC_ISSUER` 决定；默认使用 HTTPS，不能使用 Keylo 的内部监听地址。完全隔离的内网可设置 `ALLOW_INSECURE_INTERNAL_HTTP=true` 使用 HTTP origin，但必须确保 IdP、Keylo 和浏览器客户端均在受控网络内，且任何 issuer、Discovery、授权端点和回调均不暴露到不受信任网络。

OIDC 公开端点：`GET /v1/oidc/authorize`、`POST /v1/oidc/login`、`POST /v1/oidc/consent`、`POST /v1/oidc/logout`、`POST /v1/oidc/token`、`GET /v1/oidc/userinfo`。授权码有效期为 5 分钟，且只能原子消费一次。`/v1/oidc/login` 使用 `application/x-www-form-urlencoded` 提交用户名、密码及原授权请求参数，成功后创建 `HttpOnly; Secure; SameSite=Lax` 浏览器会话。仅当 OIDC Provider 配置为 `ALLOW_INSECURE_INTERNAL_HTTP=true` 且 issuer 实际为 HTTP 时，Cookie 才去除 `Secure`，并受内网 HTTP 边界限制。登录后或已有会话访问 `/v1/oidc/authorize` 会显示客户端和 scope，必须通过同站点的 `/v1/oidc/consent` 明确确认才会重定向至已登记的 redirect URI 并签发 code；拒绝不会签发 code。`POST /v1/oidc/logout` 撤销该浏览器 OIDC session 并清除 cookie，不影响 API refresh session。UserInfo 只接受 OIDC access token；始终返回 `sub`，仅在被授予 `profile` 或 `email` scope 时返回对应 profile/email claims。

授权成功重定向会包含 `code`、请求中的 `state` 以及 `iss`。`iss` 始终等于 Discovery 的 issuer，relying party 应在处理回调时校验它，防止多身份提供方场景中的授权响应混淆。

`/v1/oidc/token` 支持标准 `client_secret_basic`：confidential client 可将按表单规则编码后的 `client_id:client_secret` 以 Base64 放入 `Authorization: Basic`，并在表单中省略 `client_id` 与 `client_secret`；同时保留 `client_secret_post` 兼容既有表单客户端。一次请求只能使用其中一种客户端认证方式。public client 继续在表单中提交 `client_id`，不提交 secret。

未建立 Keylo 浏览器会话的有效 `/v1/oidc/authorize` 请求会返回同站点 HTML 登录页，并保留原始授权参数；标准 OIDC relying party 只需把浏览器导航到 authorization endpoint，无需解析 Keylo 专用 `login_required` JSON。登录和同意页使用禁止外部资源、嵌入与跨站表单提交的 CSP，并设置 `Cache-Control: no-store`。登录后显示同意页，用户确认后才重定向并签发 code；用户拒绝时，Keylo 仅在 redirect URI 已通过精确注册校验后重定向 `error=access_denied`、原始 `state` 和 `iss`，不签发 code。

`/v1/oidc/token` 失败时使用 OAuth 2.0 错误响应：`invalid_request` 表示 grant 参数不支持，`invalid_client` 表示客户端认证失败（同时返回 `WWW-Authenticate`），`invalid_grant` 表示授权码、redirect URI 或 PKCE verifier 不匹配、失效或已被消费。内部错误统一返回 `server_error`，不泄露数据库或签名细节。

### 2.2 OIDC 客户端注册

> 以下管理接口统一要求：admin access token。

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/v1/admin/oidc/clients` | 查询 OIDC relying party 客户端；支持 `limit`/`offset` 分页元数据 |
| POST | `/v1/admin/oidc/clients` | 注册 OIDC 客户端 |
| PUT | `/v1/admin/oidc/clients/{client_id}` | 更新客户端元数据或启用状态 |
| POST | `/v1/admin/oidc/clients/{client_id}/rotate-secret` | 轮换 confidential client secret |

组织 owner/admin 使用 signed active organization context 管理本组织 OIDC client。以下路径不会接受请求体中的 `organization_id`，且所有写操作要求近期 MFA；跨组织路径、非 active membership 和停用组织统一拒绝：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/v1/organizations/{organization_id}/oidc/clients` | 查询当前组织的 OIDC client；支持 `limit`/`offset` 分页元数据 |
| POST | `/v1/organizations/{organization_id}/oidc/clients` | 创建 organization-scoped OIDC client |
| GET | `/v1/organizations/{organization_id}/oidc/clients/{client_id}` | 查询当前组织的指定 client |
| PUT | `/v1/organizations/{organization_id}/oidc/clients/{client_id}` | 更新当前组织 client 元数据或启用状态 |
| POST | `/v1/organizations/{organization_id}/oidc/clients/{client_id}/rotate-secret` | 轮换当前组织 confidential client secret |

平台管理列表仅返回显式 `scope_kind=platform` 的 client；organization client 的 `scope_kind` 和 `organization_id` 在创建时由路径和 live membership 派生，作用域不可迁移。organization client 签发的 ID/access token 与 UserInfo 会带当前 `organization_id`，授权码创建、兑换和 UserInfo 每次都会实时校验组织 active、用户 Principal active 及 membership active。组织停用、归档或成员变为 pending、suspended、removed 时，未兑换的组织授权码会被原子撤销，旧 access token 不能继续通过 UserInfo。

当前仅接受 `authorization_code` grant。`public` 客户端不能登记 secret；`confidential` 客户端必须提供至少 16 个字符的 secret，服务端仅保存 bcrypt hash。redirect URI 必须为 HTTPS；开发期仅允许精确的 `127.0.0.1` 或 `[::1]` 回环地址使用 HTTP。所有回调不得携带 URL 凭据或 fragment，`127.0.0.1.example.com` 等前缀相似域名不视为回环地址。

当前可登记的 OIDC scope 为 `openid`、`profile`、`email`，且必须包含 `openid`、不得重复。Keylo 拒绝尚未实现 claims 或授权语义的自定义 scope。

`POST /v1/admin/oidc/clients/{client_id}/rotate-secret` 请求体为 `{ "new_secret": "至少 16 个字符" }`。仅 active confidential client 可轮换，服务端仅保存新 secret 的 bcrypt hash，响应不会回显 secret。

`PUT /v1/admin/oidc/clients/{client_id}` 将 active 客户端设为 `false`，或修改其 redirect URI、grant type、scope 时，Keylo 会在同一事务中删除该客户端所有未兑换授权码，并记录 `oidc_client.disabled` 或 `oidc_client.reconfigured` 审计事件。重新启用客户端不会恢复旧 code。

示例响应：

```json
{
  "issuer": "keylo",
  "jwks_uri": "http://127.0.0.1:2345/.well-known/jwks.json",
  "introspection_endpoint": "http://127.0.0.1:2345/v1/auth/introspect",
  "service_token_endpoint": "http://127.0.0.1:2345/v1/service/token",
  "service_introspection_endpoint": "http://127.0.0.1:2345/v1/service/introspect",
  "user_token_endpoint": "http://127.0.0.1:2345/v1/auth/token",
  "admin_token_endpoint": "http://127.0.0.1:2345/v1/admin/token",
  "supported_token_types": ["access", "refresh", "service_access"],
  "supported_claims": ["iss", "sub", "aud", "exp", "iat", "jti", "scope", "role", "token_type", "uid", "principal_id", "principal_type", "organization_id"],
  "supported_signing_algorithms": ["RS256"],
  "supported_audiences": ["admin-backend", "crawler"],
  "documentation_uri": "http://127.0.0.1:2345/docs/integrations/THIRD_PARTY_INTEGRATION.md"
}
```

---

## 3. 认证与令牌接口

### 3.1 获取用户 Token

- **POST** `/v1/auth/token`
- 鉴权：否
- 请求体：

```json
{
  "client_id": "alice",
  "client_secret": "Alice#12345",
  "force": false,
  "organization_id": "org-acme"
}
```

- 响应体：

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

`force` 可选，默认 `false`。仅当 `SESSION_POLICY=single_user_session` 或 `SESSION_POLICY=single_principal_session` 且认证成功后，`force=true` 才会撤销同一 Principal 的旧 refresh session 并接管登录。`organization_id` 同样可选；提供时只允许人类密码登录，服务端会实时确认该 Principal 在目标组织有 active membership，随后将相同 scope 写入 access token、refresh token 与 refresh session。省略或传 `null` 保持 platform session；空、未知、已停用或非 active membership 的组织范围均不会签发 Token。

### 3.2 获取管理 Token

- **POST** `/v1/admin/token`
- 鉴权：否（仅受信任管理客户端凭证可通过）
- 请求体使用 `client_id`、`client_secret` 和可选 `force`；不接受 `organization_id`
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
  - 通过 `POST /v1/auth/token` 获取
  - 通过 `POST /v1/admin/token` 获取
- 刷新时旧 `refresh_token` 会被 refresh session 原子消费并固定轮换。
- 并发或重复使用同一个 refresh token 只允许一个请求成功。
- 旧 refresh token 重放会撤销所属 refresh session，并写入审计日志。
- organization-scoped refresh token 只会在 session scope、签名 `organization_id`、active organization 与 active membership 全部一致时轮换；成员变为 pending/suspended/removed 或组织变为 disabled/archived 后，该 scope 的旧 session 会被撤销，重新 active 不会恢复旧 token。

### 3.4 当前用户信息

- **GET** `/v1/auth/me`
- 鉴权：是（access）
- 响应字段：`sub`、`uid`、`principal_id`、`principal_type`、`organization_id`、`scope[]`、`role[]`、`aud`、`exp`、`iss`、`jti`
- 字段说明：`uid` 为 `users` 表主键（稳定用户 ID），`principal_id` 为 Keylo 2.0 统一 Principal 主键，`sub` 为主体标识字符串。

### 3.5 退出登录

- **POST** `/v1/auth/logout`
- 鉴权：是（access）
- 作用：将当前 access token 拉黑

### 3.6 通过 Refresh Token 退出登录

- **POST** `/v1/auth/logout-refresh-token`
- 鉴权：否
- 作用：在 access token 已失效或不可用时，通过 refresh token 撤销对应 refresh session。
- 请求体：

```json
{
  "refresh_token": "..."
}
```

撤销后，该 refresh token 不能再用于 `/v1/auth/refresh`。如果 refresh token 属于 refresh session，Keylo 会撤销整个 session。

### 3.7 用户注册

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

本地注册用户的 `email_verified` 初始值为 `false`。该字段会在用户管理接口和用户创建响应中返回；管理员修改邮箱后会自动重置为 `false`。只有已验证的上游 OIDC `email_verified: true` 且邮箱与本地邮箱匹配时，Keylo 才会将本地状态提升为 `true`，并记录 `user.email_verified` 审计事件。

### 3.8 第三方 JIT 迁移注册

- **POST** `/v1/auth/migrations/jit-register`
- 鉴权：否
- 请求体：`provider`、`external_user_id`、`username`、`email`、`password?`、`active?`、`roles?`、`metadata?`

### 3.9 Token 内省（授权中心集成）

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
| GET | `/v1/admin/audit-logs` | 查询审计日志（`limit/offset`，返回 `has_more/next_offset`，敏感 detail 脱敏） |
| GET | `/v1/admin/audit-logs/export` | 稳定游标导出审计日志（管理员） |
| POST | `/v1/admin/audit-logs/cleanup` | 清理审计日志（按保留天数） |
| GET | `/v1/admin/clients?limit=&offset=` | 查询管理客户端；响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| POST | `/v1/admin/clients` | 创建管理客户端 |
| PUT | `/v1/admin/clients/{client_id}` | 更新管理客户端 |
| POST | `/v1/admin/clients/{client_id}/rotate-secret` | 轮换管理客户端密钥 |

`GET /v1/admin/audit-logs/export`：

- 仅接受 admin access token；查询参数为 `event_type`（可选精确过滤）、`limit`（默认 100，范围 1-200）和 `cursor`（上一页返回的游标）。
- 返回 `data`、`next_cursor` 和 `dedupe_key: "id"`。每条记录的 `id` 是数据库持久化的稳定事件标识，消费方应以它去重并允许重复投递安全重试。
- 导出按 `created_at DESC, id DESC` 稳定排序；新增日志不会改变已经返回游标之后的页面。无下一页时 `next_cursor` 为 `null`。
- `detail` 会对 `access_token`、`refresh_token`、`client_secret`、`api_key`、`password`、`recovery_code`、`totp_code` 和 `verifier` 字段进行 `[REDACTED]` 处理，并屏蔽形似 JWT 的值；审计日志不得写入密钥或 Token 原文。

`POST /v1/admin/clients/{client_id}/rotate-secret`：

- 请求体可选 `new_secret`。传入时服务端只保存 bcrypt hash，响应不会回显明文。
- 省略 `new_secret` 时服务端会生成新密钥，并在响应的 `new_secret` 字段中一次性返回；调用方必须立即保存。
- 响应包含 `secret_generated`，用于区分是否由服务端生成。

---

## 5. 用户管理接口

> 路径前缀：`/v1/admin/users`，统一要求：admin access token

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/users?limit=&offset=` | 用户分页列表；响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| POST | `/v1/admin/users` | 创建用户 |
| POST | `/v1/admin/users/provision` | 原子创建用户并绑定角色模板 |
| GET | `/v1/admin/users/{user_id}` | 获取用户详情 |
| PUT | `/v1/admin/users/{user_id}` | 更新用户 |
| DELETE | `/v1/admin/users/{user_id}` | 删除用户 |
| GET | `/v1/admin/users/{user_id}/effective-permissions` | 用户最终权限并集 |
| POST | `/v1/admin/users/{user_id}/reset-password` | 重置密码 |
| POST | `/v1/admin/users/{user_id}/verify-email` | 将当前邮箱标记为已验证 |
| POST | `/v1/admin/users/migrations/import` | 同步执行第三方用户导入 |
| POST | `/v1/admin/users/migrations/jobs` | 提交异步导入任务 |
| GET | `/v1/admin/users/migrations/jobs/{job_id}` | 查询异步导入任务状态 |

管理端创建、预配、更新、重置用户密码时，非空密码均需满足统一复杂度策略：至少 8 位，并包含大写字母、小写字母、数字和特殊字符。

管理员通过更新接口将用户设为 `active: false` 时，Keylo 会在同一事务中撤销该用户全部 refresh session 和 OIDC 浏览器会话，并记录包含撤销数量的 `user.disabled` 审计事件。带 Principal 的既有 access token 会在下一次受保护请求时被拒绝，不会继续等待其自然过期；已存在的 OIDC 浏览器 cookie 也不能再进入授权或同意流程。

管理员通过同一更新接口设置 `password` 时，Keylo 会在密码生效前撤销该用户的全部 refresh session 和 OIDC 浏览器会话，并记录 `user.password_updated` 审计事件；旧 refresh token 与浏览器 OIDC cookie 不能继续使用。

管理员完成近期 MFA 后可调用 `POST /v1/admin/users/{user_id}/verify-email` 标记用户当前邮箱为已验证。该操作幂等，不会发送邮件、不修改邮箱地址，并记录 `user.email_verified` 审计事件；管理员后续修改邮箱会自动清除该状态。

当管理操作由已启用 TOTP 的人类用户 Principal 发起时，禁用、删除用户、管理员改密和重置密码必须先完成与当前 access token 绑定的近期 MFA 验证；管理客户端凭据属于机器自动化身份，不适用 TOTP 挑战。

同一规则适用于角色、权限定义的创建/修改/删除/回滚，用户或 Principal 角色的授予和撤销，以及角色权限的单项或批量变更。未完成近期 MFA 验证的人类管理用户会收到 `403` 和 `mfa_required: true`，不会产生部分授权修改。

管理员删除用户时，Keylo 会在删除账户的同一事务中撤销 refresh session、删除该用户的 OIDC 浏览器会话和关联 Principal（及其角色绑定），并写入 `user.deleted` 审计事件。

### 5.1 Provision 请求体

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Alice#12345",
  "user_class": "external_customer",
  "role_ids": ["role-id-1"],
  "role_names": ["ssc_dispatcher"]
}
```

### 5.2 用户自助接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/v1/user/change-password` | user access token | 修改当前用户密码 |
| POST | `/v1/user/mfa/totp/enroll` | user access token | 创建待确认的 TOTP enrollment |
| POST | `/v1/user/mfa/totp/verify` | user access token | 用验证码确认并启用待确认的 TOTP |
| POST | `/v1/user/mfa/totp/reset` | user access token + recent MFA | 删除当前 TOTP 与全部恢复码 |
| POST | `/v1/user/mfa/verify` | user access token | 验证 TOTP 或恢复码，创建短时 MFA 凭据 |

`POST /v1/user/mfa/totp/enroll` 只可由带稳定 `uid` 的用户 token 调用。它会生成新 Base32 seed、加密保存待确认状态，并一次性返回 `manual_entry_key` 和标准 `provisioning_uri`；响应不得写入客户端日志。已经启用 TOTP 的账户不能通过此接口直接覆盖现有凭据。

调用方将 `provisioning_uri` 交给验证器应用扫码或使用 `manual_entry_key` 手动添加后，提交：

```json
{ "code": "123456" }
```

到 `POST /v1/user/mfa/totp/verify`。Keylo 采用 6 位、30 秒、SHA-1 的 RFC 6238 兼容配置，并允许相邻一个时间步来兼容轻微时钟误差。验证成功后才启用凭据、原子生成 10 个恢复码并写入审计日志；恢复码只在该响应的 `recovery_codes` 中返回一次，服务端仅保存 bcrypt hash，客户端不得记录明文。无效或已启用的 enrollment 不会产生部分状态变更。

`POST /v1/user/mfa/verify` 请求体必须且只能提交 `totp_code` 或 `recovery_code` 其中之一。验证成功后，Keylo 将最近 MFA 凭据绑定到当前 access token 的 `jti`，有效期为 10 分钟；TOTP 的同一时间步只能成功一次，恢复码成功后立即作废。该接口为改密和管理敏感操作提供二次认证前置条件，审计记录仅保存验证方式。

已启用 TOTP 的用户调用 `POST /v1/user/change-password` 前必须先调用 `/v1/user/mfa/verify` 并使用同一 access token；缺少或过期的近期 MFA 凭据会返回 `403` 与 `mfa_required=true`，不会修改密码。尚未启用 MFA 的既有用户在管理员强制 MFA 策略上线前保持兼容。

改密成功后，Keylo 会在同一事务中撤销该用户的 refresh session 和 OIDC 浏览器会话，并写入 `user.password_changed` 审计事件；客户端必须使用新密码重新登录，旧 refresh token 与旧 OIDC 浏览器 cookie 均不能继续使用。

管理员重置密码也遵循同一撤销规则，并写入 `user.password_reset` 审计事件。

`POST /v1/user/mfa/totp/reset` 必须先使用同一 access token 调用 `/v1/user/mfa/verify`。成功后会删除 TOTP seed、所有未使用恢复码和该用户的近期 MFA 凭据，并写入 `mfa.totp.reset` 审计事件；用户随后可重新 enrollment。该接口不接受验证码或恢复码明文。

管理端由已启用 TOTP 的用户 access token 发起的写操作同样要求近期 MFA；范围包括 `POST`、`PUT`、`DELETE`。设置 `MFA_REQUIRE_FOR_ADMINS=true` 后，所有人类管理员必须先 enrollment 再执行写操作。管理员客户端 access token 面向受控自动化，不适用交互式 MFA 校验。管理端查询接口不要求重复验证。

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

`POST /api/rbac/roles` 请求体：

```json
{
  "name": "crawler_service",
  "description": "Crawler service role",
  "assignable_to": "service",
  "system": false
}
```

`assignable_to` 可选，支持 `user`、`service`、`client`、`all`，默认 `all`。它用于限制角色可以绑定到哪类 Principal。当前通过用户角色、Principal 角色接口和 provision 写入的都是 platform scope；organization scope 角色只能通过组织成员关系绑定。`external_customer` 不能绑定 platform/global role，`provision` 若要创建并绑定平台角色必须显式设置 `user_class: "internal_employee"`；省略时默认为 `external_customer`。

### 6.2 权限管理

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/permissions` |
| POST | `/api/rbac/permissions` |
| GET | `/api/rbac/permissions/{permission_id}` |
| PUT | `/api/rbac/permissions/{permission_id}` |
| DELETE | `/api/rbac/permissions/{permission_id}` |

说明：`GET /api/rbac/permissions` 支持 `prefix` 查询参数，如：`?prefix=ssc.`

权限名 `*:*:*` 保留为超级权限通配符。它必须像普通权限一样显式创建并绑定到角色；绑定后，该 Principal 的 `/v1/authorize/check` 对任意权限 code 返回允许。

### 6.3 用户角色管理

| 方法 | 路径 |
|---|---|
| GET | `/api/rbac/users/{user_id}/roles` |
| POST | `/api/rbac/users/{user_id}/roles` |
| POST | `/api/rbac/users/{user_id}/roles/batch` |
| DELETE | `/api/rbac/users/{user_id}/roles/{role_id}` |

用户角色写入会在同一事务中预检全部角色。外部客户或 organization-scoped 角色会返回 `400 invalid_role_assignment`，批量请求失败时不会留下前半批绑定；历史不符合当前类别规则的绑定在权限查询、资源树和 Token introspection 中默认失败关闭。

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

## 7. Keylo 2.0 Principal、资源树与授权 API

### 7.1 Principal 自助查询

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/principals/me/effective-permissions` | access 或 service_access | 当前 Principal 的最终权限 |
| GET | `/v1/principals/me/resource-tree?app=&type=` | access 或 service_access | 当前 Principal 可见资源树 |

`resource-tree` 的 `type` 支持 `menu`、`button`、`api`、`service`、`data_scope`。用户通常消费 `menu/button/data_scope`，服务通常消费 `api/service`。

access token 或 service_access token 带有 `organization_id` 时，这两个端点会实时确认该 Principal 仍是该组织的 active member，随后只解释该组织的 `organization_role_bindings` 和该组织资源；成员被移除、暂停或组织被停用后，旧 token 不会继续获得组织权限。没有组织上下文的 access token 与 service_access 只解释 platform role 和 platform resource。独立 `device` Principal 与 API key 只能直接调用下一节明确声明的授权检查接口，不能调用本节的自助查询接口。

### 7.2 统一授权检查

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/v1/authorize/check` | access、service_access 或受限 API key | 单点授权检查 |
| POST | `/v1/authorize/batch-check` | access、service_access 或受限 API key | 批量授权检查 |

按权限 code 检查：

```json
{
  "permission": "keystone:system:user:list"
}
```

按资源解析权限后检查：

```json
{
  "app": "crawler",
  "resource_type": "service",
  "resource_code": "crawler:news:sync"
}
```

每个检查必须二选一：提供非空 `permission`，或同时提供非空 `app`、`resource_type`、`resource_code`。混用两种目标、空权限或不完整资源坐标返回 `invalid_request`，不会被静默降级为拒绝。

授权上下文只来自签名 token 或 MachineCredential 固定的 `organization_id`，不能由请求头、URL 查询参数或请求体覆盖。直接 permission 检查在带 `organization_id` 的 access token 或 API key 下只读取当前组织的 active membership 与 organization role；按资源坐标检查会先解析资源归属，tenant resource 必须属于当前组织，platform resource 只接受 platform role。未知、跨组织、已停用或不可见的资源统一返回普通 deny，不暴露其他组织是否存在。batch-check 对整批请求只解析一次相同的 live context。

机器调用仅在这两个端点通过 `X-API-Key: keylo.<key_id>.<secret>` 传递 API key。服务端只保存 bcrypt hash；它会同时检查 key 的 active/expiry、固定 scope、Principal、组织和 active membership，以及最终 RBAC。`allowed_scopes` 必须包含 `authorization`，`allowed_audiences` 必须包含 `admin-backend` 或 `*`。`Authorization: Bearer <api-key>`、同时携带 Bearer 和 `X-API-Key`、`api_key`/`x-api-key` URL 参数、错误 scope/audience、未知/撤销/过期 key 一律返回统一未授权结果。API key 不接受任何 `/v1/auth/*` 人类登录或 refresh 流程。

响应：

```json
{
  "success": true,
  "data": {
    "allowed": true,
    "decision": "allow",
    "reason": "permission_granted",
    "principal_id": "service-crawler",
    "matched_permission": "service:crawler:sync"
  }
}
```

未知 Principal、禁用 Principal、未绑定角色、无匹配权限时默认 `allowed=false`。已解析且未绑定权限时返回 `decision="deny"`、`reason="permission_not_bound"`；请求无法解析出权限时返回 `reason="permission_not_resolved"`；允许时固定返回 `decision="allow"`、`reason="permission_granted"`。这些字段是资源服务可稳定消费的决策摘要，授权审计日志记录相同 reason，不包含 token 或主体凭据。

`/v1/authorize/batch-check` 的 `checks` 必须包含 1 到 100 项；空批次和超出上限的批次返回 `invalid_request`，不会执行部分授权检查。

### 7.3 Principal 管理

> 统一要求：admin access token

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/principals?principal_type=&active=&limit=&offset=` | Principal 列表；响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| GET | `/v1/admin/authorization-audit-logs?organization_id=&principal_id=&decision=&permission_name=&resource_id=&limit=&offset=` | 授权决策审计日志；organization_id 为精确组织过滤，`decision` 可筛选 `allow` 或 `deny` |
| POST | `/v1/admin/authorization-audit-logs/cleanup` | 清理超过保留期的授权审计日志，体为 `{ "retention_days": 30 }` |
| GET | `/v1/admin/principals/{principal_id}` | Principal 详情 |
| GET | `/v1/admin/principals/{principal_id}/roles` | Principal 角色 |
| POST | `/v1/admin/principals/{principal_id}/roles` | 给 Principal 绑定角色 |
| DELETE | `/v1/admin/principals/{principal_id}/roles/{role_id}` | 撤销 Principal 角色 |
| GET | `/v1/admin/principals/{principal_id}/effective-permissions` | Principal 最终权限 |
| GET | `/v1/admin/principals/{principal_id}/refresh-sessions?include_revoked=false&limit=&offset=` | Principal refresh session 列表；limit 默认 50、最大 200，offset 默认 0 |
| DELETE | `/v1/admin/principals/{principal_id}/refresh-sessions` | 撤销该 Principal 的所有 refresh session |
| DELETE | `/v1/admin/principals/{principal_id}/refresh-sessions/{session_id}` | 撤销单个 refresh session |
| GET | `/v1/admin/principals/{principal_id}/api-keys?organization_id=` | 查询该 machine Principal 在精确 scope 内的 API key 元数据 |
| POST | `/v1/admin/principals/{principal_id}/api-keys` | 创建 service/device API key；请求体显式提供可选 `organization_id` 和 capabilities |
| POST | `/v1/admin/principals/{principal_id}/api-keys/{key_id}/rotate?organization_id=` | 创建重叠期 replacement key，旧 key 保持 active 直至显式撤销 |
| DELETE | `/v1/admin/principals/{principal_id}/api-keys/{key_id}?organization_id=` | 请求体 `{ "reason": "..." }`，撤销一把 key |
| GET | `/v1/admin/devices?organization_id=` | 查询 platform 或一个精确 organization scope 的 device Principal |
| POST | `/v1/admin/devices` | 创建 device；可选 `organization_id` 一旦写入不可变 |
| GET | `/v1/admin/devices/{device_id}?organization_id=` | 查询一个精确 scope 的 device |
| PUT | `/v1/admin/devices/{device_id}?organization_id=` | 更新 device display_name 或 active，不可迁移 scope |
| GET | `/v1/admin/refresh-sessions?include_revoked=false&organization_id=&principal_id=&client_id=&login_ip=&limit=&offset=` | 全局 refresh session 列表；organization_id 为精确组织过滤 |
| DELETE | `/v1/admin/refresh-sessions/{session_id}` | 按 session ID 强制撤销 refresh session |

绑定角色请求体：

```json
{
  "role_id": "role-id"
}
```

对 `user` Principal 的 platform role 写入会与 user-role 关系在同一事务中同步；从任一用户或 Principal 管理接口撤销都会清理两侧绑定。`external_customer` 及 organization-scoped role 均不能使用该平台绑定接口。

更新角色时可提供读取结果中的 `expected_version`。版本不一致返回 `409 role_version_conflict`；省略该字段保持兼容更新。
`change_reason` 可选，提供时会进入角色结构化变更历史；通过 `GET /api/rbac/roles/{role_id}/changes?limit=&offset=` 查询版本、操作者、原因和前后快照。
`POST /api/rbac/roles/{role_id}/changes/{version}/revert` 会恢复该历史变更的 `before_state`，请求必须包含当前 `expected_version` 与非空 `change_reason`；回滚本身会生成一个新版本和新的历史记录。

更新权限同样可提供 `expected_version`，版本不一致返回 `409 permission_version_conflict`。
`change_reason` 可选，提供时会进入权限结构化变更历史；通过 `GET /api/rbac/permissions/{permission_id}/changes?limit=&offset=` 查询版本、操作者、原因和前后快照。
`POST /api/rbac/permissions/{permission_id}/changes/{version}/revert` 会恢复该历史变更的 `before_state`，请求必须包含当前 `expected_version` 与非空 `change_reason`；回滚会产生新的版本和历史记录。

### 7.4 Resource 管理

> 统一要求：admin access token

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/resources?organization_id=&app=&type=&active=&limit=&offset=` | 资源列表；提供 organization_id 时只返回该组织资源，响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| POST | `/v1/admin/resources` | 创建或更新资源 |
| PUT | `/v1/admin/resources/{resource_id}` | 更新资源可变字段；必须提供 `expected_version`，冲突返回 `409` |
| GET | `/v1/admin/resources/{resource_id}/changes?limit=&offset=` | 资源更新版本、操作者、原因及前后快照 |
| POST | `/v1/admin/resources/{resource_id}/changes/{version}/revert` | 恢复该历史变更的 `before_state`；请求必须提供当前 `expected_version` 与非空 `change_reason` |
| GET | `/v1/admin/resources/{resource_id}/permissions` | 查询资源绑定的权限 |
| POST | `/v1/admin/resources/{resource_id}/permissions` | 给资源绑定权限，可选 `change_reason` 写入审计日志 |
| DELETE | `/v1/admin/resources/{resource_id}/permissions/{permission_id}` | 撤销资源权限绑定，请求体可选 `change_reason` 写入审计日志 |

创建资源请求体：

```json
{
  "organization_id": "organization-id-or-null",
  "app": "keystone",
  "resource_type": "menu",
  "code": "system:user",
  "name": "用户管理",
  "parent_id": null,
  "display_order": 10,
  "description": "Keystone user management menu",
  "metadata": {
    "router_name": "SystemUser",
    "path": "/system/user",
    "component": "system/user/index",
    "meta": {
      "title": "用户管理",
      "icon": "user",
      "showLink": true
    }
  },
  "permission_ids": ["permission-id"]
}
```

`organization_id` 省略或为 `null` 时创建 platform resource；提供有效 ID 时创建该组织的 resource。同一 `app/type/code` 可以在不同组织复用，但父子资源必须位于同一 scope。`metadata` 可选，用于保存资源服务自己的展示或路由元数据。Keystone 菜单迁移时可以在这里保存 `router_name`、`path`、`component`、`meta` 等字段，再由 Keystone BFF 或前端映射为原 `RouterDTO`。

资源通过 `resource_permissions` 绑定到权限点。`/v1/principals/me/resource-tree` 只返回当前 Principal 在当前授权 scope 内通过角色权限可见的资源节点，并包含必要祖先节点。若 Principal 在该 scope 拥有 `*:*:*` 权限，则返回指定 `app` 和 `type` 下的全部 active 资源。资源树响应会保留 `metadata`，并返回资源的 `organization_id`。

### 7.5 平台组织与成员状态管理

> 这些是平台管理员接口，不是组织 owner/admin 自服务接口。平台管理员的跨组织操作必须显式携带目标组织 ID；组织资源与组织角色绑定不会被当作 platform 权限。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/organizations?status=&limit=&offset=` | 分页列出组织，可按状态过滤；响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| POST | `/v1/admin/organizations` | 创建 customer 或 internal 组织 |
| GET | `/v1/admin/organizations/{organization_id}` | 查询一个组织 |
| PUT | `/v1/admin/organizations/{organization_id}/status` | 变更组织生命周期状态 |
| GET | `/v1/admin/organizations/{organization_id}/memberships?status=&limit=&offset=` | 列出组织成员关系，可按成员状态过滤；响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| GET | `/v1/admin/organizations/{organization_id}/memberships/{principal_id}` | 查询一个成员关系 |
| PUT | `/v1/admin/organizations/{organization_id}/memberships/{principal_id}` | 幂等写入成员状态 |

创建组织请求：

```json
{
  "slug": "acme",
  "name": "Acme Corporation",
  "kind": "customer"
}
```

`kind` 只能是 `customer` 或 `internal`，`slug` 全局唯一，且不是认证凭据。组织不会被物理删除。状态写入请求为 `{ "status": "active|disabled|archived" }`，只允许 `active -> disabled/archived`、`disabled -> active/archived`、`archived -> active` 或同状态重试；不允许的转换返回 `400 invalid_request`。从 active 进入 disabled 或 archived 时，系统会在同一事务中撤销该组织的未过期 refresh session。

成员状态写入请求为 `{ "status": "pending|active|suspended|removed", "management_role": "member|admin|owner" }`；`management_role` 可由平台管理员用于显式设置组织初始 owner/admin，省略时保持已有管理角色或默认为 `member`。对同一 `(organization_id, principal_id)` 的重复请求不会创建重复关系。external_customer 不能加入 internal 组织；disabled 或 archived 组织不能创建 pending/active 成员关系。成员变为 pending、suspended 或 removed 时，会原子撤销该成员在本组织的 refresh session，不影响其 platform 或其他组织 session。成功写入正常会产生 `organization.created`、`organization.status_changed` 或 `organization.membership_changed` 审计事件。

### 7.6 组织 owner/admin 自服务成员 API

组织管理员只能操作签名 access token 中的当前 `organization_id`，服务端不会信任 `X-Organization-Id` 或仅凭路径参数授权。先通过以下端点选择组织上下文：

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/v1/auth/organization-context` | user access token | 校验 active membership 后重新签发带 `organization_id` 的短期 access token；不创建 refresh session |

除首次接受邀请的 join 请求外，以下接口都要求 token 中的 `organization_id` 与路径一致，并实时确认调用者是该组织 active membership 的 `admin` 或 `owner`。人类写操作沿用近期 MFA 规则；机器 client、普通 member、pending/suspended/removed 成员和跨组织路径统一拒绝。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/organizations/{organization_id}/memberships?status=&limit=&offset=` | 查询当前组织成员 |
| POST | `/v1/organizations/{organization_id}/memberships/invitations` | `{ "principal_id": "...", "management_role": "member|admin|owner" }`，创建或重复刷新 pending 邀请 |
| PUT | `/v1/organizations/{organization_id}/memberships/{principal_id}` | 更新成员状态和管理角色；admin 不能授予或修改 owner |
| POST | `/v1/organizations/{organization_id}/memberships/{principal_id}/join` | 仅目标本人接受 pending 邀请；重复 join 幂等 |
| GET | `/v1/organizations/{organization_id}/memberships/{principal_id}/roles` | 查询组织角色绑定 |
| POST | `/v1/organizations/{organization_id}/memberships/{principal_id}/roles` | `{ "role_id": "..." }`，只接受 organization-scoped role |
| DELETE | `/v1/organizations/{organization_id}/memberships/{principal_id}/roles/{role_id}` | 幂等撤销组织角色绑定 |
| GET | `/v1/organizations/{organization_id}/services?limit=&offset=` | 查询当前组织的 service client；limit 默认 50、最大 200，offset 默认 0，返回 `has_more/next_offset` |
| POST | `/v1/organizations/{organization_id}/services` | 创建当前组织的 service client |
| GET | `/v1/organizations/{organization_id}/services/{service_id}` | 查询当前组织的 service client |
| PUT | `/v1/organizations/{organization_id}/services/{service_id}` | 更新当前组织 service 的可变元数据 |
| POST | `/v1/organizations/{organization_id}/services/{service_id}/rotate-secret` | 轮换当前组织 service secret |
| GET | `/v1/organizations/{organization_id}/devices?limit=&offset=` | 查询当前组织的 device Principal；返回 `has_more/next_offset` |
| POST | `/v1/organizations/{organization_id}/devices` | 创建当前组织 device；scope 只从路径和 signed context 派生 |
| GET | `/v1/organizations/{organization_id}/devices/{device_id}` | 查询当前组织 device |
| PUT | `/v1/organizations/{organization_id}/devices/{device_id}` | 更新 device display_name 或 active，不能迁移 scope |
| GET | `/v1/organizations/{organization_id}/principals/{principal_id}/api-keys?limit=&offset=` | 查询当前组织 machine Principal 的安全元数据；返回 `has_more/next_offset` |
| POST | `/v1/organizations/{organization_id}/principals/{principal_id}/api-keys` | 创建当前组织 service/device 的 API key |
| POST | `/v1/organizations/{organization_id}/principals/{principal_id}/api-keys/{key_id}/rotate` | 创建 replacement key，允许短暂重叠 |
| DELETE | `/v1/organizations/{organization_id}/principals/{principal_id}/api-keys/{key_id}` | 请求体 `{ "reason": "..." }`，撤销一把 key |

组织 service 创建请求与平台服务注册使用相同的 `service_id`、`service_secret`、`name`、`allowed_scopes`、`allowed_audiences`、`integration_type`、`token_ttl_seconds`、`owner` 和 `contact` 字段，但不接受 `organization_id` 或 `introspection_allowed`。组织范围只来自路径和签名 access token 的相同 active organization context；创建时会原子写入 service Principal 与 active membership。更新同样不接受 scope 或 introspection 字段，组织 service 永远不能调用内省端点。轮换请求可选 `{ "new_secret": "..." }`；省略时服务器只在该次响应的 `data.new_secret` 返回新值。

device 创建请求是 `{ "device_id": "edge-001", "display_name": "Warehouse edge agent" }`。organization 路由拒绝 body 中的 `organization_id`；创建会原子写入 immutable device scope 和 active organization membership。API key 创建请求是 `{ "allowed_scopes": ["authorization"], "allowed_audiences": ["admin-backend"], "expires_at": "2026-08-11T08:00:00Z" }`；`expires_at` 可省略，提供时必须是未来 RFC3339 时间。创建和轮换的 `data.api_key` 只在该次响应中出现；列表及审计永远不返回原值或 hash。rotation 请求可以传新的 `expires_at`、`allowed_scopes` 或 `allowed_audiences`，省略字段时沿用旧 key 的能力限制。

`organization_role_bindings` 只在持有相同 signed organization context、且组织与 membership 均为 active 时参与组织作用域的授权决策；它们不会转化为通用 platform 权限。跨组织、停用组织、非 active membership 和平台角色绑定均失败关闭。成功写操作会分别写入 `organization.membership.invited`、`organization.membership.updated`、`organization.membership.joined`、`organization.role_binding.assigned`、`organization.role_binding.revoked`、`organization.service.created`、`organization.service.updated`、`organization.service.secret_rotated`、`machine.device.created`、`machine.device.updated`、`machine.api_key.created`、`machine.api_key.rotated` 或 `machine.api_key.revoked` 审计事件。

### 7.7 受限 Customer Support 访问

Customer Support 不是组织成员关系，也不使用 `organization_role_bindings`。它只允许带有固定 platform `customer_support` 系统角色的 `internal_employee`，在平台管理员明确授予一个活跃 customer 组织、操作集合和人工原因后，临时读取该组织的排障数据。该角色不能拥有通用 RBAC permission，不能作为跨组织通配符。

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/admin/customer-support-grants?organization_id=&support_principal_id=&granted_by_principal_id=&include_revoked=&limit=&offset=` | platform admin | 精确筛选临时支持授权 |
| GET | `/v1/admin/customer-support-audit-logs?organization_id=&actor_principal_id=&grant_id=&operation=&outcome=&limit=&offset=` | platform admin | 精确筛选不可变支持审计轨迹 |
| POST | `/v1/admin/customer-support-grants` | internal human platform admin | 创建目标组织、操作与到期时间固定的授权 |
| DELETE | `/v1/admin/customer-support-grants/{grant_id}` | internal human platform admin | 请求体 `{ "reason": "..." }`；重复撤销幂等 |
| POST | `/v1/customer-support/context` | 普通、platform-scoped support user access token | 请求体 `{ "grant_id": "..." }`，换取不超过 5 分钟且不超过授权到期时间的 `customer_support_access` token |
| GET | `/v1/customer-support/organizations/{organization_id}` | `customer_support_access` | 需要 `organization.read` |
| GET | `/v1/customer-support/organizations/{organization_id}/memberships` | `customer_support_access` | 需要 `membership.read` |
| GET | `/v1/customer-support/organizations/{organization_id}/resources` | `customer_support_access` | 需要 `resource.read` |
| GET | `/v1/customer-support/organizations/{organization_id}/authorization-audit-logs` | `customer_support_access` | 需要 `authorization_audit.read` |
| GET | `/v1/customer-support/organizations/{organization_id}/refresh-sessions` | `customer_support_access` | 需要 `refresh_session.read` |

创建授权请求：

```json
{
  "support_principal_id": "user-support-1",
  "organization_id": "org-acme",
  "reason": "Investigate the reported invoice synchronization failure",
  "operations": ["organization.read", "membership.read", "resource.read"],
  "expires_at": "2026-08-10T08:00:00Z"
}
```

`reason` 必填且最多 1000 个字符；`operations` 必须非空、去重，并且只能从上述五个 read operation 中选择。`expires_at` 必须是未来 24 小时内的 RFC3339 时间。创建和撤销由 internal human platform admin 执行，并沿用已启用 MFA 的近期验证规则；machine client、external_customer、停用用户或不具备 live platform admin 权限的调用者都会被拒绝。

context 换取会实时确认授权未撤销、未过期，目标仍是 active customer 组织，support Principal 与用户仍 active、属于 `internal_employee` 并仍持有固定角色。支持 token 的 `organization_id`、`customer_support_grant_id` 与 operation scope 都由服务器签发；它不创建 refresh session，不能调用普通 `/v1/auth/*`、平台管理、授权或组织成员管理接口。每次支持读取和 introspection 都会重新检查上述 live 状态，因此授权撤销、角色移除、人员停用或组织停用会立即失效。

授权创建、撤销、context 换取、每次允许读取、拒绝和后端读取失败都会写入 `customer_support_audit_logs`。日志包含 grant、actor Principal、目标组织、operation、授权原因快照、target、allow/deny 结果和稳定 denial reason；审计写入失败时相关支持操作失败关闭。

### 7.8 Refresh Session 与会话策略

Keylo 2.0 使用 refresh session 作为稳定会话索引：

- refresh token 只保存 hash，不保存明文。
- 每次刷新固定轮换 refresh token。
- 旧 refresh token 重放会撤销所属 session。
- 管理员可以按 Principal 或单个 session 撤销 refresh session。
- 管理员可以通过全局 refresh session 列表替代 Keystone 在线用户列表和强制退出功能。列表项包含 `id`、`principal_id`、`client_id`、可选 `organization_id`、`login_ip`、`user_agent`、`issued_at`、`rotated_at`、`expires_at`、`revoked_at`、`revoke_reason`。
- 人类密码登录提供 `organization_id` 时，refresh session 固定属于该组织；只有 session 记录、refresh JWT 与实时 active membership 均保持同一 scope 才能刷新。组织停用/归档或成员变为 pending/suspended/removed 会撤销对应 scoped session，不会撤销 platform 或其他组织 session。

会话策略通过 `SESSION_POLICY` 配置：

| 值 | 说明 |
|---|---|
| `multi_session` | 默认允许多会话 |
| `single_user_session` | 同一用户只允许一个活动 refresh session |
| `single_principal_session` | 同一 Principal 只允许一个活动 refresh session |

单会话策略命中时，第二次登录默认返回 `409 conflict`。认证成功后传入 `force=true` 可显式接管并撤销旧 session。

---

## 8. OAuth 接口

### 8.1 公开 OAuth 登录流程

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/auth/oauth/login/{provider}` | 否 | 跳转到 OAuth 提供方 |
| GET | `/v1/auth/oauth/callback/{provider}` | 否 | OAuth 回调并签发系统 token |

### 8.2 OAuth 管理接口（admin）

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

### 8.3 统一身份源注册中心（admin）

身份源注册中心用于统一登记 Keylo 可接入的身份来源元数据，包括本地密码、OAuth2、OIDC upstream 和 LDAP。OIDC upstream 已支持授权码登录回调、ID Token 校验和本地账号解析；现有 `/v1/auth/oauth/*` 登录路径保持兼容。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/identity-sources?limit=&offset=` | 身份源列表（敏感配置不会回显）；响应包含 `pagination.limit`、`offset`、`has_more` 和 `next_offset` |
| POST | `/v1/admin/identity-sources` | 注册身份源 |
| GET | `/v1/admin/identity-sources/{source_id}` | 身份源详情 |
| PUT | `/v1/admin/identity-sources/{source_id}` | 更新身份源 |
| POST | `/v1/admin/identity-sources/{source_id}/oidc/discover` | 拉取并校验 OIDC Discovery；成功结果按 source 配置版本缓存 |
| GET | `/v1/admin/identity-sources/{source_id}/links` | 查看该 OIDC 身份源关联的本地用户 |
| DELETE | `/v1/admin/identity-sources/{source_id}/links/{user_id}` | 管理员解除指定本地用户的 OIDC 关联 |

`POST /v1/admin/identity-sources` 请求体：

```json
{
  "name": "github",
  "source_type": "oauth2",
  "display_name": "GitHub",
  "description": "GitHub OAuth identity source",
  "config": {
    "provider": "github",
    "issuer": "https://github.com"
  },
  "claim_mapping": {
    "external_id": "id",
    "email": "email"
  },
  "jit_enabled": true,
  "auto_link_enabled": true,
  "allowed_user_class": "external_customer",
  "organization_strategy": "fixed",
  "organization_id": "org-acme",
  "active": true
}
```

字段说明：

- `name`：稳定唯一标识，会被 trim 并转为小写，不能包含空白字符。
- `source_type`：支持 `local_password`、`oauth2`、`oidc_upstream`、`ldap`。
- `display_name`：面向管理界面或集成文档展示的名称。
- `config`：身份源配置对象。Keylo 当前只校验它是 JSON object，具体 schema 由后续接入实现定义；响应会将 key 名含 `secret`、`password` 或等于 `token` 的配置值脱敏，提交后的敏感值不能通过读取接口回显。
- `allowed_user_class`：该来源唯一允许创建或自动关联的用户类别，支持 `external_customer`、`internal_employee`，默认 `external_customer`。上游 claim、邮箱或域名不能覆盖此值。
- `organization_strategy`：组织归属策略，支持 `none`、`fixed`，默认 `none`。`fixed` 必须同时提供 `organization_id`；不支持从 claim 或请求头动态选择组织。
- `organization_id`：`fixed` 策略的唯一组织。external customer 来源只能绑定 active customer 组织，internal employee 来源只能绑定 active internal 组织。

`oidc_upstream` 现要求 `config` 包含 `issuer`、`client_id`、`client_secret`、`redirect_uri` 与可选 `scopes`。issuer 必须为不含 query/fragment 的 HTTPS URL；redirect URI 必须为 HTTPS，开发期允许 `localhost`、`127.0.0.1`、`[::1]` 的 HTTP 回调。完全隔离的内网可在该身份源的 `config` 中显式设置 `allow_insecure_internal_http: true`，允许 issuer、Discovery endpoint 和 callback 使用 HTTP；此设置只能用于受控网络，不得跨越公网、共享办公网或不受控 Wi-Fi，且不得暴露到不受信任网络。scopes 必须唯一且包含 `openid`。登录入口为 `GET /v1/upstream/oidc/{source_name}/login`，回调为 `GET /v1/upstream/oidc/callback`；回调会校验 Discovery、PKCE、state、nonce、ID Token 签名、issuer、audience、`azp` 和 expiry。Discovery 与 JWKS 请求使用 5 秒超时；经过校验的元数据按 source 的 `updated_at` 配置版本缓存最多 5 分钟，source 配置或状态更新会自然失效旧缓存，遇到未知签名 `kid` 时只执行一次 JWKS 强制刷新。多受众 ID Token 必须把 `azp` 设为 Keylo 的 client ID；单受众 token 若带 `azp`，它也必须匹配。Keylo 目前以 `client_secret_basic` 完成 confidential client 的 token 认证；若 Discovery 显式声明的 `token_endpoint_auth_methods_supported` 不包含它，注册和登录都会拒绝，避免进入必然失败的兼容性路径。若 Discovery 提供 `userinfo_endpoint`，Keylo 会用 token response 的 access token 获取资料，并要求 UserInfo 的 `sub` 与已验证 ID Token 完全一致；UserInfo 只补齐 ID Token 缺失的 profile fields，不能覆盖已验证声明。

Keylo 当前只接受 RS256 签名的 ID Token；若 Discovery 显式声明的 `id_token_signing_alg_values_supported` 不包含 RS256，注册和登录都会拒绝，避免将授权码交给无法被当前验证器安全处理的上游身份源。

成功回调返回标准 Keylo `AuthBody`，包含 Bearer access token、可轮换 refresh token 和 `expires_in`。令牌代表已关联的本地用户，沿用本地用户的角色、权限和会话策略；已验证的上游邮箱只会更新本地 `email_verified` 状态，不会自动改写本地邮箱；令牌及上游 ID Token 不会出现在审计详情中。固定组织来源的 JIT 用户会建立 active membership，access/refresh token 与 refresh session 都固定到该组织；组织、用户、Principal 或 membership 失效后，回调与刷新均失败关闭。

上游 `(source, sub)` 到 Keylo 用户的绑定是不可改绑的：并发登录若发现该上游主体已经关联到其他用户，回调会返回冲突，绝不会覆盖既有映射。JIT 创建若在绑定阶段发生该冲突，会清理刚创建的无密码用户。

已关联用户的上游邮箱变化以稳定 `sub` 为准继续登录，但不会自动改写 Keylo 的本地邮箱。Keylo 仅保存最新已观测的上游邮箱与验证状态供后续人工处理，并记录不含邮箱明文的审计事件；只有上游邮箱与本地邮箱匹配时才会提升本地 `email_verified`，管理员可按本地用户更新流程完成邮箱变更。

已登录用户可调用 `GET /v1/user/identity-sources/links` 查看自己的已关联 OIDC upstream 身份源（仅返回来源标识、展示名和关联时间），再通过 `DELETE /v1/user/identity-sources/{source_id}/link` 解除关联。解除操作会撤销仅由该身份源签发的 refresh session 并写入审计日志；若该关联是用户唯一的登录方式，接口返回冲突而不执行解除，避免用户把自己锁在账户之外。
- `claim_mapping`：外部身份字段到 Keylo 标准字段的映射对象。`oidc_upstream` 仅支持 `external_subject`、`email`、`username`、`email_verified` 四个本地字段，值为已签名 ID Token 中的 claim 名；缺省时分别使用 `sub`、`email`、`preferred_username`、`email_verified`。映射到已有账号的邮箱仍需映射后的 `email_verified` 为 `true`，不会因自定义映射降低自动关联的安全要求。
- `jit_enabled`：是否允许在没有映射和同邮箱账号时创建无密码的 Keylo 用户，默认 `false`。创建类别只能来自 `allowed_user_class`。
- `auto_link_enabled`：是否允许把已有同邮箱 Keylo 用户关联到上游身份，默认 `true`。仅上游 ID Token 声明 `email_verified: true`、本地 `user_class` 与来源策略一致且固定组织 membership 已 active 时才会自动关联；否则拒绝自动关联，避免未验证邮箱或来源策略跨越账户边界。
- `active`：是否启用该身份源，默认 `true`。

`PUT /v1/admin/identity-sources/{source_id}` 支持局部更新：`display_name`、`description`、`config`、`claim_mapping`、`jit_enabled`、`auto_link_enabled`、`active`、`allowed_user_class`、`organization_strategy`、`organization_id`。将策略切换为 `none` 会清除组织归属；策略、claim mapping 或 config 变化都属于 trust boundary 变更，会撤销该来源现有 refresh session 和未完成的回调事务。

更新 `config` 时，读取接口返回的 `[REDACTED]` 敏感字段会保留数据库中的原值；只有提交新的非脱敏值才会替换凭据。这样可以安全地读取、编辑非敏感配置后再保存。

关联列表只返回 Keylo `user_id`、用户名、邮箱和关联时间，不返回上游 `sub`、ID Token、access token 或任何身份源凭据。

管理员解除关联会撤销该用户通过此身份源签发的 refresh session，并记录审计；若该关联是用户唯一的登录方式，接口返回冲突而不执行解除。

将一个已启用的 `oidc_upstream` 身份源更新为 `active: false`，或替换其 `config`（例如 issuer、client 或凭据）时，Keylo 会立即撤销该来源的所有未撤销 refresh session，并删除尚未回调的浏览器授权事务，避免旧 trust configuration 下的 state 被继续使用。审计记录管理员、来源 ID、撤销会话数和失效事务数；禁用记录为 `identity_source.disabled`，配置替换记录为 `identity_source.reconfigured`。已经签发的短期 access token 仍按其既有过期时间失效。

---

## 9. 服务间认证接口

### 9.1 公开接口

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

响应体：

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

`expires_in` 优先使用服务客户端的 `token_ttl_seconds`；未配置时使用全局 `SERVICE_TOKEN_EXPIRY_SECONDS`。

服务 Token 的组织边界只能从已注册 service client 的持久化记录派生，`/v1/service/token` 不接受 `organization_id`、请求头或 audience/scope 以外的字段来切换组织。organization-scoped client 签发的 JWT 会包含其唯一的 `organization_id`；每次使用时都会实时检查 service client、service Principal、组织和 active membership。组织停用、服务 Principal 停用或 membership 变为 pending/suspended/removed 时，已有 Token 和新的签发请求都会被拒绝。

### 9.2 服务受保护接口

| 方法 | 路径 | 鉴权 |
|---|---|---|
| POST | `/v1/service/introspect` | service_access + `read` |

请求体：

```json
{
  "token": "..."
}
```

`/v1/service/introspect` 与 `/v1/auth/introspect` 只接受 active platform-scoped service client 作为调用方。organization-scoped service Token 不能用内省端点探测 platform 或其他组织 Token 的状态。

### 9.3 服务管理接口（admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/services?organization_id=&scope_kind=&active=&limit=&offset=` | 服务列表；精确过滤 scope，limit 默认 50、最大 200，offset 默认 0，返回 `has_more/next_offset` |
| POST | `/v1/admin/services` | 注册服务 |
| GET | `/v1/admin/services/{service_id}` | 服务详情 |
| PUT | `/v1/admin/services/{service_id}` | 更新服务 |
| POST | `/v1/admin/services/{service_id}/rotate-secret` | 轮换服务密钥 |

`POST /v1/admin/services` 请求体：

```json
{
  "service_id": "order-svc",
  "service_secret": "secret",
  "name": "Order Service",
  "description": "Order domain API",
  "organization_id": "org-acme",
  "allowed_scopes": ["read", "write"],
  "allowed_audiences": ["inventory-svc"],
  "integration_type": "internal",
  "introspection_allowed": true,
  "token_ttl_seconds": 3600,
  "owner": "Platform Team",
  "contact": "platform@example.com"
}
```

字段说明：

- `allowed_scopes`：该服务最多可申请的 scope 集合。
- `allowed_audiences`：该服务最多可访问的目标 audience 集合，`"*"` 表示不限。
- `organization_id`：可选。省略时创建显式 `platform` service client；提供时必须是 active organization，创建结果为显式 `organization` scope，并原子创建该 service Principal 的 active organization membership。
- `integration_type`：可选集成类型，默认 `internal`。建议使用 `internal`、`third_party`、`gateway`、`job` 等稳定枚举值。
- `introspection_allowed`：是否允许 platform-scoped 服务调用 `/v1/auth/introspect` 和 `/v1/service/introspect`，默认 `true`；organization-scoped 服务始终不能调用这些端点。
- `token_ttl_seconds`：该服务 token TTL。为空时使用全局 `SERVICE_TOKEN_EXPIRY_SECONDS`。
- `owner` / `contact`：运维归属信息，用于审计、轮换和事故联系。

输入约束：

- `allowed_scopes` 与 `allowed_audiences` 至少包含一个值。
- 列表项会自动 trim、去重并排序。
- 列表项不能是空字符串，也不能包含空白字符；多个 scope 请用数组多项表达，不要写成 `"read write"`。
- `allowed_audiences` 可使用 `*` 通配；`allowed_scopes` 不允许使用 `*`。
- `token_ttl_seconds` 必须大于 0，且不能超过 `REFRESH_TOKEN_EXPIRY_SECONDS`。

`GET /v1/admin/services/{service_id}` 与列表接口会返回上述服务元数据，以及不可变的 `scope_kind`（`platform` 或 `organization`）和可选 `organization_id`，但不会返回密钥或密钥 hash。`PUT` 不接受也不能变更 scope；需要变更组织边界时必须注册新的 service client 和凭证。customer organization 的 owner/admin 应使用上一节的 `/v1/organizations/{organization_id}/services` 路由管理自己的 organization-scoped service，不能通过平台管理路由获得跨组织能力。

`POST /v1/admin/services/{service_id}/rotate-secret`：

- 请求体可选 `new_secret`。传入时响应不会回显明文。
- 省略 `new_secret` 时服务端生成新密钥，并在响应的 `new_secret` 字段中一次性返回。
- 响应包含 `secret_generated`。

### 9.4 运行时安全约定

- 登录和内省接口按客户端 IP 限流。默认使用 TCP peer IP；只有 `TRUST_PROXY_HEADERS=true` 时才信任 `X-Forwarded-For` / `X-Real-IP`。
- 浏览器跨域请求按 `CORS_ALLOWED_ORIGINS` 白名单校验 Origin；配置值必须是 scheme + host + 可选端口，不应包含路径。
- `/readyz` 默认要求数据库可用；无数据库路由只应在非生产环境显式设置 `ALLOW_IN_MEMORY_FALLBACK=true` 时使用。数据库和 Redis 依赖探测均有短超时，失败时仅返回稳定公开错误，连接地址、凭据和底层错误只写入服务端日志。

---

## 10. 通用响应格式

### 10.1 业务接口（多数）

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

### 10.2 认证错误（`AuthError`）

```json
{
  "code": 1012,
  "error": "insufficient_scope",
  "message": "Insufficient scope"
}
```

---

## 11. Claims 参考

Access token 关键字段：

- `sub`：主体标识（Subject）。通常为 `user:<username>`、`client:<client_id>` 或特定主体 ID，用于后端识别请求发起方，不建议作为用户表主键使用。
- `uid`：用户主键 ID（`users.id`）。当 token 代表用户主体时应优先使用 `uid` 进行用户关联与数据查询。
- `principal_id`：Keylo 2.0 统一 Principal ID。用户、服务和客户端都应能映射到该 ID。
- `principal_type`：Principal 类型，当前为 `user`、`service` 或 `client`。
- `iss`：签发方（Issuer）。用于校验 token 来源是否可信，需与服务端配置的发行者一致。
- `aud`：受众（Audience）。标识 token 目标服务（如 `admin-backend`）；后端应校验是否匹配当前资源服务。
- `token_type`：令牌类型。当前常见为 `access`（访问令牌）、`refresh`（刷新令牌）、`service_access` 或受限的 `customer_support_access`；每个受保护接口只接受其声明的类型。
- `scope`（数组）：权限点集合。用于接口级授权判断，建议采用能力点命名（如 `ssc.camera.write`）。
- `role`（数组，兼容历史字符串）：角色集合。用于粗粒度角色判断（如 `admin`、`user`）；当前输出为数组，兼容历史单字符串。
- `exp`：过期时间（Unix 时间戳，秒）。当前时间超过该值后 token 无效。
- `iat`：签发时间（Unix 时间戳，秒）。可用于排查时钟漂移、审计与会话时序分析。
- `jti`：令牌唯一 ID（JWT ID）。用于黑名单吊销、幂等追踪与审计定位。

### 11.1 稳定契约与扩展字段

第三方服务应只把以下字段作为稳定契约消费：`iss`、`sub`、`aud`、`exp`、`iat`、`jti`、`scope`、`role`、`token_type`、`uid`、`principal_id`、`principal_type`。

Keylo 后续可能在 token 中增加更多字段。第三方服务应忽略未知 claims，避免将未文档化字段作为授权依据。

`customer_support_access` 是 Keylo 内置的受限支持 token，不是第三方通用 access token。它额外包含 `organization_id` 和 `customer_support_grant_id`；只有 Keylo 的 `/v1/customer-support/organizations/*` 路由可以将这些字段用于授权，资源服务不得仅凭这两个字段开放客户数据。

### 11.2 Audience 配置

Keylo 使用 `JWT_AUDIENCES` 配置用户/管理 access token 可接受的 audience 白名单，默认值为 `admin-backend,crawler`。新增资源服务时，建议先把服务标识加入 `JWT_AUDIENCES` 或通过服务客户端的 `allowed_audiences` 管理服务 token 的目标 audience。

## 12. 后端校验建议顺序（推荐）

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

## 13. 前端使用建议（非安全边界）

- 前端可使用 `scope` 与 `role` 做导航、按钮、页面块的显示控制。
- 前端隐藏仅用于体验优化，**不作为安全边界**。
- 真正访问控制必须由后端再次校验 token claims。
- 当权限变更后，应引导前端刷新 token，以拿到最新 claims。

## 14. 权限变更生效策略

- 角色/权限变更后，对“新签发 token”立即生效。
- 已签发旧 token 在过期前仍可能保留旧权限。
- 若需立即失效，建议结合黑名单或缩短 access token 生命周期。

<!-- markdownlint-enable MD060 -->
