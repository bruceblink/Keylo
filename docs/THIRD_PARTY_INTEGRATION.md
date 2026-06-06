# Keylo 第三方系统与服务对接指南

本文档聚焦第三方系统如何把 Keylo 作为统一认证中心接入，避免与 [API_REFERENCE.md](API_REFERENCE.md) 和 [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md) 重复。

适用对象：

- 后台管理系统（如 AgileBoot）
- API 网关 / BFF
- 内部微服务
- 需要接入外部 OAuth 提供商的场景

---

## 1. 角色边界

### 1.1 Keylo 负责

- 用户认证、管理客户端认证、服务客户端认证
- RS256 JWT 签发
- JWKS 公钥发布
- 用户 Token / 服务 Token 内省
- 管理客户端、服务客户端、RBAC、审计日志和黑名单
- Keylo 2.0 Principal、资源树、统一授权检查和 refresh session 治理

### 1.2 第三方系统负责

- 本地业务数据和业务流程
- 本地页面态、菜单态、数据权限
- 基于 Keylo claims 构造自己的安全上下文

推荐原则：认证与统一接入授权交给 Keylo，业务系统保留自身业务授权。

---

## 2. 术语统一

- **用户**：通过 `/v1/auth/token` 使用用户名/密码登录的主体
- **管理客户端**：通过 `/v1/admin/token` 获取管理 Token 的受信任客户端
- **服务客户端**：通过 `/v1/service/token` 获取 `service_access` Token 的服务账号
- **Principal**：Keylo 2.0 统一安全主体，类型为 `user`、`service`、`client`
- **Access Token**：用户与管理接口使用的 `token_type=access`
- **Refresh Token**：用户和管理客户端用于刷新 access token 的 `token_type=refresh`
- **Service Access Token**：服务调用内省等接口使用的 `token_type=service_access`

注意：`role` 在当前实现中以数组形式输出，例如 `role: ["admin"]`、`role: ["user"]`。
Refresh Token 每次刷新都会被 refresh session 原子消费和轮换，第三方系统必须用刷新响应中的新 `refresh_token` 替换旧值。旧 refresh token 重放会撤销所属 refresh session。

---

## 3. 推荐接入方式

第三方服务可以先读取 Keylo 的轻量发现配置：

```text
GET /.well-known/keylo-configuration
```

该接口返回 issuer、JWKS 地址、内省地址、服务 token 地址、支持的 token 类型、稳定 claims 和当前允许的 access token audiences。它不是完整 OIDC discovery 文档，而是 Keylo 面向轻量统一鉴权/授权中心的集成契约。

### 3.1 后台管理系统

- 如果系统本身是管理后台，优先使用管理客户端调用 Keylo 管理接口
- 如果系统需要用户登录态，则让用户通过 `/v1/auth/token` 获取用户 Token
- 如需菜单、按钮、API 或服务能力权限，优先消费 Keylo 2.0 的 Principal + RBAC 授权结果
- 前端可用 `/v1/principals/me/resource-tree?app=<app>&type=menu` 渲染菜单，但后端仍必须调用授权检查或本地策略

### 3.2 API 网关 / BFF

- 常规流量：使用 JWKS 做本地验签
- 本地验签必须校验 `iss`、`aud`、`exp`、`token_type`
- 高敏接口：本地验签后再调用 `/v1/authorize/check` 或 `/v1/authorize/batch-check`
- 网关只做认证前置和粗粒度预检，细粒度授权可由后端服务消费 Keylo 授权结果

### 3.3 内部微服务

- 在 Keylo 注册服务客户端
- 使用 `/v1/service/token` 获取 `service_access` Token
- 对用户 Token 做统一内省时，调用 `/v1/auth/introspect`
- 对服务 Token 做统一内省时，调用 `/v1/service/introspect`
- 服务自身也会映射为 `principal_type=service`，可以绑定角色并通过 `/v1/authorize/check` 判断是否允许调用某个能力

---

## 4. Token 消费建议

第三方系统建议消费以下字段：

- `sub`
- `uid`
- `principal_id`
- `principal_type`
- `iss`
- `aud`
- `token_type`
- `role[]`
- `scope[]`
- `exp`
- `iat`
- `jti`

- `sub` 用于主体标识（如 `user:<username>`、`service:<service_id>`），`uid` 用于稳定用户主键关联（用户 token 推荐优先使用）。
- `principal_id` / `principal_type` 用于 Keylo 2.0 统一主体关联；服务和客户端 token 应优先使用 Principal 语义接入授权。
- 第三方系统应忽略未知 claims，避免依赖未文档化字段。

1. 校验 Bearer Token 格式
2. 验签并检查 `iss` / `exp`
3. 校验 `token_type`
4. 校验 `aud`
5. 校验 `scope[]`
6. 校验 `role[]`
7. 如有需要，补充内省或黑名单校验

本地验签只证明“是谁”和“token 是否面向当前服务”。细粒度授权应继续使用 Keylo RBAC 或业务系统自己的授权模型，不能把“验签通过”当成全权限。

---

## 5. Keylo 2.0 授权模型

Keylo 2.0 的统一授权链路是：

```text
principal -> roles -> permissions -> resources/actions
```

### 5.1 权限检查

资源服务可以在本地验签后调用：

```text
POST /v1/authorize/check
POST /v1/authorize/batch-check
```

请求方可以携带用户 access token 或服务 `service_access` token。按权限点检查：

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

返回 `allowed=true/false`。未知 Principal、禁用 Principal、无角色或无权限默认拒绝。

### 5.2 资源树

前端、BFF 或服务可以查询当前 Principal 可见资源：

```text
GET /v1/principals/me/resource-tree?app=keystone&type=menu
GET /v1/principals/me/resource-tree?app=crawler&type=service
```

推荐用途：

- 用户后台菜单：`type=menu`
- 用户按钮能力：`type=button`
- 服务能力目录：`type=service`
- API 能力目录：`type=api`
- 数据范围策略：`type=data_scope`

资源树用于展示和预检，不替代后端最终授权判断。

### 5.3 管理入口

管理员可以通过以下接口治理 Principal 和资源：

- `GET /v1/admin/principals`
- `POST /v1/admin/principals/{principal_id}/roles`
- `GET /v1/admin/principals/{principal_id}/effective-permissions`
- `POST /v1/admin/resources`
- `POST /v1/admin/resources/{resource_id}/permissions`

旧用户 RBAC 接口仍保留兼容，但新集成应优先使用 Principal 级接口。

---

## 6. 服务客户端白名单模型

服务客户端由两类白名单共同约束：

- `allowed_scopes`
- `allowed_audiences`

申请 `service_access` Token 时，请求中的 `scope` 与 `audience` 必须落在白名单内，否则请求会被拒绝。
Keylo 2.0 中，这两个白名单仍用于服务 token 签发边界；服务能否调用具体能力，应继续通过服务 Principal 的 RBAC 权限判断。
注册或更新服务客户端时，Keylo 会对这两个列表执行 trim、去重和排序。列表项不能留空，也不能包含空白字符；`allowed_scopes` 不接受 `*`，`allowed_audiences` 可以使用 `*` 表示目标 audience 不限。

服务客户端也可以维护集成元数据：

- `integration_type`：区分 `internal`、`third_party`、`gateway`、`job` 等接入类型。
- `introspection_allowed`：是否允许该服务调用 token 内省接口。对只需要本地 JWKS 验签的服务，可以关闭内省能力以收窄权限。
- `token_ttl_seconds`：单服务 token TTL。高敏或外部集成服务建议配置更短 TTL。
- `owner` / `contact`：服务归属和故障联系人，便于审计、轮换和事故处理。

用户/管理 access token 的全局可接受 audience 由 `JWT_AUDIENCES` 配置，默认值为 `admin-backend,crawler`。新增内部资源服务时，应明确它消费哪类 token：

- 消费用户/管理 access token：将资源服务标识加入 `JWT_AUDIENCES`，并在服务端校验 `aud`。
- 消费服务间 `service_access` token：在服务客户端上维护 `allowed_audiences`，申请 token 时指定目标 `audience`。

常用管理入口：

- `POST /v1/admin/services`
- `GET /v1/admin/services`
- `GET /v1/admin/services/{service_id}`
- `PUT /v1/admin/services/{service_id}`
- `POST /v1/admin/services/{service_id}/rotate-secret`

密钥轮换接口支持两种模式：请求体提供 `new_secret` 时响应不回显明文；省略 `new_secret` 时由 Keylo 自动生成并在响应中一次性返回 `new_secret`。

建议接入策略：

- 内部可信服务：`integration_type=internal`，按需开启内省，TTL 可使用全局默认。
- API 网关 / BFF：`integration_type=gateway`，通常开启内省，严格限制 `allowed_audiences`。
- 第三方服务：`integration_type=third_party`，优先使用 JWKS 本地验签，仅在确有实时吊销需求时开启内省，并配置较短 `token_ttl_seconds`。
- 定时任务：`integration_type=job`，只授予任务所需最小 scope。

---

## 7. Refresh Token 与会话策略

Keylo 2.0 使用 refresh session 作为稳定会话索引：

- 用户登录和管理客户端登录都会返回 refresh token。
- Refresh token 固定轮换，旧 token 只能成功使用一次。
- 重放旧 refresh token 会撤销所属 refresh session。
- 管理员可以按 Principal 查询和撤销 refresh session。

会话策略由 `SESSION_POLICY` 控制：

- `multi_session`：默认允许多会话。
- `single_user_session`：同一用户只允许一个活动 session。
- `single_principal_session`：同一 Principal 只允许一个活动 session。

当单会话策略命中时，第二次登录默认返回 `409 conflict`。调用方必须先完成认证，再用 `force=true` 显式接管旧 session。

客户端保存建议：

- Web：refresh token 放在受保护的服务端会话或 HttpOnly cookie 中。
- 桌面客户端：使用系统凭据存储，并实现单飞刷新，避免并发刷新造成重放。
- 服务端/BFF：刷新时用互斥或请求合并保证同一 refresh token 只有一个刷新请求在飞。

---

## 8. 身份源注册

Keylo 提供统一身份源注册中心，用于提前登记和治理外部身份来源：

- `local_password`：Keylo 本地用户名密码。
- `oauth2`：GitHub、企业微信等 OAuth2 身份源。
- `oidc_upstream`：上游企业 IdP 或云身份提供商。
- `ldap`：企业目录服务。

常用管理入口：

- `POST /v1/admin/identity-sources`
- `GET /v1/admin/identity-sources`
- `GET /v1/admin/identity-sources/{source_id}`
- `PUT /v1/admin/identity-sources/{source_id}`

当前版本的身份源接口是注册中心能力，不会自动替代现有 `/v1/auth/oauth/*` 登录流程。第三方服务集成时可先把身份源、claim mapping、JIT 策略和启用状态登记到 Keylo，后续接入 LDAP/OIDC upstream 时复用同一套元数据模型。

---

## 9. 最小联调路径

推荐用以下路径完成第三方联调：

1. 按 [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md) 初始化 Keylo
2. 读取 `/.well-known/keylo-configuration`
3. 获取管理客户端 Token
4. 按需登记身份源
5. 创建用户、角色和权限
6. 注册服务客户端
7. 为用户或服务 Principal 绑定角色
8. 注册菜单、API 或服务能力资源并绑定权限
9. 获取用户 Token 与 `service_access` Token
10. 验证 `/.well-known/jwks.json`
11. 验证 `/v1/authorize/check`、`/v1/principals/me/resource-tree`
12. 验证 `/v1/auth/introspect` 或 `/v1/service/introspect`

具体请求体和响应体请直接查阅 [API_REFERENCE.md](API_REFERENCE.md)。

---

## 10. 常见误区

- 把管理客户端拿去调用 `/v1/auth/token`
- 认为前端隐藏按钮等于授权
- 认为 Keylo token 验签通过就可以临时授予全权限
- 只依赖 `scope[]` / `role[]`，忽略 Principal + RBAC 授权结果
- 并发刷新同一个 refresh token，导致被判定为重放
- 在生产环境依赖自动生成且未纳入备份的 RSA 密钥
- 在不可信代理链路上启用 `TRUST_PROXY_HEADERS`
- 修改已执行 migration 导致部署库校验失败
- 忽略首次 `/setup` 初始化导致管理客户端未初始化

---

## 11. 相关文档

- [API_REFERENCE.md](API_REFERENCE.md)
- [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md)
- [MULTI_CLIENT_RBAC_INTEGRATION.md](MULTI_CLIENT_RBAC_INTEGRATION.md)
- [KEYSTONE_KEYLO_2_0_MIGRATION.md](KEYSTONE_KEYLO_2_0_MIGRATION.md)
- [KEYLO_2_0_CLIENT_GUIDE.md](KEYLO_2_0_CLIENT_GUIDE.md)
- [AGILEBOOT_INTEGRATION.md](AGILEBOOT_INTEGRATION.md)
- [integrations/README.md](integrations/README.md)
