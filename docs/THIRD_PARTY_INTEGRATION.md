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
- **Access Token**：用户与管理接口使用的 `token_type=access`
- **Refresh Token**：当前主要由管理客户端链路返回的 `token_type=refresh`
- **Service Access Token**：服务调用内省等接口使用的 `token_type=service_access`

注意：`role` 在当前实现中以数组形式输出，例如 `role: ["admin"]`、`role: ["user"]`。
Refresh Token 每次刷新都会被原子消费，第三方系统必须用刷新响应中的新 `refresh_token` 替换旧值。

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
- 如需本地菜单权限，可在本地消费 `role[]` / `scope[]` 做展示控制，但后端仍应自行校验

### 3.2 API 网关 / BFF

- 常规流量：使用 JWKS 做本地验签
- 高敏接口：本地验签后再调用内省接口
- 网关只做认证前置，细粒度授权下沉至后端服务

### 3.3 内部微服务

- 在 Keylo 注册服务客户端
- 使用 `/v1/service/token` 获取 `service_access` Token
- 对用户 Token 做统一内省时，调用 `/v1/auth/introspect`
- 对服务 Token 做统一内省时，调用 `/v1/service/introspect`

---

## 4. Token 消费建议

第三方系统建议消费以下字段：

- `sub`
- `uid`
- `iss`
- `aud`
- `token_type`
- `role[]`
- `scope[]`
- `exp`
- `iat`
- `jti`

- `sub` 用于主体标识（如 `user:<username>`），`uid` 用于稳定用户主键关联（推荐优先使用）。
- 第三方系统应忽略未知 claims，避免依赖未文档化字段。

1. 校验 Bearer Token 格式
2. 验签并检查 `iss` / `exp`
3. 校验 `token_type`
4. 校验 `aud`
5. 校验 `scope[]`
6. 校验 `role[]`
7. 如有需要，补充内省或黑名单校验

---

## 5. 服务客户端白名单模型

服务客户端由两类白名单共同约束：

- `allowed_scopes`
- `allowed_audiences`

申请 `service_access` Token 时，请求中的 `scope` 与 `audience` 必须落在白名单内，否则请求会被拒绝。
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

## 6. 最小联调路径

推荐用以下路径完成第三方联调：

1. 按 [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md) 初始化 Keylo
2. 读取 `/.well-known/keylo-configuration`
3. 获取管理客户端 Token
4. 创建用户、角色和权限
5. 注册服务客户端
6. 获取用户 Token 与 `service_access` Token
7. 验证 `/.well-known/jwks.json`
8. 验证 `/v1/auth/introspect` 或 `/v1/service/introspect`

具体请求体和响应体请直接查阅 [API_REFERENCE.md](API_REFERENCE.md)。

---

## 7. 常见误区

- 把管理客户端拿去调用 `/v1/auth/token`
- 认为前端隐藏按钮等于授权
- 在生产环境继续使用内置开发密钥
- 在不可信代理链路上启用 `TRUST_PROXY_HEADERS`
- 修改已执行 migration 导致部署库校验失败
- 忽略 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET` 导致管理客户端未初始化

---

## 8. 相关文档

- [API_REFERENCE.md](API_REFERENCE.md)
- [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md)
- [MULTI_CLIENT_RBAC_INTEGRATION.md](MULTI_CLIENT_RBAC_INTEGRATION.md)
- [AGILEBOOT_INTEGRATION.md](AGILEBOOT_INTEGRATION.md)
- [integrations/README.md](integrations/README.md)
