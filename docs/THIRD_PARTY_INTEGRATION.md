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

---

## 3. 推荐接入方式

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
- `iss`
- `aud`
- `token_type`
- `role[]`
- `scope[]`
- `exp`
- `iat`
- `jti`

校验建议顺序：

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

常用管理入口：

- `POST /v1/admin/services`
- `GET /v1/admin/services`
- `GET /v1/admin/services/{service_id}`
- `PUT /v1/admin/services/{service_id}`
- `POST /v1/admin/services/{service_id}/rotate-secret`

---

## 6. 最小联调路径

推荐用以下路径完成第三方联调：

1. 按 [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md) 初始化 Keylo
2. 获取管理客户端 Token
3. 创建用户、角色和权限
4. 注册服务客户端
5. 获取用户 Token 与 `service_access` Token
6. 验证 `/.well-known/jwks.json`
7. 验证 `/v1/auth/introspect` 或 `/v1/service/introspect`

具体请求体和响应体请直接查阅 [API_REFERENCE.md](API_REFERENCE.md)。

---

## 7. 常见误区

- 把管理客户端拿去调用 `/v1/auth/token`
- 认为前端隐藏按钮等于授权
- 在生产环境继续使用内置开发密钥
- 修改已执行 migration 导致部署库校验失败
- 忽略 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET` 导致管理客户端未初始化

---

## 8. 相关文档

- [API_REFERENCE.md](API_REFERENCE.md)
- [END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md)
- [MULTI_CLIENT_RBAC_INTEGRATION.md](MULTI_CLIENT_RBAC_INTEGRATION.md)
- [AGILEBOOT_INTEGRATION.md](AGILEBOOT_INTEGRATION.md)
