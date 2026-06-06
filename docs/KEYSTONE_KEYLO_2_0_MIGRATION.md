# Keystone 接入 Keylo 2.0 迁移方案

本文档描述 Keystone 从“Keylo bearer token 验签通过即临时全权限”的过渡模式，迁移到 Keylo 2.0 Principal + RBAC 授权模型的推荐路径。

## 1. 目标状态

Keystone 在目标状态下应满足：

- 对 Keylo token 完整校验签名、`iss`、`aud`、`exp`、`iat`、`token_type`。
- 使用 `principal_id` / `principal_type` 定位 Keylo 统一主体。
- 菜单、按钮、API 和服务能力由 Keylo resource + permission 建模。
- 权限判断由 `/v1/authorize/check` 或 `/v1/authorize/batch-check` 驱动。
- 未授权 Keylo service token 不能访问 Keystone 管理接口。
- 不再把“Keylo token 验证通过”映射为 `*:*:*`；只有在 Keylo RBAC 中显式绑定了 `*:*:*` 权限的 Principal 才拥有超级权限。

## 2. 推荐迁移阶段

### 阶段 1：完整验签

Keystone 资源服务先读取：

```text
GET /.well-known/keylo-configuration
GET /.well-known/jwks.json
```

对用户 access token 和 service access token 执行本地验签，并校验：

- `iss=keylo`
- `aud` 匹配 Keystone 后端或 `admin-backend`
- `token_type=access` 或 `service_access`
- `exp` / `iat` 有效

该阶段只替换“不安全 decode payload”的旧逻辑，不改变业务权限来源。

### 阶段 2：注册 Keystone 资源

在 Keylo 中注册 Keystone 菜单、按钮和 API 资源：

```http
POST /v1/admin/resources
```

示例：

```json
{
  "app": "keystone",
  "resource_type": "menu",
  "code": "system:user",
  "name": "用户管理",
  "display_order": 10,
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
  "permission_ids": ["permission-id-for-keystone-system-user-list"]
}
```

建议权限 code 使用：

```text
keystone:system:user:list
keystone:system:user:add
keystone:system:user:edit
keystone:system:user:remove
keystone:system:dept:list
```

Keystone 既有超级管理员语义可以迁移为 Keylo 权限 `*:*:*`。该权限需要显式创建并绑定到超级管理员角色；它会允许任意 `/v1/authorize/check` 权限 code，并让 `/v1/principals/me/resource-tree` 返回指定 `app/type` 下全部 active 资源。

### 阶段 3：绑定 Principal 角色

Keylo 会为用户、服务和客户端创建 Principal。管理员可以查询并绑定角色：

```http
GET  /v1/admin/principals?principal_type=user
POST /v1/admin/principals/{principal_id}/roles
```

服务账号也应绑定角色，例如：

- `keystone_gateway`
- `keystone_admin_service`
- `keystone_report_readonly`

### 阶段 4：菜单和按钮改为 Keylo 资源树

用户登录 Keystone 后，Keystone BFF 或前端可调用：

```http
GET /v1/principals/me/resource-tree?app=keystone&type=menu
GET /v1/principals/me/resource-tree?app=keystone&type=button
```

返回结果只用于 UI 呈现和预检。后端 API 仍必须做最终授权检查。

Keystone 原 `RouterDTO` 字段可从 Keylo resource tree 映射：

| Keystone `RouterDTO` | Keylo resource tree |
|---|---|
| `name` | `resource.metadata.router_name` |
| `path` | `resource.metadata.path` |
| `component` | `resource.metadata.component` |
| `rank` | `resource.display_order` 或 `resource.metadata.rank` |
| `meta` | `resource.metadata.meta` |
| `meta.auths` | `permissions[].name` |
| `children` | `children` |

### 阶段 5：API 权限检查

Keystone 后端在处理敏感接口前调用：

```http
POST /v1/authorize/check
```

请求：

```json
{
  "permission": "keystone:system:user:list"
}
```

或按资源查询：

```json
{
  "app": "keystone",
  "resource_type": "api",
  "resource_code": "system:user:list"
}
```

返回 `allowed=false` 时 Keystone 应返回 403。

### 阶段 6：在线会话治理

Keystone 原 `/monitor/onlineUsers` 和 `/monitor/onlineUser/{tokenId}` 可迁移为 Keylo refresh session 管理：

```http
GET    /v1/admin/refresh-sessions?principal_id=&client_id=&login_ip=
DELETE /v1/admin/refresh-sessions/{session_id}
```

列表返回 `principal_id`、`client_id`、`login_ip`、`user_agent`、`issued_at`、`expires_at` 和撤销状态。强制退出时撤销对应 refresh session，后续 refresh token 会失效。

## 3. 服务 Token 接入规则

Keystone 调用 Keylo 或其他内部服务时，应使用 `/v1/service/token` 申请 `service_access` token。申请 token 时仍受 `allowed_scopes` 和 `allowed_audiences` 约束；实际能否访问 Keystone API 由服务 Principal 的角色权限决定。

迁移期可以保留旧 scope 检查作为粗粒度防线，但不能把 scope 当作最终业务权限。

## 4. Refresh Session 和单会话策略

Keylo 2.0 用户登录会返回 refresh token。Keystone Web/BFF 需要：

- 保存刷新响应中的最新 refresh token。
- 避免并发刷新同一个 refresh token。
- 如果部署启用 `SESSION_POLICY=single_user_session`，第二次登录默认会返回 409。
- 用户确认接管后，再用 `force=true` 重新登录。
- access token 不可用时，可调用 `POST /v1/auth/logout-refresh-token` 撤销 refresh session，用于替代 Keystone `/logout-refresh-token`。

## 5. 回退策略

如果 Keylo 授权检查暂时不可用，Keystone 可以短时间回退到本地权限模型，但必须：

- 写入降级审计日志。
- 不把未知 Keylo service token 视为管理员。
- 不把验签成功或授权检查失败直接升级为 `*:*:*`。
- 在恢复后重新切回 Keylo 授权结果。

## 6. 验收清单

- Keystone 可以使用 JWKS 本地验签 Keylo user access token。
- Keystone 可以使用 JWKS 本地验签 Keylo service access token。
- Keystone 菜单由 `/v1/principals/me/resource-tree?app=keystone&type=menu` 返回。
- Keystone API 权限由 `/v1/authorize/check` 返回结果驱动。
- 未绑定 Keystone 角色的服务 Principal 调用 Keystone 管理 API 返回 403。
- 旧 refresh token 重放会失败，客户端保存的新 refresh token 可以继续刷新。
- 客户端可以使用 refresh token 调用 `/v1/auth/logout-refresh-token` 主动释放 Keylo refresh session。
- 管理员可以通过 `/v1/admin/refresh-sessions` 查询在线会话，并通过 `DELETE /v1/admin/refresh-sessions/{session_id}` 强制退出。
