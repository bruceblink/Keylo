# Keylo 2.0 客户端 Token 与会话指南

本文档面向 Web、桌面客户端、BFF 和服务端集成方，说明 Keylo 2.0 中 access token、refresh token、refresh session 和单会话策略的使用规则。

## 1. Token 职责

| Token | 用途 | 保存建议 |
|---|---|---|
| `access` | 调用 Keylo 或资源服务 | 短期内存保存 |
| `refresh` | 换取新的 access token | 安全持久保存 |
| `service_access` | 服务间调用 | 服务进程内短期保存 |

Access token 用于证明“是谁”和“面向哪个 audience”。Refresh token 用于维持会话，不应传给资源服务。

## 2. Refresh Token 轮换

Keylo 2.0 固定启用 refresh token rotation：

1. 客户端使用旧 refresh token 调用 `POST /v1/auth/refresh`。
2. Keylo 原子消费旧 token。
3. Keylo 返回新的 access token 和新的 refresh token。
4. 客户端必须立即用新 refresh token 覆盖旧值。

旧 refresh token 再次使用会被视为重放，并撤销所属 refresh session。

## 3. 客户端单飞刷新

同一客户端不应并发刷新同一个 refresh token。推荐实现：

- 如果已有刷新请求在飞，后续请求等待该请求结果。
- 刷新成功后统一读取新的 access token / refresh token。
- 刷新失败且返回 401 时，清理本地登录态并重新登录。

伪代码：

```text
if refresh_in_flight:
    await refresh_in_flight
else:
    refresh_in_flight = POST /v1/auth/refresh
    save(new_refresh_token)
    clear refresh_in_flight
```

## 4. Web/BFF

推荐由 BFF 持有 refresh token：

- 浏览器只持有短期 access token，或通过 HttpOnly cookie 访问 BFF。
- Refresh token 放在服务端 session 或 HttpOnly Secure SameSite cookie。
- BFF 负责单飞刷新，避免多个浏览器请求同时刷新。

## 5. 桌面客户端

桌面客户端应：

- 使用系统凭据存储保存 refresh token。
- 应用启动后按需刷新 access token。
- 实现进程内单飞刷新。
- 收到 401 后清理 refresh token 并提示重新登录。

## 6. 服务端和管理工具

管理 CLI、后台任务或服务端工具使用 `/v1/admin/token` 获取管理 access token 和 refresh token。保存策略与 BFF 类似：

- refresh token 只存放在受保护的密钥存储中。
- 轮换管理客户端密钥后，已有 refresh session 会被撤销。
- 管理员可通过 Principal refresh session API 主动撤销会话。

## 7. 单会话策略

`SESSION_POLICY` 支持：

| 值 | 行为 |
|---|---|
| `multi_session` | 默认允许多会话 |
| `single_user_session` | 同一用户只允许一个活动 session |
| `single_principal_session` | 同一 Principal 只允许一个活动 session |

当策略命中且已有活动 session：

- 未传 `force=true`：登录返回 `409 conflict`。
- 传 `force=true`：认证成功后撤销旧 session 并签发新 session。

客户端应把 `409 conflict` 展示为“账号已在其他位置登录，是否接管”，用户确认后再带 `force=true` 重试登录。

## 8. 管理员会话治理

管理员可查询和撤销 Principal refresh session：

```text
GET    /v1/admin/principals/{principal_id}/refresh-sessions
DELETE /v1/admin/principals/{principal_id}/refresh-sessions
DELETE /v1/admin/principals/{principal_id}/refresh-sessions/{session_id}
```

撤销后，相关 refresh token 不能再刷新 access token。
