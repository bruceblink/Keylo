# Spring Boot 资源服务示例

此示例展示资源服务的两道边界：Spring Security 先通过 Keylo Discovery/JWKS 校验 JWT 的签名、issuer 与目标 audience；业务端点再把同一个 bearer token 转发给 Keylo 的 `/v1/authorize/check`，由 Keylo RBAC 给出最终允许或拒绝决定。

它适合作为 Keystone 等 Spring 服务迁移时的参考，不依赖 Keystone 的数据模型。

## 配置和运行

```powershell
$env:KEYLO_ISSUER = "https://keylo.example.test"
$env:KEYLO_REQUIRED_AUDIENCE = "admin-backend"
.\gradlew.bat bootRun
```

调用示例端点：

```text
GET /api/system/users
Authorization: Bearer <Keylo access token>
```

该端点要求 `keystone:system:user:list`。缺少目标 audience、JWT 校验失败、Keylo 返回拒绝或 Keylo 无法响应时，访问均会被拒绝；资源服务不会把“验签通过”当成业务权限。

运行测试：

```powershell
.\gradlew.bat test --no-daemon
```
