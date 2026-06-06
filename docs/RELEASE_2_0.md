# Keylo 2.0.0 发布说明

发布日期：2026年6月6日

Keylo 2.0.0 是统一主体 RBAC 版本，重点把用户、服务和客户端统一映射为 Principal，并补齐资源树、授权检查和 refresh session 治理能力。

## 主要变化

- 新增 Principal 统一主体模型，支持 `user`、`service`、`client`。
- 新增 Principal 角色绑定、最终权限查询、资源树查询和统一授权检查 API。
- 服务 token 和用户 access token 均可用于 `/v1/authorize/check` 与批量授权检查。
- 用户登录与管理客户端登录均返回 refresh token。
- Refresh token 固定轮换，旧 token 重放会撤销所属 refresh session。
- 新增 Principal refresh session 查询与撤销管理 API。
- 新增 `SESSION_POLICY`，支持 `multi_session`、`single_user_session`、`single_principal_session`。
- 登录请求新增 `force=true`，用于认证成功后的显式会话接管。
- 第三方集成文档补充 Keystone、客户端 refresh 保存策略和资源服务接入契约。

## 兼容性

- 1.x 核心认证、JWKS、OAuth、服务 token、内省、RBAC 管理接口继续保留。
- 旧 `refresh_tokens` 兼容路径保留，旧 refresh token 刷新成功后会迁移到 refresh session。
- `scope` 和 `audience` 仍作为服务 token 签发边界保留；具体业务权限建议改用 Principal RBAC 授权检查。

## 新增文档

- [API_REFERENCE.md](API_REFERENCE.md)
- [THIRD_PARTY_INTEGRATION.md](THIRD_PARTY_INTEGRATION.md)
- [KEYSTONE_KEYLO_2_0_MIGRATION.md](KEYSTONE_KEYLO_2_0_MIGRATION.md)
- [KEYLO_2_0_CLIENT_GUIDE.md](KEYLO_2_0_CLIENT_GUIDE.md)

## 发布前验证

本版本发布前已完成：

```bash
cargo fmt
cargo check
cargo test
```
