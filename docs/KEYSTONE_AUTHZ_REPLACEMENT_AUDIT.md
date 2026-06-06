# Keystone 鉴权授权替换审计

审计日期：2026-06-06

本文档基于 `F:\project\Keystone` 当前代码和 Keylo `2.0` 分支当前实现，确认 Keylo 是否已经具备替换 Keystone 核心鉴权与授权模块的能力。

## 1. 审计范围

纳入范围：

- 用户、管理客户端、服务账号 token 签发与验签。
- refresh token 轮换、重放检测、单会话策略、退出登录和强制退出。
- Keystone `@permission.has(...)` 使用的 RBAC 权限判断。
- Keystone `*:*:*` 超级权限语义。
- 菜单、按钮、API、服务能力的资源树和权限绑定。
- 当前 Principal 的角色、权限和资源查询。
- Keystone 在线会话列表和强制退出。
- Keystone 用户迁移到 Keylo 用户池。

不纳入范围：

- 部门、岗位和数据权限范围。该项按用户确认不作为本轮 Keylo 替换 Keystone 核心 RBAC 的阻塞项。
- Keystone 前端登录页的验证码、RSA 密码加密展示契约。这些属于 Keystone UI/边界输入体验，不是 Keylo 鉴权授权能力本身。

## 2. Keystone 现状证据

- Keystone 控制器中有 67 处 `@PreAuthorize`，核心授权形式是 `@permission.has('...')`。
- `MenuPermissionService` 判断权限集合是否包含目标权限或 `RoleInfo.ALL_PERMISSIONS`，即 `*:*:*`。
- `JwtAuthenticationTokenFilter` 仍有过渡实现：本地 token 失败后，若 Keylo token 验签通过，会构造 `RoleInfo.ADMIN_PERMISSIONS`。
- `LoginController` 暴露 `/login`、`/refresh-token`、`/logout-refresh-token`、`/getLoginUserInfo`、`/getRouters`。
- `MonitorController` 暴露 `/monitor/onlineUsers` 和 `/monitor/onlineUser/{tokenId}`，用于在线会话列表和强制退出。

## 3. Keylo 替换能力矩阵

| Keystone 需求 | Keylo 当前能力 | 证据 |
|---|---|---|
| 用户 access/refresh token | `/v1/auth/token`、`/v1/auth/refresh` | `tests::test_user_refresh_token_rotates_and_replay_is_rejected` |
| 管理客户端 token | `/v1/admin/token` | `tests::test_admin_client_management_api` |
| 服务 token | `/v1/service/token` | `tests::test_keylo_2_0_service_principal_authorization_flow` |
| JWKS 本地验签 | `/.well-known/jwks.json`、发现配置 | `tests::test_jwks_endpoint`、`tests::test_keylo_configuration_endpoint` |
| refresh token 轮换和重放撤销 | refresh session + token hash + replay revoke | `tests::test_user_refresh_token_rotates_and_replay_is_rejected` |
| refresh token 退出登录 | `POST /v1/auth/logout-refresh-token` | `tests::test_refresh_token_logout_revokes_session_without_access_token` |
| 单用户/单 Principal 会话策略 | `SESSION_POLICY` + `force=true` | `tests::test_single_user_session_requires_explicit_takeover` |
| 在线会话列表和强制退出 | `GET /v1/admin/refresh-sessions`、`DELETE /v1/admin/refresh-sessions/{session_id}` | `tests::test_admin_can_list_and_revoke_principal_refresh_session` |
| Principal 统一主体 | `principals`、`principal_roles` | `tests::test_keylo_2_0_service_principal_authorization_flow` |
| RBAC 角色权限 | `/api/rbac/roles`、`/api/rbac/permissions`、role-permission binding | `tests::test_batch_bindings_and_effective_permissions` |
| Keystone `*:*:*` | Keylo 权限名 `*:*:*` 显式绑定后通配任意权限 | `tests::test_keystone_wildcard_permission_allows_any_rbac_check_and_resource_tree` |
| API 权限检查 | `/v1/authorize/check`、`/v1/authorize/batch-check` | `tests::test_keylo_2_0_user_menu_resource_tree_flow` |
| 菜单/按钮资源树 | `/v1/principals/me/resource-tree?app=keystone&type=menu` | `tests::test_keylo_2_0_user_menu_resource_tree_flow` |
| Keystone RouterDTO 元数据 | `resources.metadata JSONB` | `tests::test_keylo_2_0_user_menu_resource_tree_flow` |
| 服务 Principal 授权 | service principal + RBAC check | `tests::test_keylo_2_0_service_principal_authorization_flow` |
| 用户迁移 | `/v1/admin/users/migrations/import`、JIT register | `tests::test_third_party_user_migration_import_is_idempotent`、`tests::test_jit_migration_register_can_issue_access_token` |

## 4. 结论

Keylo 当前已经具备替换 Keystone 核心鉴权与授权模块的能力，前提是 Keystone 接入时按 `docs/KEYSTONE_KEYLO_2_0_MIGRATION.md` 切换到 Principal + RBAC 模式：

1. Keystone 后端本地验签 Keylo token，并校验 `iss`、`aud`、`exp`、`iat`、`token_type`。
2. Keystone 不再使用 `JwtAuthenticationTokenFilter.buildTrustedKeyloLoginUser` 的临时 `*:*:*` 映射。
3. Keystone API 授权改为调用 `/v1/authorize/check` 或 `/v1/authorize/batch-check`。
4. Keystone 菜单和按钮改为消费 `/v1/principals/me/resource-tree`。
5. Keystone 在线会话管理改为消费 Keylo refresh session 管理接口。

因此，剩余工作不是 Keylo 功能开发缺口，而是 Keystone 侧删除过渡兼容逻辑并切换调用路径。

## 5. 已验证命令

```text
cargo check
cargo test --test integration_test
cargo test --test rbac_integration_test
```
