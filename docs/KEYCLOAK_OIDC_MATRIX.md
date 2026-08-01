# Keycloak OIDC 上游兼容矩阵

本文档是路线图中 OIDC 上游身份联邦的可执行验收基线。矩阵必须使用真实 Keycloak 服务；单元测试、模拟身份源或仅 HTTP 的本地装置都不能替代真实兼容性证据。

## 测试装置

`docker-compose.keycloak-matrix.yml` 会将 `tests/keycloak/realm/keylo-matrix-realm.json` 导入 Keycloak 26.7.0。该 Realm 定义了一个使用授权码流程的机密客户端 `keylo-upstream-matrix`，以及一个已验证邮箱的测试用户。密码、客户端密钥和 Keylo 回调地址均通过环境变量注入，不会提交到仓库。

该装置使用 `start-dev` 和 HTTP 仅用于本地启动 Realm。它本身不是正式验收环境；矩阵执行必须让 Keylo 和 Keycloak 都使用对方能够验证的 HTTPS issuer。

```powershell
$env:KEYCLOAK_MATRIX_ADMIN_PASSWORD = "..."
$env:KEYCLOAK_MATRIX_CLIENT_SECRET = "..."
$env:KEYCLOAK_MATRIX_USER_PASSWORD = "..."
$env:KEYLO_MATRIX_REDIRECT_URI = "https://identity.example.test/v1/upstream/oidc/callback"
docker compose -f docker-compose.keycloak-matrix.yml up -d
```

## 前置检查

使用实际浏览器流程将访问的 HTTPS endpoint 执行前置检查：

```powershell
.\scripts\test_keycloak_oidc_matrix_preflight.ps1 `
  -KeyloPublicIssuer "https://identity.example.test" `
  -KeycloakIssuer "https://idp.example.test/realms/keylo-matrix"
```

脚本会检查 Discovery issuer 的精确绑定、HTTPS endpoint、授权码支持、`client_secret_basic` 和 RS256。它只会在 `artifacts/oidc-matrix/` 下保存公开 Discovery 元数据和当前 Keylo commit，不会写入密钥、授权码、access token、refresh token 或 ID Token。如果任一 endpoint 无法访问，或不满足 TLS/Discovery 契约，脚本仍会生成 `status: "not_executed"` 的 artifact，并以退出码 `2` 结束；环境不可用不会被转换为矩阵通过。

前置检查通过只表示环境具备执行矩阵的条件，不代表浏览器场景已经通过。

## 场景记录

完成一次矩阵执行后，先校验 JSON 记录，再将其附加到发布或审计记录：

```powershell
.\scripts\validate_keycloak_oidc_matrix_artifact.ps1 `
  -Path .\artifacts\oidc-matrix\keycloak-run.json
```

artifact 必须包含 `executed_at_utc`、`keylo_commit`、`keycloak_version`、顶层 `status`，以及下面六个且仅六个场景名称。每个场景的状态只能是 `passed`、`failed` 或 `not_executed`。校验器会拒绝名称表示凭据、授权码、Token 或私钥的字段。结构有效但未完成的记录返回退出码 `2`；只有六个场景全部通过时才返回退出码 `0`。

每个场景只记录 HTTP 状态和结果摘要，不记录敏感值：

| 场景 | 必须满足的断言 |
| --- | --- |
| 首次登录 `first_login` | JIT 创建一个本地用户和一个稳定的身份源映射。 |
| 重复登录 `repeat_login` | 复用已有用户和映射，不重复创建。 |
| UserInfo 补充 `userinfo_completion` | 只有在 `sub` 匹配时，才能补充 ID Token 缺失的 profile 字段。 |
| 邮箱变化 `email_change` | 登录继续依据稳定的上游 `sub`，不自动改写本地邮箱。 |
| 禁用 Keylo 用户 `disabled_keylo_user` | 受保护访问被拒绝，且该用户的 refresh session 已撤销。 |
| 禁用身份源 `disabled_identity_source` | 新回调被拒绝，来源 refresh session 已撤销，审计记录包含撤销数量。 |

TLS、网络或浏览器自动化失败必须记录为 `not_executed`，不能重新归类为单元测试通过。
