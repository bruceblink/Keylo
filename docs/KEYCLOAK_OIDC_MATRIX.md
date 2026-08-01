# Keycloak OIDC 上游兼容矩阵

本文档是路线图中 OIDC 上游身份联邦的可选 Keycloak 互操作回归工具。Keycloak 用于验证代表性标准 IdP 的兼容性，但 Keylo 的主验收仍是标准 OIDC 协议契约、测试向量和 HTTP 集成测试；镜像、网络或部署条件不可用时，不应阻塞轻量化主线。

## 测试装置

`docker-compose.keycloak-matrix.yml` 会将 `tests/keycloak/realm/keylo-matrix-realm.json` 导入 Keycloak 26.7.0。该 Realm 定义了一个使用授权码流程的机密客户端 `keylo-upstream-matrix`，以及一个已验证邮箱的测试用户。客户端额外提供 `matrix_userinfo_marker`：它只出现在 UserInfo 响应，不出现在 ID Token 或 access token，用于验证 Keylo 只在 `sub` 一致时补充声明。执行该场景时，将身份源 `claim_mapping.username` 配置为 `matrix_userinfo_marker`。密码、客户端密钥和 Keylo 回调地址均通过环境变量注入，不会提交到仓库。

该装置使用 `start-dev` 和 HTTP 仅用于本地启动 Realm。默认矩阵执行要求 Keylo 和 Keycloak 使用 HTTPS issuer；完全隔离的内网可显式选择 HTTP，详见下方“内网 HTTP 边界”。

```powershell
$env:KEYCLOAK_MATRIX_ADMIN_PASSWORD = "..."
$env:KEYCLOAK_MATRIX_CLIENT_SECRET = "..."
$env:KEYCLOAK_MATRIX_USER_PASSWORD = "..."
$env:KEYLO_MATRIX_REDIRECT_URI = "https://identity.example.test/v1/upstream/oidc/callback"
docker compose -f docker-compose.keycloak-matrix.yml up -d
```

## 前置检查

默认使用实际浏览器流程将访问的 HTTPS endpoint 执行前置检查：

```powershell
.\scripts\test_keycloak_oidc_matrix_preflight.ps1 `
  -KeyloPublicIssuer "https://identity.example.test" `
  -KeycloakIssuer "https://idp.example.test/realms/keylo-matrix"
```

脚本会检查 Discovery issuer 的精确绑定、endpoint 传输模式、授权码支持、`client_secret_basic` 和 RS256。它只会在 `artifacts/oidc-matrix/` 下保存公开 Discovery 元数据和当前 Keylo commit，不会写入密钥、授权码、access token、refresh token 或 ID Token。如果任一 endpoint 无法访问，或不满足传输/Discovery 契约，脚本仍会生成 `status: "not_executed"` 的 artifact，并以退出码 `2` 结束；环境不可用不会被转换为矩阵通过。

前置检查通过只表示环境具备执行矩阵的条件，不代表浏览器场景已经通过。

## 内网 HTTP 边界

对完全隔离的内网部署，可显式传入 `-AllowInsecureInternalHttp`：

```powershell
.\scripts\test_keycloak_oidc_matrix_preflight.ps1 `
  -KeyloPublicIssuer "http://identity.internal" `
  -KeycloakIssuer "http://keycloak.internal/realms/keylo-matrix" `
  -AllowInsecureInternalHttp
```

该开关默认关闭，artifact 会记录 `transport_mode: internal_http_allowed` 和内网隔离边界。启用前必须确认 Keylo、Keycloak、反向代理和浏览器客户端均在受控网络内；不得将 issuer、Discovery、授权端点或回调暴露到公网、共享办公网或不受控 Wi-Fi。HTTP 不提供传输加密，攻击者一旦能监听或篡改链路，就可能获取登录凭据、授权码或 Token。内网 HTTP 的通过结果只适用于该边界，不能作为 HTTPS、第三方或互联网接入场景的兼容性证据。

## 场景记录

在启动浏览器场景前，使用已验证的 Keycloak 镜像 digest 创建一份初始记录：

```powershell
.\scripts\new_keycloak_oidc_matrix_artifact.ps1 `
  -KeycloakVersion "26.7.0" `
  -KeycloakImageDigest "sha256:<64 位小写十六进制>" `
  -TransportMode internal_http
```

初始化工具固定写入六个 `not_executed` 场景和当前 Keylo commit，并以退出码 `2` 表示尚未验收。执行者只能根据实际 HTTP 结果更新对应场景；不得把网络、TLS、浏览器或镜像失败改写成 `passed`。

完成一次矩阵执行后，先校验 JSON 记录，再将其附加到发布或审计记录：

```powershell
.\scripts\validate_keycloak_oidc_matrix_artifact.ps1 `
  -Path .\artifacts\oidc-matrix\keycloak-run.json
```

artifact 必须包含 `executed_at_utc`、`keylo_commit`、`keycloak_version`、`keycloak_image_digest`、顶层 `status`，以及下面六个且仅六个场景名称。`keycloak_image_digest` 必须是 `sha256:<64 位小写十六进制>`，用于将结果绑定到实际运行的 Keycloak 镜像。每个场景的状态只能是 `passed`、`failed` 或 `not_executed`。校验器会拒绝名称表示凭据、授权码、Token 或私钥的字段。结构有效但未完成的记录返回退出码 `2`；只有六个场景全部通过时才返回退出码 `0`。

每个场景只记录 HTTP 状态和结果摘要，不记录敏感值：

| 场景 | 必须满足的断言 |
| --- | --- |
| 首次登录 `first_login` | JIT 创建一个本地用户和一个稳定的身份源映射。 |
| 重复登录 `repeat_login` | 复用已有用户和映射，不重复创建。 |
| UserInfo 补充 `userinfo_completion` | 使用只存在于 UserInfo 的 `matrix_userinfo_marker`；只有在 `sub` 匹配时，才能补充 ID Token 缺失的 profile 字段。 |
| 邮箱变化 `email_change` | 登录继续依据稳定的上游 `sub`，不自动改写本地邮箱。 |
| 禁用 Keylo 用户 `disabled_keylo_user` | 受保护访问被拒绝，且该用户的 refresh session 已撤销。 |
| 禁用身份源 `disabled_identity_source` | 新回调被拒绝，来源 refresh session 已撤销，审计记录包含撤销数量。 |

TLS、网络或浏览器自动化失败必须记录为 `not_executed`，不能重新归类为单元测试通过。
