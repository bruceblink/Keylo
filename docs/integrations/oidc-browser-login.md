# OIDC Browser Login

适用场景：Web BFF、服务端渲染应用和桌面应用使用 Keylo 作为标准 OIDC Provider 登录用户。此流程使用 Authorization Code + PKCE，不依赖 Keylo 专用登录 API。

## 1. 前置配置

在 Keylo 注册 public 或 confidential OIDC client，并登记应用的精确 HTTPS callback URL。开发期只有 `127.0.0.1` 或 `[::1]` 可使用 HTTP callback。client 必须允许 `openid` scope；按需增加 `profile` 和 `email`。

应用启动时从 `https://keylo.example.com/.well-known/openid-configuration` 读取 `issuer`、`authorization_endpoint`、`token_endpoint`、`jwks_uri` 和 `userinfo_endpoint`，不要在代码中拼接端点或以内部监听地址替代 issuer。

## 2. 发起登录

每次登录生成并临时保存三个随机值：

- `state`：回调时必须逐字匹配，用于关联浏览器请求和防止 CSRF。
- `nonce`：回调后的 ID Token 必须逐字匹配，用于绑定登录响应。
- `code_verifier`：43-128 位 PKCE unreserved 字符；保存原值，并发送 `BASE64URL(SHA-256(code_verifier))` 作为 `code_challenge`。

将浏览器重定向至 Discovery 给出的 authorization endpoint，参数固定为：

```text
response_type=code
client_id=<registered client id>
redirect_uri=<registered callback>
scope=openid profile email
state=<random state>
nonce=<random nonce>
code_challenge=<S256 challenge>
code_challenge_method=S256
```

Keylo 会显示同站点登录和同意页面。成功回调包含 `code`、原始 `state` 与 `iss`；拒绝包含 `error=access_denied`、原始 `state` 与 `iss`。回调处理器必须先验证 `state` 和 `iss`，再处理 `code` 或错误。

## 3. 兑换与校验

向 token endpoint 提交 `grant_type=authorization_code`、`code`、`redirect_uri` 和保存的 `code_verifier`。public client 还提交 `client_id`；confidential client 使用 `client_secret_basic`，或使用已声明的 `client_secret_post`。

验证 ID Token 时必须通过 JWKS 校验 RS256 签名，并校验 `iss`、`aud`、`exp`、`iat` 和保存的 `nonce`。不能只 decode JWT payload。需要额外 profile 信息时，以 OIDC access token 调用 UserInfo，并确认返回的 `sub` 与 ID Token 的 `sub` 完全一致。

## 4. 会话边界

应用自己的登录会话应只保存经过验证的主体标识和最小 profile，不把 authorization code、PKCE verifier、client secret 或完整 Token 写入日志。收到回调后立即使 `state`、`nonce` 和 verifier 失效；失败、拒绝和重复回调也一样处理。

Node、Spring、Go 与 Rust 的资源服务模板继续用于验签 Keylo access token；当这些应用同时作为浏览器 relying party 时，应先按本文完成用户登录，再按各自模板保护后端 API。
