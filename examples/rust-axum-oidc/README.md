# Keylo Rust Axum OIDC Relying Party

这是一个可运行的 Axum OIDC relying party（RP）示例。它使用标准 `openidconnect` crate 读取 Discovery，执行 Authorization Code + PKCE，并校验 ID Token 的签名、issuer、audience、expiry 与 nonce。

## 前置条件

- Rust 1.85 或更高版本。
- 在 Keylo 注册允许 `openid profile email` 的 OIDC client，并登记 `http://127.0.0.1:3000/oidc/callback`。
- 生产部署使用 HTTPS。内网 HTTP 仅限浏览器、RP 和 Keylo 都在受控网络且不向不受信任网络暴露的场景。

## 启动

```powershell
$env:KEYLO_ISSUER = "http://127.0.0.1:2345"
$env:OIDC_CLIENT_ID = "example-web"
cargo run
```

机密 client 额外设置 `OIDC_CLIENT_SECRET`。访问 `http://127.0.0.1:3000` 即可开始登录。

`/login` 在服务器内存会话保存一次性的 `state`、`nonce` 与 PKCE verifier。回调无论成功、拒绝还是失败都会消费这些值，并先校验 `state` 与 Keylo 的 `iss`；验证 ID Token 后会轮换应用 session ID，只保存经过验证的主体信息。

## 验证

```powershell
cargo test
```

完整浏览器验证需要运行中的 Keylo 与已登记 client。应确认成功登录、拒绝授权、错误 `state`/`nonce`/`iss` 和回调重放都不会建立应用会话。
