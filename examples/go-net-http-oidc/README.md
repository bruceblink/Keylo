# Keylo Go net/http OIDC Relying Party

这是一个可运行的 Go `net/http` OIDC relying party（RP）示例。它使用 `github.com/coreos/go-oidc/v3` 执行 Discovery、ID Token 签名/issuer/audience/expiry 校验，并使用 `golang.org/x/oauth2` 完成 Authorization Code + PKCE。

## 前置条件

- Go 1.24 或更高版本。
- 在 Keylo 注册允许 `openid profile email` 的 OIDC client，并登记 `http://127.0.0.1:3000/oidc/callback`。
- 生产环境使用 HTTPS。内网 HTTP 只能用于浏览器、RP 与 Keylo 同处完全受控网络的部署，不能暴露给不受信任网络。

## 启动

```powershell
$env:KEYLO_ISSUER = "http://127.0.0.1:2345"
$env:OIDC_CLIENT_ID = "example-web"
go run .
```

机密 client 还需要设置 `OIDC_CLIENT_SECRET`。访问 `http://127.0.0.1:3000` 开始登录。

示例的临时会话只保存 `state`、`nonce` 与 PKCE verifier，并在所有 callback 路径消费。回调会先校验 `state` 和 Keylo 传回的 `iss`，随后兑换 code、验签 ID Token 并检查 nonce；登录成功后轮换会话 token，只保存已验证 profile。

## 验证

```powershell
go test ./...
```

完整浏览器验证需要可访问的 Keylo 与已登记 client；应分别检查成功登录、拒绝授权、错误 state/nonce、错误 issuer 和回调重放均不能建立应用会话。
