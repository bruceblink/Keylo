# Keylo Node Express OIDC Relying Party

这是一个可运行的 Express 5 OIDC relying party（RP）示例。它通过标准 `openid-client` 库从 Discovery 开始完成 Authorization Code + PKCE 登录；不调用 Keylo 的专用登录接口。

## 前置条件

- Node.js 20 或更高版本。
- 在 Keylo 创建一个 OIDC client，启用 `openid profile email` scope。
- 登记精确回调地址 `http://127.0.0.1:3000/oidc/callback`。开发期仅精确 loopback 地址可用 HTTP；生产环境使用 HTTPS。
- Keylo 的 `OIDC_PUBLIC_ISSUER` 必须是浏览器和本示例都能访问的公开 issuer。内网 HTTP 仅限完全受控网络，不能暴露给不受信任网络。

## 启动

```powershell
npm install
$env:KEYLO_ISSUER = "http://127.0.0.1:2345"
$env:OIDC_CLIENT_ID = "example-web"
$env:SESSION_SECRET = "replace-with-a-long-random-secret"
npm start
```

机密 client 还需要设置 `OIDC_CLIENT_SECRET`。示例启动后访问 `http://127.0.0.1:3000`。

`/login` 会保存一次性的 `state`、`nonce` 与 PKCE verifier 后跳转到 authorization endpoint；`/oidc/callback` 显式校验回调 `iss`，并通过库校验 state、PKCE、ID Token 签名、issuer、audience、expiry 与 nonce，随后立即清除一次性材料。应用会话只保存已验证的最小 profile。

## 验证

```powershell
npm run check
```

这项检查验证示例可被 Node 解析。端到端验证需要运行中的 Keylo 和已登记的 client；登录、拒绝授权、回调重放及错误 state/nonce 都应被拒绝。
