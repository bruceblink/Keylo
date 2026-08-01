# Keylo Spring Boot OIDC Relying Party

这是一个可运行的 Spring Boot OIDC relying party（RP）示例。Spring Security 从 Keylo 的 `issuer-uri` 执行 Discovery，以 Authorization Code + PKCE 完成登录，并使用 Discovery 公布的 JWKS 验证 ID Token。

## 前置条件

- JDK 21 或更高版本。项目已携带 Gradle Wrapper，首次运行会下载已固定的 Gradle 发行版。
- 在 Keylo 注册 confidential OIDC client，允许 `openid profile email`，回调地址登记为 `http://127.0.0.1:8080/login/oauth2/code/keylo`。
- 生产环境使用 HTTPS。内网 HTTP 只适用于浏览器、RP 和 Keylo 均处于完全受控网络且不暴露给不受信任网络的部署。

## 启动

```powershell
$env:KEYLO_ISSUER = "http://127.0.0.1:2345"
$env:OIDC_CLIENT_ID = "example-web"
$env:OIDC_CLIENT_SECRET = "replace-with-client-secret"
.\gradlew.bat bootRun
```

访问 `http://127.0.0.1:8080` 会被 Spring 引导至标准 authorization endpoint。成功回调默认路径为 `/login/oauth2/code/keylo`；示例在 Spring 兑换 code 前额外精确校验 Keylo 返回的 `iss`，防止 authorization response mix-up。

public client 可以设置 `OIDC_CLIENT_AUTH_METHOD=none` 并不提供 client secret；Spring Security 会为公开授权码客户端使用 PKCE。反向代理终止 TLS 时，必须正确转发并信任 `Forwarded` 或 `X-Forwarded-*` 头，确保 `{baseUrl}` 与已登记回调地址完全一致。

## 验证

```powershell
.\gradlew.bat test
```

测试覆盖 callback `iss` 拒绝规则；完整浏览器验证仍需要运行中的 Keylo 与已登记 client，并应检查成功登录、拒绝授权、错误 `state`/`nonce`/`iss` 和回调重放均不能建立应用会话。
