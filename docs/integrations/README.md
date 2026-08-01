# Keylo Integration Templates

这些模板面向资源服务、BFF、API 网关和第三方系统，展示如何把 Keylo 当作轻量统一鉴权与授权中心接入。

推荐优先级：

1. 读取 `/.well-known/keylo-configuration` 获取 `issuer`、`jwks_uri` 和内省端点。
2. 常规请求使用 JWKS 本地验签。
3. 验签后校验 `iss`、`aud`、`exp`、`token_type`，并读取 `principal_id` / `principal_type`。
4. 粗粒度能力可本地校验 `scope` / `role`；细粒度能力应调用 `/v1/authorize/check` 或 `/v1/authorize/batch-check`。
5. 高敏接口或需要实时吊销时，再调用 `/v1/auth/introspect` 或 `/v1/service/introspect`。

Keylo 2.0 中，用户、服务和客户端都会映射为 Principal。服务 token 验签通过只表示服务身份可信，不表示该服务拥有所有业务权限；资源服务应继续基于 Keylo 授权检查或本地业务策略做最终判定。

可用模板：

- [OIDC 浏览器登录](oidc-browser-login.md)
- [Node Express OIDC RP 示例](../../examples/node-express-oidc/README.md)
- [Go net/http OIDC RP 示例](../../examples/go-net-http-oidc/README.md)
- [Rust Axum OIDC RP 示例](../../examples/rust-axum-oidc/README.md)
- [Spring Security](spring-security.md)
- [Node Express](node-express.md)
- [Go net/http](go-net-http.md)
- [Rust Axum](rust-axum.md)

Keylo 不追求复制所有 OIDC 扩展，但承诺已公布的 Authorization Code + PKCE、Discovery、JWKS、ID Token 和 UserInfo 契约可由标准客户端使用。浏览器登录从标准 `/.well-known/openid-configuration` 的 authorization endpoint 开始；`/.well-known/keylo-configuration` 仍是面向资源服务的轻量发现契约，不替代 OIDC Discovery。
