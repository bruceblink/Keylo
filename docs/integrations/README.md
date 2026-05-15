# Keylo Integration Templates

这些模板面向资源服务、BFF、API 网关和第三方系统，展示如何把 Keylo 当作轻量统一鉴权与授权中心接入。

推荐优先级：

1. 读取 `/.well-known/keylo-configuration` 获取 `issuer`、`jwks_uri` 和内省端点。
2. 常规请求使用 JWKS 本地验签。
3. 验签后校验 `iss`、`aud`、`exp`、`token_type`、`scope`。
4. 高敏接口或需要实时吊销时，再调用 `/v1/auth/introspect` 或 `/v1/service/introspect`。

可用模板：

- [Spring Security](spring-security.md)
- [Node Express](node-express.md)
- [Go net/http](go-net-http.md)
- [Rust Axum](rust-axum.md)

Keylo 当前不承诺完整 OIDC Provider 兼容性。请把 `/.well-known/keylo-configuration` 视为 Keylo 自己的轻量发现契约，而不是 OIDC discovery 文档。
