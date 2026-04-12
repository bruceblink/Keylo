# Keylo 1.0 生产部署指南

本文档定义 Keylo 1.0 在生产环境中的最小部署要求、配置要求和上线前检查项。

## 目标

Keylo 在生产环境中承担统一认证中心职责，因此部署目标不是“能启动”，而是：

- 使用显式提供的 RSA 密钥对签发 JWT
- 通过 JWKS 暴露公开验签密钥
- 提供用户与服务 Token 内省能力
- 使用 PostgreSQL 持久化认证状态
- 可选接入 Redis 支持分布式限流、登录锁定和 OAuth state 管理

## 必要配置

生产环境必须显式提供以下配置：

```env
ENVIRONMENT=production
JWT_ISSUER=keylo
JWT_KEY_ID=keylo-rs256-1
JWT_PRIVATE_KEY_PATH=/app/keys/private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem
DATABASE_URL=postgres://keylo_user:keylo_password@postgres:5432/keylo
ADMIN_CLIENT_ID=cli-admin-root
ADMIN_CLIENT_SECRET=replace-with-strong-admin-secret
REDIS_URL=redis://redis:6379
RUST_LOG=keylo=info,axum=info
```

说明：

- 生产环境禁止使用内置开发密钥。
- 生产环境要求显式提供管理客户端。
- 生产环境要求显式提供 Redis。
- 如果数据库初始化失败，服务会直接失败启动，不再回退到内存模式。

## RSA 密钥要求

推荐：

- RSA 2048 位或更高
- 私钥仅部署在 Keylo 服务端
- 公钥仅用于 JWKS 暴露与下游系统验签
- 每次轮换都更新 `JWT_KEY_ID`

示例生成命令：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -pubout -in private.pem -out public.pem
```

## 启动前检查

上线前必须确认：

1. PostgreSQL 可连接且迁移可执行。
2. Redis 可连接。
3. `/.well-known/jwks.json` 可被内部服务访问。
4. `/v1/auth/introspect` 与 `/v1/service/introspect` 可正常工作。
5. 管理员客户端已配置，并可获取带 `admin` scope 的 token。
6. 第三方系统已切换到 RS256 + JWKS 或内省模式，不再依赖共享密钥。

## 推荐上线流程

1. 准备新的 RSA 私钥和公钥。
2. 将私钥与公钥挂载到 Keylo 运行环境。
3. 配置 `JWT_KEY_ID`、`JWT_PRIVATE_KEY_PATH`、`JWT_PUBLIC_KEY_PATH`。
4. 启动 Keylo，并确认 `/.well-known/jwks.json` 可访问。
5. 使用管理员客户端验证管理接口。
6. 使用第三方服务验证 JWKS 获取、本地验签与用户 Token 内省。
7. 在确认通过后切换业务流量。

## 运行后检查

部署成功后至少验证：

1. 用户登录可以正常获取 Access Token。
2. 服务凭证可以正常获取 `service_access` Token。
3. JWKS 返回的 `kid` 与当前配置一致。
4. 第三方系统可以基于 JWKS 验签。
5. 吊销或黑名单逻辑仍然可通过内省接口感知。

## 不推荐的生产模式

以下方式不应出现在生产环境：

- 使用内置开发 RSA 密钥
- 将 JWT 私钥分发给第三方系统
- 在生产环境使用数据库失败后的内存回退模式
- 跳过管理员客户端配置
