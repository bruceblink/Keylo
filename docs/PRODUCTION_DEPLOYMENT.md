# Keylo 1.3.1 生产部署指南

本文档定义 Keylo 1.3.1 在生产环境中的最小部署要求、配置要求和上线前检查项。

## 目标

Keylo 在生产环境中承担统一认证中心职责，因此部署目标不是"能启动"，而是：

- 使用显式提供的 RSA 密钥对签发 JWT
- 通过 JWKS 暴露公开验签密钥
- 提供用户与服务 Token 内省能力
- 使用 PostgreSQL 持久化认证状态
- **（1.1.0 起生产环境强制）** 接入 Redis 支持分布式限流、登录锁定和 OAuth state 管理

## 必要配置

生产环境必须显式提供以下配置：

```env
# Docker image defaults ENVIRONMENT=production.
# Keylo also defaults JWT_ISSUER=keylo, JWT_KEY_ID=keylo-rs256-1,
# ADMIN_CLIENT_ID=cli-admin-root, DB_POOL_SIZE=10, and standard key/secret paths.
DATABASE_URL=postgres://keylo_user@postgres:5432/keylo
ADMIN_CLIENT_SECRET=replace-with-strong-admin-secret
REDIS_URL=redis://redis:6379
```

`JWT_KEY_ID` 是当前 JWT 签名密钥的标识符，会写入 JWT header 的 `kid` 字段，同时暴露在 `/.well-known/jwks.json` 中对应公钥的 `kid` 字段。下游服务本地验签时，会根据 token header 中的 `kid` 到 JWKS 中选择同名公钥。单密钥部署可以使用类似 `keylo-rs256-1` 的稳定值；每次更换 RSA 私钥/公钥时，应同步更换 `JWT_KEY_ID`，例如递增为 `keylo-rs256-2`，避免下游 JWKS 缓存把新 token 误用旧公钥验证。

如果使用仓库内的 [docker-compose.yml](docker-compose.yml)，还需要保证：

- 宿主机存在 RSA 密钥目录，并通过 `${JWT_KEYS_DIR:-./keys}` 挂载到容器 `/app/keys`
- 宿主机存在 PostgreSQL 初始化明文密码文件 `${POSTGRES_PASSWORD_FILE:-./secrets/postgres_password}`，该文件只提供给 PostgreSQL 初始化
- 宿主机存在 Keylo 运行期数据库密文 `${DATABASE_PASSWORD_ENC_FILE:-./secrets/postgres_password.enc}` 和解密密钥 `${DATABASE_PASSWORD_KEY_FILE:-./secrets/database_password.key}`，Keylo 不读取明文数据库密码文件
- Docker Compose 中 `SERVER_ADDR` 约定为 `0.0.0.0`，避免容器内只监听回环地址
- `ADMIN_CLIENT_ID` 默认是 `cli-admin-root`；不要删除 `ADMIN_CLIENT_SECRET`，否则启动会直接失败
- 如需重装数据库，执行 `docker compose down -v --remove-orphans` 删除 PostgreSQL 数据卷后再重建

说明：

- 生产环境禁止使用内置开发密钥。
- 生产环境要求显式提供管理客户端。
- **1.1.0 起生产环境 Redis 为强制依赖**：若 Redis 不可用，限流中间件将拒绝请求，服务不会降级为内存限流。
- `DB_POOL_SIZE` 控制数据库连接池大小，默认 10；只有需要按部署规模调优时才覆盖。
- 如果数据库初始化失败，服务会直接失败启动，不再回退到内存模式。
- 非生产环境默认也会在数据库初始化失败时失败启动；只有显式设置 `ALLOW_IN_MEMORY_FALLBACK=true` 才允许无数据库路由。该模式仍会校验 RSA 密钥、管理员客户端和其他基础配置。
- 登录和内省限流默认使用连接 peer IP；只有反向代理可信且正确覆盖真实客户端地址时才应设置 `TRUST_PROXY_HEADERS=true`。
- Refresh Token 刷新会原子消费旧 token，旧 refresh token 不可并发复用。
- 客户端密钥（`client_secret`）存储为 bcrypt 哈希；从 1.0.x 升级时需重置所有客户端密钥。

## RSA 密钥要求

推荐：

- RSA 2048 位或更高
- 私钥仅部署在 Keylo 服务端
- 公钥仅用于 JWKS 暴露与下游系统验签
- 每次轮换 RSA 密钥对都更新 `JWT_KEY_ID`，使 JWT header 中的 `kid` 与 JWKS 中的新公钥对应

示例生成命令：

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -pubout -in private.pem -out public.pem
```

推荐的服务器落地步骤：

```bash
mkdir -p /opt/keylo/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /opt/keylo/keys/private.pem
openssl rsa -pubout -in /opt/keylo/keys/private.pem -out /opt/keylo/keys/public.pem
chmod 600 /opt/keylo/keys/private.pem
chmod 644 /opt/keylo/keys/public.pem
```

如果使用仓库内的 Docker Compose，可将宿主机目录通过 `JWT_KEYS_DIR=/opt/keylo/keys` 暴露给容器。此时容器内配置建议为：

```env
JWT_PRIVATE_KEY_PATH=/app/keys/private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem
```

也可以不使用文件挂载，直接通过环境变量注入 PEM 内容：

```env
JWT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
JWT_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

但生产环境更推荐使用文件挂载，而不是把完整私钥直接写进 Compose 或 Shell 历史。

## 启动前检查

上线前必须确认：

1. PostgreSQL 可连接且迁移可执行。
2. Redis 可连接。
3. `/.well-known/jwks.json` 可被内部服务访问。
4. `/v1/auth/introspect` 与 `/v1/service/introspect` 可正常工作。
5. 管理员客户端已配置，并可获取带 `admin` scope 的 token。
6. 第三方系统已切换到 RS256 + JWKS 或内省模式，不再依赖共享密钥。

## 数据库密码密文化流程

Docker Compose 首次初始化 PostgreSQL 时，PostgreSQL 仍需要读取一次明文密码文件。Keylo 不应读取该明文文件；Keylo 运行期只读取数据库密码密文和解密密钥。

密文格式统一为 `secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>`。完整格式约定和 Rust/Python/Java/.NET/C++ 解密示例见 [SECRET_ENCRYPTION.md](SECRET_ENCRYPTION.md)。

推荐在宿主机准备以下文件：

```bash
mkdir -p /opt/keylo/secrets
openssl rand -base64 32 > /opt/keylo/secrets/postgres_password

python -m pip install cryptography
python scripts/secret_tool.py generate-key \
  --out /opt/keylo/secrets/database_password.key
python scripts/secret_tool.py encrypt \
  --text-file /opt/keylo/secrets/postgres_password \
  --key-file /opt/keylo/secrets/database_password.key \
  --out /opt/keylo/secrets/postgres_password.enc

chmod 600 /opt/keylo/secrets/postgres_password \
  /opt/keylo/secrets/postgres_password.enc \
  /opt/keylo/secrets/database_password.key
```

随后启动 Compose 时指定 secret 文件位置：

```bash
POSTGRES_PASSWORD_FILE=/opt/keylo/secrets/postgres_password \
DATABASE_PASSWORD_ENC_FILE=/opt/keylo/secrets/postgres_password.enc \
DATABASE_PASSWORD_KEY_FILE=/opt/keylo/secrets/database_password.key \
  docker compose up -d --build
```

生产环境中不要配置 `DATABASE_PASSWORD`、`DATABASE_PASSWORD_FILE`，也不要把密码写入 `DATABASE_URL`。这些情况会触发 Keylo 启动校验失败。

## 推荐上线流程

1. 准备新的 RSA 私钥和公钥。
2. 将私钥与公钥挂载到 Keylo 运行环境。
3. 按约定把密钥放到 `/app/keys/private.pem` 和 `/app/keys/public.pem`，或显式配置 `JWT_KEY_ID`、`JWT_PRIVATE_KEY_PATH`、`JWT_PUBLIC_KEY_PATH`。
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
- 在不可信网络边界直接信任 `X-Forwarded-For` / `X-Real-IP`
- 跳过管理员客户端配置
