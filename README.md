# Keylo

**Keylo** 是一个轻量、可扩展的 **统一认证与授权中心**，为多服务系统提供统一的 JWT 签发、会话管理和 OAuth 支持。

快速上手建议：

* 完整使用步骤见 [docs/END_TO_END_QUICKSTART.md](docs/END_TO_END_QUICKSTART.md)
* 完整接口定义见 [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
* 多客户端权限建模见 [docs/MULTI_CLIENT_RBAC_INTEGRATION.md](docs/MULTI_CLIENT_RBAC_INTEGRATION.md)
* 统一密文配置格式见 [docs/SECRET_ENCRYPTION.md](docs/SECRET_ENCRYPTION.md)
* 发布说明见 [docs/RELEASE_1_5_1.md](docs/RELEASE_1_5_1.md)

---

## 🚀 特性

* ✅ 基于 RS256 的 JWT 签发与验证，内置 JWKS 公钥发布
* ✅ `/v1/auth/token`（用户认证）、`/v1/admin/token`（管理令牌）、`/v1/auth/refresh`、`/v1/auth/logout`、`/v1/auth/me` 核心 API（当前 refresh 主要用于管理客户端链路）
* ✅ 用户 Token 内省与服务 Token 内省
* ✅ 服务凭证模式与 `service_access` Token
* ✅ GitHub OAuth 登录，可扩展其他 OAuth 提供商
* ✅ RBAC、管理员客户端、审计日志与黑名单机制
* ✅ PostgreSQL 自动迁移，Redis 可选增强限流、锁定和 OAuth state
* ✅ 使用 Axum 0.8 + Tokio 的模块化 Rust 服务架构
* ✅ Docker / GHCR 镜像发布支持
* ✅ 客户端密钥 bcrypt 哈希存储，杜绝明文泄露风险
* ✅ 生产环境强制 Redis 限流，禁止降级为内存模式
* ✅ 密码复杂度策略（大写、小写、数字、特殊字符）
* ✅ OAuth state 原子消费（GETDEL），消除 TOCTOU 竞态
* ✅ 服务 Token audience 严格校验
* ✅ 数据库连接池大小可通过 `DB_POOL_SIZE` 环境变量配置
* ✅ 启动默认 fail-fast：数据库初始化失败不会静默降级，除非显式启用 `ALLOW_IN_MEMORY_FALLBACK`
* ✅ 登录/内省限流优先使用真实连接 IP，仅在 `TRUST_PROXY_HEADERS=true` 时信任代理头
* ✅ Refresh Token 轮换为一次性原子消费，旧 refresh token 不可并发复用

---

## 📋 前置要求

* Rust 1.70+ ([安装 Rust](https://rustup.rs/))
* PostgreSQL 12+ (或使用 Docker)
* Docker & Docker Compose (可选，用于本地开发)

---

## 🧪 测试

Keylo 包含完整的测试套件，包括单元测试、集成测试、数据库测试和负载测试。

### 运行所有测试

使用提供的测试脚本（推荐）：

```bash
# Linux/macOS
./scripts/run_tests.sh

# Windows (PowerShell)
./scripts/run_tests.ps1
```

### 手动运行测试

1. **启动测试数据库**：

```bash
mkdir -p .secrets
python -m pip install cryptography
python scripts/secret_tool.py generate-deployment --keep-database-plain
docker run -d --name keylo-test-db \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/.database_password \
  -e POSTGRES_DB=keylo_test \
  -v $(pwd)/.secrets/.database_password:/run/secrets/.database_password:ro \
  -p 5432:5432 postgres:17
```

1. **设置环境变量**：

```bash
export TEST_DATABASE_URL="postgres://postgres@localhost:5432/keylo_test"
export DATABASE_PASSWORD_ENC_FILE="./.secrets/.database_password.enc"
export DATABASE_PASSWORD_KEY_FILE="./.secrets/.database_password.key"
```

1. **运行不同类型的测试**：

```bash
# 单元测试
cargo test --lib

# 集成测试
cargo test --test integration_test

# 数据库集成测试
cargo test --test database_integration_test

# 负载测试
cargo test --test load_test

# 所有测试
cargo test
```

### 测试覆盖率

生成测试覆盖率报告：

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### CI/CD

项目包含 GitHub Actions CI/CD 配置，自动运行：

* 代码格式检查 (`cargo fmt`)
* 代码质量检查 (`cargo clippy`)
* 安全审计 (`cargo audit`)
* 完整测试套件
* 覆盖率报告

### 第三方集成

第三方系统对接 Keylo 的登录流程、Token 内省和服务接入方式见 [docs/THIRD_PARTY_INTEGRATION.md](docs/THIRD_PARTY_INTEGRATION.md)。

Spring、Node、Go、Rust 等资源服务的最小接入模板见 [docs/integrations/README.md](docs/integrations/README.md)。

多客户端统一用户池与 API 级授权接入说明见 [docs/MULTI_CLIENT_RBAC_INTEGRATION.md](docs/MULTI_CLIENT_RBAC_INTEGRATION.md)。

完整接口清单见 [docs/API_REFERENCE.md](docs/API_REFERENCE.md)。

如果你是以 AgileBoot 这类 Spring Boot 管理后台接入 Keylo，可进一步参考 [docs/AGILEBOOT_INTEGRATION.md](docs/AGILEBOOT_INTEGRATION.md)。

### 生产部署与发布说明

Keylo 的生产部署要求、发布能力边界和密钥轮换建议见以下文档：

* [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)
* [docs/SECRET_ENCRYPTION.md](docs/SECRET_ENCRYPTION.md)
* [docs/RELEASE_1_5_1.md](docs/RELEASE_1_5_1.md)
* [docs/RELEASE_1_5.md](docs/RELEASE_1_5.md)
* [docs/RELEASE_1_4.md](docs/RELEASE_1_4.md)
* [docs/RELEASE_1_3_1.md](docs/RELEASE_1_3_1.md)
* [docs/RELEASE_1_3.md](docs/RELEASE_1_3.md)
* [docs/RELEASE_1_1.md](docs/RELEASE_1_1.md)
* [docs/RELEASE_1_0.md](docs/RELEASE_1_0.md)
* [docs/KEY_ROTATION.md](docs/KEY_ROTATION.md)

---

## 🔧 开发

### 1. 克隆项目

```bash
git clone https://github.com/bruceblink/Keylo.git
cd keylo
```

### 2. 配置环境变量

复制 `.env.example` 到 `.env`:

```bash
cp .env.example .env
```

编辑 `.env` 设置你的配置：

```bash
JWT_ISSUER=keylo
JWT_KEY_ID=keylo-rs256-1
# 生产环境建议使用路径方式加载 RSA 密钥
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
DATABASE_URL=postgres://keylo_user@localhost:5432/keylo
DATABASE_PASSWORD_ENC_FILE=./.secrets/.database_password.enc
DATABASE_PASSWORD_KEY_FILE=./.secrets/.database_password.key
SERVER_ADDR=127.0.0.1
SERVER_PORT=2345
ENVIRONMENT=development
```

开发和生产环境都建议显式提供 RSA 私钥和公钥。未配置密钥时服务会初始化失败，不应依赖隐式开发密钥。

### 3. 启动 PostgreSQL (使用 Docker Compose)

```bash
mkdir -p .secrets
python -m pip install cryptography
python scripts/secret_tool.py generate-deployment --keep-database-plain
docker-compose up -d
```

如果需要自定义数据库密码，先写入 `.secrets/.database_password`，再执行 `generate-deployment --keep-database-plain`。如果使用外部数据库，或 PostgreSQL 已经完成初始化且不再需要 `.secrets/.database_password`，可以用以下命令生成 Keylo 运行期密文并删除明文文件：

```bash
python scripts/secret_tool.py generate-deployment
```

这将启动：

* PostgreSQL 数据库 (监听 `5432`)
* Redis 服务（不映射宿主机端口，仅 Keylo 内部网络访问）

等待数据库准备好：

```bash
docker-compose ps
```

### 4. 构建并运行

```bash
cargo run
```

服务将在 `http://127.0.0.1:2345` 启动。

查看日志：

```bash
RUST_LOG=keylo=debug cargo run
```

---

## 🔑 API 快速指引

为避免 README 与实现长期漂移，完整接口说明统一收敛到专门文档：

* 全量接口与鉴权规则： [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
* 多客户端统一用户池与 RBAC： [docs/MULTI_CLIENT_RBAC_INTEGRATION.md](docs/MULTI_CLIENT_RBAC_INTEGRATION.md)
* 第三方系统对接： [docs/THIRD_PARTY_INTEGRATION.md](docs/THIRD_PARTY_INTEGRATION.md)
* 接入模板： [docs/integrations/README.md](docs/integrations/README.md)
* AgileBoot 对接： [docs/AGILEBOOT_INTEGRATION.md](docs/AGILEBOOT_INTEGRATION.md)

### 常用接口（快速确认）

* 公开：`POST /v1/auth/token`、`POST /v1/admin/token`、`POST /v1/auth/refresh`、`POST /v1/service/token`
* 用户：`GET /v1/auth/me`、`POST /v1/auth/logout`、`POST /v1/user/change-password`
* 管理：`/v1/admin/*`、`/v1/admin/users/*`、`/v1/admin/services/*`、`/v1/admin/identity-sources/*`
* RBAC：`/api/rbac/*`
* OAuth：公开流程 `/v1/auth/oauth/*`，管理接口 `/api/oauth/*`

### Refresh Token 说明（重要）

当前实现中：

* `POST /v1/admin/token` 返回 `access_token + refresh_token`
* `POST /v1/auth/token` 当前仅返回 `access_token`

即：`POST /v1/auth/refresh` 所使用的 `refresh_token` 主要来源于管理客户端登录链路。

---

## 🏗️ 项目结构

```text
src/
├── main.rs          # 启动入口，服务器初始化
├── lib.rs           # 库根模块
├── config.rs        # 环境配置管理
├── state.rs         # AppState 定义，应用全局状态
├── startup.rs       # 路由初始化，应用启动逻辑
├── db/              # 数据访问层
├── handlers/        # HTTP handlers
├── middleware/      # 鉴权与授权中间件
├── models/          # 领域模型
├── routes/          # 路由定义（auth/user/rbac/oauth/service/identity）
├── errors.rs        # 错误定义
└── utils.rs         # 工具函数

docs/                # 对接、发布与运维文档
migrations/          # SQLx 迁移脚本
tests/               # 集成与负载测试
Dockerfile           # 容器镜像配置
docker-compose.yml   # 开发环境容器编排
Cargo.toml           # 项目依赖配置
```

---

## 🛠️ 技术栈

| 组件 | 技术 | 版本 |
| ------ | ------ | ------ |
| Web 框架 | Axum | 0.8 |
| 异步运行时 | Tokio | 1.0 |
| JWT | jsonwebtoken | 10 |
| 数据库 | SQLx | 0.8 |
| 数据库系统 | PostgreSQL | 12+ |
| 日志 | tracing | 0.1 |
| 序列化 | serde | 1.0 |

---

## 📝 环境变量配置

| 变量 | 默认值 | 说明 |
| ------ | -------- | ------ |
| `JWT_ISSUER` | `keylo` | JWT 签发方 |
| `JWT_KEY_ID` | `keylo-rs256-1` | JWKS 中公开的当前密钥 ID |
| `JWT_AUDIENCES` | `admin-backend,crawler` | 用户/管理 access token 可接受的 audience 白名单 |
| `JWT_PRIVATE_KEY_PATH` | `./keys/private.pem` | RSA 私钥文件路径 |
| `JWT_PUBLIC_KEY_PATH` | `./keys/public.pem` | RSA 公钥文件路径 |
| `JWT_PRIVATE_KEY_PEM` | `` | RSA 私钥 PEM 内容，可替代路径 |
| `JWT_PUBLIC_KEY_PEM` | `` | RSA 公钥 PEM 内容，可替代路径 |
| `DATABASE_URL` | `` | 数据库连接字符串（数据库模式必填） |
| `SERVER_ADDR` | `127.0.0.1`（容器镜像为 `0.0.0.0`） | 服务器监听地址 |
| `SERVER_PORT` | `2345` | 服务器监听端口 |
| `ENVIRONMENT` | `development` | 运行环境 |
| `TOKEN_EXPIRY_SECONDS` | `900` | Token 过期时间（秒） |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | `2592000` | 刷新 Token 过期时间（秒） |
| `MAX_FAILED_LOGIN_ATTEMPTS` | `5` | 连续登录失败锁定阈值 |
| `LOGIN_LOCKOUT_SECONDS` | `300` | 登录锁定时长（秒） |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60` | 登录限流窗口（秒） |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | `30` | 限流窗口内单主体最大请求数 |
| `AUTH_GLOBAL_RATE_LIMIT_MAX_REQUESTS` | `300` | 限流窗口内全局最大请求数 |
| `TRUST_PROXY_HEADERS` | `false` | 是否信任 `X-Forwarded-For` / `X-Real-IP`；关闭时使用连接 peer IP |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173` | 允许浏览器跨域携带凭证访问的 Origin 白名单，逗号分隔 |
| `ADMIN_CLIENT_ID` | `cli-admin-root` | 管理员客户端 ID |
| `ADMIN_CLIENT_SECRET` | `` | 管理员客户端密钥（启动必填） |
| `REDIS_URL_ENC` | `` | AES-256-GCM 加密后的 Redis URL；生产环境必须使用 |
| `REDIS_URL_ENC_FILE` | `./.secrets/.redis_url.enc` / `/run/secrets/.redis_url.enc` | Redis URL 密文文件路径 |
| `REDIS_URL_KEY` | `` | Redis URL 解密 key；建议改用文件路径 |
| `REDIS_URL_KEY_FILE` | `./.secrets/.redis_url.key` / `/run/secrets/.redis_url.key` | Redis URL 解密 key 文件路径 |
| `REDIS_URL` | `` | 明文 Redis 地址；仅用于非生产调试 |
| `REDIS_URL_FILE` | `` | 明文 Redis 地址文件；仅用于非生产调试 |
| `REDIS_KEY_PREFIX` | `keylo` | Redis key 前缀（多环境隔离） |
| `DB_POOL_SIZE` | `10` | 数据库连接池最大连接数 |
| `ALLOW_IN_MEMORY_FALLBACK` | `false` | 非生产环境是否允许数据库初始化失败后启动无数据库路由；默认关闭 |
| `AUDIT_LOG_RETENTION_DAYS` | `30` | 审计日志保留天数 |
| `SERVICE_TOKEN_EXPIRY_SECONDS` | `3600` | 服务 Token 过期时间（秒） |
| `ENABLE_SUPER_ADMIN_BOOTSTRAP` | `false` | 是否启用超级管理员首启引导 |
| `SUPER_ADMIN_USERNAME` | `` | 超级管理员用户名（引导启用时） |
| `SUPER_ADMIN_EMAIL` | `` | 超级管理员邮箱（引导启用时） |
| `SUPER_ADMIN_PASSWORD` | `` | 超级管理员初始密码（引导启用时） |
| `RUST_LOG` | `keylo=debug,axum=info,tower_http=info` | 日志级别；`tower_http=info` 用于 HTTP 访问日志 |
| `LOG_TO_FILE` | `true` | 是否同时写入文件日志 |
| `LOG_DIR` | `./logs` | 文件日志目录；Docker Compose 中为 `/app/logs` |
| `LOG_FILE_PREFIX` | `keylo` | 文件日志名前缀，按天滚动归档 |

HTTP 访问日志默认记录请求方法、URI、HTTP 版本、响应状态码和耗时，不记录 `Authorization` 等请求头，便于排查请求是否到达服务以及响应是否异常。

## 🔐 JWKS

Keylo 默认使用 RS256 签发 JWT，并通过 `/.well-known/jwks.json` 暴露公开验签密钥集合。

* 生产环境建议提前生成、挂载并备份固定 RSA 密钥
* 下游系统推荐优先使用 JWKS 做本地验签
* 需要统一吊销控制时，继续结合 `/v1/auth/introspect` 和 `/v1/service/introspect`

### RSA 密钥生成

本地开发和生产环境都建议显式提供 RSA 密钥。未配置私钥/公钥时，Keylo 会自动生成随机 RSA 密钥对并写入默认或指定路径。

推荐使用 `secret_tool.py` 生成 2048 位或以上的 RSA 密钥对：

```bash
python -m pip install cryptography
python scripts/secret_tool.py generate-rsa
```

默认写入 `keys/private.pem` 和 `keys/public.pem`。如需自定义位数或路径：

```bash
python scripts/secret_tool.py generate-rsa \
  --bits 3072 \
  --out-private /opt/keylo/keys/private.pem \
  --out-public /opt/keylo/keys/public.pem
```

如果在 Linux 服务器部署，建议进一步限制私钥权限：

```bash
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

随后配置环境变量：

```env
JWT_KEY_ID=keylo-rs256-1
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
```

如果使用 Docker Compose，默认会把 `${JWT_KEYS_DIR:-./keys}` 挂载到容器 `/app/keys`，因此容器内推荐配置为：

```env
JWT_PRIVATE_KEY_PATH=/app/keys/private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem
```

## 🩺 健康检查

Keylo 提供标准探针端点，便于容器编排和网关探活：

* `GET /healthz`：进程存活检查（liveness）
* `GET /readyz`：依赖就绪检查（readiness），会返回数据库/Redis 的检查状态；默认缺少数据库时返回 `503`

示例：

```bash
curl http://127.0.0.1:2345/healthz
curl http://127.0.0.1:2345/readyz
```

---

## 🗄️ 数据库迁移

服务启动时会自动执行 `migrations/` 下的 SQLx 迁移，并初始化默认客户端。当前版本迁移覆盖用户、客户端、刷新 Token、OAuth、RBAC、审计日志和服务客户端等核心表结构。

---

> 测试命令与测试脚本请以本文前面的“🧪 测试”章节为准。

---

## 🐳 使用 Docker 部署

### 使用 GitHub Container Registry 镜像

```bash
docker pull ghcr.io/bruceblink/keylo:v1.5.1
```

### 运行容器

```bash
docker run --rm -p 2345:2345 \
  -v $(pwd)/keys:/app/keys:ro \
  -v $(pwd)/.secrets:/run/secrets:ro \
  -e DATABASE_URL="postgres://keylo_user@db:5432/keylo" \
  -e ADMIN_CLIENT_SECRET="replace-with-strong-admin-secret" \
  -e REDIS_URL_ENC_FILE="/run/secrets/.redis_url.enc" \
  -e REDIS_URL_KEY_FILE="/run/secrets/.redis_url.key" \
  ghcr.io/bruceblink/keylo:v1.5.1
```

### 本地构建镜像

```bash
docker build -t keylo:latest .
```

镜像构建会执行 `web` 前端构建，并把 `web/dist` 复制到运行镜像内用于 `/setup` 安装向导。

### Docker Compose 开发依赖

```bash
docker-compose up -d
docker-compose ps
docker-compose logs -f postgres
```

如果你希望在容器中直接运行 Keylo，请确保同时提供 PostgreSQL、Redis 和 RSA 密钥文件；生产环境不再支持 `JWT_SECRET` 这种共享密钥模式。

当前仓库的 [docker-compose.yml](docker-compose.yml) 默认按生产模板组织：

* `keylo` 服务默认监听 `0.0.0.0:2345`
* compose 与本地统一使用同名变量（如 `DATABASE_URL`），Redis 生产环境通过 `REDIS_URL_ENC_FILE` 和 `REDIS_URL_KEY_FILE` 读取密文配置
* `ADMIN_CLIENT_ID` 默认是 `cli-admin-root`，部署时只需提供强 `ADMIN_CLIENT_SECRET`
* 默认挂载 `${JWT_KEYS_DIR:-./keys}` 到 `/app/keys`
* Redis 默认启用，满足生产环境的限流、登录锁定和 OAuth state 依赖
* Redis 不映射宿主机端口，只加入 `keylo_redis_network` 专用内部网络；不要让其他服务加入该网络
* Redis 通过 `./.secrets/.redis.acl` 启用 ACL，Keylo 通过 `./.secrets/.redis_url.enc` 和 `./.secrets/.redis_url.key` 在内存中解密 Redis URL

首次在服务器部署时，建议先准备 `.env` 或 shell 环境变量，再执行：

```bash
docker compose down -v --remove-orphans
docker compose up -d --build
docker compose logs -f keylo-service
```

---

## ✨ 当前核心能力

### 1. 统一认证

* 支持用户登录、客户端登录和用户注册
* 支持 Access Token / Refresh Token（当前 refresh 主要用于管理客户端链路）
* 支持 `me`、登出和黑名单

### 2. 服务间鉴权

* 支持服务客户端注册与密钥轮换
* 支持 `service_access` Token 签发
* 支持服务 Token 内省与用户 Token 内省

### 3. 第三方集成

* 默认使用 RS256 与 JWKS
* 下游系统可本地验签
* 高敏接口可叠加内省做实时吊销校验
* 提供身份源注册中心，统一登记 local password、OAuth2、OIDC upstream 和 LDAP 身份源元数据

### 4. 安装向导

* 安装向导默认启用；首次未完成 setup 时访问 `/` 会进入 `/setup`
* 如需关闭安装向导，可设置 `ENABLE_SETUP_WIZARD=false`
* 生产环境启用安装向导时必须配置 `SETUP_TOKEN`
* 未配置 RSA 密钥文件时，Keylo 会自动生成随机 RSA 密钥对并通过 JWKS 发布公钥
* React 前端位于 `web/`，构建后由 Keylo 托管 `/setup`
* 设计说明见 [docs/SETUP_WIZARD_DESIGN.md](docs/SETUP_WIZARD_DESIGN.md)

### 5. 运维与安全基线

* 启动时自动执行 SQLx 迁移
* 启动会提前校验 RSA 密钥、管理员客户端、数据库 URL、Token 时长等关键配置；缺失时直接退出
* 生产环境额外强制要求 Redis
* 非生产环境默认同样对数据库初始化 fail-fast；仅在显式设置 `ALLOW_IN_MEMORY_FALLBACK=true` 时允许无数据库模式，且仍要求 RSA 密钥和管理员客户端配置
* Refresh Token 轮换会原子消费旧 token，旧 refresh token 不能再次使用
* 支持审计日志、限流、登录锁定和 OAuth state 管理

---

## 🚦 演进方向

后续增强方向：

* 多把 RSA 密钥并行发布
* 自动密钥轮换流程
* 更细粒度的健康检查与 readiness 探针
* 更完善的网关接入样例

---

## 📖 开发指南

### 添加新的认证 Provider

在 `src/routes/oauth.rs` 和对应 handler 中注册新的 OAuth 提供商逻辑。

### 添加新的身份源类型

先扩展 `identity_sources.source_type` 的迁移约束、`src/handlers/identity.rs` 的支持类型校验和 API 文档，再接入具体登录流程。当前身份源接口是注册中心能力，不会自动替代现有 OAuth 登录路径。

### 自定义 Claims

编辑 `src/models/jwt.rs` 中的 Claims 结构与签发逻辑，并同步评估内省与下游验签兼容性。

### 数据库操作

新增表结构时，优先在 `migrations/` 中追加 SQLx 迁移，再更新 `src/db/` 下的数据访问层。

---

## ⚠️ 安全建议

1. **生产环境**:

* 使用 RSA 2048 位或更高密钥
* 私钥只保留在 Keylo 服务端
* 设置 `ENVIRONMENT=production`
* 显式配置 `ADMIN_CLIENT_SECRET` 和 Redis 密文配置（`REDIS_URL_ENC_FILE` 与 `REDIS_URL_KEY_FILE`），需要自定义管理客户端 ID 时再覆盖 `ADMIN_CLIENT_ID`
* 仅在反向代理可信且已覆盖客户端真实地址时设置 `TRUST_PROXY_HEADERS=true`
* 为外部访问启用 HTTPS 和反向代理

1. **下游系统**:

* 优先通过 JWKS 获取公钥并做本地验签
* 在 `kid` 不匹配或验签失败时刷新 JWKS 缓存
* 对强实时吊销场景补充调用内省接口

1. **数据库与运行环境**:

* 使用强数据库密码并限制网络暴露
* 定期备份 PostgreSQL 数据
* 不要在生产环境启用开发密钥或数据库失败回退模式

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request，详细开发约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 📄 许可证

MIT License - 查看 [LICENSE](LICENSE) 文件

---

## 💬 支持

* 📧 提交 Issue: [GitHub Issues](https://github.com/bruceblink/Keylo/issues)
* 💡 讨论: [GitHub Discussions](https://github.com/bruceblink/Keylo/discussions)

---

**Last Updated**: 2026年05月14日
