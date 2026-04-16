# Keylo v1.0.1

**Keylo** 是一个轻量、可扩展的 **统一认证与授权服务**（Auth Service），为你的多服务系统提供统一的 JWT 签发、Session 管理和 OAuth 支持。

---

## 🚀 特性

* ✅ 基于 RS256 的 JWT 签发与验证，内置 JWKS 公钥发布
* ✅ `/v1/auth/token`（用户认证）、`/v1/admin/token`（管理令牌）、`/v1/auth/refresh`、`/v1/auth/logout`、`/v1/auth/me` 核心 API
* ✅ 用户 Token 内省与服务 Token 内省
* ✅ 服务凭证模式与 `service_access` Token
* ✅ GitHub OAuth 登录，可扩展其他 OAuth 提供商
* ✅ RBAC、管理员客户端、审计日志与黑名单机制
* ✅ PostgreSQL 自动迁移，Redis 可选增强限流、锁定和 OAuth state
* ✅ 使用 Axum 0.8 + Tokio 的模块化 Rust 服务架构
* ✅ Docker / GHCR 镜像发布支持

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
docker run -d --name keylo-test-db \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=keylo_test \
  -p 5432:5432 postgres:15
```

1. **设置环境变量**：

```bash
export TEST_DATABASE_URL="postgres://postgres:password@localhost:5432/keylo_test"
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

如果你是以 AgileBoot 这类 Spring Boot 管理后台接入 Keylo，可进一步参考 [docs/AGILEBOOT_INTEGRATION.md](docs/AGILEBOOT_INTEGRATION.md)。

### 生产部署与发布说明

Keylo 1.0 的生产部署要求、发布能力边界和密钥轮换建议见以下文档：

* [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)
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
DATABASE_URL=postgres://keylo_user:keylo_password@localhost:5432/keylo
SERVER_ADDR=127.0.0.1
SERVER_PORT=2345
ENVIRONMENT=development
```

开发环境下如果未提供 RSA 密钥，Keylo 会使用内置开发密钥对；生产环境必须显式配置私钥和公钥。

### 3. 启动 PostgreSQL (使用 Docker Compose)

```bash
docker-compose up -d
```

这将启动：

* PostgreSQL 数据库 (监听 `5432`)
* Redis 服务 (监听 `6379`, 可选)

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

## 🔑 API 示例

### 获取用户 Token

`/v1/auth/token` 仅用于用户认证语义，不再接受未注册或未授权的客户端凭证。

```bash
curl -X POST http://127.0.0.1:2345/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"alice","client_secret":"<user-password>"}'
```

返回：

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleWxvLXJzMjU2LTEiLCJ0eXAiOiJKV1QifQ...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### 获取管理 Token

`/v1/admin/token` 仅用于受信任的管理客户端，签发的令牌带有 `role=admin`、`scope=admin`、`aud=admin-backend`。

```bash
curl -X POST http://127.0.0.1:2345/v1/admin/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"<admin-client-id>","client_secret":"<admin-client-secret>"}'
```

### 用户注册

```bash
curl -X POST http://127.0.0.1:2345/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"change-me-123"}'
```

### 获取 JWKS 公钥集合

第三方系统可通过公开端点获取 Keylo 的当前验签公钥：

```bash
curl http://127.0.0.1:2345/.well-known/jwks.json
```

### 获取当前用户信息

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:2345/v1/auth/me
```

返回：

```json
{
  "sub": "user:alice",
  "scope": ["read", "write"],
  "role": "user",
  "aud": "admin-backend",
  "exp": 1704067200,
  "iss": "keylo",
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 端点授权矩阵

| 端点 | 令牌类型 | 必需 claims |
| --- | --- | --- |
| `POST /v1/auth/token` | 无 | 仅用户名/密码用户认证 |
| `POST /v1/admin/token` | 无 | 仅受信任管理客户端 |
| `POST /v1/service/token` | 无 | 仅已注册且激活的服务客户端 |
| `POST /v1/auth/introspect` | `service_access` | `role=service`、`scope` 包含 `read`、`aud=admin-backend` |
| `POST /v1/service/introspect` | `service_access` | `role=service`、`scope` 包含 `read` |
| `GET/POST/PUT /v1/admin/*` | `access` | `role=admin`、`scope` 包含 `admin`、`aud=admin-backend` |
| `POST /v1/user/change-password` | `access` | `role=user`、`scope` 包含 `write`、`aud=admin-backend` |

未授权调用会返回稳定的 machine-readable 错误，如 `insufficient_role`、`insufficient_scope`、`service_client_not_authorized`。

### 超级管理员初始化（可选）

当你需要首启自动创建超级管理员用户时，可开启以下环境变量：

```env
ENABLE_SUPER_ADMIN_BOOTSTRAP=true
SUPER_ADMIN_USERNAME=root_bootstrap
SUPER_ADMIN_EMAIL=root_bootstrap@example.com
SUPER_ADMIN_PASSWORD=RootBootstrap#123
```

说明：

* 初始化过程幂等：重复启动会更新同一账号资料并确保绑定 `super_admin` 角色。
* 仅在数据库可用时生效。
* 建议上线后立即轮换为运维托管凭据。

### 第三方用户迁移导入

管理端提供批量迁移接口（支持幂等 external id 映射）：

```bash
curl -X POST http://127.0.0.1:2345/v1/admin/users/migrations/import \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
        "provider": "agileboot",
        "users": [
          {
            "external_user_id": "agileboot-1001",
            "username": "tom",
            "email": "tom@example.com",
            "password": "StrongPass#123",
            "active": true,
            "roles": ["super_admin"],
            "metadata": {"source": "agileboot"}
          }
        ],
        "dry_run": false
      }'
```

### 单用户 JIT 迁移注册（登录时迁移）

当第三方系统首次登录用户尚未在 Keylo 建档时，可调用 JIT 接口完成“迁移 + 发 token”：

```bash
curl -X POST http://127.0.0.1:2345/v1/auth/migrations/jit-register \
  -H "Content-Type: application/json" \
  -d '{
        "provider": "agileboot",
        "external_user_id": "ab-1001",
        "username": "tom",
        "email": "tom@example.com",
        "password": "StrongPass#123",
        "active": true,
        "roles": ["super_admin"]
      }'
```

### 异步批次导入任务

提交批次任务（管理员）：

```bash
curl -X POST http://127.0.0.1:2345/v1/admin/users/migrations/jobs \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
        "provider": "agileboot",
        "dry_run": false,
        "users": [
          {
            "external_user_id": "ab-1002",
            "username": "jerry",
            "email": "jerry@example.com",
            "password": "StrongPass#123"
          }
        ]
      }'
```

查询任务状态：

```bash
curl -X GET http://127.0.0.1:2345/v1/admin/users/migrations/jobs/<job_id> \
  -H "Authorization: Bearer <admin_access_token>"
```

### 迁移统一错误码

迁移相关接口返回稳定的 `error_code`，例如：

* `migration_invalid_input`
* `migration_conflict`
* `migration_mapping_error`
* `migration_role_assignment_failed`
* `migration_provider_invalid`
* `migration_internal_error`
* `migration_not_found`

### 第三方系统内省用户 Token

第三方后端服务应先申请自己的 `service_access` Token，再调用用户 Token 内省接口：

```bash
curl -X POST http://127.0.0.1:2345/v1/auth/introspect \
  -H "Authorization: Bearer <service_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"token":"<user_access_token>"}'
```

### 服务间调用白名单配置

Keylo 当前采用“服务账号 + scope 白名单 + audience 白名单”的模式控制服务间调用，而不是单独维护一张调用拓扑表。

你需要配置两类约束：

* `allowed_scopes`：该服务最多能申请哪些调用权限
* `allowed_audiences`：该服务最多能面向哪些目标服务申请 Token

示例：为 `agileboot-admin` 注册一个只能访问 `admin-backend` 的服务账号：

```bash
curl -X POST http://127.0.0.1:2345/v1/admin/services \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "service_id": "agileboot-admin",
    "service_secret": "replace-with-strong-secret",
    "name": "AgileBoot Admin",
    "description": "AgileBoot 管理平台服务账号",
    "allowed_scopes": ["user.read", "user.write"],
    "allowed_audiences": ["admin-backend"]
  }'
```

随后该服务只能申请被允许的 scope/audience 子集：

```bash
curl -X POST http://127.0.0.1:2345/v1/service/token \
  -H "Content-Type: application/json" \
  -d '{
    "service_id": "agileboot-admin",
    "service_secret": "replace-with-strong-secret",
    "audience": "admin-backend",
    "scope": "user.read"
  }'
```

如果请求超出白名单范围，Keylo 会拒绝签发服务 Token。

### 登出

```bash
curl -X POST -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:2345/v1/auth/logout
```

返回：

```json
{
  "message": "Successfully logged out",
  "sub": "client:web"
}
```

### 测试受保护的路由

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:2345/protected
```

### RBAC 角色和权限管理

以下接口属于管理员接口，调用时应使用带 `admin` scope 的 `admin_token`。

#### 创建角色

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/rbac/roles \
  -d '{"name": "admin", "description": "Administrator role"}'
```

#### 创建权限

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/rbac/permissions \
  -d '{"name": "user.manage", "description": "Manage users permission"}'
```

#### 为用户分配角色

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/rbac/users/{user_id}/roles \
  -d '{"role_id": "role-uuid"}'
```

#### 检查用户权限

```bash
curl -H "Authorization: Bearer <admin_token>" \
  http://127.0.0.1:2345/api/rbac/users/{user_id}/check-permission/user.manage
```

返回：

```json
{
  "success": true,
  "data": {
    "user_id": "user-uuid",
    "permission": "user.manage",
    "has_permission": true
  }
}
```

### OAuth 第三方登录

#### 配置OAuth提供商

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/oauth/providers \
  -d '{
    "name": "github",
    "client_id": "your_github_client_id",
    "client_secret": "your_github_client_secret",
    "authorization_url": "https://github.com/login/oauth/authorize",
    "token_url": "https://github.com/login/oauth/access_token",
    "user_info_url": "https://api.github.com/user",
    "scope": "read:user user:email",
    "redirect_url": "http://yourapp.com/callback/github"
  }'
```

#### 发起GitHub登录

```bash
curl -L http://127.0.0.1:2345/v1/auth/oauth/login/github
```

这将重定向到GitHub授权页面。

#### 关联OAuth账户

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/oauth/link \
  -d '{
    "provider": "github",
    "code": "authorization_code_from_callback",
    "state": "state_parameter"
  }'
```

#### 获取用户的OAuth账户

```bash
curl -H "Authorization: Bearer <admin_token>" \
  http://127.0.0.1:2345/api/oauth/accounts
```

### 审计日志（管理员）

#### 查询审计日志

```bash
curl -H "Authorization: Bearer <admin_token>" \
  "http://127.0.0.1:2345/v1/admin/audit-logs?limit=50&offset=0"
```

#### 清理历史审计日志

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/v1/admin/audit-logs/cleanup \
  -d '{"retention_days": 30}'
```

---

## 🏗️ 项目结构

```text
src/
├── main.rs          # 启动入口，服务器初始化
├── lib.rs           # 库根模块
├── config.rs        # 环境配置管理
├── state.rs         # AppState 定义，应用全局状态
├── startup.rs       # 路由初始化，应用启动逻辑
├── routes/          # 路由定义
│   ├── auth.rs      # 认证路由
│   └── mod.rs
├── handlers/        # Handler 实现
│   ├── auth.rs      # 认证 handlers
│   ├── common.rs    # 通用 handlers
│   └── mod.rs
├── models/          # 数据模型
│   ├── jwt.rs       # JWT Claims 定义
│   ├── auth.rs      # 认证模型
│   └── mod.rs
├── db/              # 数据库操作
│   └── mod.rs       # 数据库初始化、迁移、查询
├── errors.rs        # 错误类型定义
└── utils.rs         # 工具函数 (UUID、时间、验证等)

Dockerfile          # 容器镜像配置
docker-compose.yml  # 开发环境容器编排
.env.example        # 环境变量示例
Cargo.toml          # 项目依赖配置
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
| `JWT_KEY_ID` | `keylo-dev-rs256-1` | JWKS 中公开的当前密钥 ID |
| `JWT_PRIVATE_KEY_PATH` | `` | RSA 私钥文件路径，生产推荐 |
| `JWT_PUBLIC_KEY_PATH` | `` | RSA 公钥文件路径，生产推荐 |
| `JWT_PRIVATE_KEY_PEM` | `` | RSA 私钥 PEM 内容，可替代路径 |
| `JWT_PUBLIC_KEY_PEM` | `` | RSA 公钥 PEM 内容，可替代路径 |
| `DATABASE_URL` | `postgres://user:password@localhost/keylo` | 数据库连接字符串 |
| `SERVER_ADDR` | `127.0.0.1` | 服务器监听地址 |
| `SERVER_PORT` | `2345` | 服务器监听端口 |
| `ENVIRONMENT` | `development` | 运行环境 |
| `TOKEN_EXPIRY_SECONDS` | `900` | Token 过期时间（秒） |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | `2592000` | 刷新 Token 过期时间（秒） |
| `MAX_FAILED_LOGIN_ATTEMPTS` | `5` | 连续登录失败锁定阈值 |
| `LOGIN_LOCKOUT_SECONDS` | `300` | 登录锁定时长（秒） |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60` | 登录限流窗口（秒） |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | `30` | 限流窗口内单主体最大请求数 |
| `AUTH_GLOBAL_RATE_LIMIT_MAX_REQUESTS` | `300` | 限流窗口内全局最大请求数 |
| `ADMIN_CLIENT_ID` | `` | 管理员客户端 ID（建议生产配置） |
| `ADMIN_CLIENT_SECRET` | `` | 管理员客户端密钥（建议生产配置） |
| `REDIS_URL` | `` | Redis 地址（配置后启用分布式状态存储） |
| `REDIS_KEY_PREFIX` | `keylo` | Redis key 前缀（多环境隔离） |
| `AUDIT_LOG_RETENTION_DAYS` | `30` | 审计日志保留天数 |
| `RUST_LOG` | `keylo=debug` | 日志级别 |

## 🔐 JWKS

Keylo 1.0 默认使用 RS256 签发 JWT，并通过 `/.well-known/jwks.json` 暴露公开验签密钥集合。

* 生产环境不要使用内置开发密钥
* 下游系统推荐优先使用 JWKS 做本地验签
* 需要统一吊销控制时，继续结合 `/v1/auth/introspect` 和 `/v1/service/introspect`

## 🩺 健康检查

Keylo 提供标准探针端点，便于容器编排和网关探活：

* `GET /healthz`：进程存活检查（liveness）
* `GET /readyz`：依赖就绪检查（readiness），会返回数据库/Redis 的检查状态

示例：

```bash
curl http://127.0.0.1:2345/healthz
curl http://127.0.0.1:2345/readyz
```

---

## 🗄️ 数据库迁移

服务启动时会自动执行 `migrations/` 下的 SQLx 迁移，并初始化默认客户端。1.0 版本的迁移覆盖用户、客户端、刷新 Token、OAuth、RBAC、审计日志和服务客户端等核心表结构。

---

## 🧪 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定测试
cargo test test_index

# 输出详细信息
cargo test -- --nocapture --test-threads=1
```

---

## 🐳 使用 Docker 部署

### 使用 GitHub Container Registry 镜像

```bash
docker pull ghcr.io/bruceblink/keylo:v1.0.1
```

### 运行容器

```bash
docker run --rm -p 2345:2345 \
  -v $(pwd)/keys:/app/keys:ro \
  -e ENVIRONMENT=production \
  -e JWT_ISSUER=keylo \
  -e JWT_KEY_ID=keylo-rs256-1 \
  -e JWT_PRIVATE_KEY_PATH=/app/keys/private.pem \
  -e JWT_PUBLIC_KEY_PATH=/app/keys/public.pem \
  -e DATABASE_URL="postgres://keylo_user:keylo_password@db:5432/keylo" \
  -e ADMIN_CLIENT_ID="cli-admin-root" \
  -e ADMIN_CLIENT_SECRET="replace-with-strong-admin-secret" \
  -e REDIS_URL="redis://redis:6379" \
  ghcr.io/bruceblink/keylo:v1.0.1
```

### 本地构建镜像

```bash
docker build -t keylo:latest .
```

### Docker Compose 开发依赖

```bash
docker-compose up -d
docker-compose ps
docker-compose logs -f postgres
```

如果你希望在容器中直接运行 Keylo，请确保同时提供 PostgreSQL、Redis 和 RSA 密钥文件；生产环境不再支持 `JWT_SECRET` 这种共享密钥模式。

---

## ✨ 1.0 核心能力

### 1. 统一认证

* 支持用户登录、客户端登录和用户注册
* 支持 Access Token / Refresh Token
* 支持 `me`、登出和黑名单

### 2. 服务间鉴权

* 支持服务客户端注册与密钥轮换
* 支持 `service_access` Token 签发
* 支持服务 Token 内省与用户 Token 内省

### 3. 第三方集成

* 默认使用 RS256 与 JWKS
* 下游系统可本地验签
* 高敏接口可叠加内省做实时吊销校验

### 4. 运维与安全基线

* 启动时自动执行 SQLx 迁移
* 生产环境强制要求显式 RSA 密钥、管理员客户端和 Redis
* 支持审计日志、限流、登录锁定和 OAuth state 管理

---

## 🚦 1.x 后续方向

以下内容属于 1.x 后续增强，不影响 1.0 正式使用：

* 多把 RSA 密钥并行发布
* 自动密钥轮换流程
* 更细粒度的健康检查与 readiness 探针
* 更完善的网关接入样例

---

## 📖 开发指南

### 添加新的认证 Provider

在 `src/routes/oauth.rs` 和对应 handler 中注册新的 OAuth 提供商逻辑。

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
* 显式配置 `ADMIN_CLIENT_ID`、`ADMIN_CLIENT_SECRET` 和 `REDIS_URL`
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

**Last Updated**: 2026年04月16日
