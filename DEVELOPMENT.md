# 本地开发指南

本文档只保留本地开发所需的信息；完整使用流程、接口定义和集成方案分别以以下文档为准：

- [README.md](README.md)：项目概览、部署入口、环境变量说明
- [docs/END_TO_END_QUICKSTART.md](docs/END_TO_END_QUICKSTART.md)：从初始化到管理客户端、用户、RBAC、服务客户端的完整操作步骤
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md)：完整接口清单与鉴权规则

---

## 1. 快速开始

### 1.1 准备环境

```bash
git clone https://github.com/bruceblink/Keylo.git
cd keylo
cp .env.example .env
```

如果需要模拟生产签名方式，请先生成 RSA 密钥：

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem
openssl rsa -pubout -in keys/private.pem -out keys/public.pem
```

### 1.2 启动依赖

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/postgres_password
openssl rand -base64 32 > secrets/database_password.key
DATABASE_PASSWORD_FILE=./secrets/postgres_password \
DATABASE_PASSWORD_KEY_FILE=./secrets/database_password.key \
  cargo run --quiet --bin keylo-encrypt-db-password > secrets/postgres_password.enc
docker compose up -d postgres redis
docker compose ps
```

### 1.3 启动服务

```bash
RUST_LOG=keylo=debug,axum=info cargo run
```

服务默认监听 [http://127.0.0.1:2345](http://127.0.0.1:2345)。

建议启动后先确认以下日志：

- `Database migrations completed`
- `Default clients seeded`
- `Database initialized successfully`

---

## 2. 开发调试

### 2.1 查看健康状态

```bash
curl http://127.0.0.1:2345/healthz
curl http://127.0.0.1:2345/readyz
curl http://127.0.0.1:2345/.well-known/jwks.json
```

`/readyz` 默认要求数据库可用。非生产环境只有显式设置 `ALLOW_IN_MEMORY_FALLBACK=true` 时，数据库缺失才会以 `disabled` 状态通过 readiness；该模式仅用于本地临时调试。

### 2.2 查看数据库

```bash
docker exec -it keylo-postgres psql -U keylo_user -d keylo
```

常用查询：

```sql
SELECT id, active, is_admin_client FROM clients ORDER BY updated_at DESC;
SELECT id, username, email, active FROM users ORDER BY updated_at DESC;
SELECT id, service_id, active FROM service_clients ORDER BY updated_at DESC;
```

### 2.3 常用日志级别

```bash
RUST_LOG=keylo=trace,axum=trace cargo run
RUST_LOG=keylo=debug,sqlx=warn cargo run
```

---

## 3. 常见开发任务

### 3.1 修改环境配置

优先修改 `.env` 中的环境变量，而不是硬编码到代码中。

常用配置：

```env
DATABASE_URL=postgres://keylo_user@localhost:5432/keylo
DATABASE_PASSWORD_ENC_FILE=./secrets/postgres_password.enc
DATABASE_PASSWORD_KEY_FILE=./secrets/database_password.key
REDIS_URL=redis://localhost:6379
ADMIN_CLIENT_ID=cli-admin-root
ADMIN_CLIENT_SECRET=replace-with-strong-admin-secret
TOKEN_EXPIRY_SECONDS=900
DB_POOL_SIZE=20
```

`.env` 行内注释必须和配置值之间保留空格，例如 `TOKEN_EXPIRY_SECONDS=900 # 15 minutes`。不要写成 `TOKEN_EXPIRY_SECONDS=900# 15 minutes`，否则 dotenv 解析会失败，后续变量可能不会加载。

登录、管理 token 和内省接口的限流默认使用连接 peer IP。只有在反向代理可信且正确传递真实客户端地址时，才设置 `TRUST_PROXY_HEADERS=true`。

Refresh Token 刷新会原子消费旧 token；轮换客户端或服务 secret 时，只有省略 `new_secret` 并由服务端生成时，响应才一次性返回明文 `new_secret`。

### 3.2 新增路由

推荐顺序：

1. 在 `src/handlers/` 中新增 handler
2. 在 `src/routes/` 中注册路由
3. 在 `src/startup.rs` 中合并到对应公开/受保护路由树
4. 如果需要鉴权，复用 `src/middleware/auth.rs` 中现有中间件

### 3.3 新增数据库结构

推荐顺序：

1. 在 `migrations/` 中追加新迁移，不修改已执行迁移
2. 在 `src/db/` 下补充数据访问函数
3. 在集成测试中补充验证

---

## 4. 测试与质量检查

### 4.1 一键运行

```bash
./scripts/run_tests.sh
```

Windows PowerShell：

```powershell
./scripts/run_tests.ps1
```

### 4.2 常用命令

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo test --test integration_test -- --nocapture
```

如需指定测试数据库：

```bash
export TEST_DATABASE_URL="postgres://postgres@localhost:5432/keylo_test"
export DATABASE_PASSWORD_ENC_FILE="./secrets/postgres_password.enc"
export DATABASE_PASSWORD_KEY_FILE="./secrets/database_password.key"
```

---

## 5. 常见问题

### 5.1 `wrong_credentials` + `User not found: cli`

- 原因：把管理客户端拿去调用了 `/v1/auth/token`
- 处理：管理客户端应调用 `/v1/admin/token`

### 5.2 `No active admin client found ...`

- 检查 `.env` 中是否配置了 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET`
- Keylo 启动时会先加载 `.env` 到 `Config`，再用 `Config.admin_client_id` / `Config.admin_client_secret` 初始化管理客户端
- 检查 `clients` 表中目标客户端是否 `active=true` 且 `is_admin_client=true`

### 5.3 migration 校验失败

- 不要修改已执行 migration
- 如开发库可丢弃，重置数据库后重新执行迁移

---

## 6. 进一步阅读

- [docs/END_TO_END_QUICKSTART.md](docs/END_TO_END_QUICKSTART.md)
- [docs/MULTI_CLIENT_RBAC_INTEGRATION.md](docs/MULTI_CLIENT_RBAC_INTEGRATION.md)
- [docs/THIRD_PARTY_INTEGRATION.md](docs/THIRD_PARTY_INTEGRATION.md)
- [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)
