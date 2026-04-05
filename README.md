# Keylo

**Keylo** 是一个轻量、可扩展的 **统一认证与授权服务**（Auth Service），为你的多服务系统提供统一的 JWT 签发、Session 管理和 OAuth 支持。

---

## 🚀 特性

* ✅ JWT 签发与验证（Access Token + 可扩展 Refresh Token）
* ✅ `/v1/auth/token`、`/v1/auth/logout`、`/v1/auth/me` 核心 API
* ✅ 支持 GitHub OAuth 登录（可扩展其他 OAuth 提供商）
* ✅ **RBAC 角色-based访问控制系统**
* ✅ 高可维护模块化架构（routes / handlers / db / models / utils）
* ✅ 可与现有数据库表兼容，实现登录互通
* ✅ 使用 **Axum 0.8 + Tokio** 异步高性能框架
* ✅ 可轻松扩展多客户端、多角色、多服务权限控制
* ✅ PostgreSQL 数据库集成，支持自动迁移
* ✅ 完整的错误处理和日志系统
* ✅ Docker 容器化支持

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
JWT_SECRET=your-secure-secret-key
DATABASE_URL=postgres://keylo_user:keylo_password@localhost:5432/keylo
SERVER_ADDR=127.0.0.1
SERVER_PORT=2345
ENVIRONMENT=development
```

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

### 获取 Token

使用客户端凭证获取 token（请使用你在数据库或环境中配置的客户端）:

```bash
curl -X POST http://127.0.0.1:2345/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"web","client_secret":"<your-client-secret>"}'
```

返回：

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

### 获取当前用户信息

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:2345/v1/auth/me
```

返回：

```json
{
  "sub": "client:web",
  "scope": ["read", "write"],
  "aud": "admin-backend",
  "exp": 1704067200,
  "iss": "keylo",
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

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

#### 创建角色

```bash
curl -X POST -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/rbac/roles \
  -d '{"name": "admin", "description": "Administrator role"}'
```

#### 创建权限

```bash
curl -X POST -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/rbac/permissions \
  -d '{"name": "user.manage", "description": "Manage users permission"}'
```

#### 为用户分配角色

```bash
curl -X POST -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2345/api/rbac/users/{user_id}/roles \
  -d '{"role_id": "role-uuid"}'
```

#### 检查用户权限

```bash
curl -H "Authorization: Bearer <access_token>" \
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
curl -X POST -H "Authorization: Bearer <access_token>" \
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
curl -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:2345/api/oauth/accounts
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
| `JWT_SECRET` | `my-jwt-secret-change-in-production` | JWT 签名密钥 |
| `DATABASE_URL` | `postgres://user:password@localhost/keylo` | 数据库连接字符串 |
| `SERVER_ADDR` | `127.0.0.1` | 服务器监听地址 |
| `SERVER_PORT` | `2345` | 服务器监听端口 |
| `ENVIRONMENT` | `development` | 运行环境 |
| `TOKEN_EXPIRY_SECONDS` | `900` | Token 过期时间（秒） |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | `2592000` | 刷新 Token 过期时间（秒） |
| `RUST_LOG` | `keylo=debug` | 日志级别 |

---

## 🗄️ 数据库迁移

服务启动时会自动创建必要的表：

* `clients` - 客户端信息存储
* `users` - 用户信息存储
* `sessions` - 会话管理

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

### 构建镜像

```bash
docker build -t keylo:latest .
```

### 运行容器

```bash
docker run -p 2345:2345 \
  -e JWT_SECRET="your-secret" \
  -e DATABASE_URL="postgres://user:password@db:5432/keylo" \
  keylo:latest
```

### Docker Compose 完整部署

```bash
docker-compose up -d
# 检查状态
docker-compose ps
# 查看日志
docker-compose logs -f keylo
```

---

## ✨ 核心功能

### 1. JWT 认证

* 使用 HS256 对称加密
* 支持自定义 Claim 字段
* 支持 Token 过期时间设置
* 支持 JTI（JWT ID）用于 Token 吊销

### 2. 客户端管理

* 支持多客户端凭证
* 支持从数据库动态加载客户端
* 支持客户端激活/停用

### 3. Session 管理

* 自动创建 Session 记录
* 支持 Session 撤销
* 支持 Session 过期检查

### 4. 错误处理

* 统一的错误响应格式
* 详细的错误代码和信息
* 适当的 HTTP 状态码

---

## 🚦 下一步计划

* [ ] 补充 RBAC / OAuth 管理接口的 `admin` 级权限校验
* [ ] 完善 OAuth `state` 参数校验与重放防护
* [ ] 将默认客户端从内存迁移为数据库 seed 机制
* [ ] 增加审计日志（登录、登出、角色变更、OAuth 绑定）
* [ ] 增加接口级限流与暴力破解防护
* [ ] 管理后台 API
* [ ] GraphQL 支持
* [ ] 第三方集成文档

---

## 📖 开发指南

### 添加新的认证 Provider

在 `src/handlers/` 中创建新的 handler，然后在 `src/routes/auth.rs` 中注册路由。

### 自定义 Claims

编辑 `src/models/jwt.rs` 中的 `Claims` 结构体，添加所需的字段。

### 数据库操作

在 `src/db/mod.rs` 中添加新的数据库查询函数。

---

## ⚠️ 安全建议

1. **生产环境**:
   * 生成强大的 `JWT_SECRET` (至少 32 字符)
   * 使用 HTTPS 而不是 HTTP
   * 设置 `ENVIRONMENT=production`
   * 启用日志审计

2. **数据库**:
   * 使用强数据库密码
   * 定期备份
   * 启用 SSL 连接

3. **Token**:
   * 合理设置过期时间
   * 实现 Token 黑名单机制
   * 定期轮换密钥

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

```bash
# Fork 项目
# 创建特性分支
git checkout -b feature/your-feature

# 提交更改
git commit -m "Add your feature"

# 推送分支
git push origin feature/your-feature

# 创建 Pull Request
```

---

## 📄 许可证

MIT License - 查看 [LICENSE](LICENSE) 文件

---

## 💬 支持

* 📧 提交 Issue: [GitHub Issues](https://github.com/bruceblink/Keylo/issues)
* 💡 讨论: [GitHub Discussions](https://github.com/bruceblink/Keylo/discussions)

---

**Last Updated**: 2026年04月05日
