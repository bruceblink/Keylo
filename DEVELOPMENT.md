# 本地开发指南

## 快速开始

### 1. 环境准备

```bash
# 克隆仓库
git clone https://github.com/bruceblink/Keylo.git
cd keylo

# 复制环境变量
cp .env.example .env

# 启动数据库
docker-compose up -d
```

### 2. 验证数据库连接

```bash
# 进入PostgreSQL
docker exec -it keylo_postgres psql -U keylo_user -d keylo

# 查看创建的表
\dt

# 退出
\q
```

### 3. 运行服务

```bash
# 开发模式
RUST_LOG=keylo=debug cargo run

# 或使用cargo watch自动重新加载
cargo install cargo-watch
cargo watch -x run
```

服务将在 `http://127.0.0.1:2345` 启动。

---

## API 测试

### 获取 Token

```bash
curl -X POST http://127.0.0.1:2345/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"web","client_secret":"web-secret"}'
```

保存返回的 `access_token`。

### 获取用户信息

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:2345/v1/auth/me
```

### 访问受保护路由

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:2345/protected
```

### 登出

```bash
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:2345/v1/auth/logout
```

---

## 调试

### 启用详细日志

```bash
RUST_LOG=keylo=trace,axum=trace cargo run
```

### 调试 JWT Token

使用 [jwt.io](https://jwt.io) 解析 JWT Token，查看其中的声明。

### 查看数据库

```bash
# 连接数据库
docker exec -it keylo_postgres psql -U keylo_user -d keylo

# 查看客户端
SELECT * FROM clients;

# 查看会话
SELECT * FROM sessions;

# 查看用户
SELECT * FROM users;
```

---

## 常见任务

### 添加新的认证客户端

#### 方式1：直接在数据库中添加

```sql
INSERT INTO clients (id, secret, name, description) 
VALUES ('mobile', 'mobile-secret-123', 'Mobile App', 'iOS/Android app');
```

#### 方式2：通过硬编码（开发用）

在 `src/state.rs` 中修改 `AppState::new()`:

```rust
clients.insert("mobile".into(), "mobile-secret-123".into());
```

### 修改 Token 过期时间

编辑 `.env`:

```env
TOKEN_EXPIRY_SECONDS=3600  # 1小时
```

### 修改 JWT Claims

编辑 `src/models/jwt.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub scope: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    // 添加新字段
    pub custom_field: String,
}
```

### 添加新的路由

1. 在 `src/handlers/` 中创建 handler 函数
2. 在 `src/routes/` 中定义路由
3. 在 `src/startup.rs` 中注册路由

```rust
// src/handlers/custom.rs
pub async fn custom_endpoint() -> String {
    "Hello, World!".to_string()
}

// src/routes/mod.rs
pub mod custom;

// src/startup.rs
.merge(routes::custom::router())
```

---

## 性能优化

### 使用 cargo's release profile

```bash
cargo run --release
```

### 分析编译时间

```bash
cargo build -Z timings
```

### 生成火焰图

```bash
cargo install flamegraph
cargo flamegraph --bin keylo
```

---

## 容器开发

### 构建 Docker 镜像

```bash
docker build -t keylo:dev .
```

### 运行与调试

```bash
docker run -p 2345:2345 \
  -e JWT_SECRET="dev-secret" \
  -e ENVIRONMENT="development" \
  keylo:dev
```

### 查看容器日志

```bash
docker logs keylo
docker logs -f keylo  # 实时查看
```

---

## 测试

### 单元测试

```bash
# 运行所有测试
cargo test

# 运行特定测试
cargo test test_index

# 显示输出
cargo test -- --nocapture

# 单线程运行
cargo test -- --test-threads=1
```

### 集成测试

在 `tests/` 目录中创建集成测试：

```rust
// tests/integration_test.rs
#[tokio::test]
async fn test_full_auth_flow() {
    // 测试完整的认证流程
}
```

### 覆盖率

```bash
cargo tarpaulin --out Html
open tarpaulin-report.html
```

---

## 常见问题

### 数据库连接失败

```bash
# 检查容器状态
docker ps

# 查看容器日志
docker logs keylo_postgres

# 重启容器
docker-compose restart postgres
```

### 端口已被占用

```bash
# 更改 .env 中的 SERVER_PORT
SERVER_PORT=3000

# 或者杀死占用端口的进程
lsof -i :2345
```

### 编译失败

```bash
# 清理缓存
cargo clean

# 更新依赖
cargo update

# 重新编译
cargo build
```

---

## 有用的命令

| 命令 | 说明 |
| ------ | ------ |
| `cargo build` | 编译项目 |
| `cargo run` | 运行项目 |
| `cargo test` | 运行测试 |
| `cargo check` | 检查代码（不产生二进制文件） |
| `cargo fmt` | 格式化代码 |
| `cargo clippy` | 代码检查工具 |
| `cargo doc --open` | 生成并打开文档 |
| `cargo tree` | 显示依赖树 |

---

## IDE 配置

### VS Code

安装扩展：

- Rust Analyzer
- CodeLLDB (用于调试)

`.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "Debug",
            "cargo": {
                "args": [
                    "build",
                    "--bin=keylo",
                    "--package=keylo"
                ],
                "filter": {
                    "name": "keylo",
                    "kind": "bin"
                }
            },
            "args": [],
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

### IntelliJ IDEA

安装 Rust 扩展已自动配置。

---

## 文档

生成并查看文档：

```bash
cargo doc --open
```

---

祝你开发愉快！如有问题，请创建 Issue。
