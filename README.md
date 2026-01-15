# Keylo

**Keylo** 是一个轻量、可扩展的 **统一认证与授权服务**（Auth Service），为你的多服务系统提供统一的 JWT 签发、Session 管理和 OAuth 支持。

---

## 🚀 特性

* JWT 签发与验证（Access Token + 可扩展 Refresh Token）
* `/v1/auth/token`、`/v1/auth/logout`、`/v1/auth/me` 核心 API
* 支持 GitHub OAuth 登录（可扩展其他 OAuth 提供商）
* 高可维护模块化架构（routes / handlers / db / models / utils）
* 可与现有数据库表兼容，实现登录互通
* 使用 **Axum 0.8 + Tokio** 异步高性能框架
* 可轻松扩展多客户端、多角色、多服务权限控制

---

## 📦 安装与运行

### 1. 克隆项目

```bash
  git clone https://github.com/bruceblink/Keylo.git
  cd keylo
```

### 2. 设置环境变量

```bash
  export JWT_SECRET="supersecretkey"
  export DATABASE_URL="postgres://user:password@localhost/keylo"
```

> Windows 用户可使用 `set JWT_SECRET=supersecretkey`

### 3. 构建并运行

```bash
  cargo run
```

默认监听 `127.0.0.1:2345`。

---

## 🔑 API 示例

### 获取 Token

```bash
  curl -X POST http://127.0.0.1:2345/v1/auth/token \
    -H "Content-Type: application/json" \
    -d '{"client_id":"foo","client_secret":"bar"}'
```

返回：

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

---

### 获取当前用户信息

```bash
  curl -H "Authorization: Bearer <access_token>" \
     http://127.0.0.1:2345/v1/auth/me
```

---

### 登出

```bash
  curl -X POST -H "Authorization: Bearer <access_token>" \
     http://127.0.0.1:2345/v1/auth/logout
```

---

## 🏗️ 项目结构

```
src/
├── main.rs          # 启动入口
├── config.rs        # 配置管理
├── state.rs         # AppState 定义
├── routes/          # 路由
│   ├── auth.rs
│   ├── oauth.rs
│   └── mod.rs
├── handlers/        # Handler 实现
├── models/          # 数据模型 / JWT Claims
├── db/              # 数据库操作
├── errors.rs        # 错误类型与 IntoResponse
└── utils.rs         # 工具函数（JWT、密码等）
```

---

## 🛠️ 技术栈

* Rust + Axum 0.8
* Tokio 异步运行时
* jsonwebtoken (JWT)
* Axum Extra（TypedHeader）
* SQLx / Postgres（数据库，可扩展）
* tracing + tracing_subscriber（日志/追踪）

---

## ✨ 下一步计划

* 支持 Refresh Token
* 支持多客户端与 Scope/Role
* 扩展 OAuth（Google, GitHub, etc.）
* 管理后台可视化
* 单元测试和集成测试

---

## ⚡ 联系与贡献

欢迎提交 Issue 和 PR，让 Keylo 更强大！

---
