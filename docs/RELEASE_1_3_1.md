# Keylo 1.3.1 发布说明

发布日期：2026年5月

## 版本定位

Keylo 1.3.1 是 1.3.0 之后的生产可用性与部署安全增强版本，重点聚焦启动阶段 fail-fast、数据库密码密文化、重复资源错误提示和回归测试稳定性。

本版本无破坏性 API 变更，但对生产部署配置有更严格的安全要求。

---

## 主要改进

### 启动配置 fail-fast

Keylo 启动时会提前校验关键配置，避免服务运行到认证或管理接口时才失败。

新增校验覆盖：

- `JWT_ISSUER`、`JWT_KEY_ID`
- RSA 私钥/公钥
- `ADMIN_CLIENT_ID`、`ADMIN_CLIENT_SECRET`
- 数据库 URL
- token 过期时间、限流参数、日志配置
- 生产环境 `REDIS_URL`
- 超级管理员 bootstrap 配置

`ALLOW_IN_MEMORY_FALLBACK=true` 只允许非生产环境绕过数据库能力，不会绕过 JWT、管理员客户端等基础配置。

### 数据库密码密文化

Docker Compose 场景下，PostgreSQL 首次初始化仍可读取明文密码 secret，但 Keylo 运行期不再需要读取明文数据库密码。

Keylo 支持：

- `DATABASE_PASSWORD_ENC` / `DATABASE_PASSWORD_ENC_FILE`?????? `./secrets/postgres_password.enc`?`/run/secrets/postgres_password_enc`
- `DATABASE_PASSWORD_KEY` / `DATABASE_PASSWORD_KEY_FILE`?????? `./secrets/database_password.key`?`/run/secrets/database_password_key`
- `secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>` 跨语言统一密文格式
- AES-256-GCM 解密

格式设计和 Rust/Python/Java/.NET/C++ 解密示例见 [SECRET_ENCRYPTION.md](SECRET_ENCRYPTION.md)。

生产环境会拒绝：

- `DATABASE_PASSWORD`
- `DATABASE_PASSWORD_FILE`
- 带明文密码的 `DATABASE_URL`

新增辅助工具：

```bash
DATABASE_PASSWORD_FILE=./secrets/postgres_password \
python -m pip install cryptography
python scripts/secret_tool.py encrypt \
  --text-file ./secrets/postgres_password \
  --key-file ./secrets/database_password.key \
  --out ./secrets/postgres_password.enc
```

### 重复资源错误提示优化

服务客户端、管理客户端、用户、RBAC 和 OAuth 等创建/更新路径统一使用 PostgreSQL 唯一冲突错误码识别重复资源，并返回更明确的冲突说明。

例如重复注册服务客户端时，会提示选择新的 `service_id` 或更新已有服务客户端。

### Fallback 路由补齐

非生产 fallback/in-memory router 补齐 `/v1/service/token`，避免本地开发或测试模式下服务 token 路由缺失。

### 测试与脚本同步

测试脚本会生成随机数据库密码、密文和解密 key，避免在测试配置中继续保留固定明文数据库密码。

---

## 升级指南

### 从 1.3.0 升级到 1.3.1

1. 更新镜像/二进制到 `v1.3.1`。
2. 确认 `DATABASE_URL` 不包含密码，例如：

```env
DATABASE_URL=postgres://keylo_user@postgres:5432/keylo
```

3. 为 Keylo 配置数据库密码密文和解密 key：

```env
DATABASE_PASSWORD_ENC_FILE=/run/secrets/postgres_password_enc
DATABASE_PASSWORD_KEY_FILE=/run/secrets/database_password_key
```

4. 仅将 PostgreSQL 初始化明文密码文件提供给 PostgreSQL：

```env
POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
```

5. 生产环境确认 `REDIS_URL`、RSA key、管理员客户端配置完整。
6. 重启服务并检查启动日志与 `/readyz`。

详细部署步骤见 [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)。

---

## 验证结果摘要

本版本发布前已完成：

- `cargo fmt --check`
- `cargo test --lib`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --no-run`
- `cargo build --release`

注意：本地环境未安装 `cargo-audit`，安全审计需在 CI 或安装 `cargo-audit` 后执行。

---

## 兼容性说明

- HTTP API 无破坏性变更。
- 生产部署配置更严格：明文数据库密码来源会被拒绝。
- 当前 JWT 密钥轮换仍是维护窗口式单活动密钥模型；轮换 RSA 密钥后旧 JWT 会失效。
