# Keylo 1.5.0 发布说明

发布日期：2026年5月16日

## 版本定位

Keylo 1.5.0 是一次面向“低门槛部署”和“可观测运维”的功能版本。重点不是扩展完整 OIDC，而是让 Keylo 更容易首次安装、更容易接入第三方服务、更容易排查线上问题。

---

## 主要改进

### 首次安装向导

- 新增 setup API 与 React 安装向导前端。
- `ENABLE_SETUP_WIZARD` 默认启用。
- 首次未完成 setup 时访问 `/` 会进入 `/setup`。
- setup 初始化只允许执行一次；完成初始化后接口返回 403。
- setup 只能完成一次，完成后初始化入口关闭。

### 零 Key 自启动

- 未配置 RSA 私钥/公钥文件时，Keylo 会在启动时自动生成随机 RSA 密钥对。
- 公钥继续通过 JWKS 发布，下游服务仍可按标准 JWKS 验签。

### 部署与密钥体验

- Release CI 会构建 `web/` 前端资源并打入镜像。
- Docker Compose 显式传递 setup 和日志相关环境变量。
- `secret_tool.py` 新增 `encrypt-file-and-remove`：读取用户自定义明文数据库密码，自动生成加密 key 和密文文件，成功后删除明文文件。

### 身份源与接入拓展

- 新增 identity source 注册模型，为 local、OAuth、LDAP、OIDC upstream 等身份源抽象预留扩展点。
- 更新第三方接入文档和端到端快速开始。

### 可观测日志

- 启动时输出运行环境、日志配置、setup 配置和依赖配置。
- 增加 HTTP 访问日志，记录 method、uri、status、latency。
- 文件日志默认启用，使用 daily rolling appender 按天归档。
- `/favicon.ico` 返回 `204 No Content`，避免浏览器自动请求污染鉴权失败日志。

---

## 数据库迁移

新增迁移：

```text
migrations/20260516100000_add_identity_sources.sql
migrations/20260516113000_add_system_settings.sql
```

`system_settings` 用于记录 setup 完成状态；`identity_sources` 用于后续身份源扩展。

---

## 升级指南

### 从 1.4.0 升级到 1.5.0

1. 更新镜像/二进制到 `v1.5.0`。
2. 确认数据库迁移执行成功。
3. 如果生产环境启用安装向导，必须配置：

```env
ENABLE_SETUP_WIZARD=true
```

4. 如果使用 Docker Compose，建议配置：

```env
KEYLO_RUST_LOG=keylo=info,axum=info,tower_http=info
LOG_TO_FILE=true
LOG_FILE_PREFIX=keylo
```

5. 如使用内置 PostgreSQL 容器首次初始化，保留 `.secrets/.postgres_password` 供 PostgreSQL 首次读取；外部数据库或已初始化数据库可使用：

```bash
python scripts/secret_tool.py encrypt-file-and-remove
```

---

## 兼容性说明

- HTTP API 保持向后兼容。
- 安装向导默认启用；不需要时可显式设置 `ENABLE_SETUP_WIZARD=false`。
- 生产环境首次未完成 setup 时访问 `/` 会进入 `/setup`；完成后 `/` 返回服务状态 JSON。
- 文件日志默认按天滚动，不负责长期压缩和异地归档；生产环境可继续接入 Docker logging driver、Loki、ELK 或宿主机 logrotate。

---

## 验证结果摘要

本版本发布前已完成：

```bash
cargo fmt -- --check
cargo clippy -- -D warnings
npm run build
cargo test
```

验证结果：全部通过。
