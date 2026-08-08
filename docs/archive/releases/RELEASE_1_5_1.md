# Keylo 1.5.1 发布说明

发布日期：2026年5月17日

## 版本定位

Keylo 1.5.1 是 1.5 系列的部署安全与维护体验增强版本，重点收敛生产密钥、Redis、CORS 和启动结构，降低自建部署时的误配置风险。

---

## 主要改进

### 部署密钥统一

- `secret_tool.py` 新增 `generate-deployment`，可一次生成数据库密文、数据库解密 key、Redis ACL、Redis URL 密文和 Redis URL 解密 key。
- 数据库密码文件统一使用 `.database_password`、`.database_password.enc` 和 `.database_password.key`，避免绑定 PostgreSQL 专属命名。
- 如果 `.secrets/.database_password` 已存在且内容非空，脚本会使用用户自定义密码；否则自动生成包含字母、数字和特殊字符的随机密码。
- `generate-deployment --keep-database-plain` 用于内置 PostgreSQL 首次初始化；默认生成密文后删除明文数据库密码。
- `secret_tool.py` 新增 `generate-rsa`，统一生成 `keys/private.pem` 和 `keys/public.pem`。

### Redis 安全基线

- Redis 不再暴露到生产宿主机端口，只加入 Keylo 专用内部网络。
- Redis 启用 ACL 文件，ACL 中仅保存密码 SHA-256 hash。
- Keylo 运行期通过 `REDIS_URL_ENC_FILE` 和 `REDIS_URL_KEY_FILE` 读取 Redis URL 密文，并只在内存中解密。
- 本地开发通过 `docker-compose.dev.yml` 将 Redis 绑定到 `127.0.0.1`，兼顾调试便利和默认隔离。

### 生产配置收紧

- CORS 改为显式白名单配置，避免 credentialed CORS 接受过宽来源。
- 生产环境拒绝明文数据库密码来源和明文 Redis URL 来源。
- 默认读取新的 `.database_password.enc` 路径，同时保留旧 `.postgres_password.enc` 作为兼容 fallback。

### 启动结构维护

- 拆分并简化数据库版 router 初始化流程，减少启动逻辑混杂。
- 复用路由构建逻辑，降低正式入口和测试入口漂移风险。
- 精简环境变量解析辅助函数，减少配置解析重复代码。

---

## 升级指南

### 从 1.5.0 升级到 1.5.1

1. 更新镜像/二进制到 `v1.5.1`。
2. 生成或迁移 secret 文件：

```bash
python -m pip install cryptography
python scripts/secret_tool.py generate-deployment --keep-database-plain
```

如果使用外部数据库或数据库已经初始化，可省略 `--keep-database-plain`，让脚本在生成密文后删除 `.secrets/.database_password`。

3. 如果需要固定自定义数据库密码，先写入：

```bash
mkdir -p .secrets
printf '%s' 'your-strong-database-password' > .secrets/.database_password
python scripts/secret_tool.py generate-deployment --keep-database-plain
```

4. 更新数据库密文路径：

```env
DATABASE_PASSWORD_ENC_FILE=./.secrets/.database_password.enc
DATABASE_PASSWORD_KEY_FILE=./.secrets/.database_password.key
```

旧 `.postgres_password.enc` 默认路径仍可读取，但建议迁移到 `.database_password.enc`。

5. 更新 RSA 密钥生成方式：

```bash
python scripts/secret_tool.py generate-rsa
```

6. 生产环境确认 `CORS_ALLOWED_ORIGINS` 是实际前端域名列表，并继续使用 Redis URL 密文配置。

---

## 兼容性说明

- HTTP API 保持向后兼容。
- 旧数据库密文默认路径 `.postgres_password.enc` 仍作为 fallback 支持。
- Release log 文档按版本保留历史语境；旧版本发布说明不回填新部署命名。

---

## 验证结果摘要

本版本发布前已完成：

```bash
python -m py_compile scripts/secret_tool.py
docker compose config --quiet
cargo fmt --check
cargo test --lib
cargo test --tests --no-run
```

提交钩子还自动执行了：

```bash
cargo fmt --check
cargo clippy
```

验证结果：全部通过。
