# Keylo 端到端使用手册

本文档给出一条从零开始的完整使用路径，覆盖：

1. 准备配置、数据库、Redis 和 RSA 密钥
2. 启动 Keylo 并确认管理客户端可用
3. 获取管理 Token，管理管理客户端
4. 配置 RBAC：权限、角色、角色权限关系
5. 创建/开通用户并绑定角色
6. 用户登录、自助接口与受保护接口验证
7. 注册服务客户端并申请 `service_access` Token
8. 使用服务 Token 做用户 Token 内省
9. 验证轻量发现配置与第三方接入模板

建议阅读顺序：

- 这份文档负责“怎么一步步用起来”
- [API_REFERENCE.md](API_REFERENCE.md) 负责完整接口定义
- [MULTI_CLIENT_RBAC_INTEGRATION.md](MULTI_CLIENT_RBAC_INTEGRATION.md) 负责多客户端权限建模建议
- [SECRET_ENCRYPTION.md](SECRET_ENCRYPTION.md) 负责统一密文配置格式和多语言解密说明
- [integrations/README.md](integrations/README.md) 提供 Spring、Node、Go、Rust 接入模板

---

## 1. 环境准备

### 1.1 配置 `.env`

从 `.env.example` 复制：

```bash
cp .env.example .env
```

Windows PowerShell：

```powershell
Copy-Item .env.example .env
```

确保以下关键配置可用（示例）：

```env
DATABASE_URL=postgres://keylo_user@localhost:5432/keylo
DATABASE_PASSWORD_ENC_FILE=./secrets/postgres_password.enc
DATABASE_PASSWORD_KEY_FILE=./secrets/database_password.key
REDIS_URL=redis://localhost:6379
JWT_KEY_ID=keylo-rs256-1
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
ALLOW_IN_MEMORY_FALLBACK=false

# 管理客户端（用于 /v1/admin/token）
ADMIN_CLIENT_ID=cli-admin-root
ADMIN_CLIENT_SECRET=replace-with-strong-admin-secret
```

### 1.2 生成 RSA 密钥

如果不显式提供 RSA 密钥，开发环境会使用内置开发密钥；生产环境必须自己生成：

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem
openssl rsa -pubout -in keys/private.pem -out keys/public.pem
```

Linux 服务器推荐进一步限制权限：

```bash
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

### 1.3 启动依赖

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/postgres_password
python -m pip install cryptography
python scripts/secret_tool.py generate-key --out secrets/database_password.key
python scripts/secret_tool.py encrypt \
  --text-file secrets/postgres_password \
  --key-file secrets/database_password.key \
  --out secrets/postgres_password.enc
docker compose up -d postgres redis
```

### 1.4 启动 Keylo

```bash
cargo run
```

启动后默认地址：`http://127.0.0.1:2345`

如果使用 Docker Compose 直接运行 Keylo：

```bash
docker compose up -d --build
docker compose logs -f keylo-service
```

Keylo 会在启动早期校验 RSA 密钥、管理员客户端、数据库 URL、Token 时长等关键配置。缺失时会直接退出，避免运行到后续认证或管理接口时才失败。只有本地临时调试且明确接受数据库能力不可用时，才设置 `ALLOW_IN_MEMORY_FALLBACK=true`；即便启用该模式，RSA 密钥和管理员客户端仍必须配置。

### 1.5 启动后检查

至少确认日志中出现：

- `Database migrations completed`
- `Default clients seeded`
- `Database initialized successfully`

如出现：

- `Invalid startup configuration`
  - 检查 `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` 或对应 PEM 内容。
  - 检查 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET`。
  - 数据库模式下检查 `DATABASE_URL`。
  - 生产环境检查 `REDIS_URL`。

说明管理客户端没有初始化成功，后续 `/v1/admin/token` 将不可用。

### 1.6 读取轻量发现配置

第三方服务建议先读取 Keylo 的轻量发现配置，获取 `issuer`、JWKS、内省和 token 端点：

```bash
curl -s http://127.0.0.1:2345/.well-known/keylo-configuration
```

该接口不是完整 OIDC discovery 文档，而是 Keylo 面向轻量统一鉴权/授权中心的稳定集成契约。下游服务可用其中的 `jwks_uri` 做本地验签，用 `supported_claims` 和 `supported_audiences` 做接入自检。

---

## 2. 获取管理 Token（管理客户端）

> `POST /v1/auth/token` 是用户登录。
> 管理客户端必须使用 `POST /v1/admin/token`。

```bash
curl -s -X POST http://127.0.0.1:2345/v1/admin/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":"cli-admin-root",
    "client_secret":"replace-with-strong-admin-secret"
  }'
```

响应会返回：

- `access_token`（管理接口调用使用）
- `refresh_token`（用于 `/v1/auth/refresh`）

后续命令统一使用：

```bash
export ADMIN_TOKEN="<上一步 access_token>"
export ADMIN_REFRESH_TOKEN="<上一步 refresh_token>"
```

PowerShell：

```powershell
$env:ADMIN_TOKEN = "<上一步 access_token>"
$env:ADMIN_REFRESH_TOKEN = "<上一步 refresh_token>"
```

如需刷新管理 Token：

```bash
curl -s -X POST http://127.0.0.1:2345/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"'"${ADMIN_REFRESH_TOKEN}"'"}'
```

刷新成功后旧 `ADMIN_REFRESH_TOKEN` 会被原子消费，不能再次使用。请用响应中的新 `refresh_token` 替换本地保存值。

---

## 3. 管理客户端的维护方式

系统启动时会根据 `.env` 中的 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET` 自动创建一个管理客户端。

如果需要给其他后台系统单独分配管理客户端，可以继续通过管理接口维护。

### 3.1 创建额外的管理客户端

```bash
curl -s -X POST http://127.0.0.1:2345/v1/admin/clients \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":"ops-console",
    "client_secret":"OpsConsole#123",
    "name":"Ops Console",
    "description":"operations admin console",
    "active":true
  }'
```

### 3.2 查询和轮换管理客户端密钥

```bash
curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/v1/admin/clients

curl -s -X POST http://127.0.0.1:2345/v1/admin/clients/ops-console/rotate-secret \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"new_secret":"OpsConsole#456"}'
```

如果省略 `new_secret`，Keylo 会生成新密钥并在响应的 `new_secret` 字段中一次性返回；如果请求体提供了 `new_secret`，响应不会回显明文。

---

## 4. 配置 RBAC：权限、角色、绑定

### 4.1 创建权限

```bash
curl -s -X POST http://127.0.0.1:2345/api/rbac/permissions \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ssc.camera.read","description":"读取摄像头"}'

curl -s -X POST http://127.0.0.1:2345/api/rbac/permissions \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ssc.camera.write","description":"编辑摄像头"}'

curl -s -X POST http://127.0.0.1:2345/api/rbac/permissions \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ssc.user.read","description":"读取用户信息"}'
```

### 4.2 创建角色

```bash
curl -s -X POST http://127.0.0.1:2345/api/rbac/roles \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ssc_dispatcher","description":"调度角色"}'

curl -s -X POST http://127.0.0.1:2345/api/rbac/roles \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ssc_viewer","description":"只读查看角色"}'
```

### 4.3 给角色绑定权限

先查询权限与角色 ID：

```bash
curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/api/rbac/permissions

curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/api/rbac/roles
```

然后批量绑定，例如把 `ssc_dispatcher` 绑定读写权限，把 `ssc_viewer` 绑定只读权限：

```bash
curl -s -X POST http://127.0.0.1:2345/api/rbac/roles/<ROLE_ID>/permissions/batch \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"permission_ids":["<PERM_ID_READ>","<PERM_ID_WRITE>"]}'
```

### 4.4 验证角色权限绑定结果

```bash
curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/api/rbac/roles/<ROLE_ID>/permissions
```

---

## 5. 配置用户并分配角色

推荐使用原子开通接口：`/v1/admin/users/provision`

```bash
curl -s -X POST http://127.0.0.1:2345/v1/admin/users/provision \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"alice",
    "email":"alice@example.com",
    "password":"Alice#12345",
    "role_names":["ssc_dispatcher"]
  }'
```

如果你已经有用户，也可以拆分成“创建用户 + 绑定角色”两步：

```bash
curl -s -X POST http://127.0.0.1:2345/v1/admin/users \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"bob",
    "email":"bob@example.com",
    "password":"Bob#12345",
    "active":true
  }'

curl -s -X POST http://127.0.0.1:2345/api/rbac/users/<USER_ID>/roles/batch \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"role_ids":["<ROLE_ID>"]}'
```

查看用户最终权限并集：

```bash
curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/v1/admin/users/<USER_ID>/effective-permissions
```

---

## 6. 用户登录与访问

### 6.1 用户登录

```bash
curl -s -X POST http://127.0.0.1:2345/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":"alice",
    "client_secret":"Alice#12345"
  }'
```

```bash
export USER_TOKEN="<用户 access_token>"
```

### 6.2 查看当前 claims

```bash
curl -s -H "Authorization: Bearer ${USER_TOKEN}" \
  http://127.0.0.1:2345/v1/auth/me
```

### 6.3 用户自助修改密码

```bash
curl -s -X POST http://127.0.0.1:2345/v1/user/change-password \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password":"Alice#12345",
    "new_password":"Alice#12345-New"
  }'
```

### 6.4 访问受保护示例

```bash
curl -s -H "Authorization: Bearer ${USER_TOKEN}" \
  http://127.0.0.1:2345/protected
```

---

## 7. 配置服务客户端（Service-to-Service）

### 7.1 注册服务客户端（管理员）

```bash
curl -s -X POST http://127.0.0.1:2345/v1/admin/services \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "service_id":"agileboot-admin",
    "service_secret":"AgileBootSvc#123",
    "name":"AgileBoot Admin",
    "description":"agileboot backend service client",
    "allowed_scopes":["read","user.read"],
    "allowed_audiences":["admin-backend"],
    "integration_type":"internal",
    "introspection_allowed":true,
    "token_ttl_seconds":900,
    "owner":"Platform Team",
    "contact":"platform@example.com"
  }'
```

服务注册输入约束：

- `allowed_scopes` 与 `allowed_audiences` 至少包含一个值。
- 列表项会自动 trim、去重并排序。
- 列表项不能包含空白字符；多个 scope 必须写成数组多项，不要写成 `"read write"`。
- `allowed_audiences` 可使用 `*`；`allowed_scopes` 不允许 `*`。
- `token_ttl_seconds` 为空时使用全局 `SERVICE_TOKEN_EXPIRY_SECONDS`。

### 7.2 查询和维护服务客户端

```bash
curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/v1/admin/services

curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://127.0.0.1:2345/v1/admin/services/agileboot-admin

curl -s -X POST http://127.0.0.1:2345/v1/admin/services/agileboot-admin/rotate-secret \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"new_secret":"AgileBootSvc#456"}'
```

服务密钥轮换同样遵循一次性返回规则：只有省略 `new_secret` 且由服务端生成时，响应才包含明文 `new_secret`。

### 7.3 申请服务 Token

```bash
curl -s -X POST http://127.0.0.1:2345/v1/service/token \
  -H "Content-Type: application/json" \
  -d '{
    "service_id":"agileboot-admin",
    "service_secret":"AgileBootSvc#123",
    "audience":"admin-backend",
    "scope":"read"
  }'
```

```bash
export SERVICE_TOKEN="<service_access_token>"
```

### 7.4 使用服务 Token 内省用户 Token

```bash
curl -s -X POST http://127.0.0.1:2345/v1/auth/introspect \
  -H "Authorization: Bearer ${SERVICE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"token":"'"${USER_TOKEN}"'"}'
```

### 7.5 使用服务 Token 内省其他服务 Token

```bash
curl -s -X POST http://127.0.0.1:2345/v1/service/introspect \
  -H "Authorization: Bearer ${SERVICE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"token":"'"${SERVICE_TOKEN}"'"}'
```

---

## 8. 完整验收清单

建议至少做以下验证：

1. 管理客户端可以成功调用 `/v1/admin/token`
2. 可以创建权限、角色，并看到角色权限列表
3. 可以通过 `/v1/admin/users/provision` 创建用户并分配角色
4. 普通用户可以通过 `/v1/auth/token` 登录并调用 `/v1/auth/me`
5. 服务客户端可以成功申请 `service_access` token
6. `/v1/auth/introspect` 能使用服务 token 正常内省用户 token
7. 轻量发现接口 `/.well-known/keylo-configuration` 可正常访问
8. JWKS 接口 `/.well-known/jwks.json` 可正常访问
9. 第三方服务可按 [integrations/README.md](integrations/README.md) 完成本地验签接入

---

## 9. 常见问题

1. `wrong_credentials` + 日志 `User not found: cli`
   - 原因：把管理客户端拿去调用了 `/v1/auth/token`。
   - 处理：改用 `/v1/admin/token`。

2. 启动告警 `No active admin client found ...`
   - 检查 `.env` 是否有 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET`。
   - 检查 `clients` 表里目标客户端是否 `active=true` 且 `is_admin_client=true`。

3. migration 校验失败（`previously applied but has been modified`）
   - 不要修改已执行 migration；请恢复原文件或重置数据库后重新迁移。

4. Docker 中日志显示 `Environment: development`
   - 检查 Compose 实际传入的 `ENVIRONMENT`。
   - 检查服务器是否用了另一份 `docker-compose.yml` 或 `.env` 覆盖。

5. 容器启动后 `skipping admin client seed`
   - 说明容器环境变量中没有 `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET`。
   - 检查 `docker compose config` 输出，确认最终渲染后的环境变量是否正确。
