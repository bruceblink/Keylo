# Keylo 安装向导设计说明

## 1. 背景

Keylo 当前采用 API-first 的轻量统一认证与授权中心定位，核心能力通过 HTTP API 暴露。用户管理、应用管理、品牌配置、登录体验、密钥轮换、多租户和审计可视化等业务管理能力并非所有系统都需要，且 Keylo 已提供接口供接入方按需开发。

当前主要痛点集中在首次部署：

- 配置项较多：数据库、Redis、RSA 密钥、管理客户端、运行环境。
- 启动默认 fail-fast，错误安全但对首次部署用户不够直观。
- 用户需要从日志和文档中拼接初始化步骤。
- 第三方服务接入前，需要先确认 discovery、JWKS、token endpoint 和 admin token endpoint 是否可用。

因此，Keylo 需要的是安装向导，而不是完整管理后台。

## 2. 产品边界

安装向导只解决“第一次跑起来”和“为什么没跑起来”。

包含：

- 环境与依赖诊断。
- 数据库连接状态。
- migration 执行状态。
- Redis 配置状态。
- JWT RSA 密钥状态。
- 管理客户端初始化状态。
- 初始化完成后的接入端点摘要。

不包含：

- 用户管理 UI。
- 服务客户端管理 UI。
- OAuth Provider 管理 UI。
- RBAC 配置 UI。
- 品牌、登录体验、多租户配置 UI。
- 审计日志可视化。
- 密钥轮换控制台。

上述能力继续通过 API 暴露，由使用方根据业务需要自行开发。

## 3. 安全原则

- 安装向导默认关闭，必须显式设置 `ENABLE_SETUP_WIZARD=true`。
- 生产环境必须配置 `SETUP_TOKEN`，所有 setup API 都要求 `Authorization: Bearer <SETUP_TOKEN>`。
- 非生产环境也建议配置 `SETUP_TOKEN`；未配置时仅适合本地临时调试。
- 初始化完成后，setup API 返回 403，setup 页面显示已完成状态，不再执行初始化动作。
- 安装向导不能绕过生产安全基线：生产环境仍要求 Redis、非默认 RSA 密钥和有效管理客户端配置。
- 页面不展示已存在的密钥明文，也不回显管理客户端密钥；只有用户提交或生成时由用户自行保存。

## 4. 配置项

新增配置：

| 配置 | 默认值 | 说明 |
|---|---|---|
| `ENABLE_SETUP_WIZARD` | `false` | 是否启用安装向导路由 |
| `SETUP_TOKEN` | 空 | setup API 访问令牌；生产环境启用安装向导时必填 |
| `SETUP_KEYS_DIR` | `./keys` | 生成 RSA 密钥文件的目录 |

前端工程：

- 安装向导 UI 位于 `web/`。
- 技术栈为 React + TypeScript + Vite。
- 开发时运行 `cd web && npm run dev`，通过 Vite proxy 调用 Keylo 后端 setup API。
- 发布时运行 `cd web && npm run build`，Keylo 后端从 `web/dist` 托管 `/setup` 页面与 `/setup/assets/*` 静态资源。

已有配置仍作为运行基线：

- `DATABASE_URL`
- `REDIS_URL`
- `JWT_ISSUER`
- `JWT_KEY_ID`
- `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH`
- `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET`

## 5. 路由设计

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/setup` | 安装向导页面 |
| `GET` | `/setup/assets/*` | React 构建产物 |
| `GET` | `/setup/status` | 返回安装诊断状态 |
| `POST` | `/setup/initialize` | 执行初始化 |

### 5.1 `GET /setup/status`

返回字段：

```json
{
  "enabled": true,
  "completed": false,
  "environment": "development",
  "checks": [
    {
      "key": "database_url",
      "label": "Database URL",
      "ok": true,
      "required": true,
      "message": "DATABASE_URL is configured"
    }
  ],
  "endpoints": {
    "issuer": "keylo",
    "jwks_uri": "http://127.0.0.1:2345/.well-known/jwks.json",
    "admin_token_endpoint": "http://127.0.0.1:2345/v1/admin/token",
    "service_token_endpoint": "http://127.0.0.1:2345/v1/service/token"
  }
}
```

### 5.2 `POST /setup/initialize`

请求体：

```json
{
  "admin_client_id": "cli-admin-root",
  "admin_client_secret": "replace-with-strong-secret",
  "generate_rsa_keys": true
}
```

行为：

- 校验 setup token。
- 校验 setup 未完成。
- 检查数据库连接。
- 执行 migrations。
- 按需生成 RSA 密钥文件到 `SETUP_KEYS_DIR`。
- 创建或更新管理客户端。
- 写入 `system_settings.setup.completed=true`。
- 返回接入端点摘要。

第一版不支持在线修改数据库地址和 Redis 地址。它们仍通过环境变量或容器编排系统提供。

## 6. 持久化设计

新增 `system_settings` 表：

```sql
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

关键设置：

- `setup.completed`
- `setup.completed_at`

## 7. 实施阶段

### 阶段一：安装向导 MVP

- 新增 setup 配置。
- 新增 `system_settings` migration 和 DB helper。
- 新增 `/setup/status`、`/setup/initialize`。
- 新增最小 HTML 安装页面。
- 补 API 文档和集成测试。

### 阶段二：部署体验增强

- 页面显示更细的诊断建议。
- 支持复制 `.env` 示例。
- 展示 discovery-lite 结果。
- 提供 Docker Compose 场景说明。

### 阶段三：可选管理入口

只在确有需求时考虑。业务管理能力应继续保持 API-first，不作为 Keylo 核心安装向导的一部分。
