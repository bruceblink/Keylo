# Keylo 多客户端统一用户池 + API 级授权集成指南

> 本文档聚焦“如何落地集成”。完整接口清单与字段定义请以 [API_REFERENCE.md](API_REFERENCE.md) 为准。

> 如果你需要一份从系统初始化到管理客户端、用户、RBAC、服务客户端的完整操作手册，请参考：[END_TO_END_QUICKSTART.md](END_TO_END_QUICKSTART.md)

## 1. 适用场景

- 多业务客户端接入同一用户池
- 用户由管理后台统一创建与授权
- 后端按 API 级能力点强制鉴权
- 前端按 claims 做展示控制（仅体验层）

---

## 2. 统一权限模型（建议）

### 2.1 能力点命名

建议格式：`{client}.{resource}.{action}`

示例：

- `ssc.berthing.read`
- `ssc.berthing.write`
- `ssc.camera.read`
- `ssc.camera.write`
- `admin.user.create`
- `admin.user.assign`

### 2.2 角色模板

- 角色可绑定多个权限点
- 用户可绑定多个角色（最终权限取并集）
- 推荐模板：`ssc_viewer`、`ssc_dispatcher`、`admin_operator`

---

## 3. 最小接入流程（推荐）

1. 初始化权限点与角色模板
   - 创建权限：`POST /api/rbac/permissions`
   - 创建角色：`POST /api/rbac/roles`
   - 角色批量绑权限：`POST /api/rbac/roles/{role_id}/permissions/batch`

2. 用户开通即授权（原子）
   - `POST /v1/admin/users/provision`
   - 支持 `role_ids` 与 `role_names` 混用

3. 登录获取 token
   - 普通用户：`POST /v1/auth/token`
   - 管理客户端：`POST /v1/admin/token`

4. 后端接口强制鉴权
   - 校验 `token_type=access`
   - 校验 `aud`
   - 校验 `scope` 与 `role`

5. 变更后验证
   - 查询最终权限并集：`GET /v1/admin/users/{user_id}/effective-permissions`
   - 回收权限后重新签发 token，确认接口行为变化

> 以上接口的请求/响应示例见 [API_REFERENCE.md](API_REFERENCE.md)。

---

## 4. Claims 消费约定

当前建议消费字段：`sub`、`uid`、`iss`、`aud`、`token_type`、`role[]`、`scope[]`、`exp`、`iat`、`jti`。

- `uid` 推荐作为用户主键进行业务关联，`sub` 保留用于主体标识与审计。
- 后端必须作为最终安全边界，前端显示控制不等于授权。

### Refresh Token 说明（重要）

当前实现中，`refresh_token` 主要来自管理客户端链路：

- `POST /v1/admin/token`：返回 `access_token + refresh_token`
- `POST /v1/auth/token`：当前仅返回 `access_token`

即 `POST /v1/auth/refresh` 使用的 `refresh_token`，主要来源于管理客户端登录流程。
每次刷新会原子消费旧 `refresh_token`，调用方必须保存响应中的新 `refresh_token`，旧值不可重复或并发复用。

---

## 5. 多客户端 audience 建模

### 方案 A（推荐）

- 单 `aud`（如 `ssc-backend`）
- 用 `scope` 前缀隔离客户端能力（`clientA.*` / `clientB.*`）

优点：策略统一、网关与后端校验实现更简单。

### 方案 B

- 多 `aud`（每客户端独立受众）

适合：资源服务器边界天然强隔离的场景。

---

## 6. 联调验收清单

1. 用户 A 仅 `ssc.berthing.read`：
   - Berthing 读接口应通过
   - Camera 写接口应被拒绝

2. 用户 B 拥有 `ssc.camera.read/write`：
   - Camera 读写接口应通过
   - 未授权接口应被拒绝

3. 用户 C 同时具备多个客户端角色：
   - 仅能访问并集内 API

4. 回收某权限后重新签发 token：
   - 对应 API 权限应立即收敛

---

## 7. 错误码与实现细节

- 常见错误码：`insufficient_scope`、`insufficient_role`、`invalid_audience`、`token_type_invalid`、`permission_not_bound`、`role_not_bound`
- 认证中间件顺序与完整错误码定义请参考 [API_REFERENCE.md](API_REFERENCE.md)
