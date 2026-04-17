# Keylo 多客户端统一用户池 + API 级授权对接文档

## 1. 适用场景

- 多业务客户端 + 统一管理后台
- 用户由管理后台统一创建/分配角色
- 后端按 API 级能力点做强制校验
- 前端按 token 能力点渲染 UI（体验层）

---

## 2. 权限模型

### 2.1 能力点命名

建议统一：

`{client}.{resource}.{action}`

示例：

- `ssc.berthing.read`
- `ssc.berthing.write`
- `ssc.camera.read`
- `ssc.camera.write`
- `admin.user.create`
- `admin.user.assign`

### 2.2 角色模板

- 角色可绑定多个权限点
- 用户可绑定多个角色（权限并集）
- 推荐模板：`ssc_viewer`、`ssc_dispatcher`、`admin_operator`

---

## 3. 已支持接口清单

### 3.1 RBAC 管理

1. 创建权限点  
   `POST /api/rbac/permissions`

2. 创建角色  
   `POST /api/rbac/roles`

3. 角色绑定权限（批量）  
   `POST /api/rbac/roles/{role_id}/permissions/batch`

4. 用户绑定角色（批量）  
   `POST /api/rbac/users/{user_id}/roles/batch`

### 3.2 用户创建即授权（原子）

5. 创建用户并直接绑定角色模板  
   `POST /v1/admin/users/provision`

请求体（支持 role_id / role_name 混用）：

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Alice#12345",
  "role_ids": ["<role-id-1>", "<role-id-2>"],
  "role_names": ["ssc_dispatcher"]
}
```

### 3.3 查询与调试

6. 查询用户最终权限并集  
   `GET /v1/admin/users/{user_id}/effective-permissions`

7. 查询角色详情（含权限）  
   `GET /api/rbac/roles/{role_id}`

8. 按前缀查询权限点  
   `GET /api/rbac/permissions?prefix=ssc.`

---

## 4. Token Claims 规范

当前 Access Token 推荐消费字段：

- `sub`
- `iss`
- `aud`
- `token_type`（必须为 `access`）
- `role`（数组）
- `scope`（数组）
- `exp`
- `iat`
- `jti`

示例：

```json
{
  "sub": "user:alice",
  "iss": "keylo",
  "aud": "admin-backend",
  "token_type": "access",
  "role": ["ssc_dispatcher", "ssc_viewer"],
  "scope": ["ssc.berthing.read", "ssc.camera.read", "ssc.camera.write"],
  "exp": 1710000000,
  "iat": 1709990000,
  "jti": "uuid"
}
```

### 4.1 兼容策略

- `role` 已升级为数组输出。
- 服务端对历史单字符串 `role` 保持兼容反序列化（平滑升级）。

---

## 5. 多客户端 audience 建模建议

### 方案 A（推荐）

- 单 `aud`（例如：`ssc-backend`）
- 通过 `scope` 前缀隔离客户端能力（`clientA.*` / `clientB.*`）

优点：策略统一、网关和后端校验成本低。

### 方案 B

- 多 `aud`（各客户端独立受众）

适合：强隔离、多资源服务器边界非常清晰的场景。

---

## 6. 错误码规范（机读）

已支持稳定错误码：

- `insufficient_scope`
- `insufficient_role`
- `invalid_audience`
- `token_type_invalid`
- `permission_not_bound`
- `role_not_bound`

响应示例：

```json
{
  "error": "insufficient_scope",
  "message": "required: ssc.camera.write"
}
```

---

## 7. 生效与运维说明

- 权限变更后，**新签发 token** 立即反映最新权限。
- 审计日志记录角色/权限分配与回收事件。
- 支持批量接口满足模板化发放与批量变更。

---

## 8. 联调验收用例

1. 用户 A 仅有 `ssc.berthing.read`：
   - Berthing 读接口：`200`
   - Camera 写接口：`403`

2. 用户 B 有 `ssc.camera.read/write`：
   - Camera 增删改查通过
   - 其他未授权接口拒绝

3. 用户 C 同时有客户端 A/B 能力：
   - 仅能访问并集内 API

4. 回收某能力后重新获取 token：
   - 对应接口立即 `403`
