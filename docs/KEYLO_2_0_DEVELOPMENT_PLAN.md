# Keylo 2.0 统一主体 RBAC 开发计划

## 1. 背景与目标

Keylo 1.x 已具备统一认证中心的基础能力：RS256 JWT、JWKS、用户登录、管理客户端、服务客户端、OAuth、Refresh Token、Token 黑名单、RBAC、审计日志和密文配置。下一阶段的目标不是继续把这些能力横向堆叠，而是把 Keylo 演进为统一身份、统一认证、统一授权中心。

Keystone 中已经沉淀了一些值得引入 Keylo 的设计：

- Keylo token 接入 Keystone 时必须完整校验签名、issuer、audience 和时间声明，不能只 decode payload。
- 当前 Keystone 对 Keylo bearer token 的“校验通过即临时全权限”只是过渡态，最终应进入统一 Principal + RBAC。
- Refresh Token 应支持服务端状态、哈希存储、轮换、重放检测、撤销和客户端单飞刷新。
- 单账号登录应以稳定会话为占用索引，避免 access token 轮换造成账号在线状态漂移。
- 数据库、Redis 等部署 secret 应统一使用 `secret:v1:aes-256-gcm` 密文格式，明文只允许存在于初始化必要阶段。

Keylo 2.0 的总体目标：

1. 将用户、服务和客户端统一抽象为 Principal。
2. 用户和服务共同使用 RBAC 授权模型。
3. 服务也可以像用户一样绑定角色、拥有权限、访问资源树。
4. 将“菜单授权”扩展为“资源树授权”：用户消费 UI 菜单树，服务消费 API/服务能力目录。
5. 让 Keystone/AgileBoot 等后台系统成为 Keylo 的接入方或管理控制台候选，而不是长期权限源。

## 2. 产品定位

Keylo 2.0 定位为轻量统一认证与授权中心：

- 认证：用户、管理客户端、服务客户端、外部身份源。
- 授权：统一 Principal、统一 RBAC、资源树、权限检查、数据范围策略。
- 集成：JWT/JWKS 本地验签、Token introspection、服务间授权、管理 API。
- 治理：审计日志、Token 黑名单、Refresh Token 轮换、secret 加密、密钥轮换。

Keystone 的定位应收敛为：

- 后台管理系统和业务脚手架。
- Keylo 管理控制台候选。
- Keylo 授权结果的消费方。
- Keystone 菜单权限、按钮权限、部门/数据范围模型的迁移来源。

## 3. 核心模型

### 3.1 Principal

`Principal` 是 Keylo 2.0 的统一安全主体。

建议类型：

| 类型 | 说明 | 示例 |
| --- | --- | --- |
| `user` | 人类用户 | `user:alice` |
| `service` | 服务账号或内部系统 | `service:keystone-admin` |
| `client` | 管理客户端、机器客户端或外部集成客户端 | `client:admin-console` |

统一主体字段建议：

| 字段 | 说明 |
| --- | --- |
| `id` | Keylo 内部 Principal ID |
| `principal_type` | `user` / `service` / `client` |
| `subject` | 稳定主体标识，进入 JWT `sub` |
| `ref_id` | 关联现有 `users.id`、`service_clients.service_id` 或 `clients.id` |
| `display_name` | 展示名称 |
| `active` | 是否启用 |
| `created_at` / `updated_at` | 审计时间 |

### 3.2 Role

Role 不再只服务用户，也可以绑定给服务和客户端。

建议增加角色适用范围：

| 字段 | 说明 |
| --- | --- |
| `assignable_to` | `user` / `service` / `client` / `all` |
| `system` | 是否为系统内置角色 |

示例：

- `super_admin`
- `keystone_operator`
- `crawler_service`
- `report_readonly_service`

### 3.3 Permission

Permission 是统一权限点，建议继续使用字符串 code 作为外部集成契约。

命名建议：

```text
{app}:{resource}:{action}
```

示例：

- `keylo:user:list`
- `keylo:role:edit`
- `keystone:system:user:list`
- `keystone:system:dept:remove`
- `service:crawler:invoke`
- `service:report:read`

### 3.4 Resource

Resource 是菜单、按钮、API、服务能力和数据范围的统一资源表达。

建议类型：

| 类型 | 说明 |
| --- | --- |
| `menu` | UI 菜单节点 |
| `button` | UI 操作按钮 |
| `api` | HTTP API 或 RPC 能力 |
| `service` | 服务能力目录 |
| `data_scope` | 数据范围策略 |

资源树用于连接展示和授权：

```text
resource_tree
  app = keystone
  type = menu
  code = system:user
  permission = keystone:system:user:list

resource_tree
  app = crawler
  type = service
  code = crawler:news:sync
  permission = service:crawler:sync
```

## 4. 统一授权链路

Keylo 2.0 的授权链路统一为：

```text
principal -> roles -> permissions -> resources/actions
```

用户访问后台：

```text
user:alice
  -> role:keystone_operator
  -> permission:keystone:system:user:list
  -> menu:系统管理/用户管理
```

服务调用接口：

```text
service:crawler
  -> role:crawler_service
  -> permission:service:news:sync
  -> resource:news-sync-api
```

关键原则：

1. JWT 负责证明“是谁”和“面向哪个 audience”。
2. RBAC 负责判断“能做什么”。
3. 服务不再只依赖 `allowed_scopes` 和 `allowed_audiences`。
4. `allowed_scopes` / `allowed_audiences` 在 2.0 迁移期保留为服务 token 签发白名单，长期收敛为 RBAC 策略的一部分。
5. 未知 Principal、未绑定角色、无匹配权限时默认拒绝。

## 5. Token 与会话设计

### 5.1 Token 边界

JWT 中只放轻量、稳定、低频变化的 claims：

- `sub`
- `uid` 或 `principal_id`
- `principal_type`
- `iss`
- `aud`
- `role[]`
- `scope[]`
- `token_type`
- `exp`
- `iat`
- `jti`

不建议把完整权限列表和完整资源树塞进 JWT。原因：

1. 权限和菜单可能较大，token 会膨胀。
2. 权限变更后，旧 token 无法立即收敛。
3. 服务能力目录和数据范围策略需要实时查询或缓存失效机制。

细粒度授权通过 Keylo API 查询。

### 5.2 Token 类型收敛

现有类型继续保留：

| 类型 | 用途 |
| --- | --- |
| `access` | 用户、管理客户端访问 Keylo 或资源服务 |
| `refresh` | 换取新的 access token |
| `service_access` | 服务间调用 |

2.0 新增语义：

- 所有 token 都应能解析为 Principal。
- `service_access` 的 `sub` 应稳定映射到 `principal_type=service`。
- 管理客户端 token 应稳定映射到 `principal_type=client` 或受控的管理 Principal。

### 5.3 Refresh Token

Keylo 当前已支持 refresh token 哈希存储和数据库原子消费。2.0 应把 Keystone 的 refresh 会话设计吸收为后续增强方向：

- Refresh Token 继续只保存 hash，不保存明文。
- 每次刷新固定轮换 refresh token。
- 旧 refresh token 重放时撤销相关 refresh 会话，并写入审计日志。
- 管理客户端、用户客户端、桌面客户端应明确保存策略。
- Web/桌面客户端需要单飞刷新，避免并发刷新导致旧 token 被误判为重放。

建议增强：

1. 将 refresh token 记录扩展为 refresh session，关联 `principal_id`、`client_id`、`current_access_jti`、`issued_at`、`expires_at`、`revoked_at`。
2. 支持固定有效期和可选滚动有效期。
3. 支持按 Principal、client 或 session 撤销 refresh token。
4. 为用户登录链路补齐 refresh token 返回策略，解决当前普通用户 token 主要只返回 access token 的限制。

### 5.4 单账号和单主体会话

Keystone 的单账号登录设计可以迁移为 Keylo 的可配置会话策略。

建议支持：

| 策略 | 说明 |
| --- | --- |
| `multi_session` | 默认允许多会话 |
| `single_user_session` | 同一用户只允许一个在线会话 |
| `single_principal_session` | 同一 Principal 只允许一个在线会话，适用于高敏服务账号 |

实现原则：

- 在线状态不要只看短期 access token。
- 使用 refresh session 作为稳定会话索引。
- access token 过期后，是否允许重新登录由 refresh session、当前 access 状态和策略共同决定。
- 强制接管必须在认证成功后显式执行，不能只凭 `force=true` 绕过认证。

## 6. 授权 API 能力

### 6.1 权限检查

建议新增：

```http
POST /v1/authorize/check
```

用途：检查当前 token 对某资源动作是否有权限。

建议语义：

- 请求方携带 user access token 或 service access token。
- Keylo 从 token 解析 Principal。
- Keylo 基于 Principal 的 roles 和 permissions 计算结果。
- 返回 `allowed=true/false`，并可返回匹配到的权限 code。

建议新增批量接口：

```http
POST /v1/authorize/batch-check
```

用途：页面初始化、网关预检、服务批量能力判断。

### 6.2 最终权限查询

建议新增或泛化现有接口：

```http
GET /v1/principals/me/effective-permissions
GET /v1/admin/principals/{principal_id}/effective-permissions
```

当前 `GET /v1/admin/users/{user_id}/effective-permissions` 可保留兼容，并逐步改为调用统一 Principal 查询。

### 6.3 资源树查询

建议新增：

```http
GET /v1/principals/me/resource-tree?app=keystone&type=menu
GET /v1/principals/me/resource-tree?app=crawler&type=service
```

用途：

- 用户获取可见菜单树和按钮权限。
- 服务获取可调用服务能力目录。
- 管理控制台按角色预览授权结果。

### 6.4 Principal 管理

建议新增管理能力：

```http
GET    /v1/admin/principals
GET    /v1/admin/principals/{principal_id}
POST   /v1/admin/principals/{principal_id}/roles
DELETE /v1/admin/principals/{principal_id}/roles/{role_id}
GET    /v1/admin/principals/{principal_id}/roles
```

现有用户角色接口和未来服务角色接口都应逐步收敛到这组接口。

## 7. 数据模型演进计划

### 阶段性原则

1. 不修改已经执行过的 migration。
2. 新增迁移向前兼容。
3. 先引入新表和双写/回填，再切换查询路径。
4. 旧接口保留兼容窗口。

### 建议新增表

```text
principals
principal_roles
resources
resource_permissions
authorization_audit_logs
refresh_sessions
```

说明：

- `principals` 统一承载 user/service/client。
- `principal_roles` 替代长期的 `user_roles`。
- `resources` 承载菜单、按钮、API、服务能力和数据范围节点。
- `resource_permissions` 连接 resource 与 permission。
- `authorization_audit_logs` 记录关键授权检查、拒绝、角色变更。
- `refresh_sessions` 用于增强当前 refresh token 生命周期治理。

### 兼容现有表

| 现有表 | 2.0 处理 |
| --- | --- |
| `users` | 保留，作为 `principal_type=user` 的资料表 |
| `clients` | 保留，管理客户端映射为 `principal_type=client` |
| `service_clients` | 保留，服务客户端映射为 `principal_type=service` |
| `roles` | 保留，补充适用范围字段 |
| `permissions` | 保留，补充资源类型和命名规范 |
| `user_roles` | 保留兼容，逐步迁移到 `principal_roles` |
| `role_permissions` | 保留 |
| `refresh_tokens` | 保留，逐步增强为 refresh session 或与 `refresh_sessions` 关联 |

## 8. Keystone 设计引入计划

### 8.1 Token 集成经验

从 Keystone 吸收以下规则：

- 资源服务必须完整校验 Keylo token：签名、issuer、audience、时间声明、token type。
- `sub` 用于主体语义，`uid` 或 `principal_id` 用于稳定主键关联。
- 不能因为 bearer token 格式像 Keylo token 就信任它。
- Keylo token 直通全权限只允许存在于迁移期，不进入 2.0 最终模型。

Keylo 侧落地：

- 在官方集成文档和 SDK 示例中明确完整校验链路。
- 在 Keystone 接入方案中移除“校验通过即 `*:*:*`”的长期建议，替换为 Principal + RBAC 查询。
- 为 Spring Security、Axum、Express、Go middleware 示例补充权限检查接口调用。

### 8.2 Refresh Token 和会话

从 Keystone 吸收：

- refresh token 和 access token 职责分离。
- refresh token 服务端保存 hash。
- refresh token rotation 固定开启。
- token replay 触发撤销和审计。
- 客户端单飞刷新。
- 桌面客户端主动刷新。

Keylo 侧落地：

- 普通用户登录支持 refresh token。
- refresh session 记录 Principal、client、当前 access token、过期和撤销状态。
- 管理接口支持按 Principal 查询/撤销 session。
- API 文档明确 Web、桌面和服务端保存策略。

### 8.3 单账号登录

从 Keystone 吸收：

- 单账号不是默认全局规则，应作为可配置策略。
- 在线判断不能只依赖 access token 或短期缓存。
- 显式接管必须在认证通过后执行。

Keylo 侧落地：

- 默认保持多会话兼容。
- 对高安全部署提供 `single_user_session`。
- 对服务账号提供 `single_principal_session`。
- 所有拒绝、接管、撤销写入审计日志。

### 8.4 Secret 加密

从 Keystone 吸收并统一：

- 继续使用 `secret:v1:aes-256-gcm:<nonce>:<ciphertext>`。
- 数据库、Redis、服务密钥、管理客户端密钥都以密文或 hash 形式存储和注入。
- 明文数据库密码只允许用于容器首次初始化，初始化后应删除。
- Redis ACL 只保存密码 hash，Keylo 运行期读取 Redis 密文密码。

Keylo 侧落地：

- 继续维护 `scripts/secret_tool.py` 作为跨项目 secret 生成入口。
- 生产环境禁止 `DATABASE_PASSWORD` / `DATABASE_PASSWORD_FILE` 明文来源。
- 后续扩展服务客户端密钥导入时，提供一次性明文返回或密文文件导入，不在响应和日志中长期回显。

### 8.5 Keystone 菜单和数据权限

从 Keystone 吸收：

- 菜单权限 code 体系。
- 按角色绑定菜单/按钮权限。
- 数据范围模型：全部、自定义部门、本部门、本部门及子部门、仅本人。

Keylo 侧落地：

- 将菜单、按钮、API、服务能力统一建模为 resource。
- 将数据范围建模为 `resource_type=data_scope` 或 policy。
- Keystone 先通过同步/导入方式把菜单权限注册到 Keylo。
- Keystone 后端逐步改为消费 Keylo 授权结果。

## 9. 分阶段实施路线

### 阶段 0：文档和契约冻结

目标：

- 完成 Keylo 2.0 蓝图、开发计划和集成契约。
- 明确 Principal、Role、Permission、Resource 的术语。
- 更新第三方集成文档，标注 1.x 与 2.0 的差异。

验收：

- `docs/KEYLO_2_0_DEVELOPMENT_PLAN.md` 完成。
- `API_REFERENCE.md` 后续能按该计划补充 2.0 草案接口。

### 阶段 1：Principal 基础模型

目标：

- 新增 `principals` 和 `principal_roles`。
- 为现有 users、clients、service_clients 建立 Principal 映射。
- 保留 `user_roles`，新增路径优先写 `principal_roles`。

验收：

- 用户、服务、客户端都有 Principal。
- 可以给服务绑定角色。
- 原用户 RBAC 接口不破坏。

### 阶段 2：统一权限计算

目标：

- 新增统一 effective permissions 查询。
- 将用户权限和服务权限都从 Principal 计算。
- 现有用户 effective permissions 接口改为兼容包装。

验收：

- 用户和服务都能查询最终权限。
- 服务可以通过角色获得 permission。
- 未绑定角色的服务默认无权限。

### 阶段 3：资源树和菜单化授权

目标：

- 新增资源树模型。
- 支持 menu、button、api、service、data_scope 资源类型。
- 支持按 Principal 查询可见资源树。

验收：

- 用户可查询 Keystone 菜单树。
- 服务可查询服务能力目录。
- 资源树返回结果只包含已授权节点。

### 阶段 4：授权检查 API

目标：

- 新增单点和批量授权检查接口。
- 支持 user access token 和 service access token。
- 授权失败写审计日志。

验收：

- Keystone 可调用 Keylo 判断 `keystone:system:user:list`。
- 内部服务可调用 Keylo 判断 `service:crawler:invoke`。
- 批量检查满足页面初始化和网关预检。

### 阶段 5：Refresh Session 增强

目标：

- 将当前 refresh token 记录增强为 session 语义。
- 普通用户登录返回 refresh token。
- 支持按 Principal/session 撤销。
- 补充重放检测审计。

验收：

- 用户、管理客户端 refresh 行为一致。
- 旧 refresh token 重放只能成功一次，重复使用触发拒绝和审计。
- 支持查询和撤销 Principal 的活动 session。

### 阶段 6：单主体会话策略

目标：

- 增加可配置会话策略。
- 支持默认多会话、单用户会话、单 Principal 会话。
- 支持认证后显式接管。

验收：

- 默认部署保持兼容，多会话可用。
- 启用单用户策略后，同一用户第二次登录按策略拒绝或接管。
- 服务账号可限制为单活动 session。

### 阶段 7：Keystone 集成迁移

目标：

- Keystone 不再长期使用 Keylo bearer token 全权限临时主体。
- Keystone 通过 Keylo Principal + RBAC 获取权限。
- Keystone 菜单、按钮、数据范围逐步同步到 Keylo。

验收：

- Keystone token 和 Keylo token 都能定位 Principal。
- Keystone 权限判断由 Keylo 授权结果驱动。
- 未授权 Keylo service token 不能访问 Keystone 管理接口。

## 10. 测试计划

### 单元测试

- Principal subject 生成和解析。
- Principal 与 user/service/client 映射。
- Role assignable_to 校验。
- Permission 命名和资源绑定校验。
- Effective permissions 并集计算。
- Resource tree 过滤。
- Refresh token hash、rotation 和 replay。

### 集成测试

- 用户绑定角色后查询权限。
- 服务绑定角色后查询权限。
- 服务 token 调用授权检查。
- 用户 token 调用菜单资源树。
- 批量授权检查包含允许和拒绝结果。
- 未知 Principal 默认拒绝。
- 禁用 Principal 后 token introspection 或授权检查拒绝。
- Refresh token 并发刷新只有一个成功。
- 单用户会话策略拒绝第二次登录。
- 显式接管撤销旧 session。

### 兼容性测试

- 现有 `/api/rbac/users/{user_id}/roles` 行为不回归。
- 现有 `/v1/service/token` 签发逻辑不回归。
- 现有 `/v1/service/introspect` 行为不回归。
- 现有 `GET /v1/admin/users/{user_id}/effective-permissions` 返回兼容。
- 旧 `allowed_scopes` / `allowed_audiences` 仍约束 service token 签发。

### 集成方测试

- Keystone 使用 Keylo token 调用权限检查。
- Keystone 获取用户菜单资源树。
- Keystone 获取服务能力授权结果。
- Spring Security 示例完成 JWT 验签 + Keylo 授权检查。
- Axum/Node/Go 示例完成 service token 权限检查。

## 11. 发布与迁移策略

### 兼容原则

- 2.0 不一次性移除 1.x API。
- 新模型先并行引入，再逐步迁移调用路径。
- 旧数据通过 migration 和后台任务回填。
- 未回填完成前，旧 user RBAC 查询继续可用。

### 数据迁移顺序

1. 为所有 users 创建 `principal_type=user`。
2. 为所有 service_clients 创建 `principal_type=service`。
3. 为所有 clients 创建 `principal_type=client`。
4. 将 `user_roles` 回填到 `principal_roles`。
5. 将 Keystone 菜单权限导入 `permissions` 和 `resources`。
6. 验证新旧 effective permissions 一致。
7. 将查询路径切到 Principal。

### 回滚策略

- 每个阶段独立 migration 和代码提交。
- Principal 新表引入阶段不删除旧表。
- 授权查询切换前保留 feature flag。
- 如果 Keylo 授权中心不可用，Keystone 可临时回退本地权限，但应记录降级审计。

## 12. 验收标准

Keylo 2.0 第一阶段完成时，应满足：

1. 用户、服务、客户端都能映射为 Principal。
2. 用户和服务都能绑定角色。
3. 用户和服务都能通过统一接口查询最终权限。
4. 用户能获取菜单资源树。
5. 服务能获取服务能力资源树。
6. Keylo 能对用户 token 和 service token 执行统一授权检查。
7. Keystone 可以基于 Keylo 授权结果完成菜单、按钮和 API 权限判断。
8. Refresh Token 支持哈希存储、轮换、重放拒绝和审计。
9. 单用户或单主体会话策略可配置启用。
10. 所有生产 secret 继续遵循统一 AES-256-GCM 密文格式。

## 13. 非目标

Keylo 2.0 第一阶段不做以下事情：

- 不把 Keystone 整个后台系统搬进 Keylo。
- 不强制移除 Keystone 本地权限模型。
- 不要求所有资源服务同步改造。
- 不在 JWT 中塞完整权限列表或完整菜单树。
- 不把 `scope/audience` 立即废弃。
- 不支持无认证的授权检查。

## 14. 建议文档后续拆分

本计划落地后，建议继续拆出以下文档：

- `KEYLO_2_0_API_DRAFT.md`：2.0 API 草案。
- `KEYLO_2_0_SCHEMA_PLAN.md`：数据库迁移和回填计划。
- `KEYSTONE_KEYLO_2_0_MIGRATION.md`：Keystone 接入迁移方案。
- `KEYLO_2_0_CLIENT_GUIDE.md`：Web、桌面、服务客户端保存 token 和刷新策略。
- `KEYLO_2_0_AUTHZ_SDK_GUIDE.md`：Spring、Rust、Node、Go 授权中间件接入。
