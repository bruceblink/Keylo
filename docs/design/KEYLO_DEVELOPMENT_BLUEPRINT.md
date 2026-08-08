# Keylo 主线开发与核心设计

> 本文是 Keylo 唯一的主线开发与核心设计文档。它定义产品边界、当前能力、核心授权模型、近期优先级和后续能力的准入条件。专题接口、部署与集成细节以本文末尾的专题文档为准。

## 1. 产品定位

Keylo 是轻量、可扩展的通用认证与授权中心。它让 Web、移动端、桌面客户端、资源服务和内部服务能以公开协议或稳定 HTTP 契约完成身份认证与授权判断。

当前主线是让 Keylo **更好用、更易用**：独立团队应能更快理解边界、更少手工配置地完成部署和接入，并在失败时定位下一步动作。Keystone 是首个接入方和回归样本，不是 Keylo 的功能边界或专用依赖。

Keycloak 是协议、安全实践和可选互操作回归的参照，不是待追平的产品规格。Keylo 只吸收标准互通、安全默认值、会话/密钥生命周期、审计可追溯性和清晰管理边界；不复制完整 Realm 层级、脚本策略语言或无使用方的重型运维能力。

## 2. 核心边界

| 范围 | Keylo 负责 | 不作为默认主线 |
| --- | --- | --- |
| 认证 | OIDC Provider、密码、MFA、外部 OIDC 身份源、Token 与会话 | 为“协议齐全”实现 SAML、Passkey、Device Flow、CIBA、PAR、DPoP 或 Token Exchange |
| 授权 | Principal、RBAC、资源树、单点/批量授权决策、审计 | 任意表达式求值、脚本式策略引擎、完整 Realm 复制 |
| 集成 | OIDC Discovery、JWKS、标准客户端样例、授权决策接口 | Keylo 专用的客户端锁定或 Keystone 专用数据模型 |
| 运行 | health/ready、指标、密文配置、密钥和会话治理 | 无明确部署要求的事件平台、多租户和 HA 拓扑 |

默认使用 HTTPS。完全隔离的内网可以显式启用 HTTP issuer，但 Keylo、反向代理、身份源和浏览器客户端必须都处于受控网络；HTTP 流量不得跨越公网、共享办公网或不受控 Wi-Fi。内网 HTTP 验收不能代替互联网或第三方接入的 HTTPS 验收。

## 3. 当前能力基线

| 领域 | 已交付能力 | 持续门槛 |
| --- | --- | --- |
| 标准 OIDC | Discovery、Authorization Code、PKCE、`state`、`nonce`、ID Token、UserInfo、浏览器会话和退出 | 标准 `openidconnect` 真实 HTTP 集成测试及 Node、Go、Rust、Spring RP 样例持续通过 |
| 账户安全与联邦 | 密码策略、限流、TOTP、恢复码、敏感操作 MFA、邮箱验证状态（可信上游/管理员复核）、OIDC upstream、JIT、账号关联/解除关联 | 安全状态变化可审计，不记录 Token、验证码或密钥明文；本地邮箱变更必须重置验证状态 |
| 授权 | Principal、角色、权限、资源树、单点/批量检查、决策原因、变更版本和回滚 | 未知/禁用 Principal、无角色或无权限默认拒绝 |
| Token 与会话 | RS256、JWKS、服务 Token、Refresh Session 原子轮换和重放撤销 | JWT 证明主体与 audience，不承载高频变化的完整权限集合 |
| 运行 | health/ready、Prometheus 指标、审计、密文配置、密钥轮换 | 数据库和 Redis 的生产依赖、失败路径与配置边界可验证 |

已完成的 OIDC 与账户安全能力是发布基线，不因可选 Keycloak 矩阵的镜像、网络或 TLS 环境缺失而被阻塞。

## 4. 核心技术设计

### 4.1 主体与授权模型

`Principal` 是 Keylo 的统一安全主体。用户、服务账号和客户端均映射为 Principal；认证链路确认主体身份，授权链路只消费 Principal 和 RBAC 关系。

| 模型 | 作用 | 关键规则 |
| --- | --- | --- |
| Principal | `user`、`service`、`client` 的统一身份 | `subject` 稳定进入 JWT `sub`；禁用主体默认拒绝 |
| Role | 可绑定给适用类型 Principal 的权限集合 | `assignable_to` 限制绑定对象；系统角色不可被普通操作破坏 |
| Permission | 对外稳定的业务权限点 | 推荐命名为 `{app}:{resource}:{action}`，例如 `keystone:system:user:list` |
| Resource | 菜单、按钮、API、服务能力或数据范围的统一表达 | 资源树用于展示和预检，不替代服务端最终授权 |

授权链路固定为：

```text
principal -> roles -> permissions -> resources/actions
```

`allowed_scopes` 和 `allowed_audiences` 继续约束服务 Token 的签发边界；它们不替代业务授权。JWT 校验通过只说明主体和目标 audience 合法，资源服务仍需按权限或资源向 Keylo 请求最终授权决策。

### 4.2 Token 与会话边界

| Token | 用途 | 规则 |
| --- | --- | --- |
| `access` | 用户或管理客户端访问 Keylo/资源服务 | 校验签名、issuer、audience、时效和 `token_type` |
| `refresh` | 换取新 access token | 仅安全保存；每次使用原子轮换，重放撤销所属会话 |
| `service_access` | 服务间访问 | 先满足 scope/audience 白名单，再由服务 Principal 的 RBAC 判定能力 |

Refresh Session 是稳定会话索引，支持按 Principal 或单个会话撤销。会话策略可以是多会话、单用户会话或单主体会话；显式接管必须先完成认证。

### 4.3 资源服务接入边界

资源服务的推荐顺序：

1. 通过 Discovery/JWKS 本地验证 JWT 的签名、issuer、audience、过期时间和 token 类型。
2. 对细粒度或高敏操作调用 `POST /v1/authorize/check` 或 `/v1/authorize/batch-check`。
3. 对 `allowed=false` 返回 403；Keylo 不可用时不得把验签成功升级为业务权限。
4. 资源树只用于菜单、按钮和能力展示，后端 API 必须重复最终授权判断。

Spring、Node、Go、Rust 样例与授权决策契约见专题集成文档。

## 5. 近期主线：2.1 易用性与可用性

近期不以新增协议数量为目标，而是降低部署、配置、接入、授权建模和排障成本。每项工作都必须说明它减少了谁的哪一步操作，以及如何验证效果。

### P0：自助参考接入

1. 建立从部署到登录、授权检查、退出和会话撤销的可重复验收路径。
2. 为主流技术栈提供可直接运行的最小样例；样例必须表达完整验签和最终授权边界。
3. 为接入失败提供可定位的响应、审计查询路径和最小排障手册。

**完成标准：** 新环境能按文档完成端到端接入；关键拒绝场景能从客户端响应和审计定位；不新增 Keystone 专用协议或数据模型。

### P0：自助部署与运行基线

1. 明确配置校验、依赖就绪、密钥加载、HTTPS 默认要求和受控内网 HTTP 边界。
2. 用可执行步骤验证数据库迁移、密钥轮换、备份恢复和失败回退。
3. 将 health/ready、指标和审计组织成面向运维的最小诊断路径。
4. 优先把启动失败和不安全配置转换为可行动的提示，而不是要求使用者从源码推断原因。

**完成标准：** 支持环境可重复完成部署、升级、密钥轮换和恢复演练；未支持的 HA 或跨公网 HTTP 场景在文档和启动校验中明确拒绝或警示。

### P1：管理与接入反馈闭环

至少一个真实接入方完成后，记录客户端类型、主体数量、组织边界、身份来源、合规要求、威胁模型、预期协议、实际操作步骤和验收场景。优先修复重复出现的配置、授权建模或排障摩擦，不因单次愿望直接扩展平台能力。

## 6. 需求触发的扩展路线

下列能力没有默认排期；同一周期只启动一个明确触发方向。

| 触发信号 | 最小交付范围 | 明确不做 |
| --- | --- | --- |
| 两个及以上相互隔离的客户组织 | `organization`、成员关系、对象归属、跨组织默认拒绝和兼容迁移 | Realm 复制、任意策略脚本 |
| 资源服务需要所有者、部门或业务上下文 | 固定条件类型、服务端决策和审计原因 | 通用表达式引擎 |
| 企业目录自动入离职或组同步 | SCIM 用户/组 provisioning、禁用和会话撤销语义 | 未定义冲突语义的全量同步 |
| 已签约客户只能提供 SAML | 单一明确的 SP 或 IdP 场景和回归样例 | 为协议数量实现的通用 SAML 平台 |
| 管理员无密码或抗钓鱼需求 | 管理员 WebAuthn 注册、登录和恢复路径 | 未验证恢复流程的全员强制切换 |
| CLI、受限设备或受委托访问 | 在 Device Flow、DPoP、Token Exchange 中选择一项 | 多项并行实现 |
| 多实例运行或外部安全事件消费 | 一项可验证的 Trace、Outbox/Webhook 或 HA 演练 | 未验证的分布式平台改造 |

## 7. 交付规则

1. 安全、数据隔离和标准 OIDC 互操作问题优先于所有新增功能。
2. 每个小功能应有风险匹配的自动验证；验证通过后独立提交。
3. 新安全状态、会话、身份关联或数据迁移必须定义审计事件、回滚语义和兼容边界。
4. 新协议或企业能力开始前先写清客户端类型、威胁模型、撤销语义和验收场景；信息不足时保留在候选池。
5. 标准测试向量、真实 HTTP 集成测试和公开样例是协议发布门槛；Keycloak 矩阵是可选代表性互操作回归。

## 8. 专题文档

| 主题 | 权威文档 |
| --- | --- |
| API 请求、响应和错误语义 | [API_REFERENCE.md](../reference/API_REFERENCE.md) |
| 从零开始部署与联调 | [END_TO_END_QUICKSTART.md](../guides/END_TO_END_QUICKSTART.md) |
| 当前密钥和运行边界 | [SECRET_ENCRYPTION.md](../operations/SECRET_ENCRYPTION.md) 与 [KEY_ROTATION.md](../operations/KEY_ROTATION.md) |
| 第三方/资源服务接入 | [THIRD_PARTY_INTEGRATION.md](../integrations/THIRD_PARTY_INTEGRATION.md) 与 [integrations/README.md](../integrations/README.md) |
| Keystone 迁移 | [keystone.md](../integrations/keystone.md) |
| 客户端 Token 与会话保存 | [KEYLO_2_0_CLIENT_GUIDE.md](../reference/KEYLO_2_0_CLIENT_GUIDE.md) |
| 安装向导 | [SETUP_WIZARD_DESIGN.md](SETUP_WIZARD_DESIGN.md) |
| Keycloak OIDC 可选互操作矩阵 | [KEYCLOAK_OIDC_MATRIX.md](../compatibility/KEYCLOAK_OIDC_MATRIX.md) |

旧版生产部署说明已移至 `docs/archive/deployment/`，不作为当前部署依据。

历史发布说明保留在 `RELEASE_*.md`，不参与主线规划决策。
