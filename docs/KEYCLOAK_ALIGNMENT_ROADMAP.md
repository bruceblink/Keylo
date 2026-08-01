# Keylo 面向 Keycloak 的能力演进路线图

> 主线开发计划以本文档为准。`KEYLO_2_0_DEVELOPMENT_PLAN.md` 保留统一 Principal、RBAC、资源树和会话模型的设计细节，但不再单独决定阶段优先级；两份文档不一致时，以本文档的阶段、边界和验收条件为准。

## 1. 目的与边界

本计划以 Keycloak 作为成熟身份平台的能力参照，用于决定 Keylo 的后续投入；它**不**以功能数量追平 Keycloak 为目标。Keylo 的目标是成为可被通用客户端和外部系统接入的身份认证与授权中心，Keystone 只是首个使用方和集成验证对象。

Keylo 保持轻量统一身份、认证和授权中心的定位：

- 已有基础继续复用：RS256 JWT、JWKS、Principal、RBAC、资源树、服务凭证、Refresh Session、审计日志和密文配置。
- 认证负责确认主体身份；授权继续由 Keylo 的 Principal + RBAC + 资源权限模型负责。
- 不引入与实际客户需求无关的复杂部署模型、脚本式策略语言或完整 Keycloak Realm 复制品。

### 1.1 术语

| 术语 | 含义 |
| --- | --- |
| OIDC | OpenID Connect。建立在 OAuth 2.0 之上的身份认证协议，规定浏览器/移动端如何安全登录并获得身份信息。 |
| OIDC Provider | 对外提供标准 OIDC 登录、Token、UserInfo 和 Discovery 接口的身份服务。 |
| Upstream Identity Provider | Keylo 作为客户端接入的外部身份源，例如企业 OIDC、LDAP 或 GitHub。 |
| MFA | Multi-Factor Authentication，多因素认证；除密码外再要求一次独立验证。 |
| Passkey | 基于 WebAuthn 的公私钥登录凭据，可替代或增强密码登录。 |
| SCIM | 用于企业目录自动创建、更新、禁用用户和组的标准协议。 |
| Tenant / Organization | 隔离的组织边界；其成员、客户端、资源、角色和审计数据不能互相访问。 |

### 1.2 OIDC 的决策原则

Keylo 面向通用身份中心定位，因此 OIDC Provider 是主线 P0：陌生第三方应用、浏览器 SPA、移动端和企业系统应能按公开标准接入，不应依赖 Keylo 专用 Token API。

现有自定义 Token API 在迁移期继续兼容；OIDC 不替代 JWT/JWKS 或 Principal RBAC。OIDC 负责标准化登录与身份声明，Keylo 继续负责签名、会话、主体和授权决策。

## 2. 当前基线

| 领域 | 已有能力 | 当前缺口 |
| --- | --- | --- |
| 主体与授权 | Principal、角色、权限、资源树、单点/批量授权检查 | 数据范围与上下文条件尚未形成受控策略模型。 |
| Token 与会话 | RS256、JWKS、服务 Token、OIDC 授权码、PKCE、Refresh Session 原子轮换与重放撤销 | 标准测试 IdP 的端到端兼容矩阵仍需持续覆盖。 |
| 外部身份 | OAuth 登录、OIDC upstream Discovery/回调/UserInfo、claim 映射、JIT、关联/解除关联；上游 subject 仅以 SHA-256 映射键持久化 | LDAP、SCIM 等目录生命周期能力尚未进入范围。 |
| 安全 | 密码策略、限流、审计、密钥轮换、TOTP MFA、恢复码、敏感操作二次认证 | Passkey 与企业目录生命周期由明确需求触发。 |
| 运维 | health/ready 检查、结构化日志、审计日志、`/metrics` Prometheus HTTP/认证结果/refresh replay/限流拒绝与数据库/Redis 就绪探针延迟及成功/失败指标 | 缺少业务数据库/Redis 操作延迟、分布式追踪、事件投递与 HA 演练基线。 |

### 2.1 当前进度对齐（2026-08-01）

| 路线图阶段 | 当前状态 | 对齐结论 |
| --- | --- | --- |
| 阶段 A：标准 OIDC 接入 | 核心实现基本完成 | Discovery、Authorization Code、PKCE、state/nonce、ID Token、UserInfo、浏览器会话和退出已具备；真实标准客户端兼容矩阵仍需补齐。 |
| 阶段 B：账户安全与身份联邦 | 实现基本完成，验收未闭环 | TOTP、恢复码、MFA 审计、OIDC upstream、JIT、关联/解除关联和会话撤销已具备；下一主线是标准 Keycloak IdP 端到端矩阵。 |
| 阶段 C：授权治理与组织隔离 | 基础授权已具备，阶段目标未启动 | Principal/RBAC/资源树/授权检查不等于组织隔离；组织、数据范围、上下文条件和决策版本暂不进入主线。 |
| 阶段 D：企业生命周期与运行治理 | 尚未启动 | SCIM、Outbox/Webhook、OpenTelemetry、延迟指标和 HA 演练等待阶段 C 或明确客户需求。 |

当前主线准入条件：在阶段 B 的 Keycloak 标准测试 IdP 兼容矩阵完成并留存脱敏执行记录前，不推进阶段 C/D 的大范围能力扩张。

## 3. 分阶段计划

### 阶段 A：标准 OIDC 接入

**目标：** 让标准 Web、SPA 和移动端客户端能把 Keylo 当作 OIDC Provider 安全接入。

范围：

1. 实现 OIDC Discovery、客户端注册模型、Authorization Code Flow、PKCE、`state`、`nonce`、ID Token 和 UserInfo。
2. 精确校验 redirect URI、允许的 grant、Token 生命周期、客户端认证方式、受信任来源与禁用状态。
3. 建立浏览器登录会话、授权同意或明确的自动授权规则、授权码一次性消费和退出边界。
4. 提供 Node、Spring、Go、Rust 的最小标准 OIDC 接入样例，并用真实标准客户端库做兼容验证。

验收：

- 通用 OIDC 客户端库无需 Keylo 专用适配即可完成授权码 + PKCE 登录。
- 非法 redirect URI、缺少/错误 PKCE、重放 code、错误 `state` 或 `nonce` 均被拒绝。
- ID Token 的 `iss`、`aud`、`exp`、`nonce` 和签名可由独立客户端验证。
- OIDC 登录得到的主体继续通过现有 Principal RBAC 授权，不产生双套权限模型。

暂不做：Device Flow、CIBA、PAR、DPoP、Token Exchange；这些由明确协议客户需求触发。

### 阶段 B：账户安全与身份联邦

**目标：** 降低账号接管风险，并让 Keylo 能联邦接入外部身份源。

范围：

1. 实现 TOTP MFA、一次性恢复码、MFA 启用/重置审计，以及管理员强制 MFA 策略。
2. 为改密、重置密码、禁用用户、修改角色和导出审计等敏感操作增加近期 MFA 校验。
3. 实现 OIDC upstream 登录执行链路：Discovery、授权码回调、claim 映射、JIT 创建、账号关联与解除关联。
4. 统一外部账号的禁用、冲突和邮箱变更处理规则。

验收：

- 用户可启用、验证和恢复 TOTP；恢复码仅可使用一次。
- 未完成 MFA 的高风险操作返回明确拒绝，不产生部分修改。
- 可通过一个标准 OIDC 测试 IdP 完成首次登录、重复登录、账号关联和禁用后的拒绝登录。
- 每个安全状态变化都有可检索审计记录，审计中不含密钥、验证码或恢复码明文。

暂不做：SAML、Passkey、SCIM、通用规则引擎和多租户。

### 阶段 C：授权治理与组织隔离

**目标：** 在不破坏现有 RBAC 简洁性的前提下，支持真实的组织边界与数据范围。

范围：

1. 仅在存在多组织 SaaS 或独立客户隔离需求时，引入 `organization`、成员关系、资源/客户端归属和跨组织拒绝规则。
2. 为资源增加受控条件：组织、资源所有者、部门/数据范围和操作上下文。
3. 为角色、权限、资源绑定增加版本、变更原因和回滚能力。
4. 为授权检查提供稳定 decision contract，并记录允许/拒绝原因的可审计摘要。

验收：

- 不同组织的管理员不能枚举、修改或授权对方组织的对象。
- 条件权限必须在服务端授权检查中生效，不能只依赖前端隐藏。
- 权限变更可追溯到操作者、时间、原因和前后差异。
- 现有无组织的部署可通过默认组织或显式迁移保持兼容。

暂不做：可执行脚本策略、任意表达式求值和完整 Realm 层级；它们会扩大安全审计面与维护成本。

### 阶段 D：企业生命周期与运行治理

**目标：** 让企业目录、审计和多实例运行可被稳定运营。

范围：

1. 依据客户需求实现 SCIM 2.0 用户/组 provisioning，并定义禁用、删除、角色回收和冲突处理语义。
2. 扩展现有 Prometheus 基线并引入 OpenTelemetry Trace：当前已提供 HTTP、认证成功/失败、刷新重放和授权拒绝的固定基数指标；后续补齐限流、数据库/Redis 延迟、按客户端/身份源的受控维度与 Trace。
3. 使用 outbox 发布安全事件；Webhook 必须包含签名、重试、幂等键、死信和投递审计。
4. 完成多实例部署契约：Redis/数据库依赖、JWKS key 保留窗口、滚动迁移、备份恢复与故障演练。

验收：

- SCIM 重复请求幂等，离职/禁用会撤销活动 Refresh Session 与服务访问边界。
- 仪表盘可按客户端、身份源和错误类型观察成功率、P95 延迟及拒绝趋势。
- Webhook 接收方故障不会阻塞登录请求，失败事件可重放且不会重复产生业务副作用。
- 按演练手册可完成单实例故障、密钥轮换和数据库恢复验证。

## 4. Passkey、SAML 与其他能力的触发条件

| 能力 | 开始条件 | 不应开始的情形 |
| --- | --- | --- |
| Passkey/WebAuthn | 管理员账号安全要求提升，或用户需要无密码体验 | MFA 基线和账户恢复尚未完成。 |
| SAML | 已签约企业只提供 SAML IdP | 仅为“协议齐全”而实现。 |
| SCIM | 企业目录需要自动入离职、组同步 | 用户规模小且人工管理成本可接受。 |
| 多租户 | Keylo 承载多个相互隔离的客户组织 | 单一内部组织部署。 |
| Device Flow、DPoP、Token Exchange | 有 CLI、受限设备或特定零信任/委托场景 | 没有明确客户端和威胁模型。 |

## 5. 实施规则

1. 一个阶段拆分为可独立验证的小功能；每个功能通过对应测试后单独提交。
2. 所有协议实现以规范测试向量和真实客户端集成为验收依据，不能只以自研接口测试代替。
3. 新增安全状态、会话和身份关联必须有迁移方案、审计事件和回滚规则。
4. 不在 JWT 中塞入高频变化的完整权限集合；JWT 证明主体，Keylo 授权接口和资源服务策略决定访问。
5. 在实现新协议前先写清客户端类型、威胁模型、兼容性边界和撤销语义；没有这些输入的能力进入待定池。

## 6. 建议的下一项工作

实施阶段 B 的验收项：**标准 OIDC 测试 IdP 兼容矩阵**。覆盖首次登录、重复登录、UserInfo 补充声明、邮箱变化、禁用用户/身份源和 refresh session 撤销，确保联邦链路的安全规则可被真实标准客户端复现。

### 6.1 标准 IdP 矩阵执行契约

本矩阵以当前受支持的 Keycloak 发行版作为标准 OIDC upstream IdP。它是对模型与 HTTP handler 测试的补充，不以本地 mock 结果替代。执行环境必须满足：

1. Keycloak 和 Keylo 都使用可被对方验证的 HTTPS issuer；Keylo 的上游身份源配置不允许生产环境使用 HTTP issuer。
2. Keycloak client 使用 Authorization Code Flow，启用 Standard Flow，登记 Keylo 的精确 HTTPS callback URL，并采用 `client_secret_basic` 与 RS256 ID Token。
3. Keycloak realm 配置提供 `openid profile email`，其中 UserInfo 补充场景需要把 email、email_verified 或映射的自定义 profile claim 仅放入 UserInfo。
4. 运行记录必须包含 Keycloak 镜像 digest/版本、Keylo commit、已脱敏的 realm/client 配置和每个场景的 HTTP 结果；不得记录 client secret、授权码、access token、refresh token 或 ID Token 明文。

| 场景 | 预期结果 | 安全断言 |
| --- | --- | --- |
| 首次登录（JIT） | 创建无密码本地用户并建立不可改绑 `(source, sub)` 映射 | 映射与审计中不出现 token 或上游 subject 明文。 |
| 重复登录 | 复用同一用户和映射 | 不重复创建用户或覆盖映射。 |
| UserInfo 补充声明 | 仅补齐 ID Token 缺失 profile 字段 | UserInfo `sub` 必须等于已验证 ID Token `sub`，不能覆盖签名声明。 |
| 上游邮箱变化 | 继续按稳定 `sub` 登录并记录观察事件 | 不自动改写 Keylo 本地邮箱。 |
| 禁用 Keylo 用户 | 已有 access token 的受保护请求被拒绝 | 所有该用户 refresh session 已撤销。 |
| 禁用 OIDC 身份源 | 新回调被拒绝 | 该来源 refresh session 已撤销，审计包含来源与撤销数量。 |

镜像源、网络或 TLS 前置条件不可用时，矩阵应报告为“未执行”，不能以单元测试或模拟 IdP 声称该验收已完成。
