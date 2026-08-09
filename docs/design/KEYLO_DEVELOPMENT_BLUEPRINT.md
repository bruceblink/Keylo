# Keylo 主线设计与能力边界（审查版）

> 审查日期：2026-08-09
>
> 本文是 Keylo 当前唯一的主线设计文档，负责产品定位、能力取舍、当前代码基线和核心安全模型。后续开发任务、优先级、验收命令和触发条件独立维护在 [KEYLO_FOLLOW_UP_DEVELOPMENT_PLAN.md](../plans/KEYLO_FOLLOW_UP_DEVELOPMENT_PLAN.md)。docs/archive/ 只保留历史上下文，不作为新的开发或部署依据。

## 0. 审查结论

本轮审查确认：Keylo 以 Keycloak 作为协议、安全和互操作参照，而不是把 Keycloak 的全部能力搬进来，这个方向是正确的。Keycloak 官方能力覆盖 OIDC、OAuth、SAML、身份代理、LDAP/AD、用户和账户控制台、灵活认证、会话治理、管理 API 以及更细粒度的管理权限；这些能力证明了 IAM 产品需要解决的边界，但不代表每个部署都应该承担同样的复杂度。

Keylo 采用“先通用 IAM 和可用性，再以 SaaS 组织隔离为下一条主线”的策略：

1. 保留标准互操作和安全生命周期，把它们做成可验证的稳定契约。
2. 使用 Principal、RBAC、资源和显式授权决策表达通用授权，不复制 Realm 层级和任意策略语言。
3. 保留 OIDC 上游身份代理和账号关联这一类高复用能力，但不为了协议数量预先实现 SAML、Device Flow、CIBA、PAR、DPoP 或 Token Exchange。
4. 先提供 API-first 的安装、接入和排障体验；完整管理控制台、主题系统和工作流引擎不属于默认核心。
5. 组织是 SaaS 主线的确定能力；人类用户与非人类机器主体分开治理，机器可用 API key 调用明确声明的 API；目录同步、企业协议、抗钓鱼认证或多实例运行仍按真实信号触发。

审查参考：

- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak OIDC layers](https://www.keycloak.org/securing-apps/oidc-layers)
- [Keycloak feature flags](https://www.keycloak.org/server/features)

### 0.1 取其精华

| Keycloak 的可复用经验 | Keylo 的落地方式 | 当前状态 |
| --- | --- | --- |
| 标准 OIDC/OAuth 和浏览器 SSO | Discovery、Authorization Code + PKCE、UserInfo、consent、浏览器会话、退出和标准错误 | 已实现并有真实 HTTP 测试 |
| 身份代理和首次登录关联 | OIDC upstream、JIT、稳定 external subject、账号关联/解除关联和上游会话撤销 | OIDC upstream 已实现 |
| Token、密钥和会话生命周期 | RS256/JWKS、audience 约束、refresh session 原子轮换、重放撤销、按主体撤销、组织作用域撤销和审计 | 已实现；JWT 支持 active/passive overlap、轮换、回滚、下线和审计 |
| 服务账号与 client credentials | 将非人类调用映射到稳定 service Principal、scope/audience 和可撤销凭证；API key 只作为受限的直连便利，不替代 OIDC | 已实现 `service_id + service_secret -> service_access`；直接 API key 仍属于下一条主线 |
| 最小权限管理 | Principal、角色、权限、资源树、单点/批量授权检查、变更历史和拒绝原因为审计 | 已实现；暂不做任意策略引擎 |
| 安全默认值 | 精确 redirect URI、PKCE、HTTPS 默认、限流、登录锁定、MFA、密文配置、失败关闭 | 已实现并持续加固 |
| 运维可追溯性 | healthz、readyz、固定基数 Prometheus 指标、审计日志、迁移和 setup 状态 | 已实现并纳入发布门槛 |

### 0.2 明确不复制的复杂度

| Keycloak 能力或复杂度 | Keylo 的默认决策 | 只有出现什么信号才重新评估 |
| --- | --- | --- |
| master Realm、Realm 复制和跨 Realm 管理 | 采用单部署多组织模型；组织边界由数据、成员关系和组织作用域 RBAC 强制，不复制 Realm 层级 | 需要物理隔离、独立密钥或独立合规域时评估独立部署 |
| Groups、composite roles、细粒度管理员策略和策略脚本 | 继续使用固定 RBAC、资源和少量显式条件；不允许运行任意表达式或脚本 | 管理员团队需要被限制到不同客户、应用或资源子集 |
| 完整 Admin Console、Account Console、主题和可编排认证流 | 保持 API-first；setup wizard 只负责首启和诊断，先提供组织/成员/组织角色管理 API | 多个接入方重复实现同一套管理界面且 API 已稳定 |
| SAML、Kerberos、X.509、Passkey 等认证协议 | 不因兼容矩阵而排期 | 合同或明确安全政策只允许某一协议 |
| LDAP/AD 用户联邦和全量同步 | 当前只保留 identity source 注册元数据；不宣称已经支持 LDAP 登录 | 客户需要目录认证或入离职同步，并能提供测试目录 |
| SCIM、工作流、事件 SPI、插件平台 | 不预建通用平台 | 真实 IdP/HR 系统要求 provisioning、自动禁用或事件消费 |
| Device Flow、CIBA、PAR、DPoP、Token Exchange | 同一周期最多选择一个具体场景 | CLI、受限设备、委托访问或 FAPI 合规要求已确定 |
| 长生命周期机器凭证 | 支持受限的 machine Principal 与 API key；密钥只代表机器身份，不模拟用户登录，不默认授予平台权限 | 需要 OAuth Device Authorization Grant 让人类绑定受限设备时，再单独评估 Device Flow |
| 多站点 HA、分布式 outbox 和全链路 tracing | 先保证单实例数据库模式可恢复 | 多实例流量、跨可用区或外部安全事件消费成为发布条件 |

## 1. 产品定位

Keylo 是轻量、可扩展的通用认证与授权中心。它让 Web、移动端、桌面客户端、资源服务和内部服务能以公开协议或稳定 HTTP 契约完成身份认证与授权判断。

当前主线是让 Keylo 更好用、更易用，并为 SaaS 多组织做好基础：独立团队应能更快理解边界、更少手工配置地完成部署和接入，在组织边界内管理成员和权限，并在失败时定位下一步动作。Keystone 是首个接入方和回归样本，不是 Keylo 的功能边界或专用依赖。

Keycloak 是协议、安全实践和可选互操作回归的参照，不是待追平的产品规格。Keylo 只吸收标准互通、安全默认值、会话/密钥生命周期、审计可追溯性和清晰管理边界；不复制完整 Realm 层级、脚本策略语言或无使用方的重型运维能力。

## 2. 核心边界

| 范围 | Keylo 负责 | 不作为默认主线 |
| --- | --- | --- |
| 认证 | OIDC Provider、密码、MFA、OAuth 社交登录、OIDC upstream 身份代理、机器主体的 service_access/API key、Token 与会话 | 为“协议齐全”实现 SAML、Kerberos、X.509、Passkey、Device Flow、CIBA、PAR、DPoP 或 Token Exchange |
| 身份源 | local_password、oauth2、oidc_upstream 和 ldap 的注册元数据；OIDC upstream 的 Discovery、授权码、JIT 和关联 | 把 ldap 注册项描述成已经可用的目录登录；未触发时不做 LDAP/AD 联邦和 SCIM |
| 组织 | SaaS organization、成员关系、组织状态、组织作用域 RBAC 和跨组织默认拒绝 | 不做 Realm 复制、计费、套餐、市场和任意组织策略脚本 |
| 授权 | Principal、RBAC、资源树、单点/批量授权决策、审计和变更历史 | 任意表达式求值、脚本式策略引擎、Realm 复制和默认多租户 |
| 集成 | OIDC Discovery、JWKS、标准客户端样例、授权决策接口、服务 Token 和受限机器 API | Keylo 专用的客户端锁定或 Keystone 专用数据模型 |
| 运行 | PostgreSQL 迁移、Redis 生产依赖、health/ready、指标、密文配置、审计、setup wizard | 没有多实例证据时的 HA 拓扑、事件平台和完整管理后台 |

默认使用 HTTPS。完全隔离的内网可以显式启用 HTTP issuer，但 Keylo、反向代理、身份源和浏览器客户端必须都处于受控网络；HTTP 流量不得跨越公网、共享办公网或不受控 Wi-Fi。内网 HTTP 验收不能代替互联网或第三方接入的 HTTPS 验收。

## 3. 当前代码能力基线

下表按 2026-08-10 的源码、迁移和测试核对，不把历史发布说明当作现状。

| 领域 | 当前代码能力 | 仍然存在的边界 |
| --- | --- | --- |
| 标准 OIDC | Discovery、Authorization Code、PKCE、state、nonce、ID Token、UserInfo、consent、浏览器会话、退出、confidential/public client 和 secret rotation；relying party client 支持显式 platform/organization scope | 只发布 authorization_code；组织 client 需要 owner/admin 的 active organization context；没有 Dynamic Client Registration、OIDC token revocation、Device/CIBA/PAR/DPoP |
| 本地账户 | 注册、密码登录、密码复杂度、限流、登录锁定、用户/管理员密码修改或重置、email_verified 状态 | 没有 SMTP 或其他邮件投递；验证邮箱目前由可信上游或完成近期 MFA 的管理员触发；没有用户自助 forgot-password 邮件流程 |
| MFA | TOTP enrollment、近期验证、恢复码、敏感管理操作的 step-up 和审计 | 没有 WebAuthn/Passkey；不把 TOTP 自动扩展成任意认证流编排 |
| 外部身份 | OAuth provider 登录和账号关联；OIDC upstream Discovery、PKCE、JWKS、UserInfo、JIT、subject 映射、显式 user class/fixed organization 策略、邮箱变化记录、启停和会话撤销 | identity source 的 ldap 类型目前只是注册元数据，不包含 LDAP bind、同步、组映射或故障切换 |
| 非人类调用 | `service_clients` 使用 `service_id + service_secret` 换取短期 `service_access`；service/device Principal 都可绑定多个 API key，显式为 platform 或单一 organization scope，组织调用每次实时重验组织与 membership | API key 只开放给明确声明的授权检查 API；不支持把 API key 作为人类 Bearer Token |
| 授权 | Principal 类型 user/service/client；角色、权限、资源树；单点/批量 check；服务 scope/audience 白名单；授权审计、版本和回滚 | platform 与 organization 角色按 signed active context 分开决策，资源按 organization_id 过滤；组、composite role 和细粒度 delegated admin 仍未实现 |
| SaaS 组织基础 | `organizations`、`user_class`、成员关系、组织角色绑定、资源、refresh session、OIDC client、service client、identity source 和 device/API key scope 已迁移；新用户默认 external_customer，bootstrap super admin 显式归为 internal_employee 并加入内部组织；平台与组织成员管理 API 已可用 | organization role binding 和 organization OIDC client 管理只在同一 signed active context 中生效 |
| Token 与会话 | RS256/JWKS、access/refresh/service_access、内省、黑名单、refresh session 原子轮换、重放撤销、主体/客户端/单会话撤销 | 人类密码登录可显式建立 organization-scoped refresh session，生命周期会撤销该 scope；JWKS 在 overlap 窗口内同时发布 active 与 passive 公钥 |
| 运行和首启 | PostgreSQL SQLx migrations、Redis 生产就绪校验、healthz/readyz、固定基数 metrics、审计清理、密文配置、setup wizard | 尚未承诺多实例一致性、outbox/webhook、OpenTelemetry 或跨区域恢复 |
| 管理体验 | API-first 的用户、客户端、服务、身份源、Principal、RBAC、资源和审计接口；setup wizard 只做首启诊断 | 没有 Admin Console、Account Console、主题系统或管理 CLI |

## 4. 核心技术设计

### 4.1 主体与授权模型

Principal 是 Keylo 的统一安全主体。人类用户、服务/设备机器主体和协议客户端均映射为 Principal；认证链路确认主体身份，授权链路只消费 Principal 和 RBAC 关系。机器主体不走浏览器登录，也不创建人类用户会话。

| 模型 | 作用 | 关键规则 |
| --- | --- | --- |
| Principal | `user`、`service`、`device`、`client` 的统一身份；device 以 immutable platform/organization scope 记录 | subject 稳定进入 JWT sub；禁用主体默认拒绝 |
| User class | user Principal 的账户类别 | 当前至少为 internal_employee、external_customer；类别只约束入驻和可分配作用域，不直接授予权限 |
| Machine credential | 绑定到 service/device Principal 的 service secret 或 API key | 凭证不等于权限；API key 只用于机器调用，必须经过状态、组织、scope/audience 和 RBAC 校验 |
| OIDC client | 标准 relying party 的 client registration；显式为 platform 或单一 organization scope | organization scope 在创建时固定，owner/admin 只能通过同组织 active context 管理；scope 不可迁移 |
| Role | 可绑定给适用类型 Principal 的权限集合 | `scope=platform` 角色用于全局能力；`scope=organization` 角色只能经 organization membership binding 生效；assignable_to 限制绑定对象；系统角色不可被普通操作破坏 |
| Permission | 对外稳定的业务权限点 | 推荐命名为 {app}:{resource}:{action}，例如 keystone:system:user:list |
| Resource | 菜单、按钮、API、服务能力或数据范围的统一表达 | 资源树用于展示和预检，不替代服务端最终授权 |

授权链路固定为：

~~~text
principal -> roles -> permissions -> resources/actions
~~~

allowed_scopes 和 allowed_audiences 继续约束服务 Token 的签发边界；它们不替代业务授权。JWT 校验通过只说明主体和目标 audience 合法，资源服务仍需按权限或资源向 Keylo 请求最终授权决策。API key 是机器凭证而不是 JWT 或 refresh session；它不能用于 `/v1/auth/*` 人类登录，也不能通过放入 `Authorization: Bearer` 绕过机器接口声明。

### 4.2 Token、密钥与会话边界

| 凭证或 Token | 用途 | 规则 |
| --- | --- | --- |
| access | 用户、管理客户端或资源服务访问 API | 校验签名、issuer、audience、时效和 token_type |
| refresh | 换取新 access token | 仅安全保存；每次使用原子轮换，重放撤销所属会话；organization-scoped token 还必须匹配 session 记录和实时 active membership |
| OIDC ID/access | 标准 relying party 的身份和 UserInfo 访问 | organization client 的 token 只携带当前 `organization_id`；授权码兑换和 UserInfo 实时重验 client、用户 Principal、组织和 membership |
| service_access | 服务间访问 | 先满足 scope/audience 白名单，再由服务 Principal 的 RBAC 判定能力 |
| api_key | 机器/设备直接调用显式支持的 API | 使用 `X-API-Key` 传递；服务端只保存 hash 和可查找的 key id/prefix，检查 active、过期、组织、scope/audience、RBAC 和限流；不创建 refresh session |

Refresh Session 是稳定会话索引，支持按 Principal、客户端、组织或单个会话撤销。人类密码登录可显式提供 `organization_id`，服务端仅在 live membership 为 active 时同时把该 scope 写入 access token、refresh token 和 session 记录；组织停用/归档或成员变为 pending、suspended、removed 时，只撤销对应组织 session，平台与其他组织 session 不受影响。会话策略可以是 multi_session、single_user_session 或 single_principal_session；显式接管必须先完成认证。

密钥演进必须保持 issuer 和 kid 契约：新 Token 只使用 active RSA key，旧 key 在配置的 overlap 窗口内作为 passive 验证 key；平台管理员可通过受保护接口执行轮换、回滚和下线，所有操作写入审计记录。维护窗口式切换不再是唯一的轮换方式。

### 4.3 资源服务接入边界

资源服务的推荐顺序：

1. 人类或标准 OAuth 客户端通过 Discovery/JWKS 本地验证 JWT 的签名、issuer、audience、过期时间和 token 类型；机器调用可在明确声明的接口上直接使用 `X-API-Key`，或先换取短期 `service_access`。
2. 对细粒度或高敏操作调用 POST /v1/authorize/check 或 POST /v1/authorize/batch-check；API key 解析出的 machine Principal 也必须走同一授权链路。
3. 对 allowed=false 返回 403；Keylo 不可用时不得把验签成功或 API key 解析成功升级为业务权限。
4. 资源树只用于菜单、按钮和能力展示，后端 API 必须重复最终授权判断；API key 不得放在 URL 查询参数或日志中。

Spring、Node、Go、Rust 样例与授权决策契约见 [第三方系统与服务对接指南](../integrations/THIRD_PARTY_INTEGRATION.md)。

### 4.4 SaaS 组织与组织作用域 RBAC

Organization 是 SaaS 租户边界，但不是新的认证协议或 Realm 层级。Keylo 先采用单部署、多组织、共享运行时的模型；所有组织拥有的数据和关系必须显式带 organization_id，平台级对象才允许为空。

当前实现状态（2026-08-10）：组织、用户类别、成员关系、组织角色绑定、资源、refresh session、OIDC client、service client 和 device/API key scope 已经有数据库迁移、持久化访问层与 PostgreSQL 集成测试；迁移只把历史 `super_admin`/`admin.full` 平台权限账户归类为 internal_employee，避免依据 `admin*` 名称前缀误判客户管理员。新建用户默认 external_customer，bootstrap super admin 会在同一启动流程中提升为 internal_employee 并加入 `org-internal`。平台角色写入统一校验 `user_class` 与 role scope：external_customer 不能通过 user、Principal、provision 或批量接口获得 platform/global role，organization role 只能进入同组织的 organization_role_bindings；对 user Principal 的授予和撤销同步维护两张角色关系表。历史脏绑定在同步、权限、资源树、管理 Token 和 introspection 读取侧默认失败关闭，并会阻止将该账户提升为 internal_employee，直到管理员显式清理绑定。平台管理员可使用受保护的组织创建、查询、状态迁移和成员状态 API；人类调用者会实时校验 `internal_employee` 类别，管理 client 也会再次校验 active admin-client 状态。未邀请或尚未完成组织归属的 external_customer 只能停留在无 active organization context 的平台注册状态，不能进入租户资源。授权 check、batch-check、effective-permissions 与 resource-tree 每次都重验 signed active organization context、组织状态和 membership，并分别解释 platform role 或同组织 role binding；相同资源坐标可以由多个组织复用，跨组织资源保持普通 deny/forbidden 边界。人类密码登录提供 organization_id 时会创建相同 scope 的 refresh session，刷新时再次校验 scope 和 live membership，组织停用/归档或成员失效会原子撤销该 scope。service client、OIDC client 与 device 现在都明确存储 platform 或 organization scope；组织范围 device 创建会原子建立 active membership，API key 只保存 bcrypt hash，固定继承机器 Principal 的 scope，支持重叠轮换和显式撤销。`X-API-Key` 只在 `/v1/authorize/check` 与 `/v1/authorize/batch-check` 解析，且每次实时重验 key、scope/audience、Principal、组织、membership 和 RBAC；它不进入人类认证或 refresh 流程。拥有 signed active context 的 organization owner/admin 可以列出、创建、读取、更新和轮换本组织 OIDC client、service/device 与 API key；这些写操作要求近期 MFA，并且查询和写入都使用组织过滤。OIDC authorization code、Token 和 UserInfo 会实时校验 client active、组织 active、用户 Principal active 与 membership active；组织停用或成员变为 pending/suspended/removed 时，未兑换授权码被原子撤销，旧 OIDC access token 不能继续通过 UserInfo。internal_employee 的 customer-support 访问现通过固定受限角色、目标 customer 组织、read operation、人工原因与短期无 refresh token 的 context grant；每次读取和 introspection 都重新校验 grant、角色、人员和组织状态，并写入结构化审计。identity source 已落地显式 `allowed_user_class` 与 `none/fixed` 组织策略、active organization 校验、JIT membership 和 scoped session。

用户至少分为两类：

| User class | 面向对象 | 默认作用域和组织关系 | 关键限制 |
| --- | --- | --- | --- |
| internal_employee | Keylo/SaaS 运营、研发、客服和安全人员 | 可以没有组织而使用平台作用域，也可以加入 kind=internal 的内部组织 | 不因“内部”类别自动获得任何客户组织权限；访问客户数据必须有显式、最小化、可审计的支持/平台角色 |
| external_customer | 客户管理员、成员和最终用户 | 只有在 kind=customer 的 active membership 存在时才能进入组织作用域；未邀请或 pending 状态不得获得 active organization context | 只能获得组织作用域角色，不能绑定 platform/global 角色 |

User class 不是 RBAC 权限。它只参与注册、身份源映射、组织成员资格和角色可分配性校验；最终允许或拒绝仍由 Principal、membership、role binding、resource organization_id 和 active organization context 共同决定。未来若增加 partner、auditor 等类别，必须先扩展分类与迁移契约，不在 Token 中用未定义字符串绕过校验。

“设备用户”在本文中指非人类机器主体，不等同于 OAuth 2.0 Device Authorization Grant。机器主体至少包括 `service`（现有服务客户端）和后续可独立管理的 `device`（边缘设备、代理或后台任务）；它们没有 `user_class`、密码登录、浏览器会话或人类 MFA 要求，但仍必须有明确的 Principal、组织范围和最小 RBAC 权限。

机器身份与人类身份分离：

| Machine principal | 使用场景 | 凭证与作用域 |
| --- | --- | --- |
| service | 后台服务、网关、定时任务和服务间调用 | 兼容现有 `service_id + service_secret -> service_access`；后续可绑定一个或多个 API key；可为 platform-scoped 或 organization-scoped |
| device | 设备、边缘代理或无人值守客户端 | 以 API key 为主，单个 key 只绑定一个 device Principal 和一个不可变组织上下文；不因设备类型获得额外权限 |

核心对象和规则：

| 对象 | 最小字段/关系 | 规则 |
| --- | --- | --- |
| Organization | id、slug、name、kind（customer/internal）、status、created_at | id 稳定；disabled/archived 组织默认不能新建会话，并原子撤销本组织 scoped refresh session；slug 只用于展示和路由，不作为授权凭据 |
| OrganizationMembership | organization_id、principal_id、status、joined_at | 一个 Principal 可以加入多个组织；pending、active、suspended、removed 状态必须可审计，非 active 状态撤销该成员的本组织 scoped refresh session |
| OrganizationRoleBinding | organization_id、principal_id、role_id、scope | 组织角色只能作用于同一 organization_id；组织成员不能通过角色绑定获得平台级权限 |
| MachineCredential | principal_id、organization_id、key_id/prefix、secret_hash、status、expires_at、last_used_at、created_by | 原始 API key 只在创建/轮换响应中显示一次；撤销、过期、主体或组织停用必须立即拒绝；审计只记录 key id/prefix，不记录原值 |
| Tenant-owned object | organization_id + 领域字段 | 查询、创建、更新、删除都必须带组织过滤；跨组织 ID、slug 或资源引用默认返回 not found/forbidden，不泄露存在性 |

组织作用域授权固定为：

~~~text
request -> authenticated principal -> active organization context
        -> membership status -> organization role bindings
        -> permission/resource decision
~~~

认证 Token 只携带当前 active organization context（例如 organization_id）和稳定主体信息，不把所有组织的完整权限塞进 JWT。一个用户切换组织时必须重新确认 membership 并签发新的上下文；密码登录可选择创建同 scope 的 refresh session，`/v1/auth/organization-context` 只重新签发短期 access token。资源服务必须校验 Token 中的 organization_id 与请求资源所属组织一致，不能把任意 X-Organization-Id 请求头当成授权依据。

机器 API key 不支持“切换组织”；其 MachineCredential 绑定的 organization_id 就是本次调用的唯一组织上下文。请求中的组织标识只能用于资源匹配，不能覆盖凭证绑定的组织。

平台管理员与组织管理员分离：

- 平台管理员负责组织生命周期、平台客户端和全局安全配置，跨组织操作必须显式、最小化并审计。
- 组织 owner/admin 只能管理本组织成员、组织客户端、组织身份源和组织资源。
- 普通成员只能消费被授予的组织权限；组织角色不得隐式提升为平台权限。
- internal_employee 的 customer-support 访问必须通过单独的受限角色、目标组织和审计原因授予；不能把 internal_employee 作为跨组织通配符。
- external_customer 永远不能通过组织角色绑定获得 platform/global 权限。
- service/device/client Principal 必须标记为平台级或组织级，不能在每次请求中无声明地跨组织；external_customer 组织管理员创建的机器 key 只能属于本组织。
- API key 轮换允许短暂重叠但不回显旧值；删除、禁用、过期和泄露响应都必须可审计、可限流并默认失败关闭。API key 不能满足人类管理员的近期 MFA 要求。

第一阶段不包含计费、套餐、用量、市场、组织自定义策略脚本、OAuth Device Flow 或物理数据库分片；这些是 SaaS 产品层、协议扩展层或独立部署层的后续决策。

## 5. 设计与计划分工

本文只负责稳定的设计决策和当前代码事实：

- 产品定位、Keycloak 取舍、默认不做的复杂度。
- 当前已实现能力、明确缺口和身份源支持边界。
- Principal、RBAC、资源、组织作用域、Token、密钥、会话和资源服务的核心规则。

后续功能顺序、P0/P1 任务、触发式 2.2+ 能力、Docker 数据库验收、协议回归、文档门槛和提交规则见 [Keylo 后续完整开发计划](../plans/KEYLO_FOLLOW_UP_DEVELOPMENT_PLAN.md)。计划中的候选能力在满足触发信号前不得被解释为已承诺的实现。

## 6. 权威文档

| 主题 | 权威文档 |
| --- | --- |
| 主线设计与能力边界 | 本文 |
| 后续完整开发计划 | [KEYLO_FOLLOW_UP_DEVELOPMENT_PLAN.md](../plans/KEYLO_FOLLOW_UP_DEVELOPMENT_PLAN.md) |
| API 请求、响应和错误语义 | [API_REFERENCE.md](../reference/API_REFERENCE.md) |
| 从零开始部署与联调 | [END_TO_END_QUICKSTART.md](../guides/END_TO_END_QUICKSTART.md) |
| 当前密钥和运行边界 | [SECRET_ENCRYPTION.md](../operations/SECRET_ENCRYPTION.md) 与 [KEY_ROTATION.md](../operations/KEY_ROTATION.md) |
| 第三方/资源服务接入 | [THIRD_PARTY_INTEGRATION.md](../integrations/THIRD_PARTY_INTEGRATION.md) 与 [integrations/README.md](../integrations/README.md) |
| Keystone 迁移 | [keystone.md](../integrations/keystone.md) |
| 客户端 Token 与会话保存 | [KEYLO_2_0_CLIENT_GUIDE.md](../reference/KEYLO_2_0_CLIENT_GUIDE.md) |
| 安装向导 | [SETUP_WIZARD_DESIGN.md](SETUP_WIZARD_DESIGN.md) |
| Keycloak OIDC 可选互操作矩阵 | [KEYCLOAK_OIDC_MATRIX.md](../compatibility/KEYCLOAK_OIDC_MATRIX.md) |

旧版生产部署说明已移至 docs/archive/deployment/，不作为当前部署依据。历史发布说明只用于追溯，不参与主线规划决策。
