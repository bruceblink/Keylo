# Keylo 后续完整开发计划

> 本计划以 [Keylo 主线设计](../design/KEYLO_DEVELOPMENT_BLUEPRINT.md) 为前置约束，按 2026-08-09 的源码、迁移和测试制定。它只规划已经确认的后续工作；docs/archive/ 不作为计划依据。

## 1. 计划原则

路线按“发布基线 -> SaaS 组织隔离与组织作用域 RBAC -> 通用 IAM 摩擦 -> 需求触发扩展”推进。同一周期只启动一个跨边界扩展，避免在协议、数据模型和运维上同时增加不可逆复杂度。

优先级规则：

1. 安全、数据隔离和标准 OIDC 互操作问题优先于所有新增功能。
2. 先减少部署、配置、接入和排障步骤，再考虑增加协议数量。
3. 每个功能先写清客户端、威胁模型、撤销语义、审计和回滚，再实现代码。
4. Keycloak 只作为标准和代表性互操作参照，不作为逐项追平清单。
5. SaaS 组织基础能力已经进入默认版本排期；组织之上的计费、套餐、目录同步和企业协议仍需真实触发信号。

## 2. 2.1 发布线：可用性与安全基线（P0）

目标：任何新环境都能用 Docker 准备 PostgreSQL/Redis，用当前文档完成 setup、标准 OIDC 接入、授权检查、退出和会话撤销；失败能够通过稳定响应、readyz、metrics 和审计定位。

### 2.1-A 本地开发与数据库验收

- 维护 docker-compose.yml 的 PostgreSQL、Redis、密文 secret、健康检查和网络隔离，不把历史部署文档重新当成配置来源。
- 提供一条可重复的迁移、seed、setup、启动和清理路径；数据库初始化失败必须 fail-fast，只有显式开发配置才允许无数据库回退。
- 为 migration、setup advisory lock、依赖超时、重试和恢复补齐集成测试。
- 交付物：端到端快速开始、可执行 PowerShell 验证脚本、数据库测试前置检查。

完成标准：新开发者在干净工作区启动本地依赖，能完成迁移和最小登录；数据库或 Redis 不可用时得到可行动的错误而不是假成功。

### 2.1-B 标准 OIDC 与资源服务接入

- 固化 Discovery、JWKS、Authorization Code + PKCE、client_secret_basic、UserInfo、consent、logout、redirect URI 和 OAuth 错误语义。
- 保持 Node、Go、Rust、Spring OIDC relying party 和 Spring resource server 样例可运行；资源服务必须先本地验签，再显式要求 allowed=true 且 decision=allow。
- Keycloak 只作为代表性互操作回归。镜像、TLS、网络或浏览器不可用时，记录 not_executed，不把它改写成通过。
- 交付物：每个样例的最小配置、失败排查路径、标准 HTTP 集成测试和可选 Keycloak 矩阵 artifact。

完成标准：标准客户端不需要解析 Keylo 专用登录 JSON；未知主体、禁用主体、错误 audience、错误 PKCE、失效 code 和 Keylo 授权服务不可用均默认拒绝。

### 2.1-C 首启、错误和审计闭环

- 将 setup/status、readyz、metrics、日志脱敏和审计事件组织成同一条排障路径。
- 为配置错误、依赖未就绪、身份源不可用、授权拒绝、refresh replay 和会话撤销定义稳定 error code、HTTP 状态和修复提示。
- 审计事件必须包含 actor、target、原因、结果和可关联的 session/source/client 标识，但不得记录密码、Token、验证码、私钥或未必要的邮箱明文。
- 交付物：错误语义表、审计字段约束、面向运维的最小诊断清单。

完成标准：一个失败场景可以仅凭客户端响应、readyz/metrics 和审计查询定位到下一步动作；敏感值在 HTTP 日志和审计中均不可回显。

### 2.1-D 会话、密钥和账户安全

- 保持 refresh session 原子轮换、重放撤销、按主体/客户端撤销、密码修改或重置后的浏览器和 refresh 会话撤销。
- 将当前单活动 key 扩展为 active/passive JWKS overlap：新 Token 只用 active kid，旧 kid 在明确窗口内只用于验签；提供轮换、下线、回滚和审计语义。
- 固化 TOTP、恢复码、敏感管理操作近期 MFA、OAuth state 和 OIDC upstream state 的过期、一次性消费和重放测试。
- 交付物：密钥轮换 runbook（只描述当前代码已支持的步骤）、安全回归测试、升级和回滚说明。

完成标准：轮换和账户安全状态变化不会产生可继续使用的旧 refresh session；升级或回滚不会让合法的短期旧 Token 被无故拒绝。

### 2.1-E 文档与契约收敛

- 主线设计只写当前代码和已经批准的边界；本计划只写后续工作；API_REFERENCE.md 只写已发布接口。
- 设计与开发计划放在 docs/design 与 docs/plans，接口契约放在 docs/reference，使用和运维分别放在 docs/guides 与 docs/operations，历史内容放在 docs/archive。
- 每个接口或安全状态变化必须同时更新对应参考文档、样例和测试。

完成标准：相对链接检查通过，文档中的 endpoint、Token 类型、错误和配置与源码一致；archive 文档不参与新功能验收。

## 3. SaaS 组织隔离、组织作用域 RBAC 与机器身份（P1，下一条主线）

目标：在不引入 Realm 复制的前提下，把 Keylo 从单一用户池扩展为单部署多组织的 SaaS IAM。所有组织数据默认隔离，平台管理员与组织管理员边界清晰，人类用户明确分为 internal_employee 和 external_customer，非人类 service/device 主体通过 service_access 或 API key 调用，现有单组织部署可以可回滚地迁移。

### 3.1 组织领域模型与迁移

已完成的基础（2026-08-09）：

- [x] 新增 Organization：稳定 id、slug、name、kind（customer/internal）、status、created_at、updated_at；当前持久化层阻止向 disabled/archived 组织创建 pending/active 成员关系。
- [x] 新增 user_class 枚举：internal_employee、external_customer。新建人类用户默认 external_customer；启动引导的 super admin 显式提升为 internal_employee 并加入 `org-internal`。历史数据仅依据明确的 `super_admin` 或 `admin.full` 平台权限回填，禁止用 `admin*` 角色名前缀推断类别；没有明确租户归属的 external_customer 保持无 active organization context，不被静默塞入客户组织。
- [x] 新增 OrganizationMembership：organization_id、principal_id、status、joined_at、invited_by；状态支持 pending、active、suspended、removed。
- [x] 新增组织级角色绑定：organization_id、principal_id、role_id、scope；角色在数据库中区分 platform/organization scope，持久化层要求 organization scope、active organization、active membership，并复用角色 `assignable_to` 的 Principal 类型校验。
- [x] 提供平台管理员组织与成员状态 API：创建、查询、列表、`active/disabled/archived` 生命周期迁移，以及 `pending/active/suspended/removed` 幂等成员状态写入。人类调用者实时校验为 internal_employee，管理 client 同时校验仍是 active admin client；非 GET 人类管理请求沿用近期 MFA 规则并写入审计。

仍待完成：

- [x] 将 user_class 纳入 provision 与角色作用域校验；external_customer 不能获得 platform/global role，类别本身不直接授予权限；普通/批量/Principal/provision 写入、权限读取、资源树、管理 Token 与 introspection 均按 live user class 和 role scope 失败关闭。身份源映射仍需在后续接入切片中显式声明允许创建的 user_class。
- [x] 为组织 owner/admin 提供限定本组织的邀请、加入、成员管理和组织角色绑定 API；组织角色仅在相同 signed active organization context 的授权决策中生效，绝不提升为 platform 权限。
- [x] 人类密码登录可显式创建 organization-scoped refresh session；scope 同时写入 access/refresh JWT 与会话记录，刷新实时重验 session scope、组织和 membership，组织停用/归档或成员变为 pending/suspended/removed 时原子撤销对应 session。
- 将人类与机器主体分开建模：`user` 继续使用 `user_class`，`service` 保持现有服务 Principal，新增 `device` 作为设备/边缘代理/无人值守任务的机器 Principal；机器主体没有 user_class、密码登录、浏览器会话或人类 MFA 要求。
- 新增 MachineCredential/API key 记录：principal_id、organization_id、key_id/prefix、secret_hash、status、expires_at、last_used_at、created_by、allowed_scopes、allowed_audiences；原始 key 只在创建或轮换响应中显示一次。
- 为用户、OIDC client、service client、identity source、resource、refresh session 和授权审计逐项定义 organization_id 归属；resource、refresh session 与授权审计已经完成 scope、查询过滤和授权路径，用户、OIDC client、service client 与 identity source 仍不可仅加 nullable 列，必须随其完整查询约束和授权路径一起实施。
- 设计兼容迁移：现有数据必须进入明确的 default organization 或显式 platform scope，并为每个 user 生成明确的 user_class 映射；迁移保持前向、可重复和可审计。生产恢复使用已验证的备份/恢复或修复迁移，不假设未实现的 down migration；禁止用隐式 NULL 代表所有组织或用默认类别掩盖不确定性。

验收：迁移在干净数据库和已有单组织数据库上都能执行；重复执行不产生重复组织、类别或绑定；任一租户归属或 user_class 不明确的对象都会阻止发布而不是被静默归入错误组织。

### 3.2 组织生命周期与成员 API

- [x] 提供平台级组织创建、查询、停用、归档和恢复 API；组织 slug 唯一且不可作为 secret。状态只允许 `active -> disabled/archived`、`disabled -> active/archived`、`archived -> active` 或同状态幂等写入。
- [x] 提供平台级成员状态管理 API，支持 pending、active、suspended、removed；敏感成员操作沿用近期 MFA 并写审计。
- [x] 提供组织 owner/admin 管理成员、邀请和加入的 API；这些接口必须被限制在其 active organization 内。
- [x] pending/suspended/removed 成员不能创建或刷新 organization-scoped refresh session；组织 disabled/archived 会撤销该组织 session，重新 active 不恢复旧 token。
- internal_employee 可以使用平台作用域，或加入 kind=internal 的内部组织；external_customer 只有加入 kind=customer 的 active organization 后才能进入客户资源，未归属或 pending 状态不得创建组织上下文。
- 身份源必须声明允许创建的 user_class 和组织归属策略；外部 OIDC/社交登录默认只能创建 external_customer，不得通过邮箱或 claim 自动获得 internal_employee。
- 组织切换必须重新校验 membership 并签发新的 active organization context；不能信任任意 X-Organization-Id 请求头。
- 组织删除初期只允许 archive；物理删除、数据导出和保留策略另行审批。

验收：pending/suspended/removed 成员不能创建或刷新组织会话；external_customer 没有 active customer membership 时不能进入客户资源；internal_employee 没有显式支持角色时不能读取客户资源；组织停用会撤销该组织签发的 refresh session；邀请和重复请求具有幂等语义。

### 3.3 组织作用域 RBAC 与授权决策

- [x] 将现有角色绑定扩展为 global/platform 与 organization scope；平台角色和组织角色分开校验。
- [x] 资源和权限检查同时解析 authenticated principal、active organization context、membership status、组织角色绑定和资源 organization_id。
- [x] check、batch-check 与 resource-tree 对 organization_id 不一致、组织不存在或停用、成员非 active、资源属于其他组织时默认拒绝，并保持普通 deny/forbidden 边界，避免通过错误差异泄露租户存在性。
- [x] external_customer 只能绑定 organization scope；internal_employee 的平台角色和内部组织角色分离，类别本身不授予客户组织访问。
- [ ] customer-support 访问必须限定目标组织、操作和审计原因。
- [x] 组织服务账号和客户端明确标记 platform-scoped 或 organization-scoped；组织级服务 Token 只能访问所属组织。service client 的 scope 不可变，组织 client 创建会原子建立 service Principal 与 active membership；Token 签发、check、batch-check、effective-permissions、resource-tree 和服务内省路径都会实时校验 client、Principal、组织与 membership，组织级 client 不可调用内省端点。
- [ ] external_customer 组织管理员创建的 service/device Principal 与 API key 只能属于本组织；internal_employee 的平台级机器身份不得因内部类别自动访问客户组织。
- [x] JWT 只携带当前组织上下文和稳定主体信息，不携带所有组织的完整权限集合；切换组织要重新签发上下文。

验收：跨组织 check、batch-check、resource-tree、client 管理、identity source 管理和 refresh 都有拒绝测试；external_customer 绑定 platform/global role 会失败；internal_employee 的无授权客户访问会失败；平台管理员的跨组织操作必须显式调用、最小授权和审计。

当前进展：已使用真实 PostgreSQL 覆盖双组织 resource code、check、batch-check、effective-permissions、resource-tree、成员暂停、角色撤销、组织停用、organization-scoped refresh session 和 organization-scoped service Token；OIDC client、identity source、device 与 API key 仍属于后续未完成项。

### 3.4 非人类主体与 API_KEY 认证

- 固化机器调用边界：现有 `service_id + service_secret` 继续用于换取短期 `service_access`；新增 API key 作为直接机器 API 凭证，不要求登录，不创建 refresh session，也不进入人类 `/v1/auth/*` 流程。
- API key 的规范传递方式为 `X-API-Key: <raw-key>`；拒绝 URL 查询参数、日志回显和把 API key 当作 `Authorization: Bearer`。资源服务只有显式声明支持 machine credential 的路由才接受它。
- 设计并实现机器凭证管理 API（创建、列表元数据、轮换、撤销、过期和主体/组织停用联动）；建议以 `key_id/prefix` 定位，服务端只保存不可逆 hash，创建/轮换时返回一次原始 key。
- 在 API 契约阶段冻结机器凭证管理端点（例如 `POST /v1/admin/principals/{principal_id}/api-keys`、元数据列表、`rotate` 和撤销端点）；实现前先补充 API_REFERENCE，未落地前不得把这些路径写入当前已发布接口清单。
- API key 解析后必须得到唯一 service/device Principal，并依次校验 key 状态、组织归属、scope/audience、Principal active、组织 membership 和 RBAC；跨组织、过期、撤销、禁用和未知 key 默认返回统一的未授权结果。
- 机器 key 不支持组织切换；MachineCredential 的 organization_id 是唯一授权上下文，任何请求头或 URL 中的组织标识都只能用于资源匹配，不能覆盖凭证归属。
- 允许多个 key 短暂重叠以支持无停机轮换，但旧 key 不能继续刷新或换取超出原范围的权限；key 泄露、轮换、撤销、最后使用时间和调用结果写入审计，审计不得包含原始 key。
- 为下游扇出保留 API key 换取短期 `service_access` 的可选路径；保持现有 service token 的 audience/scope 白名单和服务 RBAC，不把长生命周期 API key 传播给下游服务。
- 明确 OAuth 2.0 Device Authorization Grant 不是本功能；它只在未来需要“人类绑定受限设备”时单独排期。

验收：直接携带有效 API key 的机器请求可以访问已声明的组织 API；人类登录接口、未声明的路由、错误 audience/scope、跨组织资源、停用 Principal、过期/撤销 key 和 Keylo 依赖不可用时均默认拒绝；创建响应只出现一次原始 key；轮换期间新旧 key 的边界、审计和限流可验证。

### 3.5 组织隔离测试与运行门槛

- 为每一个 tenant-owned table 增加 organization_id 过滤、复合索引和必要的复合唯一约束。
- 建立跨组织读、写、列表、批量、删除、审计查询和缓存命中测试；覆盖 ID、slug、resource_code 和外部 subject 互换场景。
- 为组织级 metrics、审计保留和管理员查询定义不泄露其他组织数据的字段边界。
- 覆盖 internal_employee 与 external_customer 的登录、组织切换、角色绑定、身份源 JIT、禁用和会话撤销矩阵。
- 覆盖 service/device Principal 的 API key 创建、直接调用、短期 service_access 换取、跨组织拒绝、轮换、撤销、过期、限流和审计矩阵。
- 为迁移、组织停用、成员移除、Token 刷新、缓存失效和回滚建立真实 PostgreSQL 集成测试。

完成标准：隔离回归全部通过，任意数据库查询路径都能追溯 organization filter；发现一次跨组织成功即阻止版本发布。

## 4. 2.1 后半段：通用 IAM 易用性（P1）

这些工作以减少真实接入方的重复操作为准，不以增加接口数量为目标。

### 2.1-P1-A 账户自助 API

- 先稳定已有的 change-password、TOTP、恢复码和 OIDC identity link/unlink 契约。
- 当真实应用需要邮件闭环时，再增加可插拔邮件投递边界：邮箱验证、forgot-password、一次性哈希 Token、过期/重放撤销、审计、密码重置后的 session revoke。
- 不在 Keylo 核心内置模板主题、营销邮件或通用工作流；测试使用 fake mail provider，生产通过受控 SMTP 或外部邮件服务。

验收：一次性 Token 不可重放；邮箱变更自动清除验证状态；邮件服务超时不影响既有认证安全边界；没有邮件依赖时当前 API 行为保持兼容。

### 2.1-P1-B 管理 API 可用性

- 统一 list/filter/pagination、幂等更新、稳定错误码和变更原因字段。
- 明确 admin client、user principal、service principal 和 future delegated admin 的权限边界；危险操作继续要求近期 MFA。
- 优先改进客户端、服务、用户、身份源、Principal、RBAC、资源和审计接口的排障反馈，不先开发完整管理后台。

验收：相同请求重试不会重复创建或重复分配；列表结果可预测；每个危险变更都可由审计和回滚历史解释。

### 2.1-P1-C OIDC upstream 可运营化

- 为每个 upstream source 提供 Discovery 校验、超时、JWKS 缓存和明确的配置版本。
- 修改或禁用 source 时，原子撤销未完成授权、来源 refresh session，并记录撤销数量。
- 保持稳定 external subject；上游邮箱变化只记录观察结果，不自动覆盖本地邮箱。

验收：IdP 错误、Discovery 变化、source 禁用、配置回滚和重复 callback 都有确定结果，不能造成账号错绑。

### 2.1-P1-D 运行可观测性

- 保持固定基数 metrics，补充按功能而不是按用户或 URI 的认证、授权、依赖和 session 指标。
- 在确认外部消费方前，优先实现一个可验证的 audit export 或 webhook/outbox 方案，不同时引入多个事件平台。
- 为 PostgreSQL/Redis 连接池、迁移、readiness、key rotation 和审计清理定义容量和失败门槛。

验收：指标不会泄露主体或 Token；审计导出重复投递可检测；依赖故障不会把拒绝转换成成功。

## 5. 需求触发的 2.2+ 扩展

组织基础模型、组织作用域 RBAC 和机器 API key 已从候选池提升为上一节的确定主线。下列是组织之上的增强能力，只有满足触发条件、威胁模型、数据迁移和可测试验收后才转为排期。每次只选择一个方向。

| 触发信号 | 最小交付 | 必须先定义 | 明确不做 |
| --- | --- | --- | --- |
| 组织需要域名发现、自动加入或外部邀请 | 组织域名映射、邀请、identity-first 路由或受控自动加入 | 域名冲突、验证、默认组织和恢复流程 | 以邮箱域名自动授予高权限 |
| 资源服务需要所有者、部门或业务上下文 | 固定 organization_id、owner_id、department_id 等条件的服务端决策和审计原因 | 条件优先级、缺失值和缓存失效 | 通用表达式或脚本引擎 |
| 企业 IdP/HR 要求自动入离职 | SCIM Users/Groups 的最小 subset、PATCH、disable、会话撤销、幂等和审计 | externalId、冲突、删除语义、服务 Token scope | 未定义冲突语义的全量同步 |
| 企业只能提供 LDAP/AD 目录登录 | TLS bind、连接池、超时、搜索分页、禁用和组映射的单一场景 | 目录不可用时 fail-closed、密码归属和会话撤销 | 先做多目录、Kerberos 或通用 SPI |
| 已签约客户只能提供 SAML | 只选择一个明确的 SP 或 IdP 场景、映射和回归 fixture | 签名算法、metadata、时钟偏差、登出和属性边界 | 为协议数量实现完整 SAML 平台 |
| 管理员需要抗钓鱼认证 | 管理员 WebAuthn 注册、step-up、恢复和审计 | 恢复责任、设备丢失和强制策略 | 未验证恢复流程就让全体用户强制迁移 |
| CLI、受限设备上的人类绑定或委托访问 | Device Flow、CIBA、PAR、DPoP 或 Token Exchange 中只选一项；非人类 API 调用不重复走这条线，使用上一节机器 API key | 客户端类型、轮询/重放、proof、撤销和审计 | 多项并行、通用 OAuth 扩展平台 |
| 多实例或跨区域运行 | 共享 PostgreSQL/Redis 语义、迁移锁、session 一致性和一次可验证的 outbox/trace/HA 演练 | RTO/RPO、故障模型、数据备份和回滚 | 未验证的分布式平台改造 |
| 多个管理员团队需要分权 | 固定资源类型和操作范围的 delegated admin | 管理员角色不可绕过、越权回归和审计 | 直接复制 Keycloak FGAP 的策略/脚本模型 |

## 6. 发布、测试与完成门槛

每个小功能先验证再提交；尚不可测试、验证失败或只完成一部分的工作不标记完成。

### 6.1 代码与数据库验证

~~~powershell
cargo fmt --all -- --check
cargo check --lib
cargo test --lib
cargo clippy --lib --tests -- -D warnings
~~~

需要数据库的测试使用本地 Docker 依赖，不把网络不可用伪装成通过：

~~~powershell
docker compose up -d postgres redis
docker compose ps
$env:TEST_DATABASE_URL = "postgres://keylo_user:<local-password>@localhost:5432/keylo"
cargo test --test integration_test -- --test-threads=1
~~~

### 6.2 协议和样例验证

- 运行 scripts/validate_oidc_rp_examples.ps1，Node、Go、Rust、Spring RP 和 Spring resource server 必须全部通过。
- OIDC 标准 HTTP 集成测试必须覆盖 Discovery、PKCE、nonce、state、redirect URI、client authentication、UserInfo、logout 和错误响应。
- Keycloak 矩阵只在 HTTPS、镜像、网络和浏览器条件满足时执行；脚本生成的 not_executed 记录保持原状，不得改成 passed。

### 6.3 文档与安全验证

- 修改 endpoint、Token、权限、配置、数据库或安全状态时，同一提交必须包含参考文档和回归测试。
- 运行 git diff --check 和仓库内相对 Markdown link check。
- 检查日志、审计、metrics、错误响应和测试 artifact 中没有密码、client secret、API key 原值、access/refresh token、验证码或私钥。
- 每个功能使用单一 Conventional Commit 前缀：feat、fix、docs、test 或 chore；一个小功能一个提交。

## 7. 需求准入检查表

任何新增 Keycloak 类能力在进入排期前必须回答：

1. 哪个真实客户端、组织或运维事件提出了需求，频率和影响是什么？
2. 采用的公开标准和最小互操作范围是什么？
3. 威胁模型是什么，主体、Token、API key、会话、密钥和撤销语义是什么？
4. 失败时是否默认拒绝，是否需要审计、指标、回滚和数据迁移？
5. 能否用当前 Principal/RBAC/资源模型表达，为什么必须新增协议或数据模型？
6. 是否能在 Docker 本地环境和真实 HTTP 测试中复现？
7. 是否会引入 Realm、策略脚本、插件或分布式基础设施维护成本？如果会，为什么收益足以承担？

有任一项没有答案时，需求停留在候选池，不进入实现。

## 8. 权威文档

| 主题 | 权威文档 |
| --- | --- |
| 主线设计与边界 | [KEYLO_DEVELOPMENT_BLUEPRINT.md](../design/KEYLO_DEVELOPMENT_BLUEPRINT.md) |
| API 请求、响应和错误语义 | [API_REFERENCE.md](../reference/API_REFERENCE.md) |
| 从零开始部署与联调 | [END_TO_END_QUICKSTART.md](../guides/END_TO_END_QUICKSTART.md) |
| 第三方/资源服务接入 | [THIRD_PARTY_INTEGRATION.md](../integrations/THIRD_PARTY_INTEGRATION.md) |
| Keycloak OIDC 可选互操作矩阵 | [KEYCLOAK_OIDC_MATRIX.md](../compatibility/KEYCLOAK_OIDC_MATRIX.md) |

旧版生产部署说明已移至 docs/archive/deployment/，不作为当前部署依据。历史发布说明只用于追溯，不参与主线规划决策。
