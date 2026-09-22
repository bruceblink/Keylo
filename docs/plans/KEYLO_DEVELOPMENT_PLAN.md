# Keylo 线性开发主线与功能清单

> 更新时间：2026-09-22
>
> 整理基线：2026-09-19；交付后由 `main` 维护主线，`dev` 与 `main` 对齐；当前发布线为 `v2.1.1`。
>
> 本文是 Keylo 唯一维护中的开发计划和功能清单。主线设计只描述产品边界和技术规则，接口、使用、运维和历史发布文档分别承担各自职责；`docs/archive/` 不作为开发依据。

## 1. 使用规则

Keylo 的主线目标是让通用 IAM 更容易部署、接入、理解和排障。开发顺序固定为：

1. 已交付能力作为当前基线，不再重复排期。
2. 只实现“下一切片”，完成验证、提交和推送后再决定下一切片。
3. 新增功能必须先明确使用场景、接口约定、数据迁移、权限边界、失败行为、审计和回滚，再进入实现。
4. 需要数据库的集成测试只使用本机 Docker；不可用时标记为未完成，不用 mock 或静态结果代替。
5. 每个可独立验收的功能单独提交并立即推送；Rust 仓库提交前必须通过 `cargo fmt --all -- --check` 和 `cargo clippy --workspace --all-targets -- -D warnings`。

状态含义：

- `已完成`：代码、文档和与风险匹配的验证已经交付。
- `下一切片`：当前唯一允许进入实现的功能范围。
- `未排期`：不是当前主线任务；除非出现真实使用信号，否则不得转入实现。
- `待环境验证`：功能边界已经写清，但验证所需的外部环境本次没有执行。

## 2. 线性路线

| 顺序 | 阶段 | 状态 | 结果 |
| --- | --- | --- | --- |
| 0 | 认证、会话、授权、组织和运行基线 | 已完成 | 形成当前 `v2.1.1` 发布线的可用能力和安全边界。 |
| 1 | 账户自助安全闭环 | 已完成 | 邮箱验证、忘记密码申请、密码重置邮件流程、首次强制改密、会话撤销和真实 SMTP 账户链路已完成并通过本机 Docker 验收。 |
| 2 | 需求审查后的单一扩展 | 未排期 | 阶段 1 完成后，根据真实接入方需求只选择一个扩展，不预先并行实现协议或基础设施。 |

阶段 2 不是功能承诺清单。没有真实客户端、组织或运维事件时，主线停留在阶段 1 的稳定维护和回归验证。

## 3. 当前已完成功能清单

| 领域 | 已交付能力 | 当前边界 |
| --- | --- | --- |
| 部署与首启 | SQLx 迁移、Docker Compose 依赖、PostgreSQL/Redis 就绪检查、启动 fail-fast、密文配置、RSA 密钥加载、setup wizard、healthz/readyz、固定基数 metrics。 | 当前以单实例 PostgreSQL/Redis 运行边界为准，不承诺多实例高可用或跨区域恢复。 |
| 标准 OIDC | Discovery、Authorization Code + PKCE、state/nonce、JWKS、UserInfo、consent、浏览器会话、logout、public/confidential client 和 client secret rotation。 | 仅发布已实现的授权码流程；不包含 Dynamic Client Registration、Device Flow、CIBA、PAR、DPoP 或 Token Exchange。 |
| 本地认证 | 用户注册、密码登录、密码复杂度、登录限流、登录锁定、`email_verified` 状态、用户/管理员改密、管理员重置密码、邮箱验证、忘记密码和密码重置。 | `MailProvider` 保持可插拔；当前提供默认禁用模式和 SMTP 适配器，外部邮件服务适配器仍不在主线范围；邮件投递不参与认证授权决策。 |
| MFA 与会话 | TOTP enrollment、近期 MFA、恢复码一次性消费、敏感管理操作 step-up、refresh session 原子轮换、replay 撤销、按主体/客户端/单会话撤销、组织状态联动撤销。 | 人类组织会话只使用当前显式组织上下文；不可把请求头当作组织授权依据。 |
| 密钥与 Token | RS256/JWKS active/passive overlap、access/refresh/service access Token、Token introspection、黑名单、密钥轮换/回滚/下线和审计。 | passive key 只在配置的 overlap 窗口内用于验签，新 Token 只使用 active key。 |
| Principal 与 RBAC | `user`、`service`、`device`、`client` Principal；platform/organization 角色；权限、资源树、单点和批量授权检查；默认拒绝和授权审计。 | 不提供任意策略脚本、composite role 或通用策略表达式引擎。 |
| SaaS 组织 | Organization、user class、membership、组织生命周期、组织角色绑定、组织作用域 OIDC/service client、组织资源过滤、跨组织拒绝、兼容迁移。 | 组织不是 Realm；不做 Realm 复制、计费、套餐、市场或物理分片。 |
| 机器身份 | `service_id + service_secret -> service_access`、`device` Principal、组织绑定 API key、hash-only 存储、轮换、撤销、过期、限流和审计。 | API key 只用于明确声明支持 machine credential 的接口，不进入人类登录或 Bearer Token 流程。 |
| 外部身份 | OAuth provider 登录和账号关联；OIDC upstream Discovery、PKCE、JWKS、UserInfo、JIT、subject 映射、固定组织策略、启停和来源会话撤销。 | `ldap` 目前只有身份源注册元数据，不代表已经支持 LDAP bind、组映射或目录同步。 |
| 管理与运营 | 用户、Principal、客户端、服务、身份源、组织、成员、OIDC client、RBAC、资源、审计、customer-support API；列表接口统一有界分页；审计导出支持稳定游标。 | 当前保持 API-first，不把完整 Admin Console、Account Console、主题系统或管理 CLI 当作默认主线。 |
| 接入与文档 | Node、Go、Rust Axum、Spring OIDC RP 和 Spring resource server 样例；数据库错误响应脱敏；Markdown 相对链接检查接入 CI；自助安全 API 与 SMTP 运维文档。 | 样例构建和本地测试已通过；Keycloak 镜像、TLS、浏览器和跨系统矩阵仍为待环境验证。 |

## 4. 当前基线验证证据

以下证据记录于 2026-09-21，后续功能必须在相同边界上追加新的验证记录：

| 验证 | 结果 |
| --- | --- |
| `.\scripts\run_tests.ps1 -DatabasePort 55432` | 使用本机 Docker `postgres:17-alpine`（宿主 `127.0.0.1:55432` -> 容器 `5432`）和 `axllent/mailpit:v1.21.8`（SMTP `127.0.0.1:11025` -> `1025`，API `127.0.0.1:18025` -> `8025`）；PostgreSQL readiness、Mailpit readiness、fmt、workspace Clippy、148 个单元、1 个 customer-support、26 个 database、76 个 HTTP、3 个 load、3 个 OAuth、12 个 RBAC、1 个 SMTP 和 12 个 user 测试全部通过；真实 `AppState::new` 账户邮件流程已验证邮箱验证、密码重置、首次强制改密和失败撤销，邮件已从 Mailpit API 查到，脚本结束后容器、匿名卷、端口映射和临时密钥目录已清理。 |
| `.\scripts\validate_oidc_rp_examples.ps1` | Node、Go、Rust Axum、Spring Boot OIDC RP 和 Spring resource server 样例通过；该结果不等同于 Keycloak/TLS/浏览器互操作通过。 |
| `.\scripts\check_markdown_links.ps1` | README 和 `docs/` 下相对 Markdown 链接通过；外部 URL、锚点和围栏代码示例不在检查范围内。 |
| `actionlint .github/workflows/ci.yml`、`git diff --check` | 通过。 |

## 5. 已完成切片：账户自助安全闭环

### 5.1 目标

让本地账户在不依赖管理员人工操作的情况下完成邮箱验证和密码恢复，同时不泄露账户是否存在、不记录可重放的敏感值，并保持现有 refresh session 和 OIDC 浏览器会话的撤销规则。

### 5.2 功能清单

| 顺序 | 功能 | 实现要求 | 验收结果 |
| --- | --- | --- | --- |
| 1 | 可插拔邮件投递边界 | 已完成：定义最小异步 `MailProvider` 接口、默认禁用 provider、SMTP 适配器、STARTTLS/隐式 TLS、开发测试明文模式、超时、稳定错误分类、加密密码配置和内存测试 provider；邮件内容及配置密钥在 debug 输出中统一脱敏。 | provider 未配置、消息无效、超时、临时失败和永久拒绝均有稳定结果；本机 Docker Mailpit 已验证真实 SMTP 投递；认证核心不依赖具体邮件服务。 |
| 2 | 用户邮箱验证 | 已完成：认证用户请求短时一次性 token；服务端仅保存 SHA-256 摘要，token 绑定当前邮箱；provider 失败会撤销未投递 token；真实 SMTP 流程通过应用默认装配路径发送。 | `POST /v1/user/email-verification/request` 和 `POST /v1/auth/email-verification/confirm` 已覆盖真实 Mailpit 投递、成功、重放、过期、邮箱变更、限流和投递失败；审计不写入原 token。 |
| 3 | 忘记密码申请 | 已完成：按邮箱或用户名申请；响应不区分账户存在性，identifier 和 IP 均受限流保护；只为 active、已验证邮箱且有本地密码的账户投递；真实 SMTP 流程通过应用默认装配路径发送。 | 无账户枚举；每个账户只保留一个有效待消费 token；Mailpit 已验证真实邮件内容和收件人；投递失败会撤销 token。 |
| 4 | 密码重置 | 已完成：校验一次性恢复 token、密码复杂度和账户状态；成功后撤销该用户现有 refresh session 与 OIDC 浏览器会话，并保留首次登录强制改密标记；真实 SMTP 账户流程已验证首次登录和改密闭环。 | 旧密码、旧 refresh token、旧浏览器会话和已消费 token 均不能继续使用；改密后新登录不再携带强制改密标记。 |
| 5 | 接口、文档和回归 | 已完成：同步更新 API 参考、开发计划、匿名响应、错误码语义和 HTTP/数据库回归测试。外部邮件 provider 适配器仍保持在边界之外。 | 客户端能按公开接口完成闭环；数据库故障、邮件故障、token 重放、邮箱变更和并发消费默认拒绝。 |

### 5.3 实施顺序与提交边界

邮件 provider、用户邮箱验证、忘记密码申请和密码重置已完成。真实 `AppState::new` 已验证会按配置装配 SMTP provider，账户接口能从 Mailpit 收到验证和重置邮件，并完成 token 消费、首次强制改密和失败撤销。SMTP 适配器只负责一次投递尝试，密码可通过统一 AES-256-GCM 密文文件加载；投递失败会撤销新建的一次性 token。密码恢复 token 只保存 SHA-256 摘要，绑定当前已验证邮箱，成功消费在同一事务内更新密码、撤销 refresh/OIDC 会话并写入审计。下一切片进入 SMTP 生产运维加固；阶段 2 协议和基础设施扩展仍未排期。

这是面向用户的认证功能。若实现涉及 `web/` 页面，提交前必须完成真实窗口验收；真实窗口无法启动时，至少执行 headless 渲染和交互测试，并在验证记录中明确限制。仅修改 API 和服务端时，以真实 HTTP 测试和本机 Docker PostgreSQL 集成测试为准。

## 6. 下一切片：SMTP 生产运维加固

状态：进行中。该切片只处理已经接入 SMTP 后的运维可见性和恢复验证，不引入 outbox、后台重试或新的邮件服务适配器。

当前进度：固定基数投递指标已完成并通过本机 Docker 全量验证。`/metrics` 暴露
`keylo_mail_deliveries_total`，应用只记录六种固定结果：成功、消息无效、未配置、超时、
暂时不可用和永久拒绝；指标不包含收件人、用户标识、令牌、邮件正文或 SMTP 原始回复。
剩余工作是启动失败分类日志、Mailpit 故障恢复回归和运维操作记录。

范围固定为：

1. 为投递成功、超时、临时不可用、永久拒绝和配置禁用增加固定基数指标；指标不得包含收件人、账号标识、token、邮件正文或 SMTP 原始回复。
2. 增加 SMTP 配置启动检查和证书/超时失败的可操作日志分类；日志只保留稳定错误类别和下一步动作。
3. 增加本机 Docker Mailpit 的恢复回归：服务重启后重新投递、SMTP 端口不可达、TLS 配置错误和超时均必须保持失败关闭与 token 撤销。
4. 更新运维文档和发布前验证记录，说明密文轮换、证书更新、故障恢复和清理步骤。

验收条件：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、本机 Docker PostgreSQL 17 + Mailpit 集成测试、固定基数指标测试、失败分类测试和 Markdown/CI 检查全部通过；不得把 Mailpit 结果描述成真实外部 SMTP 供应商互操作结果。

明确不在本切片内：投递队列、异步 outbox、自动重试、邮件模板系统、邮件供应商管理后台和新的外部邮件 API。

## 7. 阶段 2 的进入条件

账户自助安全闭环完成后，下一功能必须同时满足以下条件才可加入本文件：

1. 有明确的真实客户端、组织或运维事件，并说明影响范围。
2. 能用现有 Principal、组织和 RBAC 模型表达，若不能，必须说明新增数据模型或协议的必要性。
3. 明确失败关闭、撤销、审计、限流、迁移、回滚和兼容策略。
4. 能在本机 Docker 和真实 HTTP 测试中复现；面向用户的 UI 还要有 UI 验收证据。
5. 只选择一个扩展方向，完成后再重新评估下一方向。

在满足上述条件前，以下内容保持未排期，不属于当前功能清单：LDAP/AD 登录与同步、SCIM、SAML、WebAuthn/Passkey、Device Flow/CIBA/PAR/DPoP/Token Exchange、完整管理控制台、计费/套餐、通用策略脚本、多实例 HA、outbox/webhook 和跨区域恢复。

## 8. 每个功能的发布前检查

代码或配置变更完成后，至少执行与影响范围匹配的检查；Rust 仓库的提交前检查固定为：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

涉及数据库或集成测试时，使用本机 Docker 的 `scripts/run_tests.ps1`，记录镜像、容器、宿主端口、readiness、测试结果和清理状态。涉及 OIDC 样例时运行 `scripts/validate_oidc_rp_examples.ps1`；涉及 CI 或文档时运行 `actionlint`、`scripts/check_markdown_links.ps1` 和 `git diff --check`。

提交标题使用单一 Conventional Commit 前缀（`feat:`、`fix:`、`test:`、`docs:` 或 `chore:`），验证通过后立即推送当前分支。未完成、未验证或验证失败的功能不写入“已完成”清单。

## 9. 文档职责

| 内容 | 唯一入口 |
| --- | --- |
| 线性开发顺序与功能状态 | 本文 |
| 产品定位、能力边界和核心安全规则 | [KEYLO_DEVELOPMENT_BLUEPRINT.md](../design/KEYLO_DEVELOPMENT_BLUEPRINT.md) |
| API 请求、响应和错误语义 | [API_REFERENCE.md](../reference/API_REFERENCE.md) |
| 从零部署和联调步骤 | [END_TO_END_QUICKSTART.md](../guides/END_TO_END_QUICKSTART.md) |
| 密文配置和密钥轮换 | [SECRET_ENCRYPTION.md](../operations/SECRET_ENCRYPTION.md) 与 [KEY_ROTATION.md](../operations/KEY_ROTATION.md) |
| 第三方和资源服务接入 | [THIRD_PARTY_INTEGRATION.md](../integrations/THIRD_PARTY_INTEGRATION.md) 与 [integrations/README.md](../integrations/README.md) |
| Keycloak 可选互操作证据 | [KEYCLOAK_OIDC_MATRIX.md](../compatibility/KEYCLOAK_OIDC_MATRIX.md) |
| 历史发布和旧部署说明 | `docs/archive/`，只用于追溯 |
