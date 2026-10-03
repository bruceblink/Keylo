# Keylo 线性开发主线与功能清单

> 更新时间：2026-10-03
>
> 整理基线：2026-09-25；由 `main` 维护主线，本轮只更新当前 `main`，不调整其他分支；当前发布线为 `v2.1.2`。
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
- `进行中`：范围已确认，正在实现或补齐验收证据。
- `后续候选`：已有代码或验证缺口，但必须等当前切片完成后再确认实现范围。
- `未排期`：不是当前主线任务；除非出现真实使用信号，否则不得转入实现。
- `待环境验证`：功能边界已经写清，但验证所需的外部环境本次没有执行。

## 2. 线性路线

| 顺序 | 阶段 | 状态 | 结果 |
| --- | --- | --- | --- |
| 0 | 认证、会话、授权、组织和运行基线 | 已完成 | 形成当前 `v2.1.2` 发布线的可用能力和安全边界。 |
| 1 | 账户自助安全闭环 | 已完成 | 邮箱验证、忘记密码申请、密码重置邮件流程、首次强制改密、会话撤销和真实 SMTP 账户链路已完成并通过本机 Docker 验收。 |
| 2 | 托管账户恢复页面 | 已完成 | 已将邮箱验证和密码恢复 API 接入同源可点击页面，并通过真实后端、Docker 邮件链路和 UI 验收。 |
| 3 | 托管账户恢复 UI 自动化回归 | 已完成 | Playwright/Chromium 回归、Computer Use 可见窗口验收和 CI 门禁均已通过；不增加产品 API 或账户功能。 |
| 4 | OIDC 登录页的账户恢复入口 | 已完成 | 代码、单元/HTTP、真实后端 headless 和 Codex 内置浏览器可见交互通过；独立标签不转发授权参数，不改变登录和同意协议。 |
| 5 | 真实后端账户恢复浏览器门禁 | 下一切片 | 把现有真实 HTTP/SMTP 测试与浏览器交互串成可重复执行的本机 Docker 回归，补齐受控 API 响应不能证明的装配与邮件链路。 |
| 6 | OIDC 登录失败后的重试体验 | 后续候选 | 当前错误密码返回 JSON；在不改变认证判断和非浏览器 API 错误契约的前提下，让浏览器保留已验证授权参数并重试。 |
| 7 | 接入样例的 CI 清单对齐 | 后续候选 | 核对本地样例验证脚本与 CI；当前 Spring resource server 已有本地验证，但 CI 的样例步骤未执行该样例。 |

阶段 3 源于用户对账户恢复 UI 集成测试的明确要求。Playwright/Chromium 回归、Computer Use 本地可见窗口验收和 CI 门禁均已完成。2026-10-03 的 CI run `37089762986`（提交 `1d0b616`）中，Security Audit、Run Tests 和 Code Coverage 全部通过；Run Tests 包含 `Test account recovery UI`，Codecov 上传也成功。Computer Use 检查未提交真实密码变更。浏览器测试中使用受控 API 响应的场景只证明 UI 契约，不替代真实 HTTP、PostgreSQL 和 Mailpit 集成测试。2026-10-03 源码核对发现 OIDC 登录页尚未提供恢复入口，因此选择阶段 4；阶段 5 只解决已有功能的验证缺口，不扩展新协议。

阶段 3 验收条件：

1. Chromium 浏览器回归覆盖密码恢复申请的统一成功提示、有效/无效重置 token、邮箱验证成功/失败及无 token 状态。
2. 回归确认敏感 token 从 URL fragment 读取后立即清除、不进入 query string 或浏览器持久化存储，邮箱验证请求只发送一次。
3. 在桌面和 `390x844` 移动视口检查页面可用且无横向溢出；页面控制台无应用错误。
4. `npm ci`、`npm run build` 和浏览器回归通过，CI 对相关前端测试文件执行同一回归。
5. 使用 Computer Use 对本地运行页面完成可见窗口交互验收；真实账户状态或真实密码变更不通过 Computer Use 提交。

## 3. 当前已完成功能清单

| 领域 | 已交付能力 | 当前边界 |
| --- | --- | --- |
| 部署与首启 | SQLx 迁移、Docker Compose 依赖、PostgreSQL/Redis 就绪检查、启动 fail-fast、密文配置、RSA 密钥加载、setup wizard、healthz/readyz、固定基数 metrics。 | 当前以单实例 PostgreSQL/Redis 运行边界为准，不承诺多实例高可用或跨区域恢复。 |
| 标准 OIDC | Discovery、Authorization Code + PKCE、state/nonce、JWKS、UserInfo、consent、浏览器会话、logout、public/confidential client、client secret rotation 与登录页的独立账户恢复入口。 | 仅发布已实现的授权码流程；不包含 Dynamic Client Registration、Device Flow、CIBA、PAR、DPoP 或 Token Exchange；恢复入口不自动继续授权或绕过 consent。 |
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

基线证据记录于 2026-09-25，后续切片按日期追加；不同工具、提交和环境的证据不能相互替代：

| 验证 | 结果 |
| --- | --- |
| OIDC 账户恢复入口代码回归（2026-10-03） | `npm ci`、`npm run build`、原有 Chromium 7 项 UI 契约回归、`cargo build --bin keylo`、fmt、workspace Clippy、Markdown 链接和 `git diff --check` 通过。`scripts/run_tests.ps1 -DatabasePort 55432` 使用本机 Docker `postgres:17-alpine`（`127.0.0.1:55432` -> `5432`）与 `axllent/mailpit:v1.21.8`（SMTP `11025` -> `1025`，API `18025` -> `8025`）；readiness、150 单元、1 customer-support、26 database、77 HTTP、3 load、3 OAuth、12 RBAC、4 SMTP 和 13 user 共 289 项全部通过；测试容器、匿名卷和脚本临时密钥目录已清理。 |
| OIDC 账户恢复入口真实后端 headless 检查（2026-10-03） | 独立本机 Docker PostgreSQL 17（`55433`）、Mailpit `v1.21.8`（SMTP `11026`、API `18026`）与真实 Keylo（`127.0.0.1:2346`）readiness 通过。Chromium 在 `1280x720` 和 `390x844` 点击恢复入口，确认同源新标签、`window.opener=null`、无 Referer、原授权 URL/hidden fields/合成用户名不变、无横向溢出/持久化存储/应用错误/外部资源请求；匿名恢复申请经真实 HTTP 返回统一提示，未提交密码修改或真实凭据。后端与 Docker 容器、匿名卷和端口映射已清理；系统策略拒绝递归删除 `C:\Users\likanug\AppData\Local\Temp\keylo-oidc-recovery-ui-9dc0a119da3a`，本轮临时测试密钥、构建副本与辅助脚本待人工清理，不在 Git 中。截图保留在独立临时证据目录。 |
| OIDC 账户恢复入口 Codex 内置浏览器（2026-10-03） | 在可见 Codex In-app Browser 打开真实 Keylo `/v1/oidc/authorize`，点击 `Forgot your password?` 后实际出现独立恢复标签；输入 `.test` 合成标识符并提交真实恢复申请，页面返回统一成功提示，关闭恢复标签后原登录页、原授权 URL 与 8 项 hidden fields 不变。`1280x720` 和 `390x844` 视口检查通过，缺失 token、表单启用/恢复和控制台 error/warn 均正常；截图保存于仓库外。Windows Chrome 首次状态读取因无法可靠判断 URL 而停止，未重试该窗口输入；按用户要求切换内置浏览器后验收通过。未输入真实凭据、未提交密码变更；本次可见交互不证明真实账户邮件投递，SMTP 证据来自独立 Docker Rust 测试。 |
| OIDC 账户恢复入口远端 CI（2026-10-03） | 功能提交 `e789ea3` 已推送到 `main`；run `37104858502` 已创建，交付核对时 Run Tests、Security Audit 和 Code Coverage 均为 `in_progress`，结论待下一次核对。既有 `1d0b616` 的绿灯不作为本次提交的证据，也不把本地通过等同于远端通过。 |
| 托管账户恢复 UI 自动化回归（2026-10-03） | `web` 执行 `npm ci`、`npm run build` 和 `npm run test:e2e`；Chromium 7 项通过，覆盖账户存在性统一提示、密码重置成功/失败、邮箱验证成功/失败/缺失 token、fragment 清理与存储检查、重复提交防护、桌面和 `390x844` 无横向溢出，以及共享 setup 页面回归。API 响应由测试控制，只作为 UI 契约验证；页面运行时错误断言为空。Playwright 1.63.0、锁定的 Vite 7.3.6；`npm audit` 为 0 vulnerabilities。 |
| Computer Use 可见窗口检查（2026-10-03） | Codex In-app Browser 在 `1280x720` 可见窗口打开本地 Vite 页面；核对密码恢复表单可输入并启用提交按钮（仅输入 `.test` 合成标识符、未提交），随后打开邮箱验证缺失 fragment 页面并确认稳定提示；浏览器控制台 error/warn 为空。真实密码变更未通过 UI 提交。 |
| UI 自动化 CI 门禁（2026-10-03） | `.github/workflows/ci.yml` 已将 Chromium UI 回归接入 Run Tests job，相关 `web/tests/**` 文件纳入触发路径；提交 `1d0b616` 的 run `37089762986` 已完成，Security Audit、Run Tests 和 Code Coverage 全部通过。该证据只对应此提交，不代表后续代码已经通过远端验证。 |
| `.\scripts\run_tests.ps1 -DatabasePort 55432` | 使用本机 Docker `postgres:17-alpine`（宿主 `127.0.0.1:55432` -> 容器 `5432`）和 `axllent/mailpit:v1.21.8`（SMTP `127.0.0.1:11025` -> `1025`，API `127.0.0.1:18025` -> `8025`）；PostgreSQL readiness、Mailpit readiness、fmt、workspace Clippy、149 个单元、1 个 customer-support、26 个 database、77 个 HTTP、3 个 load、3 个 OAuth、12 个 RBAC、4 个 SMTP 和 13 个 user 测试全部通过；真实 `AppState::new` 账户邮件流程已验证邮箱验证、密码重置、首次强制改密和失败撤销，Mailpit 重启后再次投递成功，端口不可达和黑洞超时均撤销 token，无效 TLS 配置在投递前拒绝，脚本结束后容器、匿名卷、端口映射和临时密钥目录已清理。 |
| `.\scripts\validate_oidc_rp_examples.ps1` | Node、Go、Rust Axum、Spring Boot OIDC RP 和 Spring resource server 样例通过；该结果不等同于 Keycloak/TLS/浏览器互操作通过。 |
| `.\scripts\check_markdown_links.ps1` | README 和 `docs/` 下相对 Markdown 链接通过；外部 URL、锚点和围栏代码示例不在检查范围内。 |
| `actionlint .github/workflows/ci.yml`、`git diff --check` | 通过。 |
| 托管账户恢复页面 UI 验收 | 使用 computer-use 在可见 Codex In-app Browser 窗口完成真实交互；页面访问本地 Keylo `127.0.0.1:2345`，邮件来自本机 Docker Mailpit，覆盖恢复申请、邮箱验证成功、密码重置有效 token 表单、fragment 清除、无效 token 错误状态，并在 `390x844` 视口检查移动布局。Computer Use 要求最终改密步骤交由用户接管，因此未通过该工具提交新密码；此前 Playwright headless 真实后端流程已完成密码更新和新密码登录验证。 |
| 托管账户恢复文档和全量回归 | API 参考、端到端快速开始、主线验证记录已更新；本机 Docker 全量测试使用 `postgres:17-alpine`（`127.0.0.1:55432`）和 `axllent/mailpit:v1.21.8`（SMTP `11025`、API `18025`），fmt、Clippy、149 单测、1 customer-support、26 database、77 HTTP、3 load、3 OAuth、12 RBAC、4 SMTP、13 user 全部通过，容器和临时密钥已清理。 |
| GitHub Actions `CI/CD Pipeline`（`main` run `35738231390`、`dev` run `35738263636`） | 均在提交 `b987a2a` 上完成；Security Audit、Run Tests 和 Code Coverage 全部通过。 |
| GitHub Actions `Release`（run `35741991437`） | `v2.1.2` 发布成功，生成双语变更说明并发布 GHCR 镜像。 |

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

邮件 provider、用户邮箱验证、忘记密码申请和密码重置已完成。真实 `AppState::new` 已验证会按配置装配 SMTP provider，账户接口能从 Mailpit 收到验证和重置邮件，并完成 token 消费、首次强制改密和失败撤销。SMTP 适配器只负责一次投递尝试，密码可通过统一 AES-256-GCM 密文文件加载；投递失败会撤销新建的一次性 token。密码恢复 token 只保存 SHA-256 摘要，绑定当前已验证邮箱，成功消费在同一事务内更新密码、撤销 refresh/OIDC 会话并写入审计。SMTP 生产运维加固已完成；阶段 2 协议和基础设施扩展仍未排期。

这是面向用户的认证功能。若实现涉及 `web/` 页面，提交前必须完成真实窗口验收；真实窗口无法启动时，至少执行 headless 渲染和交互测试，并在验证记录中明确限制。仅修改 API 和服务端时，以真实 HTTP 测试和本机 Docker PostgreSQL 集成测试为准。

## 6. 已完成切片：SMTP 生产运维加固

状态：已完成。该切片只处理已经接入 SMTP 后的运维可见性和恢复验证，不引入 outbox、后台重试或新的邮件服务适配器。

交付结果：固定基数投递指标、启动配置检查、SMTP 失败分类日志、Mailpit 故障恢复回归和
SMTP 运维文档均已完成并通过本机 Docker 全量验证。`/metrics` 暴露
`keylo_mail_deliveries_total`，应用只记录六种固定结果；启动和运行时日志只记录稳定分类
与下一步动作，不包含敏感邮件或 SMTP 原始诊断。详细操作步骤见
[SMTP 账户邮件运维](../operations/SMTP_OPERATIONS.md)。

范围固定为：

1. 为投递成功、超时、临时不可用、永久拒绝和配置禁用增加固定基数指标；指标不得包含收件人、账号标识、token、邮件正文或 SMTP 原始回复。
2. 增加 SMTP 配置启动检查和证书/超时失败的可操作日志分类；日志只保留稳定错误类别和下一步动作。
3. 增加本机 Docker Mailpit 的恢复回归：服务重启后重新投递；SMTP 端口不可达和超时保持失败关闭并撤销 token；TLS 配置错误在启动阶段拒绝且不创建 token。已完成。
4. 更新运维文档和发布前验证记录，说明密文轮换、证书更新、故障恢复和清理步骤。已完成。

验收条件：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、本机 Docker PostgreSQL 17 + Mailpit 集成测试、固定基数指标测试、失败分类测试和 Markdown/CI 检查全部通过；不得把 Mailpit 结果描述成真实外部 SMTP 供应商互操作结果。

明确不在本切片内：投递队列、异步 outbox、自动重试、邮件模板系统、邮件供应商管理后台和新的外部邮件 API。

## 7. 已完成切片：托管账户恢复页面

### 7.1 使用场景和边界

用户收到邮箱验证或密码重置邮件后，可以直接打开同源页面完成操作，不需要复制 token 或自行编写 API 请求。页面只消费现有一次性 token API，不新增账户状态、数据库表、邮件队列或外部邮件 provider。

本切片包含：

1. `/account/email-verification` 页面：从 URL fragment 读取 token，立即用 `history.replaceState` 清除 fragment，然后调用现有邮箱验证确认接口。
2. `/account/password-reset` 页面：支持输入 identifier 申请重置；从 URL fragment 读取重置 token、设置新密码并调用现有确认接口。
3. 邮件正文只提供同源可点击链接；token 仅位于 URL fragment，不放入查询参数，不写入服务端访问日志、审计记录或浏览器持久化存储。
4. setup 页面与 account 页面共用前端构建和静态资源处理，但保持 setup 初始化和只读状态行为不变。
5. 页面提供匿名、过期、重放、限流、投递失败和网络错误的稳定提示；申请页面不得泄露账户是否存在。

本切片不包含登录、注册、账户资料、MFA 管理、会话管理、完整 Account Console、邮件模板系统、outbox、自动重试或新的外部邮件 API。

### 7.2 实施顺序和提交边界

1. 先更新本计划并单独提交，确认范围和验收条件。
2. 实现共享前端入口、密码重置申请/确认页面、邮件链接和安全响应头，作为一个可独立验收提交。
3. 实现邮箱验证页面和邮件链接，作为一个可独立验收提交。
4. 更新 API/使用文档和验证记录；每个提交通过对应测试后立即推送当前功能分支。

### 7.3 验收条件

1. `npm ci`、前端构建和页面交互测试通过；优先使用真实浏览器窗口完成桌面和移动宽度验收，无法启动真实窗口时使用 headless 并记录限制。
2. 本机 Docker 使用 `postgres:17-alpine` 与 `axllent/mailpit:v1.21.8`，验证邮件链接、成功消费、过期、重放、邮箱变化、投递失败撤销和容器清理。
3. token 只作为收件人邮件中的一次性链接 fragment 传递；页面不将其写入 query string、日志、审计详情、localStorage 或 sessionStorage。
4. Rust 提交前通过 `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings` 和完整 `scripts/run_tests.ps1`；相关文档变更通过 Markdown 链接检查和 `git diff --check`。
5. setup、OIDC、现有邮箱验证 API、密码重置 API 和会话撤销行为无回归。

## 8. 下一切片的进入条件

### 8.1 已完成切片：OIDC 登录页的账户恢复入口

状态：代码、自动化验证和 Codex 内置浏览器可见交互均已完成。2026-10-03 在此边界结束开发，不启动阶段 5；独立 UI 环境已停止并移除 Docker 资源，受系统删除策略限制的临时文件保留为明确清理事项。

使用场景：标准 OIDC 客户端把用户带到 `/v1/oidc/authorize` 后，切片前忘记密码的用户无法从登录页进入已有恢复流程。该缺口来自源码核对，不假设新的客户、协议或管理控制台需求。

实施范围：

1. 在服务器渲染的登录页增加固定同源 `/account/password-reset` 链接，放在登录表单外；补充页面标题、UTF-8 和移动 viewport 元数据，不重做登录或同意页布局。
2. 使用独立标签和 `rel="noopener noreferrer"`；原登录页保留 `state`、`nonce`、redirect URI 和 PKCE hidden fields，恢复页不得接收这些参数、账号或密码。
3. 不新增 API、配置或迁移；不自动继续授权、不跳过 consent、不新增任意 return URL，不修改认证、限流、审计或一次性 token 的边界。
4. 同步更新 OIDC 接口与账户恢复使用说明；在一个功能提交中交付实现、回归和验证记录。

验收条件：

- 单元和真实 HTTP 测试确认链接地址、独立标签、安全属性、客户端名称转义以及完整授权参数保留；没有浏览器 session 时仍显示登录表单。
- 浏览器验证点击入口后打开同源恢复页，`window.opener` 为 `null`，请求无 Referer，原表单和原授权 URL 不变；桌面和 `390x844` 视口可用。
- Computer Use 在真实窗口点击入口并确认恢复表单，返回原标签后仍能看到原登录页；不输入或提交真实认证凭据、不提交密码变更。
- `npm ci`、`npm run build`、现有 7 项 Chromium UI 回归、Rust fmt、workspace Clippy、构建、本机 Docker 全量测试、Markdown 链接和 diff 检查通过。

回滚边界：移除该静态链接、页面元数据及其回归即可回到原登录 UI；账户恢复 API、邮件链接、数据库结构和已有会话均不变。

### 8.2 后续顺序

下次先核对功能提交 `e789ea3` 的 CI run `37104858502`，失败时先修复；并清理本轮剩余临时目录。通过后只推进阶段 5。阶段 6、7 依次等待前一切片交付，不并行实施：

1. 使用独立本机 Docker PostgreSQL 17 和 Mailpit，启动真实 Keylo 而非仅使用 Vite proxy 或受控 API 响应。
2. 用合成账户和真实邮件驱动邮箱验证、密码恢复、重放拒绝及新密码登录；浏览器日志和失败产物不得包含原始 token、密码、密钥或收件人。
3. 增加有界启动、readiness、失败退出、端口隔离与清理；通过一个入口执行，并接入 CI。现有快速 UI 契约测试保留，真实链路测试单独标识。
4. 阶段 6 只处理浏览器错误密码重试：保持统一错误提示、密码不回显、原始已验证授权参数保留，并验证停用用户、外部身份账户和组织状态拒绝；首次强制改密和 MFA 等认证流程不能因此被绕过。
5. 阶段 7 检查接入样例与 CI 清单是否一致，补上 Spring resource server 构建和失败关闭回归；只补实际缺失的门禁，不借此新增 SDK、客户端协议或管理界面。

阶段 5 不承诺外部 SMTP 供应商、Keycloak/TLS 矩阵或发布结果；这些仍需对应独立环境证据。新产品功能必须同时满足以下条件才可加入本文件：

1. 有明确的真实客户端、组织或运维事件，并说明影响范围。
2. 能用现有 Principal、组织和 RBAC 模型表达，若不能，必须说明新增数据模型或协议的必要性。
3. 明确失败关闭、撤销、审计、限流、迁移、回滚和兼容策略。
4. 能在本机 Docker 和真实 HTTP 测试中复现；面向用户的 UI 还要有 UI 验收证据。
5. 只选择一个扩展方向，完成后再重新评估下一方向。

在满足上述条件前，以下内容保持未排期，不属于当前功能清单：LDAP/AD 登录与同步、SCIM、SAML、WebAuthn/Passkey、Device Flow/CIBA/PAR/DPoP/Token Exchange、完整管理控制台、计费/套餐、通用策略脚本、多实例 HA、outbox/webhook 和跨区域恢复。

## 9. 每个功能的发布前检查

代码或配置变更完成后，至少执行与影响范围匹配的检查；Rust 仓库的提交前检查固定为：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

涉及数据库或集成测试时，使用本机 Docker 的 `scripts/run_tests.ps1`，记录镜像、容器、宿主端口、readiness、测试结果和清理状态。涉及 OIDC 样例时运行 `scripts/validate_oidc_rp_examples.ps1`；涉及 CI 或文档时运行 `actionlint`、`scripts/check_markdown_links.ps1` 和 `git diff --check`。

提交标题使用单一 Conventional Commit 前缀（`feat:`、`fix:`、`test:`、`docs:` 或 `chore:`），验证通过后立即推送当前分支。未完成、未验证或验证失败的功能不写入“已完成”清单。

## 10. 文档职责

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
