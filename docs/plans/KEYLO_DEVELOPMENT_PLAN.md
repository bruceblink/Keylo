# Keylo 线性开发主线与功能清单

> 更新时间：2026-10-15
>
> 整理基线：2026-09-25；原始代码审查基于 `94c4565`。阶段 8–11 已完成，阶段 12 为下一切片。阶段 9 提交 `415d3d5` 的 [CI run 38698663616](https://github.com/bruceblink/Keylo/actions/runs/38698663616) 已通过 Run Tests、Security Audit 与 Code Coverage。各切片的本地及远端证据见第 4 节；当前发布线为 `v2.1.2`。
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
| 3 | 托管账户恢复 UI 自动化回归 | 已完成 | Playwright/Chromium 回归、Computer Use 可见窗口验收和 CI 检查均已通过；不增加产品 API 或账户功能。 |
| 4 | OIDC 登录页的账户恢复入口 | 已完成 | 代码、单元/HTTP、真实后端 headless 和 Codex 内置浏览器可见交互通过；独立标签不转发授权参数，不改变登录和同意协议。 |
| 5 | 真实后端账户恢复浏览器回归 | 已完成 | 本机独立 Docker、真实 Keylo、Mailpit 和 4 项桌面/移动浏览器测试通过；CI 的 Run Tests 与 Code Coverage 通过。 |
| 6 | OIDC 登录失败后的重试体验 | 已完成 | 只将浏览器 `WrongCredentials` 显示为可重试表单；保留已验证授权参数，不回显密码，不改变认证判定或 API 错误契约。 |
| 7 | 接入样例的 CI 清单对齐 | 已完成 | CI 已触发资源服务样例文件变更，但验证步骤漏掉 Spring resource server；补上 Gradle 测试和 wrapper 配置触发路径，并执行失败关闭回归。 |
| 8 | 强制改密限制覆盖统一授权入口 | 已完成 | 四个统一授权入口复用强制改密检查；新增真实数据库回归确认受限 token 拒绝、重新登录恢复、组织隔离及 service/machine 授权保持。 |
| 9 | 真实依赖测试失败关闭 | 已完成 | 显式配置数据库时，连接、迁移和初始化失败必须导致测试非零退出，不能回退内存路由后报告通过。 |
| 10 | OIDC 登录的限流与账号锁定 | 已完成 | 与已有密码登录入口共用失败计数、账号锁定及来源限流，阻止改用浏览器登录绕过限制。 |
| 11 | MFA 验证的猜码保护 | 已完成 | TOTP、恢复码和 enrollment 确认共享稳定用户 ID 与来源 IP 请求额度，并在解密和 bcrypt 之前限流。 |
| 12 | 改密后撤销旧恢复链接 | 下一切片 | 自行改密、管理员 reset 和管理员 update password 均在同一事务撤销待消费恢复 token。 |
| 13 | JWT 轮换状态的持久化与恢复 | 后续候选 | 保存 passive key 的绝对到期时间，重启不能重新启用已过期旧 key；失败写入保持一致。 |
| 14 | 默认生产 Compose 的启动闭环 | 后续候选 | 对齐必需配置、密钥卷权限和文档，以容器启动、readiness 及重启证明模板可用。 |

阶段 8–14 来自第 11 节的现有代码缺陷。阶段 8–11 已修复并完成本地验证；只有阶段 12 可以直接进入实现，其余候选按表中顺序在前一切片完成后复核。MFA enrollment 并发、组织角色类型兼容性和成员暂停后的 OIDC code 撤销列为阶段 14 后的候选，见第 8.6 节。新增协议和控制台功能仍遵守第 8.2 节的进入条件。

阶段 3 源于用户对账户恢复 UI 集成测试的明确要求。Playwright/Chromium 回归、Computer Use 本地可见窗口验收和 CI 检查均已完成。2026-10-03 的 CI run `37089762986`（提交 `1d0b616`）中，Security Audit、Run Tests 和 Code Coverage 全部通过；Run Tests 包含 `Test account recovery UI`，Codecov 上传也成功。Computer Use 检查未提交真实密码变更。浏览器测试中使用受控 API 响应的场景只证明 UI 交互约定，不替代真实 HTTP、PostgreSQL 和 Mailpit 集成测试。2026-10-03 源码核对发现 OIDC 登录页尚未提供恢复入口，因此选择阶段 4；阶段 5 只解决已有功能的验证缺口，不扩展新协议。

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
| 阶段 11：MFA 验证猜码保护（2026-10-15） | 新增两个真实 PostgreSQL HTTP 回归通过，覆盖 UID 限额跨 TOTP/enrollment、换 access token 后有效恢复码仍受限，以及可信来源 IP 在不同账户间共享额度；新增额度单元回归验证账号/来源独立上限与窗口过期恢复。现有 MFA 生命周期回归通过。`cargo check --workspace --all-targets --locked`、fmt、workspace Clippy、Markdown 链接和 diff 检查通过。独立 PostgreSQL 17 测试容器及数据已清理；Redis 多实例故障未新增验证，本轮远端 CI 待确认。 |
| 阶段 10：OIDC 登录共享保护（2026-10-15） | 新增回归先因实际 200、预期 429 失败；实现后 9 项新增回归通过。`scripts/run_tests.ps1 -DatabasePort 36132 -SmtpPort 36225 -SmtpApiPort 36825` 完整以 0 退出：152 单元 + 153 集成共 305 项通过（含 91 HTTP，另 1 项默认 ignored 专用故障探针），21 项故障/对照检查通过。使用本机 `postgres:17-alpine`、`axllent/mailpit:v1.21.8`，容器后缀 `e964003522f7`；readiness、fmt、workspace Clippy、actionlint、Markdown 链接和 diff 检查通过。`npm run test:e2e:real` 在 Chromium 153、`1280x720` / `390x844` 真实服务中完成 6 项浏览器回归；前后端构建、PostgreSQL/Mailpit/Keylo readiness 通过。本轮全部容器、匿名卷、临时密钥/凭据及红测数据库均已清理。Redis 多实例和命令故障未新增验证；本轮远端 CI 待确认。 |
| 阶段 9：真实依赖测试失败关闭（2026-10-15） | Bash Docker runner 完整通过，全量 296 项测试通过（152 单元、144 集成；另有 1 项默认 ignored 的专用故障探针），21 项故障/对照检查全部通过。PowerShell 的全量 296 项测试也通过；修复多 Python 路径选择后，单独复测脚本的实际故障调用，21 项检查通过。两套环境均使用本机 `postgres:17-alpine` 和 `axllent/mailpit:v1.21.8`：Bash PostgreSQL/SMTP/API 端口为 `35632/35225/35925`，PowerShell 为 `35532/35125/35825`。两套 runner 的容器后缀分别为 `2d832498bf3e8ee1`、`223a57bee1c8`，依赖均达到 readiness；本轮容器、匿名卷与临时凭据已清理。额外 PowerShell 故障调用使用 `35732` 端口上的独立 PostgreSQL，也已清理。fmt、workspace Clippy、actionlint、Python/Bash/PowerShell 语法和 Markdown 相对链接检查通过。`415d3d5` 的 [run 38698663616](https://github.com/bruceblink/Keylo/actions/runs/38698663616) 已通过 Run Tests（含故障检查）、Security Audit 与 Code Coverage。 |
| CI 安全依赖修复（2026-10-15） | [run 38684723853](https://github.com/bruceblink/Keylo/actions/runs/38684723853) 的 Security Audit 失败；本地复现为 `rustls 0.23.45` 命中 RUSTSEC-2026-0346、0347、0348、0349。仅将锁文件中的 rustls 更新为 `0.23.46`，未新增审计豁免；同一 `cargo audit --ignore RUSTSEC-2023-0071` 以 0 退出，原有 6 条非阻塞警告保留。`fa5bf36` 的 [run 38696219788](https://github.com/bruceblink/Keylo/actions/runs/38696219788) 已确认 Security Audit 与 Run Tests 通过；包含此修复的阶段 9 提交已通过三项 CI，见上一行。 |
| 阶段 8：统一授权强制改密限制（2026-10-15） | 先执行新增回归，原实现因实际 200、预期 403 失败；共享检查接入后新增 3 项全部通过。`tests/authorization/password_change.rs` 由现有 `integration_test` 引入，CI 的 PostgreSQL 测试入口会执行。不可达 `TEST_DATABASE_URL` 的故障注入以 101 退出，不回退内存或跳过。fmt、workspace Clippy、Markdown 相对链接和 diff 检查通过；最终 152 单元、1 customer-support、26 database、82 HTTP、3 load、3 OAuth、12 RBAC、4 SMTP、13 user，共 296 项 Rust 测试通过。本机 Docker 使用独立 PostgreSQL 17（宿主 `32768`）和 Mailpit `v1.21.8`（SMTP `32769`、API `32770`）；首轮 Mailpit 使用随机宿主端口，重启后端口变化导致恢复测试失败，改用固定映射后重跑 SMTP 和尚未执行的 user 套件通过。容器及匿名卷已清理；本切片不改 UI，未执行浏览器回归或确认本次远端 CI。 |
| 代码审查与定向复现（2026-10-15，`94c4565`） | 当前库 `cargo build --lib --locked` 通过。仓库外合成账户 harness 在独立本机 Docker PostgreSQL 17 中确认：受限改密 token 得到 `allowed=true`、普通改密/管理员 reset 后旧恢复链接仍能覆盖密码、组织角色类型变更漏查绑定、成员暂停后恢复使旧 OIDC code 重新可兑换。直接调用真实 OIDC handler 确认已有账号锁不能阻止创建浏览器会话。启动加载器实验确认 1 秒 overlap 到期后旧 token 被拒绝，但重新加载配置又可验签。`docker compose config --format json` 确认生产模板缺少两个必需变量。显式使用不可达 `TEST_DATABASE_URL` 运行迁移测试，错误地得到退出码 0、1 passed；这是测试门禁缺陷的证据，不是数据库验收通过。MFA 猜码保护与 enrollment 竞争仅做静态调用链审查，未运行穷举或并发复现。测试容器及匿名卷已清理；未执行全量测试、外部 SMTP 或远端 CI。 |
| OIDC 登录重试与 Spring Boot 资源服务 CI（2026-10-13） | 提交 `7eb85c0` 的 [GitHub Actions run 38401038528](https://github.com/bruceblink/Keylo/actions/runs/38401038528) 中，`Run Tests`、`Security Audit` 和 `Code Coverage` 全部通过。测试任务包含真实服务 Chromium 回归和 Spring Boot resource server 的 Gradle 测试。该结果关闭阶段 6、7。 |
| OIDC 账户恢复入口代码回归（2026-10-03） | `npm ci`、`npm run build`、原有 Chromium 7 项 UI 交互约定回归、`cargo build --bin keylo`、fmt、workspace Clippy、Markdown 链接和 `git diff --check` 通过。`scripts/run_tests.ps1 -DatabasePort 55432` 使用本机 Docker `postgres:17-alpine`（`127.0.0.1:55432` -> `5432`）与 `axllent/mailpit:v1.21.8`（SMTP `11025` -> `1025`，API `18025` -> `8025`）；readiness、150 单元、1 customer-support、26 database、77 HTTP、3 load、3 OAuth、12 RBAC、4 SMTP 和 13 user 共 289 项全部通过；测试容器、匿名卷和脚本临时密钥目录已清理。 |
| OIDC 账户恢复入口真实后端 headless 检查（2026-10-03） | 独立本机 Docker PostgreSQL 17（`55433`）、Mailpit `v1.21.8`（SMTP `11026`、API `18026`）与真实 Keylo（`127.0.0.1:2346`）readiness 通过。Chromium 在 `1280x720` 和 `390x844` 点击恢复入口，确认同源新标签、`window.opener=null`、无 Referer、原授权 URL/hidden fields/合成用户名不变、无横向溢出/持久化存储/应用错误/外部资源请求；匿名恢复申请经真实 HTTP 返回统一提示，未提交密码修改或真实凭据。后端与 Docker 容器、匿名卷和端口映射已清理；系统策略拒绝递归删除 `C:\Users\likanug\AppData\Local\Temp\keylo-oidc-recovery-ui-9dc0a119da3a`，本轮临时测试密钥、构建副本与辅助脚本待人工清理，不在 Git 中。截图保留在独立临时证据目录。 |
| OIDC 账户恢复入口 Codex 内置浏览器（2026-10-03） | 在可见 Codex In-app Browser 打开真实 Keylo `/v1/oidc/authorize`，点击 `Forgot your password?` 后实际出现独立恢复标签；输入 `.test` 合成标识符并提交真实恢复申请，页面返回统一成功提示，关闭恢复标签后原登录页、原授权 URL 与 8 项 hidden fields 不变。`1280x720` 和 `390x844` 视口检查通过，缺失 token、表单启用/恢复和控制台 error/warn 均正常；截图保存于仓库外。Windows Chrome 首次状态读取因无法可靠判断 URL 而停止，未重试该窗口输入；按用户要求切换内置浏览器后验收通过。未输入真实凭据、未提交密码变更；本次可见交互不证明真实账户邮件投递，SMTP 证据来自独立 Docker Rust 测试。 |
| OIDC 账户恢复入口远端 CI（2026-10-03） | 功能提交 `e789ea3` 已推送到 `main`；run `37104858502` 已完成，Run Tests、Security Audit 和 Code Coverage 全部通过。Run Tests 包含 UI 回归、完整 Rust 集成测试、OIDC relying-party 样例和 release 构建；Code Coverage 完成 tarpaulin 与 Codecov 上传。 |
| 真实服务账户恢复浏览器回归（2026-10-13） | `npm run test:e2e:real` 独立启动本机 Docker `postgres:17-alpine`（本次 loopback 端口 `9061`）、`axllent/mailpit:v1.21.8`（SMTP `9063`、API `9064`）和真实 Keylo（`127.0.0.1:9065`）。就绪检查、前端和后端构建均通过；桌面与移动视口共 4 项浏览器测试通过，覆盖真实 OIDC 恢复入口、授权字段保留、真实 SMTP 邮件链接、邮箱验证、密码重置、token 重放拒绝、新密码登录、旧密码与旧 refresh token 拒绝。`--skip-build -- --grep __force_no_test__` 的受控失败检查返回非零；两次运行都清理本轮容器、匿名卷、Keylo 进程和临时密钥。Computer Use 在 Codex 内置浏览器以 `.test` 合成标识符验证本机恢复申请提示和原登录标签保持；未输入真实账户或提交密码变更。 |
| 真实服务账户恢复浏览器远端 CI（2026-10-13） | 提交 `b7b059e` 的 run `38391938023` 与 `38391937263` 均通过 Run Tests（含真实服务浏览器回归）和 Code Coverage。两次唯一失败项是 Security Audit：锁定的 `quinn-proto 0.11.15` 命中 5 条 RustSec 漏洞。提交 `148b4b8` 将其更新到 `0.11.18`，并满足该版本的 `rand 0.10.1` 依赖；本机 fmt、Clippy 和 289 项 Rust 测试通过。后续 CI run `38395463385` 已全部通过 Security Audit、Run Tests 和 Code Coverage。 |
| OIDC 登录失败重试本机验证（2026-10-13） | `scripts/run_tests.ps1 -DatabasePort 55432` 使用本机 Docker PostgreSQL `17-alpine`（`55432` -> `5432`）和 Mailpit `v1.21.8`（SMTP `11025` -> `1025`，API `18025` -> `8025`）；启动和 readiness 通过，fmt、workspace Clippy 和 293 项 Rust 测试通过，容器、匿名卷与临时密钥目录已清理。`npm run build`、`git diff --check` 和 Markdown 相对链接检查通过。 |
| OIDC 登录失败重试真实服务浏览器测试（2026-10-13） | `npm run test:e2e:real` 启动本机 Docker PostgreSQL `17-alpine`（本次 `8321` -> `5432`）、Mailpit `v1.21.8`（SMTP `8323` -> `1025`，API/UI `8324` -> `8025`）和真实 Keylo（`127.0.0.1:8326`）。前端、后端构建及 readiness 通过；桌面和移动 Chromium 共 6 项测试通过，覆盖真实 OIDC 登录失败、清空密码、保留授权字段、同标签正确重试进入 consent，以及账户恢复和 SMTP 流程；容器、匿名卷和临时密钥目录已清理。 |
| OIDC 登录失败重试 Computer Use 可见窗口检查（2026-10-13） | Codex 内置浏览器连接本机真实 Keylo（`127.0.0.1:3901`）、Docker PostgreSQL `17-alpine`（`3894` -> `5432`）和 Mailpit `v1.21.8`（SMTP `3896` -> `1025`，API/UI `3897` -> `8025`）。只使用合成账户；可见窗口显示统一错误提示、同标签重试页保留用户名且密码为空，正确密码进入 consent。服务进程与带本次 run 标签的 Docker 容器已移除。Shell 自动审批拒绝删除本次 `--serve` 运行的临时目录；临时配置与合成测试密钥仍在本机，未加入 Git。 |
| 托管账户恢复 UI 自动化回归（2026-10-03） | `web` 执行 `npm ci`、`npm run build` 和 `npm run test:e2e`；Chromium 7 项通过，覆盖账户存在性统一提示、密码重置成功/失败、邮箱验证成功/失败/缺失 token、fragment 清理与存储检查、重复提交防护、桌面和 `390x844` 无横向溢出，以及共享 setup 页面回归。API 响应由测试控制，只作为 UI 交互约定验证；页面运行时错误断言为空。Playwright 1.63.0、锁定的 Vite 7.3.6；`npm audit` 为 0 vulnerabilities。 |
| Computer Use 可见窗口检查（2026-10-03） | Codex In-app Browser 在 `1280x720` 可见窗口打开本地 Vite 页面；核对密码恢复表单可输入并启用提交按钮（仅输入 `.test` 合成标识符、未提交），随后打开邮箱验证缺失 fragment 页面并确认稳定提示；浏览器控制台 error/warn 为空。真实密码变更未通过 UI 提交。 |
| UI 自动化 CI 检查（2026-10-03） | `.github/workflows/ci.yml` 已将 Chromium UI 回归接入 Run Tests job，相关 `web/tests/**` 文件纳入触发路径；提交 `1d0b616` 的 run `37089762986` 已完成，Security Audit、Run Tests 和 Code Coverage 全部通过。该证据只对应此提交，不代表后续代码已经通过远端验证。 |
| 本机 Docker 全量验证（2026-09-25） | 使用本机 Docker `postgres:17-alpine`（宿主 `127.0.0.1:55432` -> 容器 `5432`）和 `axllent/mailpit:v1.21.8`（SMTP `127.0.0.1:11025` -> `1025`，API `127.0.0.1:18025` -> `8025`）；PostgreSQL readiness、Mailpit readiness、fmt、workspace Clippy、149 个单元、1 个 customer-support、26 个 database、77 个 HTTP、3 个 load、3 个 OAuth、12 个 RBAC、4 个 SMTP 和 13 个 user 测试全部通过；真实 `AppState::new` 账户邮件流程已验证邮箱验证、密码重置、首次强制改密和失败撤销，Mailpit 重启后再次投递成功，端口不可达和黑洞超时均撤销 token，无效 TLS 配置在投递前拒绝，脚本结束后容器、匿名卷、端口映射和临时密钥目录已清理。 |
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

邮件 provider、用户邮箱验证、忘记密码申请和密码重置已完成。真实 `AppState::new` 已验证会按配置装配 SMTP provider，账户接口能从 Mailpit 收到验证和重置邮件，并完成 token 消费、首次强制改密和失败撤销。SMTP 适配器只负责一次投递尝试，密码可通过统一 AES-256-GCM 密文文件加载；投递失败会撤销新建的一次性 token。密码恢复 token 只保存 SHA-256 摘要，绑定当前已验证邮箱，成功消费在同一事务内更新密码、撤销 refresh/OIDC 会话并写入审计。SMTP 生产运维加固已完成；协议和基础设施扩展仍未排期。

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

状态：代码、自动化验证和 Codex 内置浏览器可见交互均已完成。2026-10-11 复审确认阶段 4 已交付。独立 UI 环境已停止并移除 Docker 资源；系统策略拒绝递归删除的临时目录位于仓库外，不阻塞阶段 5，也不属于 Git 交付内容。

使用场景：标准 OIDC 客户端把用户带到 `/v1/oidc/authorize` 后，切片前忘记密码的用户无法从登录页进入已有恢复流程。该缺口来自源码核对，不假设新的客户、协议或管理控制台需求。

实施范围：

1. 在服务器渲染的登录页增加固定同源 `/account/password-reset` 链接，放在登录表单外；补充页面标题、UTF-8 和移动 viewport 元数据，不重做登录或同意页布局。
2. 使用独立标签和 `rel="noopener noreferrer"`；原登录页保留 `state`、`nonce`、redirect URI 和 PKCE hidden fields，恢复页不得接收这些参数、账号或密码。
3. 不新增 API、配置或迁移；不自动继续授权、不跳过 consent、不新增任意 return URL，不修改认证、限流、审计或一次性 token 的边界。
4. 同步更新 OIDC 接口与账户恢复使用说明；以一个功能切片交付，代码回归使用功能提交 `e789ea3`，可见浏览器和 CI 证据记录使用后续文档提交 `809f5ee` 及本计划更新。

验收条件：

- 单元和真实 HTTP 测试确认链接地址、独立标签、安全属性、客户端名称转义以及完整授权参数保留；没有浏览器 session 时仍显示登录表单。
- 浏览器验证点击入口后打开同源恢复页，`window.opener` 为 `null`，请求无 Referer，原表单和原授权 URL 不变；桌面和 `390x844` 视口可用。
- Computer Use 在真实窗口点击入口并确认恢复表单，返回原标签后仍能看到原登录页；不输入或提交真实认证凭据、不提交密码变更。
- `npm ci`、`npm run build`、现有 7 项 Chromium UI 回归、Rust fmt、workspace Clippy、构建、本机 Docker 全量测试、Markdown 链接和 diff 检查通过。

回滚边界：移除该静态链接、页面元数据及其回归即可回到原登录 UI；账户恢复 API、邮件链接、数据库结构和已有会话均不变。

### 8.2 后续顺序

2026-10-13 阶段 5 已完成。本机 Docker 真实服务回归和受控失败清理检查通过；提交 `b7b059e` 的远端 Run Tests 与 Code Coverage 通过。其 Security Audit 发现旧锁文件中的 `quinn-proto 0.11.15` 漏洞，已在独立提交 `148b4b8` 修复；CI run `38395463385` 的 Security Audit、Run Tests 和 Code Coverage 均已通过。阶段 6 和阶段 7 随后完成；阶段 6、7 的合并验收证据见本计划第 4 节。

阶段 5 的完成判定：

1. 一个入口能够有界启动本机 Docker PostgreSQL 17、Mailpit 和真实 Keylo，等待 readiness，失败时退出非零，并在成功或失败后清理容器、端口映射、匿名卷和临时密钥。
2. 测试使用合成账户和合成 OIDC 客户端，通过真实 HTTP/SMTP 和浏览器完成邮箱验证、密码恢复、重放拒绝和新密码登录；不得输出原始 token、密码、密钥或收件人。
3. 浏览器证据覆盖 OIDC 登录页进入恢复页、独立标签安全属性、原授权参数保持、桌面与 `390x844` 视口、控制台错误和横向溢出；邮件投递证据来自本机 Docker Mailpit，并单独标注其边界。
4. CI 执行该真实链路测试；现有受控 API UI 交互约定测试继续保留并单独命名。Rust fmt、workspace Clippy、相关集成测试、Markdown 链接和 `git diff --check` 全部通过。

阶段 5 的回滚边界：移除测试入口、CI 步骤和测试辅助代码即可回滚；不修改生产认证判断、账户恢复 API、数据库迁移或邮件 provider 接口约定。

阶段 5 不承诺外部 SMTP 供应商、Keycloak/TLS 矩阵或发布结果；这些仍需对应独立环境证据。新产品功能必须同时满足以下条件才可加入本文件：

1. 有明确的真实客户端、组织或运维事件，并说明影响范围。
2. 能用现有 Principal、组织和 RBAC 模型表达，若不能，必须说明新增数据模型或协议的必要性。
3. 明确失败关闭、撤销、审计、限流、迁移、回滚和兼容策略。
4. 能在本机 Docker 和真实 HTTP 测试中复现；面向用户的 UI 还要有 UI 验收证据。
5. 只选择一个扩展方向，完成后再重新评估下一方向。

在满足上述条件前，以下内容保持未排期，不属于当前功能清单：LDAP/AD 登录与同步、SCIM、SAML、WebAuthn/Passkey、Device Flow/CIBA/PAR/DPoP/Token Exchange、完整管理控制台、计费/套餐、通用策略脚本、多实例 HA、outbox/webhook 和跨区域恢复。

### 8.3 已完成切片：OIDC 登录失败后的重试体验

当前 `/v1/oidc/login` 把错误凭据返回为 JSON。浏览器用户不能从该响应继续登录。本切片只调整浏览器错误呈现，不改变用户查找、密码校验、组织成员状态检查或授权判断。

实现与本机验收已完成：Rust 单元/HTTP 集成测试、真实服务 Chromium 桌面/移动回归和 Computer Use 可见窗口检查均通过。提交 `0f15c56` 已包含在 `main`；后续提交 `7eb85c0` 的 GitHub Actions run `38401038528` 中，`Run Tests`、`Security Audit` 和 `Code Coverage` 均通过，故本切片已完成。可见窗口测试的 Docker 容器已清理；系统策略拒绝删除 `--serve` 运行的临时测试目录，目录中的测试密钥仍待本机清理，不在 Git 中。

验收条件：

1. 仅 `WrongCredentials` 返回登录重试页，并使用统一错误提示；表单保留用户名和已验证授权参数，不包含密码值。
2. 错误页不设置 OIDC 浏览器会话 Cookie，不签发授权码；输入正确凭据后，浏览器可从同一表单进入既有 consent 流程。
3. 停用用户、无本地密码的外部身份账户、非活动组织或成员关系继续拒绝登录，且失败时不创建浏览器会话。
4. `PasswordChangeRequired` 和其他错误不转换为重试成功；`/v1/auth/token` 的状态码和 JSON 错误格式保持不变。
5. 真实服务 Chromium 回归覆盖错误后在同一标签重试、授权字段保留、密码清空和错误账户拒绝；在 `1280x720` 与 `390x844` 下检查无横向溢出和控制台错误。使用 Computer Use 在可见窗口检查真实服务登录错误和重试，不提交真实凭据。
6. Rust fmt、workspace Clippy、全量本机 Docker 测试、真实服务浏览器测试、Markdown 链接和 diff 检查通过；CI 执行同一真实服务浏览器回归。

回滚边界：撤销错误重试页、对应测试和本节记录即可回到当前 JSON 错误呈现；不修改认证规则、非浏览器 API、数据库结构、MFA 策略或 token 生命周期。

### 8.4 已完成切片：Spring Boot 资源服务样例 CI 对齐

本地脚本已运行 Spring Boot 资源服务样例，但 CI 只运行 Spring Boot OIDC RP。此切片把资源服务 Gradle 测试加入 `Run Tests`，并让 Gradle wrapper 配置文件变更也触发 CI。样例测试必须验证只有 Keylo 明确允许时才放行，并在 Keylo 无法返回授权结果时拒绝请求。

交付与验收：提交 `7eb85c0` 补齐 push/PR 路径和 Gradle 测试步骤；GitHub Actions run `38401038528` 的 `Run Tests`、`Security Audit`、`Code Coverage` 均通过。本切片已完成。

验收条件：

1. CI 的 push 和 pull request 路径规则都覆盖资源服务 Gradle wrapper 配置文件。
2. `Run Tests` 执行 `examples/spring-boot-resource-server` 的 `gradlew test`，并运行明确允许与 Keylo 不可用时拒绝授权的测试。
3. 本机 `.\examples\spring-boot-resource-server\gradlew.bat test --no-daemon`、`actionlint`、Markdown 链接检查和 `git diff --check` 通过。
4. Rust 检查、Docker 服务集成测试和 UI 验收不适用：本切片只调整 CI 路径与测试调用，不改 Rust 代码、服务协议或用户界面。

回滚边界：移除资源服务 CI 步骤及对应路径触发规则即可回滚；不修改样例运行逻辑、授权结果格式或生产服务行为。

### 8.5 已完成切片：强制改密限制覆盖统一授权入口

状态：实现与本地验证已完成。普通 JWT 中间件和四个统一授权入口使用同一签名 claim 检查；改密后旧受限 token 仍拒绝，重新登录才获得正常授权。第 4 节记录实际执行的验证；阶段 8 提交的远端 Run Tests 和 Code Coverage 已确认通过，安全依赖补丁另见第 4 节。

依据：第 11 节 R1。用户被管理员重置密码后，现有 API 允许其用临时密码获得 `password_change_required=true` 的 access token。相同 token 在 `/protected` 被拒绝，却可以通过统一授权接口得到业务放行结果，违反恢复流程限制。

本切片的接口与权限约定：

1. 在统一授权入口解析人类 access token 时复用现有强制改密限制；在权限查询或授权计算之前返回与普通受保护入口一致的 `403 password_change_required`。
2. 覆盖 `/v1/authorize/check`、`/v1/authorize/batch-check`、`/v1/principals/me/effective-permissions`、`/v1/principals/me/resource-tree`。普通已完成改密的人类 token、service token 和明确支持的 machine credential 继续按既有权限规则判断。
3. 拒绝受限人类 token 后不得转而尝试 service/machine 身份解释；原有改密和必要 MFA 恢复路径的允许列表继续由现有策略负责。
4. 无数据库迁移、配置和新产品 API。拒绝行为遵循现有 HTTP/审计约定，不写入 token、密码或恢复链接。

验收与提交边界：

- 使用独立本机 Docker PostgreSQL 和合成内部员工，赋予实际业务权限，再由管理员重置密码。确认临时密码登录返回受限标记，以上四个入口都拒绝，即使该主体本来拥有目标权限。
- 完成改密并重新登录后四个入口恢复正常授权；普通用户、组织作用域、service 和 machine credential 的允许/拒绝案例保持原规则。
- 此切片新增的真实数据库测试必须对连接/迁移失败直接报错，不使用会静默回退或返回成功的 helper；阶段 9 再统一修复既有测试设施。
- 执行相关真实 HTTP/数据库回归、Rust fmt、workspace Clippy、Markdown 链接和 diff 检查后，以一个独立修复提交交付。只有本轮实际执行的结果才能加入“已完成”。

回滚：撤销统一授权入口的受限 token 检查及对应回归即可恢复原行为；这会重新暴露 R1，不涉及数据恢复或迁移回滚，应在明确接受风险时才执行。

### 8.6 当前切片与后续候选的范围与验收

阶段 9 已完成实现与本地验收。真实数据库 helper 现已要求显式 `TEST_DATABASE_URL`；连接、迁移、fixture 和路由初始化错误直接失败，管理员认证 500 不再提前 return。12 项无数据库 HTTP 测试归入 `tests::dependency_free`，负载测试对缺少字段的 JSON 固定要求 422。SMTP 用例要求显式 Mailpit 参数，CI 提供真实容器 ID 以执行重启回归。

测试脚本为本轮生成独立 Docker 容器和临时凭据，传播 Cargo、格式化、Clippy 和清理错误。新增 `scripts/check_test_failures.py` 运行实际测试二进制，验证各数据库套件缺配置和连接失败、迁移 checksum 错误、管理员 fixture 初始化错误及真实认证 500 的非零退出；每个探针还核对恰好运行一个测试，避免将编译错误或无匹配测试当作证据。破坏性探针只进入脚本新建的 `keylo_fault_` 临时数据库，正常数据库不参与故障写入。

阶段 9 未更改产品接口、认证规则或数据库，也未新增审计事件。回滚阶段 9 只需撤销测试、脚本、CI 与文档改动，但会恢复对依赖失败的错误通过判定。阶段 10–11 已完成，阶段 12 为下一切片，阶段 13–14 保持后续候选；这些后续功能尚未在本轮实现或验收；每项仍须按第 9 节独立提交。

阶段 10 已完成实现与本地验收，具体约定如下：

- 共享密码 API 的 `global:{ip}`、`{ip}:{username}` 限流键及原始用户名锁定键；按全局、账号来源、账号锁定的既有顺序检查。OIDC 授权参数仍先验证，保护检查在用户查询及 bcrypt 之前完成。
- 不存在、停用、无本地密码和错误密码统一累计失败并保留原 HTTP 200 重试页；触发账号锁定的本次仍返回原凭据失败结果，后续请求返回 `429 too_many_requests` / `1011`。来源额度的第一个超限请求直接返回 429。拒绝时不创建浏览器 session 或设置 cookie。
- 正确密码仍须通过强制改密与组织上下文检查；这些拒绝不清失败计数，也不算新的密码错误。只有浏览器 session 及响应 cookie 构造成功后才清理计数，consent 仍是签发 code 的必经步骤。
- 复用现有环境变量和 Redis 状态方法，无数据库迁移、新产品 API 或页面改动。非生产且无 Redis 时仅在同一 AppState 内共享；不扩大对既有 Redis 命令故障行为的承诺。
- API 审计事件名保持原值；OIDC 使用固定 `oidc.login.*` 事件，复用固定基数限流指标，新增审计详情不包含密码、cookie、完整表单或明文来源 IP。回滚只撤销此切片的共享保护调用与回归，但会重新暴露 R2。

阶段 11 已完成实现；三个 MFA 因子验证入口共用以下保护约定：

- `/v1/user/mfa/verify` 与 `/v1/user/mfa/totp/verify` 使用同一个 `mfa:account:{uid}` 桶，以及按可信 IP 计算的 `mfa:source:{ip}` 桶；分别复用 `AUTH_RATE_LIMIT_MAX_REQUESTS`、`AUTH_GLOBAL_RATE_LIMIT_MAX_REQUESTS`，并使用 `AUTH_RATE_LIMIT_WINDOW_SECONDS` 窗口。UID 稳定键让更换 token、TOTP/恢复码切换和 enrollment 状态都共享额度。
- 单一因子提交均计入额度，包括成功验证；超限在加载因子、解密 TOTP seed 或 bcrypt 验证恢复码前返回 429，并增加固定基数的拒绝指标。请求不写入验证码或恢复码审计信息。
- 不新增 MFA 配置、API、数据迁移或锁定状态。已配置 Redis 的实例共享已有 Redis 限流键；非生产且未配置 Redis 时由现有 AppState 内存状态实现单进程额度，生产环境沿用现有限流规则在没有 Redis 时拒绝请求。回滚撤销两个 handler 的额度检查和文档条款，会重新开放无界猜码尝试。

| 顺序 | 对应问题 | 最小实现边界 | 必须能失败的验收 | 迁移、审计和回滚 |
| --- | --- | --- | --- | --- |
| 9 | R7：测试误报通过 | 显式 `TEST_DATABASE_URL` 的连接、迁移、初始化错误直接失败；数据库测试不得使用内存 fallback，管理员认证 500 不得直接 return。无依赖测试与依赖测试明确分组。 | 故意不可达数据库、迁移失败和初始化/认证 500 均返回非零；正常 Docker 流程执行真实断言并给出准确数量。 | 只改测试设施和 CI，不改认证规则或数据库；回滚会恢复错误的通过判定。 |
| 10 | R2：OIDC 绕过密码登录保护 | 复用已有来源/IP+账号限流与账号失败锁定，在 bcrypt 前检查，失败更新共享计数，成功按既有规则清理；保持授权参数验证和统一错误提示。 | API 锁定后 OIDC 不能创建 session；OIDC 连续失败也能锁定同一账号；阈值返回 429，窗口恢复；正确重试不绕过组织、首次改密或 consent。 | 优先复用现有状态和 Redis 配置，无迁移；沿用固定基数指标和脱敏审计，回滚只撤销此入口保护。 |
| 11 | R3：MFA 无猜码保护 | TOTP、恢复码和 enrollment verify 在解密/bcrypt 前执行账号与来源限流；更换 access token 不能重置账号额度。 | 连续错误达到阈值后 429，正确因子也不能在限流期绕过；窗口恢复；配置 Redis 时两个 AppState 共享额度，无 Redis 时验证单进程边界。 | 优先复用既有限流配置，无新增 MFA/登录协议；不记录原始验证码，回滚会恢复无限尝试。 |
| 12 | R4：旧恢复链接仍有效 | 自行改密、管理员 reset、管理员 update password 与待消费恢复 token 撤销使用同一事务及一致锁顺序；保留一次性消费和会话撤销。 | 三种改密之后旧链接全部拒绝；与恢复消费并发时结果符合提交顺序、无死锁；新申请链接可用，失败事务不能误撤销。 | 优先使用现存 `revoked_at`，不新增表；记录撤销数量而非 token。已撤销的旧链接不应随代码回滚恢复。 |
| 13 | R5：旧 JWT key 重启复活 | 持久化完整 keyset 的绝对到期时间；先验证新 kid/key 再更新文件和内存，失败保持可恢复的一致状态；覆盖 rotate、retire 和 rollback。 | 1 秒 overlap 到期后，重启前后旧 key 均不在 JWKS，旧签名 token 均拒绝；自定义 overlap 不被默认值覆盖；重复 kid、只读目录及中途写失败不改变有效 signer。 | 如新增 keyset 元数据，须定义旧六文件格式的显式迁移；未知到期时间不得默认重新授予 overlap。保留受保护的可恢复备份，审计不含私钥。 |
| 14 | R6：生产 Compose 缺配置 | 对齐 `OIDC_PUBLIC_ISSUER`、稳定的 `MFA_SECRET_KEY` 和配置文档；明确只读密钥部署与托管轮换的可写存储方案；不将密钥写入镜像或仓库。 | 从干净的合成配置生成生产环境，启动到 `/readyz` 200；停止再启动仍可使用已存 MFA 状态和 keyset；缺必需变量时提供明确错误且退出。 | 只修改部署模板和配置契约，真实容器验证使用本机 Docker；密钥存储切换需备份与恢复步骤，不降低生产校验以让模板通过。 |

阶段 14 后先复核以下 P2 候选，再考虑新的产品能力：

- R8：MFA enrollment 使用版本/seed 标识的条件写入；验证 A 后并发替换为 B 必须冲突，已经 enabled 的因子不能被迟到 enroll 覆盖。若新增版本字段，需要数据库迁移和旧记录兼容规则。
- R9：角色 update/restore 与组织角色绑定共用兼容性检查，在同一事务中联合三类绑定验证主体类型；覆盖组织 user/service/device 以及并发授予，原绑定和角色在拒绝后不变。优先复用现有表，无新增授权模型。
- R10：平台与组织管理员共用成员失效的事务式撤销逻辑；pending/suspended/removed 后删除待兑换 OIDC code。恢复成员后旧 code 继续拒绝，新授权流程可用；不恢复被撤销的证明，不新增表或授权协议。

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

## 11. 2026-10-15 代码审查记录

审查基线为 `94c4565`，范围包括本地认证、OIDC、恢复、MFA、组织授权、密钥、默认部署及测试失败路径。以下为审查快照；R1 已由阶段 8 修复，R7 已由阶段 9 修复，R2 已由阶段 10 修复，R3 已由阶段 11 修复，其余问题仍未修复。P1 表示应优先修复的认证/运行缺陷，P2 表示随后处理的约束或验证缺陷，不把所有未实现的 IAM 功能都视作漏洞。

| 编号 | 优先级 | 触发条件、影响与代码位置 | 本轮证据与覆盖缺口 |
| --- | --- | --- | --- |
| R1 | P1（已修复） | 审查基线的 [统一授权 bearer 分支](../../src/routes/authorization.rs#L98) 不检查 `password_change_required`，且由 [public router](../../src/startup.rs#L204) 挂载，未经过普通 JWT 中间件的改密限制。恢复流程 token 因而可以得到业务授权。 | 原实现的隔离数据库和完整 Router 实测确认 `200 allowed=true`。阶段 8 已接入共享检查；[新增严格回归](../../tests/authorization/password_change.rs) 确认四个入口 403、旧 token 持续受限，以及重新登录后的真实权限恢复。 |
| R2 | P1（已修复） | [OIDC login](../../src/handlers/oidc.rs#L816) 直接查用户并验证密码，没有使用 [API 登录](../../src/handlers/auth.rs#L500) 的限流、失败计数和账号锁。持有合法 client/PKCE 参数即可切换入口绕过锁定。 | 使用真实 handler、AppState 和独立数据库：阈值为 1 时三次 OIDC 错误仍未锁定；预置账号锁后，正确密码仍返回 session Cookie。未运行在线穷举。阶段 10 先以新增真实数据库 HTTP 回归复现 API 锁定后 OIDC 仍返回 200；共享保护接入后，新增 9 项回归全部通过，覆盖跨入口计数、锁定/限流恢复、代理头、审计和失败时计数保留。 |
| R3 | P1（已修复） | [MFA verify](../../src/routes/mfa.rs#L132) 和 [enrollment verify](../../src/routes/mfa.rs#L300) 在基线中没有账号或来源额度，持有用户 token 的攻击者可连续尝试第二因子；恢复码失败还会触发多次 bcrypt。 | 两个新增真实 PostgreSQL HTTP 回归验证跨因子/跨 token 的稳定 UID 额度和不同账户共享来源额度；额度单元回归验证窗口恢复。有效恢复码在限流期间也返回 429。未新增 Redis 多实例故障测试。 |
| R4 | P1 | [管理员 reset](../../src/db/user.rs#L501)、[自行改密](../../src/db/user.rs#L623) 和管理员 update password 不撤销恢复 token；[恢复消费](../../src/db/password_reset.rs#L181) 不绑定密码版本。旧链接持有人仍可覆盖已经更新的密码。 | 当前库在隔离 PostgreSQL 中实测：申请链接后自行改密，旧链接仍 Reset 且其新密码可登录；管理员 reset 后同样成立。管理员 update 路径仅静态确认；现有测试只覆盖恢复链接本身的单次消费与重放。 |
| R5 | P1 | [启动加载 passive key](../../src/models/jwt.rs#L236) 每次按 now + overlap 重新到期；[轮换落盘](../../src/handlers/auth.rs#L1636) 只保存 PEM/kid，未保存绝对期限，而且在重复 kid 检查前已经写文件。 | 运行启动加载器实验：1 秒 overlap 到期后旧 key 消失、旧 token 拒绝；重新 `Keys::from_config` 后旧 key 与旧 token 验签恢复。未运行完整容器重启或磁盘故障实验；现有轮换测试缺少跨进程期限与失败一致性。 |
| R6 | P1 | [默认 Compose](../../docker-compose.yml#L50) 设置 production，却未向容器传入 `OIDC_PUBLIC_ISSUER` 和 `MFA_SECRET_KEY`；[生产配置校验](../../src/config.rs#L1047) 强制要求两者，宿主 `.env` 不会自动成为容器环境。密钥目录又为只读挂载，托管轮换无法写入。 | `docker compose config --format json` 实际输出缺少两项，环境为 production，keys 卷 read_only=true。未构建并启动完整生产镜像，不能声称已完成部署验收。 |
| R7 | P2（已修复） | [数据库 test helper](../../tests/database_integration_test.rs#L64) 将错误返回给 [测试中的 skip/return](../../tests/database_integration_test.rs#L147)；[HTTP helper](../../tests/integration_test.rs#L163) 在数据库初始化失败后回退内存，部分安全测试在管理员 500 时直接 return。 | 实际执行 `TEST_DATABASE_URL=postgres://postgres@127.0.0.1:1/review cargo test --locked --test database_integration_test test_database_migrations -- --nocapture`，输出数据库不可用却退出 0、报告 1 passed。此结果说明门禁误报。阶段 9 移除了真实套件的跳过与内存 fallback，新增 21 项故障/对照检查验证非零退出和正常断言。 |
| R8 | P2 | [enrollment 读取并校验 seed](../../src/routes/mfa.rs#L265) 与 [按 user_id 启用](../../src/db/mfa.rs#L78) 分离；[无条件 upsert](../../src/db/mfa.rs#L16) 可在中间替换 seed，或覆盖刚启用的凭据。 | 静态交错：verify 读取 A → enroll 写 B → verify 启用 B；另一交错为 enroll 已读 pending → verify 启用 → 迟到 upsert 重置 enabled。未做并发运行复现，现有测试仅顺序操作。 |
| R9 | P2 | [角色类型变更检查](../../src/db/rbac.rs#L73) 遗漏 organization_role_bindings；角色改为 service-only 后，既有组织 user 仍继承权限。update 与 restore 共享该检查。 | 在隔离数据库中真实执行组织 user 绑定、角色 user→service 更新后，权限查询仍为 true。现有兼容性测试只覆盖平台绑定。 |
| R10 | P2 | [组织管理员变更成员状态](../../src/db/organization.rs#L770) 只撤销 refresh session，未像平台路径删除待兑换 OIDC code。暂停后再恢复成员，会使旧授权在其 300 秒寿命内重新可用。 | 独立数据库和真实 token handler 的 HTTP 请求确认：暂停时同一 code 兑换 400，恢复 active 后兑换 200 并返回 access token。客户端本来就持有回调 code 与 PKCE verifier，无需读取数据库；现有撤销测试只覆盖平台路径。 |

审查限制：初次审查未执行全量回归；阶段 8–11 的本地验证见第 4 节。阶段 9 远端三项 CI 已通过，阶段 10、11 远端结果待确认；外部 IdP/TLS 和真实 SMTP 供应商矩阵尚未验证。静态发现需要在对应修复切片中增加能复现交错/故障的回归。本节不构成所有代码路径均无缺陷的保证，也不把合成测试凭据用于真实账户操作。
