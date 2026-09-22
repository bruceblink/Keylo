# SMTP 账户邮件运维

本文说明 Keylo 账户邮箱验证和密码重置使用 SMTP relay 时的配置、轮换、故障恢复和本机验收边界。

## 术语

- **SMTP relay**：负责接受并转发 Keylo 账户邮件的邮件传输服务；它不负责生成或验证 Keylo 的一次性 token。
- **Mailpit**：本机 Docker 测试服务，用于检查 SMTP 消息是否真正到达；它不代表外部邮件供应商的 TLS、信誉或投递互操作性。
- **一次性 token 撤销**：SMTP 投递失败后，Keylo 将本次新建 token 标记为不可消费；Keylo 不在邮件适配器内自动重试。

## 生产配置

生产环境必须使用 `MAIL_PROVIDER=smtp`、`SMTP_TLS_MODE=starttls` 或 `tls`，并将认证密码配置为 AES-256-GCM 密文来源：

```env
MAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_TLS_MODE=starttls
SMTP_FROM=Keylo <no-reply@example.com>
SMTP_USERNAME=keylo@example.com
SMTP_PASSWORD_ENC_FILE=/run/secrets/.smtp_password.enc
SMTP_PASSWORD_KEY_FILE=/run/secrets/.smtp_password.key
SMTP_TIMEOUT_SECONDS=10
```

服务启动时会检查主机、发送地址、端口、TLS 模式、超时和凭据成对关系。生产环境拒绝明文
`SMTP_PASSWORD`、`SMTP_PASSWORD_FILE` 和 `SMTP_TLS_MODE=plain`。配置错误会阻止启动，
避免服务在无法发送账户安全邮件时继续接受恢复请求。

## 密文轮换

1. 使用仓库内 `scripts/secret_tool.py` 为新密码生成或准备新的密文和解密 key，不把明文密码提交到仓库或写入日志。
2. 将新 `.smtp_password.enc` 和 `.smtp_password.key` 以只读 secret 挂载到服务使用的路径，并限制文件权限。
3. 保留旧密文直到新文件完成部署检查，然后重启 Keylo，使进程重新读取配置。
4. 检查启动日志只出现配置成功或稳定失败分类，再调用一次测试环境的账户邮件流程确认投递结果。
5. 确认所有实例完成切换后，按部署系统的 secret 清理流程移除旧密文和旧 key；不要删除仍被运行实例引用的文件。

Keylo 进程只在内存中持有解密后的 SMTP 密码。日志、metrics、审计详情和 SMTP 失败结果不得包含密码、收件人、用户标识、token、邮件正文或 relay 原始回复。

## 证书和超时

- `starttls` 和 `tls` 使用 `SMTP_HOST` 参与 relay 证书校验；证书更新时必须同时确认主机名、证书链和运行环境的 CA bundle。
- `SMTP_TIMEOUT_SECONDS` 必须为正数。先检查 DNS、网络策略和 relay 响应时间，再调整超时，不能用无限等待掩盖 relay 故障。
- TLS/证书失败、超时、网络不可用、临时不可用和永久拒绝会分别写入稳定的 `error_category` 与 `next_action` 字段；不会写入原始 SMTP 错误。

## 监控和故障恢复

`/metrics` 暴露固定基数的 `keylo_mail_deliveries_total`，`outcome` 只包含以下值：

| outcome | 含义 | 处理动作 |
| --- | --- | --- |
| `success` | relay 接受消息 | 观察正常投递和队列状态。 |
| `not_configured` | 邮件 provider 被禁用 | 检查 `MAIL_PROVIDER` 和部署环境是否符合预期。 |
| `timeout` | 单次投递超时 | 检查 relay 延迟、网络路径和 `SMTP_TIMEOUT_SECONDS`。 |
| `temporarily_unavailable` | relay 暂时不可用或 TLS/证书握手失败 | 检查 relay 状态、主机名、证书链、CA bundle 和网络策略。 |
| `rejected` | relay 永久拒绝消息 | 检查发送地址、收件人策略、relay 授权和账号状态。 |
| `invalid_message` | 消息在 provider 边界校验失败 | 检查服务版本和调用方构造逻辑，不重放原 token。 |

投递失败后，邮箱验证或密码重置请求产生的 token 会立即撤销。恢复步骤是修复配置、证书或
relay 可用性后重新发起用户请求；系统不在适配器内自动重试，也不把未确认的消息加入 outbox。

## 本机 Docker 验收

Windows PowerShell 使用：

```powershell
.\scripts\run_tests.ps1
```

脚本使用 PostgreSQL `17-alpine` 和 `axllent/mailpit:v1.21.8`，默认端口为 PostgreSQL
`127.0.0.1:55432 -> 5432`、Mailpit SMTP `127.0.0.1:11025 -> 1025`、Mailpit API
`127.0.0.1:18025 -> 8025`。脚本会等待 readiness，运行 workspace、HTTP、账户和 SMTP
测试，并在结束时删除临时容器、匿名卷、端口映射和临时密钥目录。

恢复回归包括：

- Mailpit 容器重启后，使用同一个 provider 再次投递；
- SMTP 端口不可达时保持通用响应并撤销密码重置 token；
- SMTP 黑洞导致超时时保持通用响应并撤销密码重置 token；
- 无效 TLS 配置在启动配置阶段被拒绝。

本机 Mailpit 结果只证明 Keylo 与该测试服务的本地 SMTP 边界，不证明外部邮件供应商、真实证书、信誉策略或浏览器互操作性。

