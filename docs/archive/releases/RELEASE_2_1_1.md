## [2.1.1] - 2026-09-13

### 🔒 安全 / Security

- 服务 Token 换取增加数据库查询前的客户端 IP 与 `service_id` 双层限流、失败凭证锁定、成功后清除失败记录、脱敏审计和固定基数 metrics。[0b375b4](https://github.com/bruceblink/Keylo/commit/0b375b47a89a20914fd26875c825e207cd92b404)

### 🧰 维护、文档与测试 / Maintenance, Docs & Tests

- 增加 TOTP enrollment、恢复码一次性消费、token-bound recent MFA、密码修改前置校验和 TOTP reset 的真实 HTTP 回归覆盖。[c57c477](https://github.com/bruceblink/Keylo/commit/c57c477068dce4a06f9be4af5f9e10f3b585dd59)
- 增加 OIDC upstream 身份自助列表、解除关联、上游 refresh session 定向撤销和重复解除错误边界的真实 HTTP 回归覆盖。[a868957](https://github.com/bruceblink/Keylo/commit/a868957e8e976a8fafec7c2ebdd4ddb8fedaa679)
- 统一 GitHub Release 的双语变更说明生成与发布工作流。[9c8ce11](https://github.com/bruceblink/Keylo/commit/9c8ce1136e67ae3e4540e26b284406551ea275fe)
- 修复签名 annotated tag 的发布日期解析，确保生成的 Release 标题只使用对应提交日期。

---

**Full Changelog:** [v2.1.0...v2.1.1](https://github.com/bruceblink/Keylo/compare/v2.1.0...v2.1.1)
