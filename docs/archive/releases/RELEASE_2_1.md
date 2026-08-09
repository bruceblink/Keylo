# Keylo 2.1.0 发布说明

发布日期：2026年8月10日

Keylo 2.1.0 将统一 IAM 核心扩展为单部署、多组织 SaaS 基线，重点是组织隔离、组织作用域授权、标准 OIDC 互操作、机器身份和可运营性。平台角色、组织角色、用户类别与机器凭证均保持显式作用域，授权和会话状态在运行时失败关闭。

## 主要变化

- 新增 Organization、OrganizationMembership、组织角色绑定和 `internal_employee` / `external_customer` 用户类别，并提供平台与组织管理员 API。
- 授权 check、batch-check、effective-permissions 和 resource-tree 实时校验 signed active organization context、组织状态、membership、角色绑定和资源归属，跨组织访问默认拒绝。
- 人类 organization-scoped refresh session、service client、OIDC client、identity source、resource、device 和 API key 均有明确且不可隐式迁移的组织作用域。
- 新增 device Principal 与机器 API key 管理；原始 key 只在创建/轮换时返回，服务端只保存 hash，支持过期、撤销、轮换和实时主体/组织校验。
- Customer Support 使用固定受限角色、目标组织、操作范围、人工原因和短期 context token，并对每次读取、内省和撤销写入结构化审计。
- OIDC upstream 增加 Discovery/JWKS 缓存、配置版本失效、PKCE/state/nonce 校验、JIT 组织策略、邮箱观察和来源会话撤销。
- JWT signing key 支持 active/passive overlap、轮换、回滚和下线；管理列表统一返回有界 `limit/offset`、`has_more` 和 `next_offset` 元数据。
- readiness、metrics、审计导出、日志脱敏、迁移兼容性和第三方 Node/Go/Rust/Spring 接入样例完成发布门槛收敛。

## 兼容性与迁移

- 现有 `v2.0.0` 的认证、JWKS、OAuth、service token、RBAC 和 refresh session 接口保持兼容。
- 迁移会为历史主体建立明确的 `user_class` 与 platform scope；不明确的租户归属不会被静默放入客户组织。
- `service_id + service_secret -> service_access` 继续保留；API key 只在显式支持的授权检查接口使用，不进入人类登录或 refresh 流程。
- 组织 client、service client、device 和 API key 的 scope 在创建时固定，不支持通过请求参数或请求头切换组织。

## 发布前验证

本版本发布前已完成：

```text
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --tests -- --test-threads=1  # fresh Docker PostgreSQL
scripts/validate_oidc_rp_examples.ps1
Markdown relative-link check
```

真实 PostgreSQL 矩阵覆盖组织隔离、OIDC、refresh lifecycle、service/device/API key、Customer Support、RBAC、审计、迁移和旧数据兼容性。
