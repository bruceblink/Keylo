# Keylo 文档导航

这里按文档职责组织当前设计、接口参考、操作指南、集成说明和历史资料。当前代码与设计以“当前主线”区域为准；`archive/` 仅保留历史上下文，不作为新的部署或开发依据。

## 当前主线

### 设计与开发计划

- [主线开发与核心设计](design/KEYLO_DEVELOPMENT_BLUEPRINT.md)
- [后续完整开发计划](plans/KEYLO_FOLLOW_UP_DEVELOPMENT_PLAN.md)
- [安装向导设计](design/SETUP_WIZARD_DESIGN.md)

### 接口与客户端参考

- [API 参考](reference/API_REFERENCE.md)
- [客户端 Token 与会话指南](reference/KEYLO_2_0_CLIENT_GUIDE.md)

### 使用与运维指南

- [端到端快速开始](guides/END_TO_END_QUICKSTART.md)
- [密文配置](operations/SECRET_ENCRYPTION.md)
- [JWT 密钥轮换](operations/KEY_ROTATION.md)

### 集成

- [第三方系统集成边界](integrations/THIRD_PARTY_INTEGRATION.md)
- [多客户端统一用户池与 RBAC](integrations/MULTI_CLIENT_RBAC_INTEGRATION.md)
- [AgileBoot 集成](integrations/AGILEBOOT_INTEGRATION.md)
- [Keystone 迁移方案](integrations/keystone.md)
- [OIDC、Node、Go、Rust、Spring 样例](integrations/README.md)

### 兼容性

- [Keycloak OIDC 可选互操作矩阵](compatibility/KEYCLOAK_OIDC_MATRIX.md)

## 历史资料

- [历史发布说明](archive/releases/README.md)
- [旧版生产部署文档](archive/deployment/README.md)

历史文件保持原内容，避免把旧版本的部署假设误当成当前配置。新的部署步骤请使用[端到端快速开始](guides/END_TO_END_QUICKSTART.md)，配置和接口边界请分别查看运维、参考与设计文档。
