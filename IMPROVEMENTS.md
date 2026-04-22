# Keylo 文档与能力演进说明

本文档不再逐项重复描述代码实现细节，也不作为当前能力的权威来源。

早期版本中的大量内容已经与当前实现脱节，例如：

- 使用 `HS256` 或 `JWT_SECRET` 的描述
- “Refresh Token 计划中” 之类的历史阶段性说明
- 将管理客户端、普通用户和服务客户端混称为同一种“客户端”
- 与当前路由、RBAC、服务内省模型不一致的接口示例

为降低维护成本，当前文档职责统一如下：

- [README.md](README.md)：项目概览、环境变量、部署入口
- [DEVELOPMENT.md](DEVELOPMENT.md)：本地开发、调试和测试约定
- [docs/END_TO_END_QUICKSTART.md](docs/END_TO_END_QUICKSTART.md)：从初始化到完整闭环的操作步骤
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md)：接口与鉴权规则权威定义
- [docs/MULTI_CLIENT_RBAC_INTEGRATION.md](docs/MULTI_CLIENT_RBAC_INTEGRATION.md)：多客户端权限模型与落地建议
- [docs/THIRD_PARTY_INTEGRATION.md](docs/THIRD_PARTY_INTEGRATION.md)：第三方系统接入边界与推荐方式
- [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)：生产部署基线

如果需要了解当前实现，请以上述文档和代码为准；本文件仅保留为“文档收敛说明”。
