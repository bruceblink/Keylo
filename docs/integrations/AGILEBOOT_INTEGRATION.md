# AgileBoot 接入 Keylo 指南

本文档面向类似 AgileBoot-Back-End 这样的 Spring Boot + Spring Security + MySQL 管理平台，说明如何把 Keylo 作为独立认证中心接入现有后台系统。

## 目标架构

推荐职责拆分如下：

* Keylo：统一认证中心，负责用户认证、JWT 签发、JWKS、公钥发布、用户 Token 内省、服务 Token 内省
* AgileBoot：后台 UI、本地 RBAC、菜单权限、数据权限、业务表数据
* MySQL：AgileBoot 本地用户映射、本地角色、菜单、数据权限和业务数据

这意味着 AgileBoot 不需要迁移到 PostgreSQL，也不需要直接访问 Keylo 的数据库。

## 核心原则

* 系统之间通过 HTTP API + JWT/JWKS 协作，不通过数据库直连协作
* Keylo 提供“身份认证结果”
* AgileBoot 保留“本地业务授权结果”
* MySQL 与 PostgreSQL 可以并存，互不冲突

## 推荐接入路径

### 方案一：AgileBoot 代理登录

适合希望保持现有前端登录入口不变的系统。

流程：

1. 前端调用 AgileBoot 登录接口
2. AgileBoot 将用户名密码转发到 Keylo `/v1/auth/token`
3. Keylo 返回 Access Token
4. AgileBoot 将 `sub` 映射为本地用户
5. AgileBoot 返回登录结果给前端
6. 前端后续请求携带 Keylo Access Token

### 方案二：前端直连 Keylo 登录

适合前后端边界比较清晰的系统。

流程：

1. 前端直接调用 Keylo 登录
2. 前端拿到 Access Token 后访问 AgileBoot
3. AgileBoot 作为资源服务器校验 Token
4. AgileBoot 按 `sub` 建立本地授权上下文

## Spring Security 接入建议

AgileBoot 作为资源服务器时，推荐使用 Keylo 的 JWKS 做本地验签。

最小配置思路：

* issuer：Keylo 的 `JWT_ISSUER`
* jwk-set-uri：`https://<keylo-domain>/.well-known/jwks.json`

资源服务器职责：

1. 验证 JWT 签名
2. 校验 `iss`
3. 校验 `aud`
4. 校验 `token_type=access`
5. 将 `sub` 解析为外部身份
6. 进入 AgileBoot 本地授权流程

高敏场景补充：

* 对权限变更、账号冻结、资金类、审计敏感接口
* 在本地验签通过后，再调用 Keylo `/v1/auth/introspect`
* 用于实时感知吊销、黑名单与状态变化

## MySQL 侧需要保留什么

AgileBoot 不需要把 Keylo 的用户体系整库同步到 MySQL，但建议保留一张“外部身份映射表”。

示例字段：

* `id`
* `external_subject`
* `local_user_id`
* `status`
* `last_login_at`
* `created_at`
* `updated_at`

其中：

* `external_subject` 对应 Keylo 的 `sub`
* 典型值如 `user:alice`、`user:10001`

这样 AgileBoot 在拿到 Keylo Token 后，可以：

1. 解析 `sub`
2. 查 MySQL 映射表
3. 找到本地用户
4. 加载本地角色、菜单、数据权限

## 服务间调用怎么接

如果 AgileBoot 还需要作为内部服务调用其他受保护系统，则推荐同时接入 Keylo 的服务账号模式。

配置方式：

1. 在 Keylo 中注册 `agileboot-admin` 服务账号
2. 为它配置 `allowed_scopes`
3. 为它配置 `allowed_audiences`
4. AgileBoot 用 `/v1/service/token` 获取 `service_access` Token

这样 AgileBoot 可以同时承担两种角色：

* 资源服务器：接收并验证用户 Access Token
* 调用方服务：主动申请 `service_access` Token 调用其他系统

## 对接顺序建议

建议按以下顺序推进，不要一次把所有认证逻辑都推翻：

1. 先接入 JWKS，本地验签用户 Token
2. 再补 `sub -> MySQL 用户` 映射
3. 再把本地角色/菜单/数据权限接到映射后的用户上
4. 再补高敏接口的内省调用
5. 最后再接服务账号模式做服务间调用

## 常见误区

### 误区一：Keylo 用 PostgreSQL，AgileBoot 用 MySQL，就不能对接

错误。

它们是通过协议集成，不是通过数据库集成。

### 误区二：接入 Keylo 后 AgileBoot 的角色菜单都要迁过去

不需要。

Keylo 负责认证，AgileBoot 继续负责本地授权。

### 误区三：为了简单，直接把 Keylo 私钥给 AgileBoot

不建议。

AgileBoot 应该通过 JWKS 获取公钥，而不是持有 Keylo 私钥。

## 最终效果

接入完成后，你会得到这样的架构：

* Keylo 成为独立认证中心
* AgileBoot 保留管理后台能力
* MySQL 继续承载本地业务与授权数据
* PostgreSQL 继续承载 Keylo 的认证域数据
* 两套数据库通过身份映射协作，而不是耦合
