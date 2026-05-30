# Keylo 1.5.2 发布说明

发布日期：2026年5月30日

## 版本定位

Keylo 1.5.2 是 1.5 系列的安装向导与本地 Compose 启动体验修复版本，重点让首次 setup 更直接、完成后状态更清晰，并避免本地 Docker 复用旧镜像。

---

## 主要改进

### 一次性 setup 流程

- 移除 `SETUP_TOKEN` 配置和 setup token 校验。
- 首次未完成 setup 时访问 `/` 会进入 `/setup`。
- `/setup/initialize` 只允许在 setup 未完成时执行；完成后再次调用返回 `403`。
- setup 完成后访问 `/setup` 会跳转到只读状态页。

### 服务状态入口

- setup 完成后访问 `/` 返回服务状态 JSON，而不是纯文本欢迎信息。
- `/readyz` 的 `checks` 中增加 setup 状态，便于健康检测系统读取 `setup.completed`。
- setup 状态接口无需额外 token，可用于初始化后状态确认。

### Docker Compose 启动修复

- Compose 本地镜像标签改为 `keylo-local:dev`，避免复用旧的 `keylo:latest` 镜像。
- `ADMIN_CLIENT_SECRET` 默认不再写入配置文件，管理客户端密钥通过首次 `/setup` 录入。

---

## 升级指南

### 从 1.5.1 升级到 1.5.2

1. 更新镜像/二进制到 `v1.5.2`。
2. 从 `.env` 或部署环境中移除 `SETUP_TOKEN`。
3. 首次未完成 setup 时，访问 `http://<host>:2345/setup`，输入 `ADMIN_CLIENT_ID` 和新的 `Admin Client Secret` 完成初始化。
4. 初始化完成后，访问 `/` 或 `/setup/status` 查看服务与 setup 状态。
5. 使用 Docker Compose 本地部署时，重新构建镜像：

```bash
docker compose up -d --build
```

---

## 兼容性说明

- HTTP API 保持向后兼容。
- `SETUP_TOKEN` 已移除，不再作为配置项读取或校验。
- 已完成 setup 的实例不会重新打开初始化入口。
- 管理客户端 secret 仍只以哈希形式写入数据库，不写入配置文件。

---

## 验证结果摘要

本版本发布前已完成：

```bash
cargo fmt --check
npm run build
cargo test setup
cargo test test_index
cargo clippy --all-targets -- -D warnings
docker compose build keylo
docker compose up -d keylo
```

验证结果：全部通过。
