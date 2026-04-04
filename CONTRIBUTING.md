# 贡献指南

感谢你对 Keylo 项目的兴趣！本指南将帮助你了解如何贡献代码。

## 开发环境设置

### 前置要求

- Rust 1.70+ ([安装 Rust](https://rustup.rs/))
- PostgreSQL 12+ 或 Docker
- Git

### 本地开发

1. **Fork 和克隆仓库**

```bash
git clone https://github.com/your-username/Keylo.git
cd keylo
```

2. **设置环境变量**

```bash
cp .env.example .env
# 编辑 .env 文件以配置你的开发环境
```

3. **启动开发数据库**

```bash
docker-compose up -d
```

4. **构建和运行**

```bash
cargo run
```

5. **运行测试**

```bash
cargo test
```

## 开发工作流

### 创建特性分支

```bash
git checkout -b feature/your-feature-name
# 或者修复bug
git checkout -b fix/your-bug-fix
```

### 代码风格

- 遵循 Rust 官方风格指南
- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查常见问题

```bash
cargo fmt
cargo clippy -- -D warnings
```

### 提交信息

使用清晰、简洁的提交信息：

```
feature: 添加用户角色支持
fix: 修复JWT过期验证错误
docs: 完善API文档
refactor: 重构数据库模块
test: 添加认证handler测试
```

### 提交更改

```bash
git add .
git commit -m "your commit message"
git push origin feature/your-feature-name
```

## 创建 Pull Request

1. 推送你的分支到 GitHub
2. 创建 Pull Request，描述你的更改
3. 等待代码审查
4. 根据反馈进行调整
5. 合并到主分支

### PR 检查清单

- [ ] 代码通过 `cargo fmt` 格式化
- [ ] 代码通过 `cargo clippy` 检查
- [ ] 添加了相关测试
- [ ] 更新了文档
- [ ] 提交信息清晰
- [ ] 本地测试通过

## 测试

### 运行所有测试

```bash
cargo test
```

### 运行特定测试

```bash
cargo test test_auth_token
```

### 生成覆盖率

```bash
# 使用 tarpaulin（需要安装）
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

## 文档

- 为公开API添加文档注释
- 使用 `///` 进行文档注释
- 使用 `` ``` `` 包含代码示例

```rust
/// 生成JWT令牌
///
/// # 参数
/// * `claims` - JWT声明
///
/// # 返回值
/// 返回编码后的JWT字符串
///
/// # 示例
/// ```
/// let token = encode_token(claims)?;
/// ```
pub fn encode_token(claims: &Claims) -> Result<String> {
    // ...
}
```

## 问题和改进建议

### 报告 Bug

创建一个 Issue 并包含：
- Bug 描述
- 复现步骤
- 预期行为
- 实际行为
- 环境信息（OS、Rust 版本等）

### 建议新功能

创建一个 Issue 并描述：
- 功能概述
- 使用场景
- 可能的实现方式

## 项目结构

```
src/
├── main.rs          # 应用入口
├── lib.rs           # 库根模块
├── config.rs        # 配置管理
├── state.rs         # 应用状态
├── startup.rs       # 启动逻辑
├── errors.rs        # 错误定义
├── utils.rs         # 工具函数
├── routes/          # 路由
├── handlers/        # 请求处理
├── models/          # 数据模型
└── db/              # 数据库操作
```

## 代码审查标准

我们会检查以下方面：

- ✅ 代码质量和风格
- ✅ 功能正确性
- ✅ 测试覆盖
- ✅ 文档完整性
- ✅ 性能考虑
- ✅ 安全问题

## 常见问题

### 如何添加新的认证方式？

1. 在 `src/handlers/` 中创建新的handler
2. 在 `src/routes/auth.rs` 中添加路由
3. 添加相应的测试
4. 更新文档

### 如何修改数据库schema？

1. 在 `src/db/mod.rs` 中更新迁移SQL
2. 运行 `cargo run` 以应用迁移
3. 更新相关的数据库函数

### 如何添加新的环境变量？

1. 在 `src/config.rs` 中添加新字段
2. 在 `.env.example` 中添加示例
3. 更新 README 中的环境变量表

## 沟通

- 📧 Issue 和 PR 讨论：使用 GitHub
- 💬 实时讨论：创建 GitHub Discussion
- 📝 邮件：通过项目中的联系方式

## 行为规范

我们致力于创建一个包容和尊重的社区。请遵守 [Rust 社区行为准则](https://www.rust-lang.org/conduct.html)。

---

感谢你的贡献！🎉
