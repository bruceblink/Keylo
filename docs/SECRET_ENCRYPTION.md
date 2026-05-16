# 统一密文配置格式

本文档定义 Keylo 及周边服务统一使用的部署密文格式。它适用于数据库密码、Redis 密码、服务客户端密钥、管理客户端密钥等“配置密文 at rest”场景。

JWT 签名仍然使用 Keylo 的 RSA/JWKS 体系。RSA 公钥不用于配置密文加密，避免把身份认证密钥和部署 secret 管理混在一起。

## 标准格式

统一密文格式为：

```text
secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>
```

约定：

- 算法：AES-256-GCM
- key：32 bytes，文件中保存为标准 base64
- nonce：12 bytes，每次加密随机生成
- tag：16 bytes GCM tag，追加在 ciphertext 末尾
- AAD：空
- 明文编码：UTF-8
- base64：标准 base64，不使用 urlsafe base64
- 文件读取：允许末尾换行，读取后 trim

## 为什么选择 AES-256-GCM

AES-256-GCM 是跨语言支持最好的认证加密方案之一：

- Rust：`aes-gcm`
- Python：`cryptography`
- Java：JDK `Cipher.getInstance("AES/GCM/NoPadding")`
- .NET：`System.Security.Cryptography.AesGcm`
- C++：OpenSSL/BoringSSL/LibreSSL、Botan、Crypto++

它同时提供机密性和完整性校验。相比 RSA，它更适合加密部署配置；相比 AES-ECB，它不会暴露重复明文模式。

## 生成密钥和密文

推荐统一使用仓库内 Python 工具生成：

```bash
python -m pip install cryptography
python scripts/secret_tool.py generate-key --out secrets/database_password.key
python scripts/secret_tool.py encrypt \
  --text-file secrets/postgres_password \
  --key-file secrets/database_password.key \
  --out secrets/postgres_password.enc
```

也可以直接加密命令行文本：

```bash
python scripts/secret_tool.py encrypt \
  --text "your-secret" \
  --key-file secrets/database_password.key \
  --out secrets/your_secret.enc
```

## 解密流程

所有语言的解密流程一致：

1. 读取密文并 trim。
2. 按 `:` 分割，校验前缀为 `secret:v1:aes-256-gcm`。
3. base64 解码 key，结果必须是 32 bytes。
4. base64 解码 nonce，结果必须是 12 bytes。
5. base64 解码 ciphertext，内容为 `ciphertext || tag`。
6. 使用 AES-256-GCM、空 AAD 解密。
7. 将明文按 UTF-8 转为字符串。

## Rust

Keylo 当前实现使用 `aes-gcm`：

```rust
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext_and_tag.as_ref())?;
```

## Python

Python 使用 `cryptography`：

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext_and_tag, None)
```

## Java

Java 使用 JDK 内置 JCE：

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), spec);
byte[] plaintext = cipher.doFinal(ciphertextAndTag);
```

注意：`ciphertextAndTag` 是密文和 16-byte tag 拼在一起的完整字节数组。

## .NET

.NET 使用 `AesGcm`：

```csharp
using var aes = new AesGcm(keyBytes, 16);
byte[] ciphertext = ciphertextAndTag[..^16];
byte[] tag = ciphertextAndTag[^16..];
byte[] plaintext = new byte[ciphertext.Length];
aes.Decrypt(nonce, ciphertext, tag, plaintext);
```

## C++

C++ 推荐使用 OpenSSL 3.x EVP 接口：

```cpp
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, nullptr);
EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);
EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
int ok = EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len);
```

其中 `ciphertext_base64` 解码后需要拆成两段：前面是 ciphertext，最后 16 bytes 是 tag。

## 运维建议

- 每个 secret 可以使用独立 key，也可以按部署域共享一个 key；高敏 secret 建议独立 key。
- key 文件权限建议为 `600`，只允许部署用户或容器运行用户读取。
- 密文文件可以进入部署工件，但 key 文件不应进入 Git 仓库。
- 轮换密码时，先用新明文重新生成密文，再同步更新目标系统中的实际密码。
- 不要把明文密码写入 `DATABASE_URL`、Compose 文件、Shell 历史或日志。
