# Security Policy

## 数据存储与加密设计

| 数据 | 位置 | 保护 |
|---|---|---|
| Hub 账号快照 | `%APPDATA%\Roaming\zcode-hub\profiles\<账号>\credentials.snap` | 整包 AES-256-GCM；随机密钥经 **Windows DPAPI** 绑定当前用户 + 机器 |
| 快照密钥 | `%APPDATA%\Roaming\zcode-hub\snapkey` | 本体 DPAPI 加密后落盘 |
| 口令备份包 | 用户自选（默认桌面）`.zhb` | PBKDF2-HMAC-SHA256（120k 迭代）+ AES-256-GCM，随机盐/nonce |
| ZCode 官方凭据 | `~\.zcode\v2\credentials.json` | **保持 ZCode 官方格式与保护级别不变**（客户端需直接读取），本工具不修改其保护方式 |
| Hub 设置 | `%APPDATA%\Roaming\zcode-hub\hub-config.json` | 明文（不含任何凭据） |

- 快照文件被拷贝到其他机器 / 其他 Windows 账户后**无法解密**。
- `.zhb` 备份包仅凭口令可解；口令不存储、不可找回。
- 换机迁移：口令导出 → 新机导入；或整目录拷贝 `%APPDATA%\Roaming\zcode-hub`（仅限同机同用户场景）。

## 已知边界

- 客户端运行时读取的 `~\.zcode\v2\credentials.json` 使用 ZCode 官方自身的凭据保护方案（可推导 fallback），其安全强度由 ZCode 官方决定，本工具不放大也不缩小该暴露面。
- 本工具不包含任何遥测；所有网络请求仅发往 `zcode.z.ai` / `chat.z.ai` / `api.z.ai` / `bigmodel.cn` 官方域。

## 泄露应对

若怀疑账号凭据泄露：立即在 ZCode 客户端退出登录并重新登录（使旧令牌失效），随后在 Hub 中删除对应存档并重新保存。

## 报告漏洞

请通过 GitHub Private Security Advisory（仓库 Security 页 → Report a vulnerability）私下报告，勿直接开公开 Issue。会在 72 小时内响应。
