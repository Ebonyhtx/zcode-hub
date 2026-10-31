# NOTICE / 版权与组件声明

ZCode Hub — Copyright (c) 2026 Ebonyhtx，以 [MIT License](LICENSE) 发布。

本产品为独立开发的**非官方**工具，与 Z.ai / 智谱（BigModel）无任何隶属或合作关系。ZCode 及相关名称归其各自所有者所有。

## 主要依赖

运行时与构建依赖的完整清单见 [src-tauri/Cargo.lock](src-tauri/Cargo.lock)。主要组件及其许可：

| 组件 | 用途 | 许可 |
|---|---|---|
| [Tauri](https://tauri.app)（tauri, tauri-build） | 应用框架 / WebView 桥接 | MIT / Apache-2.0 |
| tauri-plugin-notification | 系统通知 | MIT / Apache-2.0 |
| tauri-plugin-updater | 签名自更新 | MIT / Apache-2.0 |
| [reqwest](https://github.com/seanmonstar/reqwest) | HTTP 客户端 | MIT / Apache-2.0 |
| [aes-gcm](https://github.com/RustCrypto/AEADs) | AES-256-GCM 加密 | MIT / Apache-2.0 |
| [pbkdf2](https://github.com/RustCrypto/password-hashes) / [hmac](https://github.com/RustCrypto/hmacs) / [sha2](https://github.com/RustCrypto/hashes) | 口令 KDF 与摘要 | MIT / Apache-2.0 |
| [rand](https://github.com/rust-random/rand), [uuid](https://github.com/uuid-rs/uuid) | 随机数与标识 | MIT / Apache-2.0 |
| [serde](https://github.com/serde-rs/serde) / serde_json | 序列化 | MIT / Apache-2.0 |
| [base64](https://github.com/marshallpierce/rust-base64), [url](https://github.com/servo/rust-url), [dirs](https://github.com/dirs-dev/dirs-rs), [whoami](https://github.com/ardaku/whoami), [chrono](https://github.com/chronotope/chrono) | 工具库 | MIT / Apache-2.0 |

前端（`ui/`）为零依赖的原生 HTML/CSS/JavaScript，不含第三方运行时。

上述许可文本的完整副本可在各上游仓库获取；MIT/Apache-2.0 双许可组件在任一许可条款下均可使用。
