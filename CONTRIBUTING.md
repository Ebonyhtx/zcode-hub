# 贡献指南

感谢关注 ZCode Hub！本文件覆盖开发环境、防泄密机制、测试与发布流程。

## 开发环境

- Rust (stable) + Node.js（用于 `npx @tauri-apps/cli`）
- Windows 10/11（本项目深度使用 Win32 API，暂不支持其他平台交叉开发验证）

```bash
# 日常构建（调试）
cd src-tauri && cargo build
# 运行单元测试
cargo test
# 打安装包
npx --yes @tauri-apps/cli build --bundles nsis
# 前端脚本语法检查
node --check ui/app.js
```

## 防泄密机制（必读）

本工具的仓库**绝不能出现**凭据、令牌、账号快照。为此有三层防线：

### 1. 本地 Git 钩子（提交/推送时自动拦截）

```bash
# 克隆后执行一次，把项目钩子接到本地
git config core.hooksPath .githooks
```

- `pre-commit`：扫描暂存区 —— `scripts/secret-scan.sh --staged`
- `pre-push`：推送前全历史复扫 —— `scripts/secret-scan.sh --history`

### 2. 扫描器检测什么

**值特征**（正则）：
| 特征 | 对应内容 |
|---|---|
| `enc:v1:` + 40 位以上密文 | ZCode 凭据加密值 |
| `eyJ…` 三段式 | 任何 JWT 令牌 |
| `AQAAANCMnd8…` | Windows DPAPI 保护数据 |
| `ZHB1:` + 密文 | 口令备份包内容 |
| `minisign` 签名头 / PEM 私钥头 | 更新签名私钥 |

**文件路径**（一律禁止入库）：`credentials.snap`、`snapkey`、`hub-config.json`、`benefits.json`、`*.zhb`、`profiles/`、`dist/`、`backups/`

### 3. CI 强制执法

`.github/workflows/ci.yml` 的 `secret-scan` job 会对**全部历史**重扫一遍并运行扫描器自检——本地钩子被绕过时这是最后防线。

### 泄漏处置

万一真实凭据进入提交历史：① 在 ZCode 客户端退出登录并重新登录（旧令牌立即失效）② 删除对应账号存档 ③ 联系维护者决定是否需要历史重写。扫描器不会误伤源码里的格式常量（如 `enc:v1:` 七字符前缀）——特征正则要求 40 位以上的实际密文。

## 提交与测试

- 提交信息用英文 conventional 风格（`feat:` / `fix:` / `chore:` / `docs:`）
- 涉及加密 / 路径处理 / 解析逻辑的改动请附单元测试（参考 `src/main.rs` 底部 `mod tests`）
- `cargo test` 必须全绿；UI 改动请同时 `node --check ui/app.js`
- 改动 UI 文案时记得同步 `ui/app.js` 里 `I18N` 的中英两份字典

## 版本发布（维护者）

1. 更新 `CHANGELOG.md` 与 `tauri.conf.json` / `Cargo.toml` 版本号（两处必须一致）
2. `git tag vX.Y.Z && git push origin vX.Y.Z` —— CI 自动构建签名安装包并发布 Release（含 `latest.json` 更新清单）
3. 发布前流水线会再跑一次全历史泄密扫描

## 行为准则

保持友善、对事不对人。安全问题请走 [SECURITY.md](SECURITY.md) 的私下报告渠道，不要开公开 Issue。
