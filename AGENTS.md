# AGENTS.md — 仓库工作约定（面向 AI 代理与人类贡献者）

本文件给在本仓库工作的 AI 代理（ZCode / Claude / Codex 等）和人类贡献者提供速查约定。

## 项目一句话

Tauri 2 桌面工具：ZCode 多账号切换 + 额度展示 + 官方 preview 福利检测 + 设备身份隔离。Windows 10/11 x64 专属。

## 代码布局

- `src-tauri/src/main.rs` — **全部**后端逻辑（单文件，含 `mod tests`）；命令通过 `tauri::generate_handler!` 注册
- `ui/` — 前端三件套（index.html / style.css / app.js），零依赖，CSP `script-src 'self'`（禁止内联事件，用 `data-action` 事件委托）
- `scripts/secret-scan.sh` — 泄密守卫（三层：钩子/CI/发布）
- `docs/DESIGN.md` — 架构与安全模型，改架构先读它

## 硬性规则

1. **凭据/令牌/账号数据永不入库**。写入前 `secret-scan` 会拦；别尝试绕过
2. **加密布局动不得**：AES 是 `IV.TAG.CT`；`user_info` 必须规范化档案；zai token 必须换业务 token——细节见 `docs/DESIGN.md` 的「五条铁律」，每条都有测试守护
3. **版本号两处同步**：`tauri.conf.json` 与 `src-tauri/Cargo.toml`，改完跑 `bash scripts/repo-check.sh`
4. **UI 文案双语**：改 `ui/app.js` 里 `I18N` 的 zh/en 两份
5. **CSP**：前端禁止内联事件与内联脚本；交互一律 `data-action` 委托（`ui/app.js` 里的 delegation）
6. **边界**：不做自动领取福利、不做验证码处理、不做遥测事件仿真——PR 引入这些会被拒

## 常用命令

```bash
cargo test                                    # 单测（src-tauri 下）
bash scripts/secret-scan.sh --history         # 全历史泄密扫描
bash scripts/repo-check.sh                    # 仓库一致性门禁
node --check ui/app.js                        # 前端语法
npx --yes @tauri-apps/cli build --bundles nsis  # 打包（需 TAURI_SIGNING_PRIVATE_KEY）
```

## 提交

英文 conventional（feat/fix/chore/docs/test）。改动 crypto/路径/解析逻辑必须带单测。详见 CONTRIBUTING.md。
