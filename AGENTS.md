# AGENTS.md — 仓库工作约定（面向 AI 代理与人类贡献者）

本文件给在本仓库工作的 AI 代理（ZCode / Claude / Codex 等）和人类贡献者提供速查约定。

## 项目一句话

Tauri 2 桌面工具：ZCode 多账号切换 + 额度展示 + 营销福利检测/人工验证码领取 + 设备身份隔离。Windows 10/11 x64 专属。

## 代码布局

- `src-tauri/src/main.rs` — 入口与 `tauri::generate_handler!` 命令注册（不再承载业务逻辑）
- `src-tauri/src/` 业务模块：
  - `identity.rs` — 账号指纹 / 切换（热/冷/安全模式）/ 设备身份隔离
  - `profiles.rs` — 账号库 CRUD / 回收站 / 口令备份导入导出
  - `quota.rs` — 额度拉取、缓存与历史
  - `benefits.rs` — 福利检测、批量调度、领取流程
  - `settings.rs` / `window.rs` — 设置、窗口几何与窗口控制
  - `client.rs` / `system.rs` — 客户端探测/版本、更新、Shell、自启
  - `oauth.rs` / `app.rs` — OAuth 登录、托盘、通知、首屏状态
  - `crypto.rs` / `util.rs` — DPAPI 快照、`enc:v1`、路径与隐私 key
  - `backup.rs` / `diagnostics.rs` — 本地自动备份、脱敏诊断报告与启动耗时日志
- `src-tauri/src/{formats,claim,platform,audit,history}.rs` — 客户端格式 / 领取链路 / 平台抽象 / 审计 / 额度历史
- `tests/ui/` + `playwright.config.js` — 真实 UI + mock IPC 的功能 E2E（CI 失败自动上传截图）
- `ui/` — 前端三件套（index.html / style.css / app.js），零依赖，CSP `script-src 'self'`（禁止内联事件，用 `data-action` 事件委托）
- `scripts/secret-scan.sh` — 泄密守卫（三层：钩子/CI/发布；含 commit message 扫描）
- `docs/DESIGN.md` — 架构与安全模型，改架构先读它

## 硬性规则

1. **凭据/令牌/账号数据永不入库**。写入前 `secret-scan` 会拦；别尝试绕过
2. **加密布局动不得**：AES 是 `IV.TAG.CT`；`user_info` 必须规范化档案；zai token 必须换业务 token——细节见 `docs/DESIGN.md` 的「五条铁律」，每条都有测试守护
3. **版本号两处同步**：`tauri.conf.json` 与 `src-tauri/Cargo.toml`，改完跑 `bash scripts/repo-check.sh`
4. **UI 文案双语**：改 `ui/app.js` 里 `I18N` 的 zh/en 两份，键集合必须一致（CI 检查）；新增交互请同步 `tests/ui/` 用例
5. **CSP**：前端禁止内联事件与内联脚本；交互一律 `data-action` 委托（`ui/app.js` 里的 delegation）
6. **边界**（2026-11-02 调整）：允许①以用户本人账号上报 `app_launch`/`app_daily_active` 活动事件（与客户端启动行为一致，用于检测解锁）；②人工完成阿里云验证码后一键领取。**仍禁止**：自动/定时领取、验证码绕过自动化、批量刷取、遥测造假——见 `docs/DESIGN.md` §4
7. **身份与回滚**：账号身份用 token 明文指纹判定，禁止用展示名匹配；任何写 live 凭据的路径必须先备份、失败回滚；`snapkey` 解密失败必须硬失败，绝不重建覆盖
8. **格式化与供应链**：提交前 `cargo fmt`（CI 跑 `--check`）；依赖策略在仓库根目录 `deny.toml`，CI 跑 cargo-deny

## 常用命令

```bash
cargo test                                    # 单测（src-tauri 下）
cargo fmt --check                             # 格式门禁
cargo clippy --all-targets -- -D warnings      # 零警告门禁
cargo deny check                              # RustSec / licenses / bans / sources
bash scripts/secret-scan.sh --history          # 全历史泄密扫描（含 commit message）
bash scripts/secret-scan.sh --selftest         # 扫描器自检
bash scripts/repo-check.sh                     # 仓库一致性门禁
node --check ui/app.js                         # 前端语法
node scripts/i18n-check.js                     # 双语键集合
npm ci && npx playwright install chromium && npm run test:e2e  # UI E2E
npx --yes @tauri-apps/cli@2.12.4 build --bundles nsis  # 打包（需 TAURI_SIGNING_PRIVATE_KEY）
```

## 提交

英文 conventional（feat/fix/chore/docs/test）。改动 crypto/路径/解析逻辑必须带单测。详见 CONTRIBUTING.md。
