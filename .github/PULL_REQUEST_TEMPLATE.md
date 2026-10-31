<!-- 标题格式: feat|fix|chore|docs|test: 摘要 -->

## 变更说明 / What does this change?

<!-- 一两句话说明动机与方案 / Motivation and approach -->

## 自查清单 / Checklist

- [ ] `cargo test` 全绿（src-tauri 下运行）
- [ ] 改了 UI 文案 → `ui/app.js` 的 I18N 中英字典已同步
- [ ] 改了版本号 → `tauri.conf.json` 与 `Cargo.toml` 两处一致，CHANGELOG 已补
- [ ] 已运行 `bash scripts/secret-scan.sh --staged`（若已配置 hooksPath 则自动执行）
- [ ] 未引入任何凭据、令牌、账号数据（见 SECURITY.md）
