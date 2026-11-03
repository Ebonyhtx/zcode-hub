# 性能基线 / Performance baseline

ZCode Hub 在启动完成时（托盘、窗口恢复、自动检测线程就绪后）向
`%APPDATA%\zcode-hub\startup.log` 追加一行 JSON：

```json
{"ts":"2026-11-03T12:00:00+00:00","version":"1.10.0","ms":412}
```

日志保留最近 200 次启动。它只记录版本、时间和耗时，不含账号/token。

## 如何测量

```powershell
cd src-tauri; cargo build --release
cd ..
powershell -ExecutionPolicy Bypass -File scripts/perf-baseline.ps1
```

- 应用**未运行**时，脚本会启动 release 包、等待 8 秒、读取启动日志和
  `WorkingSet64 / PrivateMemorySize64`，然后关闭它自己启动的实例。
- 应用已在运行时，脚本不会打断它，只读取最近一次启动日志和当前内存。
- 测量前关闭其它重型程序；Windows Defender 首次扫描会影响第一次启动。

## 参考基线

本仓库不记录任何具体机器的实测数值；请在目标机器上运行上面的脚本自行建立基线。

| 指标 | 量级参考 | 说明 |
|---|---|---|
| 启动到 ready | 数百毫秒 | release 构建、SSD；首次启动受 Defender 扫描影响 |
| 托盘常驻 Working Set | 数十 MB | 随 WebView2 与系统版本变化 |
| 空闲 CPU | 接近 0 | 自动检测线程每 30 秒醒来一次，按设置周期才发请求 |

这些只是量级参考，不是硬性阈值；CI 不做性能门禁（托管 runner 抖动大），
只在本地或真机回归时对比。测量时如果 Hub 已在运行，脚本不会打断它，
只读取当前内存和最近一次启动日志。

## 诊断报告

设置 → 导出诊断报告会生成脱敏 JSON，包含版本、OS/架构、兼容状态、
账号/额度摘要（账号键已哈希）、审计日志尾部、启动日志尾部和崩溃日志尾部
（`crash.log` 最近 20 条）。报告不含 token、邮箱、展示名或真实账号目录名。
用户报障时附上该文件即可。

## 测试覆盖率基线

`Coverage` workflow 每周一跑 `cargo-llvm-cov`，产物是 `coverage-lcov` 构件。
行覆盖率基线约 **46%**（2026-11-03，72 个 Rust 单测）。这不是一个「好」数字，
而是当前的诚实状态：`app.rs` / `identity.rs` / `oauth.rs` / `system.rs` /
`window.rs` 的大部分代码依赖 Tauri 运行时、WebView2 与 Windows API，单测里
没有宿主可跑，只能靠三平台编译 + Playwright 功能用例兜底。

`scripts/coverage-gate.py` 把门槛设在 **45%**，只用于防退化，不是目标值：

```bash
cargo llvm-cov --manifest-path src-tauri/Cargo.toml --lcov --output-path lcov.info
python3 scripts/coverage-gate.py lcov.info            # 默认 45%
python3 scripts/coverage-gate.py lcov.info --min 50   # 需要更高要求时显式传
```

补充单测或重构提升基线后，请同步上调 `scripts/coverage-gate.py` 的
`DEFAULT_MIN`，否则覆盖率回退不会被发现。

