# 架构与设计 / Design

本文说明 ZCode Hub 的内部结构、数据流与安全模型。面向贡献者；使用者请看 [README](../README.md)。

## 总体结构

```
┌────────────────────────── ZCode Hub (Tauri 2) ──────────────────────────┐
│  ui/  index.html + style.css + app.js      ← 零依赖前端，CSP: script 'self' │
│        │  IPC (invoke)                                                       │
│  src-tauri/src/main.rs                     ← 命令、状态、业务流程             │
│   ├─ 状态: get_state / capture / switch / delete                            │
│   ├─ OAuth: init → 浏览器登录 → poll → 业务token交换 → 档案规范化            │
│   ├─ 额度: billing/balance（成功 90s / 失败 20s 负缓存）                      │
│   ├─ 福利: marketing/touch（横幅同源，preview 兜底）                          │
│   ├─ 设备身份: 每账号独立 deviceMid + arms_uid                              │
│   └─ 守卫: safe_key 路径穿越校验 / 原子写入 / 泄密扫描                        │
│  src-tauri/src/formats.rs                  ← 客户端文件格式纯逻辑（注入式）   │
│   └─ credentials / setting / telemetry-state / arms store + 契约测试        │
│  src-tauri/src/claim.rs                    ← 事件上报 / 营销活动 / 验证码 / 领取 │
│  src-tauri/src/platform.rs                 ← 平台抽象：Windows 实现 + 占位    │
│   └─ DPAPI / 进程 / Shell / 自启 / arms 目录（main.rs 零平台符号）
│  src-tauri/src/{audit,history}.rs          ← 本地审计日志 / 额度历史与燃尽率  │
└──────────────────────────────────────────────────────────────────────────┘
          │ 读/写（仅切换时）                          │ 只读探测
          ▼                                            ▼
  ~/.zcode/v2/credentials.json          %APPDATA%/Roaming/zcode-hub/
  （ZCode 客户端官方格式，Hub 不改动        ├─ profiles/<账号>/credentials.snap
    其保护方式）                           │  （AES-GCM 整包，密钥经 DPAPI 绑定）
                                          ├─ snapkey（DPAPI 加密的随机密钥）
                                          └─ hub-config.json / benefits.json
```

## 关键设计决策

### 1. 快照与活跃凭据分离
客户端运行时只认 `~/.zcode/v2/credentials.json` 的官方格式，因此 Hub：
- **切换** = 把存档明文写回该文件（切换前杀进程确认 + 备份回滚）
- **存档** = 整包 DPAPI 加密进 `profiles/`，与官方文件的保护互不干涉

### 2. OAuth 凭据「五条铁律」（踩坑实录，全部有对应测试或守卫）
1. AES 布局是 `IV.TAG.CT`（顺序错 → 全部存档解密失败）
2. `user_info` 必须是规范化档案 `{id, username, displayName, rawProfile}`
3. 键名与官方一致（`oauth:{provider}:access_token` 等）
4. zai 的 access_token 必须先经 `api.z.ai/api/auth/z/login` 换长效业务 token
5. 切换必须同步 `setting.json` 的 `providerFamilyDomain`

### 3. 福利检测走客户端横幅同源接口
`GET /api/v1/marketing/touch` 是客户端左下角领取横幅的真实数据源
（`deliveries[].banner` 的 `claim_zcode_plan` 动作携带 `plan_id`）；
`billing/preview` 只作兜底，并用于解析已领取计划。两路结果按 `plan_id` 去重。
批量检测间隔 800ms 规避 429，连续失败按 1→2→5→10 分钟退避；
成功结果缓存 90s，失败短负缓存 20s（避免恢复后仍显示旧错误）。

### 4. 安全边界（2026-11-02 用户拍板调整，见 CHANGELOG v1.7.0）
- **允许**：以用户本人账号上报 `app_launch` / `app_daily_active` 活动事件（与官方客户端启动行为一致，用于检测解锁；每账号 30 分钟节流；领取重试共用同一节流表）
- **允许**：人工完成阿里云验证码后一键领取——验证码页为本地回环 + 系统浏览器（不破坏应用 CSP），验证参数仅在本机传递，令牌不离开本机
- **仍禁止**：自动/定时领取、验证码绕过自动化、批量刷取、遥测造假（伪造用户行为统计/设备指纹）
- 不触碰 ZCode 自身凭据文件的保护方式（客户端要读）
- **安全模式**（客户端格式异常或手动开启）：合并「token + active_provider + 目标家族的
  access/refresh/user_info」，保留客户端未知字段，但不再保留旧账号身份；写前备份，
  校验失败恢复原文件。校验依据 token 明文指纹，不依据可重名的展示名。

### 5. 两套加密的分工（勿混淆）
- **`enc:v1:` 字段加密**（`IV.TAG.CT`）是 **ZCode 客户端官方格式的一部分**（asar oauthCredentialRepo），
  密钥派生公式（`SHA256("zcode-credential-fallback:win32:{home}:{user}")`）与客户端保持一致。
  **不可改**：改了客户端就读不懂 credentials.json，切换即坏。字段名常量与解析逻辑收敛在 `formats.rs`。
- **`ZH-SNAP1:` 整包快照加密**是 Hub 自有格式：随机 32 字节密钥经 **DPAPI** 绑定当前 Windows 用户+机器
  （`snapkey` 文件），拷走文件无法解密。`write_snapshot` 原子写入。**`snapkey` 已存在但无法解密时硬失败**，
  绝不生成新密钥覆盖（否则全部存档永久不可解）。
- **`.zhb` 备份 v2**：导出时用本机密钥解开 `enc:v1` 字段，放入外层口令加密（PBKDF2 + AES-256-GCM）的 bundle；
  导入时用目标机密钥重新加密，因此可跨用户名/跨机器恢复。v1 旧备份仍可导入，无法解密的账号会标记为需重新登录。
- **审计/额度历史/福利持久化**：账号 key 只以 SHA-256 前 16 位形式落盘（文件名/JSON 键），不出现邮箱或昵称。

## 测试策略

- **Rust 单测**（`main.rs` / `formats.rs` / `claim.rs` / `history.rs` / `audit.rs` 的 `mod tests`）：
  加密往返与布局守护、畸形 IV 拒绝、路径穿越、JWT 过期、marketing/preview 解析、原子写入、
  安全模式合并、热切换验证回路、历史追加/裁剪、审计轮转、验证码回环、KDF —— 纯函数优先，不碰真实凭据
- **格式契约测试**（`src-tauri/tests/fixtures/*.json` + `formats::tests`）：脱敏构造的客户端
  文件样本钉死字段名与解析语义——客户端格式变更会先打破测试而非线上行为
- **泄漏扫描器自检**：`scripts/secret-scan.sh --selftest` 构造已知泄漏（文件、文档明文密码、
  commit message）断言能抓到
- **领取协议集成测试**：本地 mock HTTP 服务走通「事件上报 → marketing 检测 → preview 兜底 →
  验证码配置 → 领取」，不依赖真实账号或外网
- **回归测试**：通知触发条件（开关/有无福利/手动托盘检测/失败数）、领取后活动乐观移除、
  验证码大 body/错误 Origin、额度历史缓存失效、畸形 IV、安全模式合并等
- **前端检查**：`node --check ui/app.js` + I18N zh/en 键集合一致性（CI 门禁）
- **响应式矩阵**：520×620 / 620×800 / 1100×800 / 1560×900 / 1920×1080，中英文各跑一遍；
  验证 1/2/3 列、排序与手动排序、领取按钮、设置弹窗、路径提示无裁切/无横向溢出
- **CI**：三平台 `cargo test`；Windows 额外跑 `clippy -D warnings`；全历史泄密扫描 + 仓库一致性门禁

## 已知限制

- 功能仅 Windows 10/11 x64 可用（CI 已在 ubuntu/macOS 上编译并跑纯逻辑测试，平台占位返回不支持）
- BigModel 基础套餐额度走智谱自有接口，Hub 只显示 billing/balance 里的桶
- 热切换为实验特性：依赖客户端不会在切换瞬间写回凭据（冷切换始终可用）
- 安全模式跨账号切换会替换目标家族的账号身份字段并移除旧家族字段；若客户端未来重命名字段，
  可能仍需关闭安全模式做完整切换
- v1 旧备份在用户名/机器不同的环境可能无法解密字段，导入后需重新登录；新导出均为 v2
- 自动检测受服务端 429 影响：连续失败会退避，成功结果与失败负缓存分别计时
- 格式兼容知识锚定客户端 3.17.x：客户端 major.minor 变化会触发兼容警告并自动走安全模式切换

## 前端约定

- **语义色 token**：`--brand`（可操作）/ `--warn`（待生效、临期、福利）/ `--danger`（真错误、删除）/ `--ok`（仅成功）；
  不再用同一个琥珀色同时表示主按钮与警告
- **对比度**：正文/辅助文字按 WCAG AA 选取；暗色使用分层表面（背景/卡片/次级表面）+ 描边
- **CSP**：`script-src 'self'`，无内联事件、无内联脚本；交互一律 `data-action` 委托
- **刷新**：`get_state` 返回本地状态与上次额度快照 → 先渲染 → 逐卡回填；force 刷新排队而非丢弃，
  过期响应按请求代次丢弃；窗口隐藏时暂停轮询
- **卡片更新**：按 `data-key` 局部替换，不整表重建；折叠只切 class，保留滚动与焦点
- **i18n**：`ui/app.js` 内 zh/en 两份，键集合必须一致（CI 检查）；日期/数字使用本地化单位与千分位
- **响应式**：默认单列；≥1100px 两列、≥1560px 三列（内容最大 1500px）。卡片内部使用
  grid/flex，宽屏下额度、福利、操作按钮仍按卡片宽度重排
- **排序**：当前优先 / 待领福利（最近检测结果）/ 即将到期（真实最早到期时间）/ 手动顺序
  （卡片 ↑↓ 调整并持久化）；手动顺序的边界按钮禁用
- **托盘**：显示 / 立即检测（手动检测必回结果通知，有福利才响铃）/ 打开 ZCode / 退出
