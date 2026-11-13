# 架构与设计 / Design

本文说明 ZCode Hub 的内部结构、数据流与安全模型。面向贡献者；使用者请看 [README](../README.md)。

## 总体结构

```
┌────────────────────────── ZCode Hub (Tauri 2) ──────────────────────────┐
│  ui/  index.html + style.css + app.js      ← 零依赖前端，CSP: script 'self' │
│        │  IPC (invoke)                                                       │
│  src-tauri/src/main.rs                    ← 入口 / 43 commands 注册      │
│  src-tauri/src/identity.rs                ← 身份指纹 / 切换 / 设备隔离   │
│  src-tauri/src/profiles.rs                ← 账号库 CRUD / 回收站 / 备份  │
│  src-tauri/src/quota.rs                   ← 额度 / 缓存 / 燃尽率历史     │
│  src-tauri/src/benefits.rs                ← 福利检测 / 批量调度 / 领取   │
│  src-tauri/src/{client,system}.rs         ← 客户端 / 更新 / Shell / 自启 │
│  src-tauri/src/{window,settings}.rs       ← 窗口几何 / 设置              │
│  src-tauri/src/{oauth,app}.rs             ← OAuth / 托盘 / 通知 / 状态   │
│  src-tauri/src/{crypto,util}.rs           ← 快照加密 / 原子写 / 隐私 key │
│  src-tauri/src/{backup,diagnostics}.rs    ← 备份 / 诊断 / 启动基线       │
│  src-tauri/src/crash.rs                   ← panic / 前端异常落盘        │
│   └─ 守卫: safe_key 路径穿越校验 / 原子写入 / 泄密扫描                        │
│  src-tauri/src/formats.rs                  ← 客户端文件格式纯逻辑（注入式）   │
│   └─ credentials / setting / telemetry-state / arms store + 契约测试        │
│  src-tauri/src/claim.rs                    ← 事件上报 / 营销活动 / 验证码 / 领取 │
│  src-tauri/src/platform.rs                 ← 平台抽象：Windows 实现 + 占位    │
│   └─ DPAPI / 进程 / Shell / 自启 / arms 目录（业务模块零平台符号）
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
- **允许**：人工完成阿里云验证码后一键领取——验证码页为本地回环 + 系统浏览器（不破坏应用 CSP），验证参数仅在本机传递，令牌不离开本机。
  验证码**按需**触发：先裸提交 `billing/claim`，仅当服务端返回 3007（要求验证码）时才起回环页；
  不需要验证码的活动全程零弹窗（2026-11-07 起，与参考实现的按需索要语义一致）。
  验证页**会话复用**（2026-11-13 起）：同一回环页可在多次领取间反复使用——页面每 1.5s 轮询
  `/<nonce>/next` 心跳（10 分钟会话时限），下一次领取在同一页进入下一轮验证，不再新开标签页；
  页面关闭后心跳超时（6s 宽限），下一次领取才新开一页
- **领取错误语义分类**（`ClaimErrKind`，照 magpie 社区插件 claimOne 语义表逐码对应）：
  1003=已领取（视为成功收尾，UI 显示「今日已领取」）、1004=未开放（当天可复查）、
  3007/msg 含 captcha=需人工验证码、HTTP 429 或 3002=限流（必须读 Retry-After）、
  其他 5xx=暂时性、其余=Fatal（never guess）。body 不可解析时按 HTTP 状态行分类
- **账号级限流 hold**（照 magpie 插件 rateWait 设计，仅存内存）：429/3002 后在等待期内对
  该账号的领取与检测**零请求**直接复答——持续请求本身会把限流一直续着
  （magpie plugins#503：一个账号 4 天被限流 180 次的事故教训）。
  claim/marketing/preview 三条路径的 429 都会触发（marketing 是检测主数据源，preview 只是兜底）；
  等待 = Retry-After 优先，否则 30 分钟起步逐次翻倍、封顶 6 小时；
  解除只有两种：期满自然过期 / 一次真实请求成功读通。
  hold 中账号不计入「全部失败」，避免把其他健康账号拖进高频检测
- **仍禁止**：自动/定时领取、验证码绕过自动化、批量刷取、遥测造假（伪造用户行为统计/设备指纹）
- 不触碰 ZCode 自身凭据文件的保护方式（客户端要读）
- **切换写入一律是合并**（v1.11.0 起，见 §6「客户端演进策略」）：以 live 为基底，只替换
  「token + active_provider + 目标家族的 access/refresh/user_info」，并按前缀清掉按账号内嵌 ID 的键；
  客户端新增的未知字段全部保留。写前备份，校验失败恢复原文件。校验依据 token 明文指纹，不依据可重名的展示名。
- **严格模式**（设置项 `safe_mode`，默认关）：live 凭据缺失或结构异常时**拒绝切换**，
  而不是留档为 `.corrupt` 后继续。它总是重启客户端，不再走热切换路径。

### 5. 加密的三层分工（勿混淆）
- **`enc:v1:` 字段加密**（`IV.TAG.CT`）是 **ZCode 客户端官方格式的一部分**（asar oauthCredentialRepo），
  密钥派生公式（`SHA256("zcode-credential-fallback:win32:{home}:{user}")`）与客户端保持一致。
  **不可改**：改了客户端就读不懂 credentials.json，切换即坏。字段名常量与解析逻辑收敛在 `formats.rs`。
- **`enc:v2:` 系统安全存储**（客户端 3.18.0 起）：`enc:v2:<os|env>:<fp>:<iv>.<tag>.<ct>`，
  随机 32 字节密钥存在**系统凭据库**（Windows Credential Manager，service `ZCode Credential Encryption`，
  account = 凭据文件绝对路径的 SHA-256 hex，口令为 UTF-16LE 的 43 字符 base64url），
  文件只存指纹 `sha256(key).hex[..24]`。Hub 做**只读兼容**：`creds_v2.rs` 用 `CredEnumerateW`
  按指纹匹配取密钥（进程级缓存，失败也缓存到重启，避免反复触发系统授权），
  **v2 永不尝试弱派生密钥**（指纹不匹配直接拒绝）。写入路径暂不变（继续写 `enc:v1:`，
  客户端读取时自动迁移到 v2）；判断「值是否加密」**必须用 `ENC_ANY_PREFIX`（`enc:`）**——
  只认 `enc:v1:` 会把 v2 密文当明文，v1.12.x 曾因此在 UI 里显示密文与误报登录过期。
  env 来源支持 `ZCODE_CREDENTIAL_SECRET` / `_FILE`（32–4096 字节、按原字节、不 trim）。
- **`ZH-SNAP1:` 整包快照加密**是 Hub 自有格式：随机 32 字节密钥经 **DPAPI** 绑定当前 Windows 用户+机器
  （`snapkey` 文件），拷走文件无法解密。`write_snapshot` 原子写入。**`snapkey` 已存在但无法解密时硬失败**，
  绝不生成新密钥覆盖（否则全部存档永久不可解）。
- **`.zhb` 备份 v2**：导出时用本机密钥解开加密字段（v1/v2 均可），放入外层口令加密（PBKDF2 + AES-256-GCM）
  的 bundle；导入时用目标机密钥重新加密（写 v1，客户端迁移到 v2），因此可跨用户名/跨机器恢复。
  v1 旧备份仍可导入，无法解密的账号会标记为需重新登录。
- **本地自动备份**：每 24h 把 `profiles/`（DPAPI 快照）与设置复制到 `backups/<时间戳>/`，默认保留 7 份；
  它是本机恢复点，不跨机。跨机仍用 `.zhb`。导入前 `inspect_bundle` 只解密预览（新增/重复/需重登），确认后才写入。
- **备份恢复**：可列出全部备份并选择具体一份（不再只有「最近一份」）。恢复前校验 manifest 记录的账号数
  与实际目录数：实际更少即判定为残缺，**拒绝恢复**（不让截断的备份覆盖账号库）；恢复前自动再做一次安全备份，
  替换失败回滚原目录。恢复成功后清空额度/福利的内存与落盘缓存并重置 `last_check`，避免卡片显示已不存在的账号额度。
- **诊断报告**：设置里导出的脱敏 JSON 只含版本、OS/架构、兼容状态、哈希后的账号/额度摘要、审计与启动日志尾部、
  崩溃日志尾部（最近 20 条），不含 token、邮箱、展示名或真实账号目录名。
- **崩溃日志**：进程 panic（全局 hook）与前端未捕获异常（`window.onerror` / `unhandledrejection`）追加到
  `crash.log`：只记版本、时间、类别、消息与来源文件名（绝对路径经 `redact_path` 压成文件名），
  超过 512KB 保留最新一半。前端同类错误 60 秒内只报一次，避免死循环刷盘。
- **审计/额度历史/福利持久化**：账号 key 只以 SHA-256 前 16 位形式落盘（文件名/JSON 键），不出现邮箱或昵称。

## 测试策略

- **Rust 单测**（各模块底部的 `mod tests`，共 102 个）：
  加密往返与布局守护、畸形 IV 拒绝、路径穿越、JWT 过期、marketing/preview 解析、原子写入、
  字段合并与 carry-over、按账号键清理、版本关系判定、存档陈旧判定、热切换验证回路、历史追加/裁剪、审计轮转、崩溃日志轮转与路径脱敏、
  备份完整性校验与恢复目标解析、验证码回环、KDF —— 纯函数优先，不碰真实凭据
- **格式契约测试**（`src-tauri/tests/fixtures/*.json` + `formats::tests`）：脱敏构造的客户端
  文件样本钉死字段名与解析语义——客户端格式变更会先打破测试而非线上行为
- **泄漏扫描器自检**：`scripts/secret-scan.sh --selftest` 构造已知泄漏（文件、文档明文密码、
  commit message）断言能抓到
- **领取协议集成测试**：本地 mock HTTP 服务走通「事件上报 → marketing 检测 → preview 兜底 →
  领取（裸提交）→ 3007 索验时带凭证重试」，不依赖真实账号或外网；
  另有 ClaimErrKind 逐码分类、Retry-After（秒数/HTTP-date/缺失）、
  hold 行为（退避翻倍封顶 6h、期满过期、成功清除、入口零请求拒绝）单测
- **回归测试**：通知触发条件（开关/有无福利/手动托盘检测/失败数）、领取后活动乐观移除、
  验证码大 body/错误 Origin、额度历史缓存失效、畸形 IV、合并保留客户端字段等
- **前端检查**：`node --check ui/app.js` + I18N zh/en 键集合一致性（CI 门禁）
- **Playwright 功能 E2E**（30 例，真实页面 + `__TAURI_INTERNALS__` mock IPC）：主题/折叠/搜索筛选/
  置顶/标签/设置持久化/导入预览/领取历史/备份目录/备份选择恢复/领取状态机
  （preparing → waiting_captcha → claiming → success，含失败分支）/前端错误上报/存档陈旧与刷新/客户端版本展示/切换模式文案/严格模式与热切换互斥/响应式列数
- **无障碍检查**：axe（WCAG 2.0 A/AA）扫主界面与设置、备份弹窗；`color-contrast` 规则因主题色
  由设计规范控制而单独人工核验。当前发现并修复了 4 个 `<select>` 缺少可访问名称的问题
  （`data-i18n-aria` 随语言切换更新）
- **响应式矩阵**：520×620 / 620×800 / 1100×800 / 1560×900 / 1920×1080，中英文各跑一遍；
  验证 1/2/3 列、排序与手动排序、领取按钮、设置弹窗、路径提示无裁切/无横向溢出
- **CI**：三平台 `cargo test`；Windows 额外跑 `clippy -D warnings`；全历史泄密扫描 + 仓库一致性门禁

## 已知限制

- 功能仅 Windows 10/11 x64 可用（CI 已在 ubuntu/macOS 上编译并跑纯逻辑测试，平台占位返回不支持）
- BigModel 基础套餐额度走智谱自有接口，Hub 只显示 billing/balance 里的桶
- 热切换为实验特性：依赖客户端不会在切换瞬间写回凭据（冷切换始终可用）
- 严格模式拒绝在 live 凭据不可读时切换；此时需要用户手动处理或从备份恢复
- v1 旧备份在用户名/机器不同的环境可能无法解密字段，导入后需重新登录；新导出均为 v2
- 自动检测受服务端 429 影响：连续失败会退避，成功结果与失败负缓存分别计时

## 6. 客户端演进策略（v1.11.0）

客户端每个版本都可能在 `credentials.json` 里加新键（3.17.2 就新增了 4 类 `mcp:oauth:*` 与
`project-key-location:v1:*`）。Hub 的策略是**结构上不丢字段、语义上只看结构**：

1. **只增不丢**：除身份字段与按账号键外，切换时 live 的每个键都原样保留。Hub 不需要认识它们。
   新增客户端字段因此天然安全，不需要为每个新字段发版。
2. **身份字段是白名单替换**：`FIELD_TOKEN`、`FIELD_ACTIVE_PROVIDER`、两家族的
   `access_token`/`refresh_token`/`user_info` 由 `merge_account_fields` 精确增删，
   其余一概不动。这比"整文件覆盖"更安全——后者会连带删掉客户端的授权数据。
3. **按账号键必须换**：`ACCOUNT_SCOPED_PREFIXES` 里的前缀（当前只有 `project-key-location:v1:`）
   内嵌账号 ID，切换时必须整条替换。发现新的同类键时，在 `formats.rs` 的常量里加一行即可，
   `merge_drops_account_scoped_keys` 会覆盖。判断标准是「键名是否随账号变化」。
4. **结构变化靠探测，不靠版本号**：`probe_credentials` 检查必需键与可解析性；
   `errors` 非空才算故障。版本号（`VERIFIED_CLIENT_VERSION`）只用于**设置页的展示与提示**，
   不参与切换决策——客户端升级不该被当成故障。
5. **存档新鲜度可见**：`meta.json` 记录抓取时的 `client_version` 与 `field_count`。
   同版本下字段更少 = 存档落后，卡片显示「旧 x.y.z」，当前账号可一键刷新
   （非当前账号由下次切换时的 `preserve_current_login` 自动刷新）。
   v1.11.0 之前写的存档没有 `client_version`，升级后由 `backfill_snapshot_field_counts`
   按快照实际键数补一次 `field_count`（**只读快照，不重新抓取**），标签从升级当刻就有效；
   版本未知时陈旧判定退回纯字段数比较（卡片只显示「旧」，不露占位符）。
   「旧」标签只给**可刷新**的存档：当前账号与登录已过期的账号都不标（后者没有有效 live 可抓）。
6. **live 不可读的两种态度**：普通模式留档为 `.corrupt` 后继续；严格模式直接拒绝。
7. **严格模式与热切换互斥**：严格模式要求客户端完全重新初始化，后端忽略热切换
   （`want_hot && !strict_requested`）；UI 同步禁用热切换开关并说明原因，不让用户误以为它还生效。

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
