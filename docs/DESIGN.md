# 架构与设计 / Design

本文说明 ZCode Hub 的内部结构、数据流与安全模型。面向贡献者；使用者请看 [README](../README.md)。

## 总体结构

```
┌────────────────────────── ZCode Hub (Tauri 2) ──────────────────────────┐
│  ui/  index.html + style.css + app.js      ← 零依赖前端，CSP: script 'self' │
│        │  IPC (invoke)                                                       │
│  src-tauri/src/main.rs                     ← 全部后端逻辑（单文件）            │
│   ├─ 状态: get_state / capture / switch / delete                            │
│   ├─ OAuth: init → 浏览器登录 → poll → 业务token交换 → 档案规范化            │
│   ├─ 额度: billing/balance（90s 缓存）   福利: billing/preview（官方同源）    │
│   ├─ 设备身份: 每账号独立 deviceMid + arms_uid                              │
│   └─ 守卫: safe_key 路径穿越校验 / 原子写入 / 泄密扫描                        │
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

### 3. 福利检测走官方同源
`GET /api/v1/zcode-plan/billing/preview` 是客户端领取弹窗的数据源。
不使用 marketing/touch（实测 400，且不区分已领/未领）。
批量检测间隔 800ms 规避 429；结果 90s 缓存 + 持久化。

### 4. 安全边界（刻意不做的事）
- 不做自动领取、验证码处理、遥测事件仿真（用户知情拍板的边界见 CHANGELOG v1.2.1）
- 不触碰 ZCode 自身凭据文件的保护方式（客户端要读）
- 自动领取相关讨论一律引回「检测 + 通知 + 用户手动领取」

## 测试策略

- **Rust 单测**（`src/main.rs` mod tests）：加密往返与布局守护、路径穿越、JWT 过期、
  preview 解析、原子写入、热切换验证回路、KDF —— 纯函数优先，不碰真实凭据
- **泄漏扫描器自检**：`scripts/secret-scan.sh --selftest` 构造已知泄漏断言能抓到
- **CI**：Windows 测试 + 全历史泄密扫描（见 .github/workflows/）

## 已知限制

- Windows 10/11 x64 专属（跨平台见 README Roadmap）
- BigModel 基础套餐额度走智谱自有接口，Hub 只显示 billing/balance 里的桶
- 热切换为实验特性：依赖客户端不会在切换瞬间写回凭据（冷切换始终可用）
