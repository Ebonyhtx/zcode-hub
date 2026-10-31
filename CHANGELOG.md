# Changelog

本文件记录 ZCode Hub 的显著变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-10-31

### 新增
- 应用内「设置 / 关于」面板：版本信息、检查更新（GitHub Releases）、开机自启、ZCode 客户端路径覆盖、数据目录直达
- GitHub Actions 发布流水线（tag 驱动，自动产出 NSIS 安装包并发布 Release）
- 仓库合规文件（README / LICENSE / SECURITY / CHANGELOG）

## [1.2.2] - 2026-10-31

### 新增
- arms_uid 隔离：每账号独立 AliyunRUM 遥测标识，切换时写入 rum-electron-store 并清除会话残留

## [1.2.1] - 2026-10-31

### 新增
- 设备身份隔离：每账号独立 deviceMid，切换时写入客户端 telemetry-state.json（用户知情拍板）

## [1.2.0] - 2026-10-31

### 新增
- 口令加密账号备份包 `.zhb`（PBKDF2-HMAC-SHA256 120k + AES-256-GCM），跨机迁移
- ZCode 数据目录跟随（`dataBaseDir`）、客户端未运行时的 exe 路径兜底

### 修复
- 切换时清理 coding-plan-cache.json，避免上一账号套餐状态残留
- 切换前把客户端刷新过的新凭据回写匹配存档（token 保鲜）
- 所有 JSON 原子写入（临时文件 + rename），杜绝半截文件

## [1.1.2] - 2026-10-31

### 安全
- 账号快照整包加密升级：随机密钥 + DPAPI 绑定当前 Windows 用户/机器，拷走不可解
- 配额请求 90s 缓存；窗口几何持久化；Esc 关闭弹窗

### 修复
- 全量检测的账号发现未适配加密快照文件名的回归（v1.2.3 修复）
- 当前账号判定改为按账号名（快照加密后文件哈希必不相等）

## [1.1.0] - 2026-10-31

### 新增
- 双协议 OAuth 登录（Z.AI / BigModel）：业务 token 自动交换、档案规范化
- 官方 `billing/preview` 福利检测（全量/单账号/托盘触发 + 系统通知 + 周期设置）
- 切换安全化：确认式杀进程、备份回滚、providerFamilyDomain 同步
- 浅色/深色双主题、自绘标题栏、单账号检测按钮、Z.AI/BigModel 徽章
- 数据目录迁移至标准 `%APPDATA%` 位置

### 修复
- 快照 AES 布局反向导致的解密失败（aead::Error）
- 切换后客户端「未登录」——缓存档案必须为规范化结构
- 切换后模型配置「请登录」——providerFamilyDomain 需随账号同步

## [1.0.0] - 2026-10-31

初始版本：账号保存/切换、额度展示、托盘常驻、Tauri 2 实现。
