/* ZCode Hub app — CSP-safe (no inline handlers), zh/en i18n, keyed card patching */
"use strict";

/* ---------------- i18n ---------------- */
var I18N = {
  zh: {
    running: "ZCode 运行中", not_running: "未运行", process_unknown: "无法确认运行状态",
    add: "添加账号", capture: "保存当前登录", backup: "备份 / 导入",
    auto_check: "自动检测", notify: "通知", off: "关闭", min5: "每 5 分钟", min15: "每 15 分钟", min30: "每 30 分钟", min60: "每 60 分钟",
    check_all: "检测全部", checking_dots: "检测中…", checking_progress: "检测中 {done}/{total}", refresh: "刷新额度",
    last_check: "上次", never_checked: "未自动检测",
    accounts: "账号库", n_accounts: " 个账号",
    week_plan: "周末福利", base_plan: "基础套餐", other_plan: "其他", switch_to: "⇄ 切换到此账号",
    client_not_found: "未检测到 ZCode 客户端。请安装客户端，或在设置中指定安装路径。",
    t_save_fail: "保存失败：{e}", err_generic: "操作失败：{e}", err_process: "无法确认或关闭 ZCode 进程", err_snapshot: "账号存档读取失败", err_path: "客户端路径无效", err_password: "口令不正确或备份损坏", delete_body: "删除「{name}」？存档、额度历史和福利记录会一并移除，可在提示中撤销。", kill_confirm: "关闭 ZCode 客户端？正在运行的任务会中断。",
    t_closed: "ZCode 已关闭", t_restored: "已恢复「{x}」", import_fail: "导入失败：{e}",
    sort: "排序", sort_current: "当前优先", sort_claimable: "待领福利", sort_expiry: "即将到期", sort_manual: "手动顺序", sort_manual_hint: "用卡片右上角 ↑↓ 调整", move_up: "上移", move_down: "下移",
    expand_all: "全部展开", fold_all: "全部收起",
    no_profile_title: "还没有账号", no_profile_body: "先安装并登录 ZCode 客户端，然后点「添加账号」；如果已经登录，点「保存当前登录」。",
    install_zcode: "打开 ZCode 官网", recheck: "重新检测",
    unsaved_title: "当前登录尚未保存", unsaved_body: "这是 ZCode 客户端当前登录的账号。保存后会出现在账号库里，可随时切换。", save_current: "保存这个账号",
    current: "当前", expired: "登录已过期", unknown: "未知", not_signed_in: "(未登录)", encrypted_account: "(已加密账号)", snapshot_error: "存档无法读取：{e}",
    fold_show: "展开账号", fold_hide: "收起账号", rename: "重命名", rename_title: "重命名账号", rename_sub: "只改显示名称，不影响登录凭据。", rename_ph: "账号显示名称",
    delete: "删除账号", check_one: "检测这个账号的福利",
    no_quota: "暂无额度数据", no_quota_hint: "客户端当前没有生效套餐（可能已到期，或刚领取还没生效）。", quota_fail: "获取额度失败",
    updated_at: "更新于 {t}", cached: "缓存", retry: "重试", relogin: "重新登录",
    auth_expired: "登录已过期，请重新登录这个账号。", rate_limited: "请求过于频繁，约 {n} 秒后自动重试。", server_error: "服务端暂时不可用，稍后自动重试。", network_error: "网络不可用，请检查连接后重试。",
    used_up: "已用完", remain: "剩余", total: "总", used: "已用", expires: "到期", unknown_total: "总量未知",
    exp_soon: "{h} 小时后到期", exp_lt1h: "不到 1 小时后到期", burn: "按当前速度约 {d} 天", burn_lt1: "按当前速度不足 1 天",
    spark_label: "趋势", spark_hint: "最近几次采样的剩余额度走势",
    search_ph: "搜索账号或标签…", filter_all: "全部", filter_current: "当前", filter_benefits: "有福利", filter_expired: "已过期", no_match: "没有匹配的账号",
    pin: "置顶", unpin: "取消置顶", tags: "标签", tags_title: "编辑标签", tags_sub: "用逗号分隔；最多 8 个，每个最多 16 字。", tags_ph: "例如：工作, 团队", tags_saved: "标签已保存", tags_fail: "保存标签失败：{e}",
    stale_tag: "旧", stale_hint: "存档只有 {n} 个字段，缺少客户端新增的字段。切换时会自动合并保留，也可以现在就刷新。", stale_refresh: "刷新存档", stale_refreshed: "存档已刷新：{n} 个字段", stale_refresh_fail: "刷新存档失败：{e}",
    stale_tag_ver: "旧 {v}", stale_hint_ver: "存档来自 {v}，只有 {n} 个字段，缺少客户端新增的字段。切换时会自动合并保留，也可以现在就刷新。",
    zcode_verified: "已验证至 {v}", zcode_unverified: "未验证",
    quota_notify: "额度提醒", quota_notify_hint: "即将到期或不足 10% 时通知", auto_backup: "自动备份", auto_backup_hint: "每天备份到本机，保留 7 份", update_notify: "新版本提醒", update_notify_hint: "每 24 小时检查一次",
    backup_now: "立即备份", backup_done: "备份完成：{n} 个账号", backup_fail: "备份失败：{e}", diagnostics: "导出诊断报告", diag_done: "诊断报告已导出", diag_fail: "导出失败：{e}",
    backup_dir: "备份目录", open_backup_dir: "打开备份目录", backup_info: "共 {n} 份备份", backup_info_none: "暂无备份", backup_open_fail: "打开备份目录失败：{e}", backup_open_toast: "已打开备份目录",
    restore_backup: "恢复备份", restore_confirm_title: "恢复备份", restore_confirm_body: "将用所选本地备份替换当前账号库。恢复前会自动再做一份安全备份；确认继续？", restore_done: "已恢复 {n} 个账号", restore_fail: "恢复失败：{e}", backup_last: "最近 {t}",
    restore_pick_title: "选择要恢复的备份", restore_pick_sub: "按时间从新到旧；标「不完整」的备份无法恢复。", restore_pick_btn: "恢复这份", restore_bad: "备份不完整，未恢复：{e}", restore_warn: "已恢复，但{e}", restore_none: "没有可恢复的备份", backup_verified: "完整", backup_broken: "不完整", backup_accounts: "{n} 个账号",
    import_preview_btn: "预览", import_confirm: "确认导入", import_preview_hint: "新增 {n} · 重复 {d} · 需重登 {r}", import_preview_fail: "预览失败：{e}", import_none: "没有可导入的账号",
    preview_new: "新增", preview_dup: "重复", preview_relogin: "需重登", preview_invalid: "无效", import_confirm_hint: "确认后将合并导入，重复账号会跳过。",
    history_export: "导出 JSON", history_export_done: "已导出 {n} 条记录", history_export_fail: "导出失败：{e}", update_banner: "新版本 v{v} 可用",
    plan_pending: "{t} 生效", plan_active_syncing: "已生效 · 额度同步中", plan_daily: "/天",
    not_checked: "未检测", ben_none: "无待领福利", ben_has: "{n} 个待领福利", ben_fail: "检测失败：{e}", ben_transient: "暂时无法检测，稍后自动重试", ben_hold: "限流等待中，{time} 恢复",
    claim: "去领取", claim_btn_prep: "准备中", claim_btn_verify: "验证中", claim_btn_claim: "领取中",
    claim_wait: "请在验证页完成验证码，通过后会自动领取。验证页保持打开，后续领取会继续复用同一页。", claim_ok: "领取成功：{p}（{t} 生效）", claim_fail: "领取失败：{e}", claim_busy: "上一次领取仍在进行中，请稍候。",
    claim_already: "该福利今日已领取", claim_not_eligible: "活动此刻未开放，稍后自动复查", claim_rate_hold: "账号限流中，{time} 前不再请求，稍后自动恢复",
    claim_timeout: "等待验证超时，请重试。", claim_bg: "领取仍在后台进行，完成后会自动刷新。", claim_reopen: "重新打开验证页",
    claim_steps_prep: "准备", claim_steps_verify: "浏览器验证", claim_steps_claim: "领取",
    switch_title: "切换账号", switch_body: "从「{from}」切换到「{to}」。\n{mode}", switch_hot: "热切换：客户端不重启，直接更换登录身份。", switch_cold: "ZCode 将自动关闭并重启。",
    switch_expired: "目标账号的登录已过期，切换后需要在 ZCode 里重新登录。", switched_strict: "已用严格模式切换并重启 ZCode。",
    switched_hot: "已热切换。客户端左下角的账号名需要重启 ZCode 才会更新。", switched_re: "已切换并重启 ZCode。", switched_nore: "凭据已切换，ZCode 未自动重启，请手动打开。", switch_fail: "切换失败：{e}",
    switching: "切换中…", open_client: "打开 ZCode", restart_client: "重启 ZCode 以同步名称", hot_notice: "已热切换为「{name}」。客户端左下角账号名来自本地缓存，需重启 ZCode 才会更新。",
    add_title: "添加账号", add_sub: "选择账号类型，在浏览器完成官方登录后自动存入账号库。",
    zai_name: "Z.AI 账号", zai_desc: "chat.z.ai · Start Plan / Coding Plan", bm_name: "BigModel 账号", bm_desc: "bigmodel.cn · 智谱个人 / 团队套餐",
    opening: "正在打开 {p} 官方登录页…", oauth_pending: "等待浏览器完成登录…", oauth_already: "已有登录流程进行中，已为你继续。", oauth_ready: "登录成功：{l}", oauth_fail: "登录失败：{e}",
    oauth_timeout: "登录等待超时，请重试。", oauth_countdown: "剩余 {t}", reopen: "重新打开登录页", copy_link: "复制链接", copied: "链接已复制", copy_fail: "复制失败，请手动打开登录页",
    retry_signin: "重新登录", cancel: "取消",
    cfg_title: "设置 / 关于", about: "关于", about_line: " · 非官方多账号管理工具", check_upd: "检查更新", repo: "GitHub 仓库",
    zcode_sec: "ZCode", client_path: "客户端路径", path_ph: "C:\\Program Files\\ZCode\\ZCode.exe", path_hint: "留空 = 自动探测；也可以点右侧文件夹图标选择 ZCode.exe", browse: "选择文件", save: "保存",
    datadir: "数据目录", open_hub_data: "打开 Hub 数据", open_zdata: "打开 ZCode 数据",
    sys_sec: "系统", autostart: "开机自启", autostart_hint: "写入启动文件夹快捷方式", start_min: "启动时最小化", start_min_hint: "启动后直接驻留托盘",
    close_action: "关闭窗口时", close_tray: "最小化到托盘", close_quit: "退出程序",
    hot: "热切换（实验）", hot_hint: "不重启客户端直接换号，失败自动回退", hot_note: "热切换不重启客户端：套餐与额度立即按新账号生效，但左下角账号名来自客户端本地缓存，需重启 ZCode 才会更新。",
    safe_mode: "严格模式", safe_hint: "当前凭据缺失或结构异常时拒绝切换，而不是留档后继续", lang: "语言",
    hot_blocked_by_strict: "严格模式已开启：切换必然重启客户端，热切换不生效", strict_overrides_hot: "开启严格模式后会关闭热切换（严格模式要求客户端重新初始化）",
    kill: "关闭 ZCode", claim_history: "领取历史", claim_history_title: "领取历史", claim_history_sub: "只记录本机领取的套餐与时间，不含账号信息。", no_claim_history: "暂无领取记录",
    bak_title: "备份 / 导入账号库", bak_sub: "备份文件用口令加密（PBKDF2 + AES-256-GCM），可在其他电脑导入恢复；口令丢失无法找回。",
    export_to: "导出到桌面", bak_ph: "设置口令（至少 6 位）", export_btn: "导出 .zhb", import_from: "从文件导入",
    imp_path_ph: "选择或粘贴 .zhb 文件路径", imp_pwd_ph: "备份口令", import_btn: "导入", drop_hint: "把 .zhb 文件拖到这里，或点右侧文件夹图标选择",
    open_folder: "打开所在文件夹", exported: "备份完成：{n} 个账号", export_fail: "导出失败：{e}",
    import_done: "导入完成：新增 {n} 个", import_skipped: "跳过 {n} 个（已存在或无效）", import_relogin: "{n} 个账号的字段无法解密，切换后需要重新登录", close: "关闭",
    checking_upd: "检查中…", update_confirm_title: "安装更新", update_confirm: "更新会重启 ZCode Hub，正在运行的领取/切换会中断。继续？", upd_latest: "已是最新（v{v}）", upd_found: "发现新版本 v{v}", install_upd: "立即更新", upd_go: "前往下载", upd_fail: "检查失败：{e}", install_fail: "更新失败：{e}", upd_installing: "正在下载并安装…", updating_pct: "正在下载 {p}%", updating: "正在下载…",
    confirm_ok: "确认",
    notice_offline: "网络不可用，无法刷新账号状态。", notice_process: "无法确认 ZCode 进程状态：{e}", notice_claim: "正在领取「{p}」，其他账号暂时锁定。", dismiss: "关闭提示", details: "详情",
    settings: "设置", theme: "切换主题", minimize: "最小化", maximize: "最大化", close_window: "关闭窗口",
    t_saved: "已保存：{x}", t_quota_refreshed: "额度已刷新（{n} 个账号）", t_quota_refreshed_partial: "额度已刷新：{n} 个成功，{f} 个失败", t_deleted: "账号已删除", t_undo: "撤销", t_settings_saved: "设置已保存", t_notify_on: "已开启系统通知", t_notify_off: "已关闭系统通知",
    t_autostart_on: "已开启开机自启", t_autostart_off: "已关闭开机自启", t_autostart_fail: "设置失败：{e}", t_path_saved: "客户端路径已保存（留空 = 自动探测）",
    t_refresh_fail: "刷新失败：{e}", t_check_done0: "检测完成：{ok}/{all} 个账号正常，均无待领福利", t_check_done: "检测完成：{w}/{all} 个账号有 {n} 项福利待领",
    t_check_partial: "检测完成：{ok}/{all} 个正常，{f} 个暂时无法检测", t_one_has: "该账号有 {n} 项待领福利", t_one_none: "该账号暂无待领福利", t_one_transient: "暂时无法检测，稍后自动重试",
    t_one_fail: "检测失败", t_close_fail: "无法关闭 ZCode：{e}", t_pwd_short: "口令至少 6 位", t_fill_both: "先选择文件并填写口令",
    t_rename_saved: "已重命名为「{x}」", t_rename_fail: "重命名失败：{e}", t_claim_history_fail: "读取领取历史失败：{e}",
    t_restart_fail: "重启 ZCode 失败：{e}", t_open_client_fail: "打开 ZCode 失败", t_export_path: "已导出到：{p}", t_copied: "已复制"
  },
  en: {
    running: "ZCode running", not_running: "Not running", process_unknown: "Running state unknown",
    add: "Add account", capture: "Save current login", backup: "Backup / Import",
    auto_check: "Auto check", notify: "Notify", off: "Off", min5: "Every 5 min", min15: "Every 15 min", min30: "Every 30 min", min60: "Every 60 min",
    check_all: "Check all", checking_dots: "Checking…", checking_progress: "Checking {done}/{total}", refresh: "Refresh quota",
    last_check: "Last", never_checked: "Not checked yet",
    accounts: "Accounts", n_accounts: " accounts",
    week_plan: "Weekend bonus", base_plan: "Base plan", other_plan: "Other", switch_to: "⇄ Switch to this",
    client_not_found: "ZCode client not found. Install it, or set its path in Settings.",
    t_save_fail: "Save failed: {e}", err_generic: "Operation failed — please retry. Check the details in Chinese if needed.", err_process: "Cannot confirm or close the ZCode process", err_snapshot: "Failed to read the account snapshot", err_path: "Invalid client path", err_password: "Wrong password or corrupt backup", delete_body: "Delete \"{name}\"? Its snapshot, quota history and benefit records will be removed; you can undo from the toast.", kill_confirm: "Close ZCode? Running tasks will be interrupted.",
    t_closed: "ZCode closed", t_restored: "Restored \"{x}\"", import_fail: "Import failed: {e}",
    sort: "Sort", sort_current: "Current first", sort_claimable: "Claimable", sort_expiry: "Expiring soon", sort_manual: "Manual order", sort_manual_hint: "Use ↑↓ on cards to reorder", move_up: "Move up", move_down: "Move down",
    expand_all: "Expand all", fold_all: "Collapse all",
    no_profile_title: "No accounts yet", no_profile_body: "Install and sign in to ZCode, then choose \"Add account\". If you're already signed in, use \"Save current login\".",
    install_zcode: "Open ZCode website", recheck: "Re-check",
    unsaved_title: "Current login is not saved", unsaved_body: "This is the account currently signed in to ZCode. Save it to keep it in your library.", save_current: "Save this account",
    current: "Current", expired: "Session expired", unknown: "Unknown", not_signed_in: "(not signed in)", encrypted_account: "(encrypted account)", snapshot_error: "Cannot read snapshot: {e}",
    fold_show: "Expand account", fold_hide: "Collapse account", rename: "Rename", rename_title: "Rename account", rename_sub: "Only the display name changes; credentials are untouched.", rename_ph: "Display name",
    delete: "Delete account", check_one: "Check benefits for this account",
    no_quota: "No quota data", no_quota_hint: "No active plan in the client (expired, or newly claimed and not yet effective).", quota_fail: "Failed to fetch quota",
    updated_at: "Updated {t}", cached: "cached", retry: "Retry", relogin: "Sign in again",
    auth_expired: "This account's session expired. Please sign in again.", rate_limited: "Too many requests — retrying in about {n}s.", server_error: "Server temporarily unavailable — will retry.", network_error: "Network unavailable — check your connection and retry.",
    used_up: "Used up", remain: "left", total: "Total", used: "used", expires: "expires", unknown_total: "Total unknown",
    exp_soon: "expires in {h}h", exp_lt1h: "expires in <1h", burn: "~{d}d at this pace", burn_lt1: "under a day at this pace",
    spark_label: "trend", spark_hint: "Remaining quota across recent samples",
    search_ph: "Search accounts or tags…", filter_all: "All", filter_current: "Current", filter_benefits: "Has benefits", filter_expired: "Expired", no_match: "No matching accounts",
    pin: "Pin", unpin: "Unpin", tags: "Tags", tags_title: "Edit tags", tags_sub: "Comma-separated; up to 8 tags, 16 chars each.", tags_ph: "e.g. work, team", tags_saved: "Tags saved", tags_fail: "Failed to save tags: {e}",
    stale_tag: "old", stale_hint: "Saved with only {n} fields — missing fields the client added since. Switching merges them in automatically, or refresh now.", stale_refresh: "Refresh snapshot", stale_refreshed: "Snapshot refreshed: {n} fields", stale_refresh_fail: "Failed to refresh snapshot: {e}",
    stale_tag_ver: "old {v}", stale_hint_ver: "Saved by {v} with only {n} fields — missing fields the client added since. Switching merges them in automatically, or refresh now.",
    zcode_verified: "verified up to {v}", zcode_unverified: "unverified",
    quota_notify: "Quota alerts", quota_notify_hint: "Notify when expiring soon or below 10%", auto_backup: "Auto backup", auto_backup_hint: "Daily local backup, keep 7 copies", update_notify: "Update alerts", update_notify_hint: "Check every 24 hours",
    backup_now: "Back up now", backup_done: "Backup complete: {n} accounts", backup_fail: "Backup failed: {e}", diagnostics: "Export diagnostics", diag_done: "Diagnostics exported", diag_fail: "Export failed: {e}",
    backup_dir: "Backup folder", open_backup_dir: "Open backup folder", backup_info: "{n} backup(s)", backup_info_none: "No backups yet", backup_open_fail: "Failed to open the backup folder: {e}", backup_open_toast: "Opened the backup folder",
    restore_backup: "Restore backup", restore_confirm_title: "Restore backup", restore_confirm_body: "Replace the current account library with the selected local backup? A safety backup is created first.", restore_done: "Restored {n} accounts", restore_fail: "Restore failed: {e}", backup_last: "latest {t}",
    restore_pick_title: "Choose a backup to restore", restore_pick_sub: "Newest first; entries marked incomplete cannot be restored.", restore_pick_btn: "Restore this one", restore_bad: "Incomplete backup, nothing restored: {e}", restore_warn: "Restored, but {e}", restore_none: "No backups to restore", backup_verified: "Complete", backup_broken: "Incomplete", backup_accounts: "{n} accounts",
    import_preview_btn: "Preview", import_confirm: "Import", import_preview_hint: "{n} new · {d} duplicate · {r} need re-login", import_preview_fail: "Preview failed: {e}", import_none: "Nothing to import",
    preview_new: "New", preview_dup: "Duplicate", preview_relogin: "Re-login", preview_invalid: "Invalid", import_confirm_hint: "Import merges new accounts and skips duplicates.",
    history_export: "Export JSON", history_export_done: "Exported {n} records", history_export_fail: "Export failed: {e}", update_banner: "v{v} is available",
    plan_pending: "starts {t}", plan_active_syncing: "active · syncing quota", plan_daily: "/day",
    not_checked: "Not checked", ben_none: "Nothing to claim", ben_has: "{n} claimable", ben_fail: "Check failed: {e}", ben_transient: "Check temporarily unavailable — will retry", ben_hold: "Rate-limited; retry after {time}",
    claim: "Claim", claim_btn_prep: "Preparing", claim_btn_verify: "Verifying", claim_btn_claim: "Claiming",
    claim_wait: "Complete the captcha in the verification page — claiming continues automatically. Keep the page open; later claims will reuse it.", claim_ok: "Claimed: {p} (starts {t})", claim_fail: "Claim failed: {e}", claim_busy: "A claim is already in progress. Please wait.",
    claim_already: "Already claimed today", claim_not_eligible: "The campaign isn't open yet — it will be re-checked automatically", claim_rate_hold: "Rate-limited: no requests until {time}; it will recover automatically",
    claim_timeout: "Verification timed out. Please retry.", claim_bg: "Claim is still running in the background; the UI will refresh when it finishes.", claim_reopen: "Reopen verification page",
    claim_steps_prep: "Prepare", claim_steps_verify: "Browser check", claim_steps_claim: "Claim",
    switch_title: "Switch account", switch_body: "Switch from \"{from}\" to \"{to}\".\n{mode}", switch_hot: "Hot switch: the client keeps running and the identity is swapped in place.", switch_cold: "ZCode will close and restart.",
    switch_expired: "The target account's session has expired. You'll need to sign in again in ZCode.", switched_strict: "Switched in strict mode and restarted ZCode.",
    switched_hot: "Hot-switched. ZCode's bottom-left account name updates only after a restart.", switched_re: "Switched and restarted ZCode.", switched_nore: "Credentials switched — start ZCode manually.", switch_fail: "Switch failed: {e}",
    switching: "Switching…", open_client: "Open ZCode", restart_client: "Restart ZCode to sync name", hot_notice: "Hot-switched to \"{name}\". The bottom-left name comes from ZCode's cache and updates only after a restart.",
    add_title: "Add account", add_sub: "Pick a provider; finish the official login in your browser and it is saved automatically.",
    zai_name: "Z.AI account", zai_desc: "chat.z.ai · Start Plan / Coding Plan", bm_name: "BigModel account", bm_desc: "bigmodel.cn · Zhipu individual / team plans",
    opening: "Opening {p} official login…", oauth_pending: "Waiting for the browser to finish signing in…", oauth_already: "A sign-in is already in progress — continuing it.", oauth_ready: "Signed in: {l}", oauth_fail: "Sign-in failed: {e}",
    oauth_timeout: "Sign-in timed out. Please retry.", oauth_countdown: "{t} left", reopen: "Reopen login page", copy_link: "Copy link", copied: "Link copied", copy_fail: "Copy failed — open the login page manually",
    retry_signin: "Try again", cancel: "Cancel",
    cfg_title: "Settings / About", about: "About", about_line: " · unofficial multi-account manager", check_upd: "Check updates", repo: "GitHub repo",
    zcode_sec: "ZCode", client_path: "Client path", path_ph: "C:\\Program Files\\ZCode\\ZCode.exe", path_hint: "Empty = auto-detect; or use the folder icon to choose ZCode.exe", browse: "Choose file", save: "Save",
    datadir: "Data dirs", open_hub_data: "Hub data", open_zdata: "ZCode data",
    sys_sec: "System", autostart: "Launch at startup", autostart_hint: "Startup-folder shortcut", start_min: "Start minimized", start_min_hint: "Stay in the tray after launch",
    close_action: "When closing", close_tray: "Minimize to tray", close_quit: "Quit app",
    hot: "Hot switch (exp.)", hot_hint: "Switch without restarting; falls back on failure", hot_note: "Hot switch keeps the client running: plan and quota apply immediately, but the bottom-left account name comes from the client cache and only updates after restarting ZCode.",
    safe_mode: "Strict mode", safe_hint: "Refuse to switch when the live credentials are missing or malformed, instead of archiving them and continuing", lang: "Language",
    hot_blocked_by_strict: "Strict mode is on: switching always restarts the client, so hot switch has no effect", strict_overrides_hot: "Turning on strict mode disables hot switch (strict mode requires a client re-init)",
    kill: "Close ZCode", claim_history: "Claim history", claim_history_title: "Claim history", claim_history_sub: "Only plans and times claimed on this machine; no account identifiers.", no_claim_history: "No claims yet",
    bak_title: "Backup / Import accounts", bak_sub: "Bundles are password-encrypted (PBKDF2 + AES-256-GCM) and portable across machines; a lost password cannot be recovered.",
    export_to: "Export to Desktop", bak_ph: "Set a password (at least 6 chars)", export_btn: "Export .zhb", import_from: "Import from file",
    imp_path_ph: "Choose or paste the .zhb path", imp_pwd_ph: "Backup password", import_btn: "Import", drop_hint: "Drop a .zhb here, or use the folder icon to choose",
    open_folder: "Open containing folder", exported: "Backup complete: {n} accounts", export_fail: "Export failed: {e}",
    import_done: "Imported: {n} added", import_skipped: "{n} skipped (already exist or invalid)", import_relogin: "{n} accounts could not be decrypted; sign in again after switching", close: "Close",
    checking_upd: "Checking…", update_confirm_title: "Install update", update_confirm: "The app will restart; any running claim or switch will be interrupted. Continue?", upd_latest: "Up to date (v{v})", upd_found: "New version v{v} available", install_upd: "Update now", upd_go: "Download", upd_fail: "Check failed: {e}", install_fail: "Update failed: {e}", upd_installing: "Downloading and installing…", updating_pct: "Downloading {p}%", updating: "Downloading…",
    confirm_ok: "Confirm",
    notice_offline: "Network unavailable — account state cannot be refreshed.", notice_process: "Cannot confirm ZCode process state: {e}", notice_claim: "Claiming \"{p}\" — other accounts are locked.", dismiss: "Dismiss", details: "Details",
    settings: "Settings", theme: "Toggle theme", minimize: "Minimize", maximize: "Maximize", close_window: "Close window",
    t_saved: "Saved: {x}", t_quota_refreshed: "Quota refreshed ({n} accounts)", t_quota_refreshed_partial: "Quota refreshed: {n} ok, {f} failed", t_deleted: "Account deleted", t_undo: "Undo", t_settings_saved: "Settings saved", t_notify_on: "Notifications on", t_notify_off: "Notifications off",
    t_autostart_on: "Autostart enabled", t_autostart_off: "Autostart disabled", t_autostart_fail: "Failed: {e}", t_path_saved: "Client path saved (empty = auto-detect)",
    t_refresh_fail: "Refresh failed: {e}", t_check_done0: "Check done: {ok}/{all} accounts fine, nothing to claim", t_check_done: "Check done: {w}/{all} accounts have {n} claimable",
    t_check_partial: "Check done: {ok}/{all} fine, {f} temporarily unavailable", t_one_has: "{n} claimable for this account", t_one_none: "Nothing to claim for this account", t_one_transient: "Temporarily unavailable — will retry",
    t_one_fail: "Check failed", t_close_fail: "Cannot close ZCode: {e}", t_pwd_short: "Password must be at least 6 characters", t_fill_both: "Choose a file and enter the password first",
    t_rename_saved: "Renamed to \"{x}\"", t_rename_fail: "Rename failed: {e}", t_claim_history_fail: "Failed to read claim history: {e}",
    t_restart_fail: "Restart failed: {e}", t_open_client_fail: "Failed to open ZCode", t_export_path: "Exported to: {p}", t_copied: "Copied"
  }
};
/* Locale registry: 新增语言时调用 registerLocale(code, name, dict) 并补一份字典即可；
   t() 始终回退到 zh，缺失键不会显示成 key。语言选择器目前只暴露 zh/en。 */
var LOCALES = { zh: { name: "中文" }, en: { name: "English" } };
function registerLocale(code, name, dict) {
  LOCALES[code] = { name: name };
  if (dict) I18N[code] = dict;
}
var LANG = (function() { try { return localStorage.getItem("hub-lang") || ((navigator.language || "zh").indexOf("zh") === 0 ? "zh" : "en"); } catch(e) { return "zh"; } })();
function t(key, vars) {
  var s = (I18N[LANG] && I18N[LANG][key]) || I18N.zh[key] || key;
  if (vars) Object.keys(vars).forEach(function(k) { s = s.split("{" + k + "}").join(vars[k]); });
  return s;
}

/* ---------------- basics ---------------- */
function el(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/'/g,"&#39;").replace(/"/g,"&quot;"); }
function invoke(cmd, args) {
  if (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke) return window.__TAURI_INTERNALS__.invoke(cmd, args || {});
  return Promise.reject("Tauri not ready");
}
function api(cmd, args) {
  return invoke(cmd, args).then(function(r) {
    if (r && r.ok === false && r.error) r.error = localizeErr(r.error);
    return r;
  });
}
function localizeErr(msg) {
  var m = String(msg == null ? "" : msg);
  if (LANG === "zh" || !/[一-鿿]/.test(m)) return m;
  if (/无法关闭 ZCode|无法确认 ZCode/.test(m)) return t("err_process");
  if (/存档|快照/.test(m)) return t("err_snapshot");
  if (/路径不存在|不是文件/.test(m)) return t("err_path");
  if (/口令|密码/.test(m)) return t("err_password");
  if (/登录已过期|重新登录/.test(m)) return t("auth_expired");
  if (/网络|连接|超时|timeout/i.test(m)) return t("network_error");
  return t("err_generic");
}
function errText(e) { return localizeErr((e && (e.message || e.error)) || String(e || "?")); }
function fmtT2(v) {
  if (v == null || v === "") return "?";
  // 兼容三种来源：秒级时间戳、毫秒级时间戳、ISO 字符串（manifest/审计里的 created_at）
  var ms;
  if (typeof v === "string" && !/^\d+$/.test(v.trim())) {
    ms = Date.parse(v);
  } else {
    ms = Number(v) < 1e12 ? Number(v) * 1000 : Number(v);
  }
  if (!isFinite(ms)) return String(v);
  var d = new Date(ms), p = function(n) { return String(n).padStart(2, "0"); };
  return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}
function fmtClock(v) {
  if (v == null) return "?";
  var ms = Number(v) < 1e12 ? Number(v) * 1000 : Number(v);
  var d = new Date(ms), p = function(n) { return String(n).padStart(2, "0"); };
  return p(d.getHours()) + ":" + p(d.getMinutes());
}
function fmtInt(n) {
  n = Number(n) || 0;
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
function fmtParts(n) {
  n = Number(n) || 0;
  var a = Math.abs(n);
  if (LANG === "zh") {
    if (a >= 1e8) return { v: (n / 1e8).toFixed(a >= 1e9 ? 1 : 2).replace(/\.?0+$/, ""), u: "亿" };
    if (a >= 1e4) return { v: (n / 1e4).toFixed(a >= 1e6 ? 0 : 1).replace(/\.0$/, ""), u: "万" };
  } else {
    if (a >= 1e9) return { v: (n / 1e9).toFixed(2).replace(/\.?0+$/, ""), u: "B" };
    if (a >= 1e6) return { v: (n / 1e6).toFixed(1).replace(/\.0$/, ""), u: "M" };
    if (a >= 1e3) return { v: (n / 1e3).toFixed(1).replace(/\.0$/, ""), u: "K" };
  }
  return { v: fmtInt(n), u: "" };
}
function fmtQ(n) {
  var p = fmtParts(n);
  return '<span class="num">' + esc(p.v) + '</span>' + (p.u ? '<span class="unit">' + esc(p.u) + '</span>' : "");
}
function fmtQText(n) { var p = fmtParts(n); return p.v + p.u; }

/* ---------------- state ---------------- */
var S = {
  st: null, quota: {}, history: {}, quotaSeq: {}, folded: loadFold(), sort: loadSort(), order: loadOrder(),
  query: "", filter: "all", pins: loadPins(), tagKey: null, pendingImport: null,
  claim: null, busyKey: null, checking: false, checkProgress: {done:0,total:0},
  refreshing: false, queued: false, queuedForce: false, queuedKey: null, queuedDone: [],
  notice: null, noticeClosed: false, offline: false, lastRefresh: 0,
  renderedKeys: "", lastFocus: null, confirmResolve: null,
  renameKey: null, exportPath: null, oauthActive: false, oauthProvider: null, oauthState: null,
  theme: "system", claimTimer: null, checkTimer: null, lastErrToast: 0
};
function loadFold() { try { return JSON.parse(localStorage.getItem("hub-fold") || "{}"); } catch(e) { return {}; } }
function saveFold() { try { localStorage.setItem("hub-fold", JSON.stringify(S.folded)); } catch(e) {} }
function loadSort() { try { return localStorage.getItem("hub-sort") || "current"; } catch(e) { return "current"; } }
function loadOrder() { try { var a = JSON.parse(localStorage.getItem("hub-order") || "[]"); return Array.isArray(a) ? a : []; } catch(e) { return []; } }
function saveOrder() { try { localStorage.setItem("hub-order", JSON.stringify(S.order)); } catch(e) {} }
function loadPins() { try { var o = JSON.parse(localStorage.getItem("hub-pins") || "{}"); return o && typeof o === "object" ? o : {}; } catch(e) { return {}; } }
function savePins() { try { localStorage.setItem("hub-pins", JSON.stringify(S.pins)); } catch(e) {} }
function ensureOrder() {
  if (!S.st) return;
  var keys = (S.st.profiles || []).map(function(p) { return p.key; });
  var next = S.order.filter(function(k) { return keys.indexOf(k) >= 0; });
  keys.forEach(function(k) { if (next.indexOf(k) < 0) next.push(k); });
  if (next.join("|") !== S.order.join("|")) { S.order = next; saveOrder(); } else { S.order = next; }
}

/* ---------------- theme ---------------- */
function resolvedTheme(mode) {
  if (mode === "system") {
    try { return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; } catch(e) { return "light"; }
  }
  return mode;
}
function applyTheme(mode) {
  S.theme = mode || "system";
  var resolved = resolvedTheme(S.theme);
  document.body.setAttribute("data-theme", resolved);
  var use = document.querySelector("#themeBtn use");
  if (use) use.setAttribute("href", resolved === "light" ? "#i-moon" : "#i-sun");
  try { localStorage.setItem("hub-theme", S.theme); } catch(e) {}
}
function toggleTheme() {
  // 按“当前实际显示”切换：首击在浅色下立刻变深色（旧实现 system→light 会看起来没反应）
  applyTheme(resolvedTheme(S.theme) === "dark" ? "light" : "dark");
}

/* ---------------- toasts ---------------- */
function pushToast(msg, kind, action) {
  var box = el("toasts");
  if (!box) return;
  Array.prototype.slice.call(box.children).forEach(function(c) {
    if (c.getAttribute("data-msg") === msg || c.textContent === msg) c.remove();
  });
  var div = document.createElement("div");
  div.className = "toast " + (kind || "");
  div.setAttribute("data-msg", msg);
  div.setAttribute("role", kind === "bad" ? "alert" : "status");
  var span = document.createElement("span");
  span.className = "toast-msg";
  span.textContent = msg;
  div.appendChild(span);
  if (action && action.label && typeof action.onClick === "function") {
    var act = document.createElement("button");
    act.className = "linkbtn";
    act.textContent = action.label;
    act.addEventListener("click", function() { action.onClick(); div.remove(); });
    div.appendChild(act);
  }
  var close = document.createElement("button");
  close.className = "icon-btn tiny";
  close.setAttribute("aria-label", t("dismiss"));
  close.textContent = "×";
  close.addEventListener("click", function() { div.remove(); });
  div.appendChild(close);
  box.appendChild(div);
  while (box.children.length > 3) box.firstChild.remove();
  var ttl = kind === "bad" || action ? 10000 : 5200;
  var timer = setTimeout(function() { div.remove(); }, ttl);
  div.addEventListener("mouseenter", function() { clearTimeout(timer); });
}

/* ---------------- modal helpers ---------------- */
function isOpen(id) { var m = el(id); return !!m && !m.hidden; }
function openModal(id, focusSel) {
  S.lastFocus = document.activeElement;
  var m = el(id);
  if (!m) return;
  m.hidden = false;
  var f = focusSel ? m.querySelector(focusSel) : m.querySelector("button, input, select");
  if (f && f.focus) setTimeout(function() { try { f.focus(); } catch(e) {} }, 30);
}
function hideModal(id) {
  var m = el(id);
  if (m) m.hidden = true;
  if (S.lastFocus && S.lastFocus.focus) { try { S.lastFocus.focus(); } catch(e) {} }
  S.lastFocus = null;
}
function topModal() {
  var ids = ["confirmModal", "renameModal", "tagModal", "restoreModal", "historyModal", "bakModal", "cfgModal", "addModal"];
  for (var i = 0; i < ids.length; i++) if (isOpen(ids[i])) return el(ids[i]);
  return null;
}
function closeTopModal() {
  var m = topModal();
  if (!m) return;
  if (m.id === "confirmModal") resolveConfirm(false);
  else if (m.id === "addModal") closeAddModal(true);
  else if (m.id === "renameModal") hideModal("renameModal");
  else hideModal(m.id);
}
function askConfirm(title, body, okLabel) {
  if (isOpen("confirmModal")) return Promise.resolve(false);
  el("confirmTitle").textContent = title || "";
  el("confirmBody").textContent = body || "";
  var ok = el("confirmModal").querySelector('[data-action="confirm-ok"]');
  ok.textContent = okLabel || t("confirm_ok");
  openModal("confirmModal", '[data-action="confirm-cancel"]');
  return new Promise(function(resolve) { S.confirmResolve = resolve; });
}
function resolveConfirm(v) {
  var r = S.confirmResolve;
  S.confirmResolve = null;
  hideModal("confirmModal");
  if (r) r(!!v);
}

/* ---------------- formatting helpers ---------------- */
function displayLabel(label) {
  if (label === "(未登录)") return t("not_signed_in");
  if (label === "(已加密账号)") return t("encrypted_account");
  if (label === "(未知)") return t("unknown");
  return label;
}
function provMeta(p) {
  if (p === "bigmodel") return { cls: "bm", ch: "M" };
  if (p === "zai") return { cls: "zai", ch: "Z" };
  return { cls: "q", ch: "?" };
}
function planTag(plans, planId) {
  if (!Array.isArray(plans) || !planId) return "";
  var p = null;
  plans.forEach(function(x) { if (x.plan_id === planId) p = x; });
  var nm = ((p && p.name) || "") + " " + planId;
  if (/weekend|build|-wk\d/i.test(nm)) return t("week_plan");
  if (/start.?plan/i.test(nm)) return t("base_plan");
  return (p && p.name) || "";
}
function bucketAvail(b) { return Number(b.available_units !== undefined ? b.available_units : (b.remaining_units || 0)); }
function bucketRemainH(b) {
  var exp = Number(b.expires_at || b.period_end || 0);
  if (!exp) return null;
  if (exp < 1e12) exp *= 1000;
  return (exp - Date.now()) / 3600000;
}
function planEffectiveTs(p) {
  var effs = (Array.isArray(p.entitlements) ? p.entitlements : [])
    .map(function(e) { return Number(e.effective_at || 0); }).filter(function(x) { return x > 0; });
  return effs.length ? Math.min.apply(null, effs) : Number(p.starts_at || 0);
}
function benefitCount(key) {
  var b = S.st && S.st.benefits && S.st.benefits[key];
  return b && b.ok && b.count ? Number(b.count) : 0;
}
function quotaData(qd) {
  if (!qd || !qd.ok) return null;
  var d = qd.data;
  if (!d || !d.data) return null;
  return d.data;
}

/* ---------------- list ordering ---------------- */
function sortedProfiles() {
  var arr = ((S.st && S.st.profiles) || []).slice();
  function cur(a, b) { return (b.is_current ? 1 : 0) - (a.is_current ? 1 : 0) || String(a.label).localeCompare(String(b.label)); }
  if (S.sort === "claimable") {
    arr.sort(function(a, b) { return benefitCount(b.key) - benefitCount(a.key) || cur(a, b); });
  } else if (S.sort === "expiry") {
    arr.sort(function(a, b) {
      var qa = quotaData(S.quota[a.key]), qb = quotaData(S.quota[b.key]);
      var ha = qa ? minExpiryH(qa.balances || []) : null, hb = qb ? minExpiryH(qb.balances || []) : null;
      return (ha === null ? 1e9 : ha) - (hb === null ? 1e9 : hb) || cur(a, b);
    });
  } else if (S.sort === "manual") {
    ensureOrder();
    var idx = {};
    S.order.forEach(function(k, i) { idx[k] = i; });
    arr.sort(function(a, b) {
      var ia = idx[a.key], ib = idx[b.key];
      if (ia === undefined && ib === undefined) return String(a.label).localeCompare(String(b.label));
      if (ia === undefined) return 1;
      if (ib === undefined) return -1;
      return ia - ib;
    });
  } else {
    arr.sort(cur);
  }
  return arr;
}
function currentPseudo() {
  return { key: "__current__", label: (S.st && S.st.current_label) || "", is_current: true,
    provider: (S.st && S.st.current_provider) || "", pseudo: true, jwt_expired: false };
}
function displayProfiles() {
  var arr = sortedProfiles();
  if (S.st && S.st.current_logged_in && !arr.some(function(p) { return p.is_current; })) arr.unshift(currentPseudo());
  var q = String(S.query || "").trim().toLowerCase();
  arr = arr.filter(function(p) {
    if (S.filter === "current" && !p.is_current) return false;
    if (S.filter === "benefits" && benefitCount(p.key) <= 0) return false;
    if (S.filter === "expired" && !p.jwt_expired) return false;
    if (q) {
      var hay = [p.label || "", p.provider || "", (p.tags || []).join(" ")].join(" ").toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  });
  // 稳定排序：置顶账号保持当前排序模式内的相对顺序
  arr.sort(function(a, b) { return (S.pins[a.key] ? 0 : 1) - (S.pins[b.key] ? 0 : 1); });
  return arr;
}
function profileByKey(key) {
  if (!S.st) return null;
  for (var i = 0; i < S.st.profiles.length; i++) if (S.st.profiles[i].key === key) return S.st.profiles[i];
  if (key === "__current__" && S.st.current_logged_in) return currentPseudo();
  return null;
}
function soonestExpireH(balances) {
  var m = null;
  (balances || []).forEach(function(b) {
    if (bucketAvail(b) <= 0) return;
    var h = bucketRemainH(b);
    if (h !== null && h <= 24 && (m === null || h < m)) m = h;
  });
  return m;
}
function minExpiryH(balances) {
  var m = null;
  (balances || []).forEach(function(b) {
    if (bucketAvail(b) <= 0) return;
    var h = bucketRemainH(b);
    if (h !== null && h > 0 && (m === null || h < m)) m = h;
  });
  return m;
}

/* ---------------- card rendering ---------------- */
function isFolded(p) {
  if (S.folded[p.key] !== undefined) return !!S.folded[p.key];
  return !p.is_current;
}
function setFold(key, v) {
  S.folded[key] = !!v;
  saveFold();
  var node = document.querySelector('.acct[data-key="' + key + '"]');
  if (node) {
    node.classList.toggle("folded", !!v);
    var chev = node.querySelector(".chev");
    if (chev) chev.setAttribute("aria-expanded", v ? "false" : "true");
    var body = node.querySelector(".acct-body");
    if (body) body.hidden = !!v;
    // 同步签名：否则“折叠 → 全部展开”时新旧签名可能恰好相同，patch 会被跳过
    var p = profileByKey(key);
    if (p) node.setAttribute("data-sig", cardSig(p));
  }
}
function moveProfile(key, delta) {
  var list = sortedProfiles().map(function(p) { return p.key; });
  var i = list.indexOf(key), j = i + delta;
  if (i < 0 || j < 0 || j >= list.length) return;
  var tmp = list[i]; list[i] = list[j]; list[j] = tmp;
  S.order = list; saveOrder(); renderList();
}
function doRefreshQuota() {
  var n = displayProfiles().length;
  refreshAll(true, null, function() {
    var failed = displayProfiles().filter(function(p) {
      var q = S.quota[p.key]; return q && q.ok === false;
    }).length;
    if (failed) pushToast(t("t_quota_refreshed_partial", {n: Math.max(0, n - failed), f: failed}), "warn");
    else pushToast(t("t_quota_refreshed", {n: n}), "ok");
  });
}
function foldAll(v) {
  displayProfiles().forEach(function(p) { S.folded[p.key] = !!v; });
  saveFold();
  renderList();
}

function cardSig(p) {
  return [LANG, S.sort, S.sort === "manual" ? S.order.indexOf(p.key) : "", p.key, p.label, p.is_current, p.jwt_expired, p.error || "",
    JSON.stringify(p.tags || []), S.pins[p.key] ? 1 : 0,
    p.stale ? 1 : 0, p.client_version || "", p.field_count || 0,
    JSON.stringify(S.quota[p.key] || null),
    JSON.stringify((S.st.benefits || {})[p.key] || null),
    JSON.stringify((S.history[p.key] || {}).forecast || null),
    isFolded(p) ? 1 : 0,
    S.claim ? JSON.stringify({s:S.claim.status, p:S.claim.planId}) : "",
    S.busyKey === p.key ? 1 : 0].join("|");
}

function manualMoveButtons(p) {
  var list = sortedProfiles();
  var idx = -1;
  for (var i = 0; i < list.length; i++) if (list[i].key === p.key) { idx = i; break; }
  var up = idx > 0, down = idx >= 0 && idx < list.length - 1;
  return '<button class="icon-btn small" data-action="move-up" data-key="' + esc(p.key) + '"' + (up ? "" : " disabled")
    + ' aria-label="' + esc(t("move_up")) + '" title="' + esc(t("move_up")) + '"><svg class="icon"><use href="#i-up"/></svg></button>'
    + '<button class="icon-btn small" data-action="move-down" data-key="' + esc(p.key) + '"' + (down ? "" : " disabled")
    + ' aria-label="' + esc(t("move_down")) + '" title="' + esc(t("move_down")) + '"><svg class="icon"><use href="#i-down"/></svg></button>';
}
/* 存档落后提示：只有当前账号能刷新（其他账号没有 live 状态可抓）。
   版本未知时（v1.11.0 前的旧存档）用不带版本的文案，不要把 "?" 露给用户。 */
function staleTagText(p) {
  return p.client_version ? t("stale_tag_ver", {v: p.client_version}) : t("stale_tag");
}
function staleHintText(p) {
  var n = p.field_count || 0;
  return p.client_version
    ? t("stale_hint_ver", {v: p.client_version, n: n})
    : t("stale_hint", {n: n});
}
function staleNoticeHtml(p) {
  if (!p.stale) return "";
  var hint = staleHintText(p);
  if (!p.is_current) {
    return '<div class="stale-note"><span class="mut">' + esc(hint) + '</span></div>';
  }
  return '<div class="stale-note"><span class="mut">' + esc(hint) + '</span>'
    + '<button class="linkbtn" data-action="refresh-profile" data-key="' + esc(p.key) + '">'
    + esc(t("stale_refresh")) + '</button></div>';
}

function refreshProfile(key) {
  api("refresh_profile", { key: key }).then(function(r) {
    if (!r || r.ok === false) {
      pushToast(t("stale_refresh_fail", {e: (r && r.error) || "?"}), "bad");
      return;
    }
    pushToast(t("stale_refreshed", {n: r.fields || 0}), "ok");
    refreshAll(false, null, null);
  }).catch(function(e) { pushToast(t("stale_refresh_fail", {e: errText(e)}), "bad"); });
}

function cardHtml(p) {
  var m = provMeta(p.provider);
  var folded = isFolded(p);
  var bd = (S.st.benefits || {})[p.key];
  var qd = S.quota[p.key];
  var benCount = bd && bd.ok ? (bd.count || 0) : 0;
  var tags = (p.is_current ? '<span class="tag cur">' + esc(t("current")) + '</span>' : "")
    + (p.jwt_expired ? '<span class="tag expired">' + esc(t("expired")) + '</span>' : "")
    + (p.stale ? '<span class="tag warn" title="' + esc(staleHintText(p)) + '">' + esc(staleTagText(p)) + '</span>' : "")
    + (p.tags || []).map(function(tg) { return '<span class="tag tag-user">' + esc(tg) + '</span>'; }).join("");
  var body;
  if (p.error) {
    body = '<div class="inline-error">' + esc(t("snapshot_error", {e: localizeErr(p.error)})) + '</div>';
  } else {
    var benefit = benefitHtml(bd, p), quiet = "";
    if (benefit.indexOf('bstate quiet') !== -1) { quiet = benefit; benefit = ""; }
    body = benefit + bucketsHtml(qd, p) + staleNoticeHtml(p) + footerHtml(p, qd, quiet);
  }
  return '<div class="acct' + (p.is_current ? " cur" : "") + (folded ? " folded" : "") + '" data-key="' + esc(p.key) + '" data-provider="' + esc(p.provider) + '" data-sig="' + esc(cardSig(p)) + '">'
    + '<div class="acct-head" data-action="foldhead" data-key="' + esc(p.key) + '">'
    + '<button class="chev" data-action="foldchev" data-key="' + esc(p.key) + '" aria-expanded="' + (folded ? "false" : "true") + '" aria-controls="body-' + esc(p.key) + '" aria-label="' + esc(folded ? t("fold_show") : t("fold_hide")) + '"><svg class="icon"><use href="#i-chev"/></svg></button>'
    + '<span class="pchip ' + m.cls + '">' + m.ch + '</span>'
    + '<span class="acct-ident"><span class="acct-name" title="' + esc(displayLabel(p.label)) + '">' + esc(displayLabel(p.label)) + '</span>' + tags
    + (folded && benCount > 0 ? '<span class="tag warn">' + esc(t("ben_has", {n: benCount})) + '</span>' : '')
    + '</span>'
    + '<span class="acct-actions">'
    + (S.sort === "manual" && !p.pseudo ? manualMoveButtons(p) : "")
    + (p.pseudo ? "" : '<button class="icon-btn' + (S.pins[p.key] ? " on" : "") + '" data-action="pin" data-key="' + esc(p.key) + '" aria-label="' + esc(S.pins[p.key] ? t("unpin") : t("pin")) + '" title="' + esc(S.pins[p.key] ? t("unpin") : t("pin")) + '"><svg class="icon"><use href="#i-pin"/></svg></button>')
    + (p.pseudo ? "" : '<button class="icon-btn" data-action="tags" data-key="' + esc(p.key) + '" aria-label="' + esc(t("tags")) + '" title="' + esc(t("tags")) + '"><svg class="icon"><use href="#i-tag"/></svg></button>')
    + (p.pseudo ? "" : '<button class="icon-btn" data-action="rename" data-key="' + esc(p.key) + '" aria-label="' + esc(t("rename")) + '" title="' + esc(t("rename")) + '"><svg class="icon"><use href="#i-pencil"/></svg></button>')
    + (p.pseudo ? "" : '<button class="icon-btn danger" data-action="del" data-key="' + esc(p.key) + '" aria-label="' + esc(t("delete")) + '" title="' + esc(t("delete")) + '"><svg class="icon"><use href="#i-trash"/></svg></button>')
    + '</span></div>'
    + '<div class="acct-body" id="body-' + esc(p.key) + '"' + (folded ? " hidden" : "") + '>' + body + '</div></div>';
}

function sparkHtml(points) {
  if (!points || points.length < 2) return "";
  var pts = points.slice(-24);
  var vals = pts.map(function(p) { return Number(p[1]) || 0; });
  var min = Math.min.apply(null, vals), max = Math.max.apply(null, vals);
  var span = max - min || 1;
  var step = 56 / (pts.length - 1);
  var d = pts.map(function(p, i) {
    var y = 14 - ((Number(p[1]) - min) / span) * 12;
    return (i * step).toFixed(1) + "," + y.toFixed(1);
  }).join(" ");
  return '<span class="spark-wrap" title="' + esc(t("spark_hint")) + '">'
    + '<svg class="spark" viewBox="0 0 56 16" aria-hidden="true"><polyline points="' + d + '"/></svg>'
    + '<span>' + esc(t("spark_label")) + '</span></span>';
}
function bucketRow(b, burnMap, sparkMap) {
  var name = b.show_name || b.model || "?";
  var avail = bucketAvail(b);
  var total = Number(b.total_units || 0);
  var used = Number(b.used_units || 0);
  var exp = b.expires_at || b.period_end;
  var pct = total > 0 ? Math.max(0, Math.min(100, Math.round(avail / total * 100))) : null;
  var done = avail <= 0;
  var remainH = done ? null : bucketRemainH(b);
  var state = done ? "empty" : (remainH !== null && remainH <= 6 ? "danger" : (pct !== null && pct < 10 ? "danger" : (pct !== null && pct < 40 ? "warn" : "ok")));
  var bar = total > 0
    ? '<div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + (done ? 0 : pct) + '" aria-label="' + esc(name) + '"><i class="' + state + '" style="width:' + (done ? 0 : Math.max(2, Math.min(100, pct))) + '%"></i></div>'
    : '';
  var availHtml = done
    ? '<span class="brow-avail empty">' + esc(t("used_up")) + '</span>'
    : '<span class="brow-avail">' + fmtQ(avail) + '<span class="unit"> ' + esc(t("remain")) + '</span></span>';
  var pctHtml = done ? "" : (pct === null ? '<span class="pct-badge">' + esc(t("unknown_total")) + '</span>'
    : '<span class="pct-badge ' + state + '">' + pct + '%</span>');
  var spark = done ? "" : sparkHtml(sparkMap && sparkMap[(b.plan_id || "") + "|" + name]);
  var burn = "";
  if (!done && burnMap) {
    var f = burnMap[b.plan_id + "|" + name];
    if (f !== undefined) {
      var dl = Number(f);
      burn = dl < 1
        ? '<span class="chip danger">' + esc(t("burn_lt1")) + '</span>'
        : '<span class="chip warn">' + esc(t("burn", {d: Math.round(dl)})) + '</span>';
    }
  }
  var expiry = "";
  if (exp) {
    if (remainH !== null && remainH <= 24) {
      expiry = '<span class="chip ' + (remainH <= 1 ? "danger" : "warn") + '" title="' + esc(fmtT2(exp)) + '">'
        + '<svg class="icon tiny"><use href="#i-clock"/></svg>'
        + esc(remainH < 1 ? t("exp_lt1h") : t("exp_soon", {h: Math.ceil(remainH)})) + '</span>';
    } else {
      expiry = '<span class="chip neutral"><svg class="icon tiny"><use href="#i-clock"/></svg>' + esc(fmtT2(exp)) + ' ' + esc(t("expires")) + '</span>';
    }
  }
  var meta = esc(t("total")) + " " + fmtQText(total) + (used ? " · " + esc(t("used")) + " " + fmtQText(used) : "");
  return '<div class="brow" data-state="' + state + '">'
    + '<div class="brow-top"><span class="brow-model" title="' + esc(name) + '">' + esc(name) + '</span>' + availHtml + pctHtml + '</div>'
    + bar
    + '<div class="brow-sub"><span class="brow-meta num">' + meta + '</span><span class="brow-chips">' + spark + burn + expiry + '</span></div>'
    + '</div>';
}

function renderPendingPlans(plans, excludeIds, onlyPending) {
  var now = Date.now();
  var rows = (Array.isArray(plans) ? plans : []).filter(function(p) {
    if (!p || (p.status && p.status !== "active")) return false;
    if (excludeIds && p.plan_id && excludeIds[p.plan_id]) return false;
    if (onlyPending) {
      var eff = planEffectiveTs(p);
      if (!(eff > 0 && eff * 1000 > now)) return false;
    }
    return true;
  });
  if (!rows.length) return "";
  return rows.map(function(p) {
    var eff = planEffectiveTs(p);
    var pending = eff > 0 && eff * 1000 > now;
    var badge = pending ? t("plan_pending", {t: fmtT2(eff)}) : t("plan_active_syncing");
    var ents = (Array.isArray(p.entitlements) ? p.entitlements : []).map(function(e) {
      var nm = e.show_name || e.entitlement_id || "?";
      var amt = Number(e.grant_units || 0);
      var daily = e.period === "daily" ? t("plan_daily") : "";
      var unit = e.unit_type === "token" ? " Token" : "";
      return '<div class="plan-ent"><span class="plan-ent-name">' + esc(nm) + '</span><span class="plan-ent-amt">' + fmtQ(amt) + esc(unit + daily) + '</span></div>';
    }).join("");
    return '<div class="plan"><div class="plan-head"><svg class="icon"><use href="#i-gift"/></svg><span class="plan-name">' + esc(p.name || p.plan_id || "Plan") + '</span>'
      + '<span class="chip ' + (pending ? "warn" : "info") + '">' + esc(badge) + '</span></div>'
      + '<div class="plan-ents">' + ents + '</div></div>';
  }).join("");
}

function bucketsHtml(qd, p) {
  if (!qd) return '<div class="skeleton"><span></span><span></span><span></span></div>';
  if (qd.ok === false) return quotaErrorHtml(qd, p);
  var d = quotaData(qd);
  if (!d) return quotaErrorHtml({ code: "parse", error: t("quota_fail") }, p);
  var balances = Array.isArray(d.balances) ? d.balances : [];
  var plans = Array.isArray(d.plans) ? d.plans : [];
  var burnMap = null;
  var sparkMap = null;
  var h = S.history[p.key];
  if (h && h.ok && Array.isArray(h.forecast)) {
    burnMap = {};
    h.forecast.forEach(function(f) { burnMap[f.plan_id + "|" + f.model] = f.days_left; });
  }
  if (h && h.ok && Array.isArray(h.points)) {
    sparkMap = {};
    h.points.forEach(function(sample) {
      (sample.balances || []).forEach(function(x) {
        var mn = x.model || "?";
        var sk = (x.plan_id || "") + "|" + mn;
        (sparkMap[sk] = sparkMap[sk] || []).push([sample.ts, x.available]);
      });
    });
  }
  if (!balances.length) {
    var pend = renderPendingPlans(plans, null, false);
    return pend || ('<div class="quota-empty">' + esc(t("no_quota")) + '<span>' + esc(t("no_quota_hint")) + '</span></div>');
  }
  var groups = {}, order = [];
  balances.forEach(function(b) {
    var key = planTag(plans, b.plan_id) || t("other_plan");
    if (!groups[key]) { groups[key] = []; order.push(key); }
    groups[key].push(b);
  });
  var wk = order.indexOf(t("week_plan"));
  if (wk > 0) { order.splice(wk, 1); order.unshift(t("week_plan")); }
  var html = order.map(function(key) {
    var rows = groups[key].map(function(b) { return bucketRow(b, burnMap, sparkMap); }).join("");
    return '<div class="pgroup"><div class="plabel">' + esc(key) + '</div>' + rows + '</div>';
  }).join("");
  var exclude = {};
  balances.forEach(function(b) { if (b.plan_id) exclude[b.plan_id] = 1; });
  return html + renderPendingPlans(plans, exclude, true);
}

function quotaErrorHtml(q, p) {
  var code = q.code || "";
  var msg = localizeErr(q.error || t("quota_fail"));
  var action = "";
  if (code === "auth") {
    msg = t("auth_expired");
    action = '<button class="linkbtn" data-action="relogin" data-provider="' + esc(p.provider || "") + '">' + esc(t("relogin")) + '</button>';
  } else if (code === "rate") {
    msg = t("rate_limited", {n: q.retry_after || 60});
  } else if (code === "server") {
    msg = t("server_error");
  } else if (code === "network") {
    msg = t("network_error");
  }
  return '<div class="inline-error">' + esc(msg)
    + '<button class="linkbtn" data-action="retry-quota" data-key="' + esc(p.key) + '">' + esc(t("retry")) + '</button>' + action + '</div>';
}

function claimActive() { return !!(S.claim && ["preparing", "waiting_captcha", "claiming"].indexOf(S.claim.status) >= 0); }
function claimStatusText(status) {
  if (status === "waiting_captcha") return t("claim_btn_verify");
  if (status === "claiming") return t("claim_btn_claim");
  return t("claim_btn_prep");
}
function claimStepsHtml(planId) {
  if (!claimActive() || !S.claim || S.claim.planId !== planId) return "";
  var idx = S.claim.status === "waiting_captcha" ? 1 : (S.claim.status === "claiming" ? 2 : 0);
  var labels = [t("claim_steps_prep"), t("claim_steps_verify"), t("claim_steps_claim")];
  var steps = labels.map(function(l, i) {
    return '<span class="claim-step' + (i <= idx ? " on" : "") + '"><i></i>' + esc(l) + '</span>';
  }).join("");
  var reopen = (S.claim.status === "waiting_captcha" && S.claim.captchaUrl)
    ? '<button class="linkbtn" data-action="claim-reopen">' + esc(t("claim_reopen")) + '</button>' : "";
  return '<div class="claim-steps" role="status">' + steps + reopen + '</div>';
}

function benefitHtml(bd, p) {
  if (!bd) return '<span class="bstate quiet">' + esc(t("not_checked")) + '</span>';
  var when = bd.checked_at ? ' <span class="whn num">· ' + fmtClock(bd.checked_at) + '</span>' : "";
  if (bd.ok === false) {
    // 账号被限流 hold：等待期内零请求，展示恢复时刻
    if (bd.held) return '<span class="bstate quiet">' + esc(t("ben_hold", {time: fmtClock(bd.until)})) + '</span>';
    if (bd.transient) return '<span class="bstate quiet">' + esc(t("ben_transient")) + when + '</span>';
    return '<div class="inline-error">' + esc(t("ben_fail", {e: localizeErr(bd.error || "?")}))
      + '<button class="linkbtn" data-action="checkone" data-key="' + esc(p.key) + '">' + esc(t("retry")) + '</button></div>';
  }
  if (!bd.count) return '<span class="bstate quiet">' + esc(t("ben_none")) + when + '</span>';
  var locked = claimActive() || !!S.busyKey;
  var rows = (bd.campaigns || []).map(function(c) {
    var planId = c.plan_id || "";
    var active = S.claim && S.claim.planId === planId && claimActive();
    var label = active ? claimStatusText(S.claim.status) : t("claim");
    var detail = c.detail ? ' · ' + esc(c.detail) : "";
    return '<div class="camp-wrap">'
      + '<div class="camp"><div class="camp-info"><b title="' + esc(c.title) + '">' + esc(c.title) + '</b>'
      + '<span>' + esc(c.grant) + ' Token' + detail + '</span></div>'
      + '<button class="camp-btn" data-action="claim" data-key="' + esc(p.key) + '" data-plan="' + esc(planId) + '" data-plan-name="' + esc(c.title) + '"'
      + (locked ? " disabled" : "") + '>' + esc(label) + '</button></div>'
      + claimStepsHtml(planId) + '</div>';
  }).join("");
  return '<div class="benefit-alert"><div class="benefit-head"><svg class="icon"><use href="#i-gift"/></svg>'
    + '<b>' + esc(t("ben_has", {n: bd.count})) + '</b><span class="whn num">' + (bd.checked_at ? fmtClock(bd.checked_at) : "") + '</span></div>'
    + rows + '</div>';
}

function footerHtml(p, qd, quiet) {
  var updated = "";
  if (qd && qd.fetched_at) updated = esc(t("updated_at", {t: fmtClock(qd.fetched_at)}));
  else if (qd && qd.ok === false) updated = "";
  var left = (quiet || '') + (updated ? '<span class="mut">' + updated + '</span>' : '');
  var check = '<button class="mini-check" data-action="checkone" data-key="' + esc(p.key) + '" aria-label="' + esc(t("check_one")) + '" title="' + esc(t("check_one")) + '"><svg class="icon"><use href="#i-search"/></svg></button>';
  var right;
  if (p.pseudo) {
    right = '<button class="switch-btn" data-action="capture">' + esc(t("save_current")) + '</button>';
  } else if (p.is_current) {
    right = '<span class="curmark"><svg class="icon tiny"><use href="#i-check"/></svg>' + esc(t("current")) + '</span>';
  } else if (S.busyKey === p.key) {
    right = '<button class="switch-btn" aria-busy="true" disabled><span class="spin-mini"></span>' + esc(t("switching")) + '</button>';
  } else {
    right = '<button class="switch-btn" data-action="switch" data-key="' + esc(p.key) + '"' + ((S.busyKey || claimActive()) ? " disabled" : "") + '>' + esc(t("switch_to")) + '</button>';
  }
  return '<div class="bfoot">' + left + check + right + '</div>';
}

function onboardingHtml() {
  return '<div class="empty onboarding"><div class="empty-icon"><svg class="icon"><use href="#i-gift"/></svg></div>'
    + '<h3>' + esc(t("no_profile_title")) + '</h3><p>' + esc(t("no_profile_body")) + '</p>'
    + '<div class="empty-actions">'
    + '<button class="btn primary" data-action="add"><svg class="icon"><use href="#i-plus"/></svg><span>' + esc(t("add")) + '</span></button>'
    + '<button class="btn" data-action="capture"><svg class="icon"><use href="#i-save"/></svg><span>' + esc(t("capture")) + '</span></button>'
    + '<button class="btn ghost" data-action="open-site"><svg class="icon"><use href="#i-external"/></svg><span>' + esc(t("install_zcode")) + '</span></button>'
    + '</div></div>';
}

/* ---------------- render ---------------- */
function renderHeader() {
  if (!S.st) return;
  var st = S.st;
  el("runDot").className = "dot" + (st.zcode_running ? " on" : "");
  el("runText").textContent = st.process_error ? t("process_unknown") : (st.zcode_running ? t("running") : t("not_running"));
  el("profCount").textContent = st.profiles.length + t("n_accounts");
  el("countTxt").textContent = st.profiles.length + t("n_accounts");
  var sel = el("autoCheckSel");
  var mins = st.settings && st.settings.auto_check_minutes !== undefined ? st.settings.auto_check_minutes : 15;
  if (document.activeElement !== sel && String(sel.value) !== String(mins)) sel.value = String(mins);
  el("notifyTgl").checked = !(st.settings && st.settings.notify_enabled === false);
  el("lastCheckTxt").textContent = st.last_check ? t("last_check") + " " + fmtT2(st.last_check) : t("never_checked");
  if (document.activeElement !== el("sortSel")) el("sortSel").value = S.sort;
  if (S.sort === "manual") ensureOrder();
  var sh = el("sortHint");
  if (sh) { sh.hidden = S.sort !== "manual"; sh.textContent = t("sort_manual_hint"); }
  syncForm(false);
  renderCheckButton();
}

function renderCheckButton() {
  var btn = el("chkBtn");
  if (!btn) return;
  var span = btn.querySelector("span");
  var label = S.checking ? t("checking_progress", {done: S.checkProgress.done, total: S.checkProgress.total}) : t("check_all");
  if (span) span.textContent = label; else btn.textContent = label;
  btn.disabled = S.checking;
  el("refreshBtn").classList.toggle("spin", S.refreshing);
}

function renderCompat() {
  var bar = el("compatBar"), txt = el("compatText"), notes = el("compatNotes");
  var c = S.st && S.st.compat;
  var errs = (c && Array.isArray(c.errors)) ? c.errors : [];
  var nds = (c && Array.isArray(c.notes)) ? c.notes : [];
  if (errs.length) {
    txt.textContent = errs[0];
    notes.textContent = errs.concat(nds).join("\n");
    bar.hidden = false;
  } else if (c && c.installed === false) {
    txt.textContent = t("client_not_found");
    notes.textContent = nds.join("\n");
    bar.hidden = false;
  } else {
    bar.hidden = true;
  }
}

function renderNotice() {
  var bar = el("noticeBar"), txt = el("noticeText"), act = el("noticeAction");
  var text = "", action = null;
  if (claimActive()) {
    text = t("notice_claim", {p: (S.claim.planName || "?")});
    if (S.claim.captchaUrl) action = { label: t("claim_reopen"), act: "open-claim-captcha" };
  } else if (S.notice) {
    text = S.notice.text;
    action = { label: S.notice.label, act: S.notice.act };
  } else if (S.offline) {
    text = t("notice_offline");
    action = { label: t("retry"), act: "retry" };
  } else if (S.st && S.st.process_error) {
    text = t("notice_process", {e: S.st.process_error});
    action = { label: t("retry"), act: "retry" };
  }
  if (!text || S.noticeClosed) { bar.hidden = true; return; }
  bar.hidden = false;
  txt.textContent = text;
  if (action) { act.hidden = false; act.textContent = action.label; act.setAttribute("data-act", action.act); }
  else { act.hidden = true; }
}

function renderList() {
  var list = displayProfiles();
  var box = el("acctList");
  if (!list.length) {
    box.innerHTML = (S.st && S.st.profiles && S.st.profiles.length)
      ? '<div class="empty small">' + esc(t("no_match")) + '</div>'
      : onboardingHtml();
    S.renderedKeys = "";
    return;
  }
  var keys = list.map(function(p) { return p.key; }).join("|");
  if (keys !== S.renderedKeys) {
    box.innerHTML = list.map(cardHtml).join("");
    S.renderedKeys = keys;
  } else {
    list.forEach(function(p) { patchCard(p.key); });
  }
}
function patchCard(key) {
  var p = profileByKey(key);
  var box = el("acctList");
  if (!p || !box) return;
  var node = box.querySelector('.acct[data-key="' + key.replace(/["\\]/g, "") + '"]');
  if (!node) return;
  if (node.getAttribute("data-sig") !== cardSig(p)) node.outerHTML = cardHtml(p);
}

function renderAll() {
  if (!S.st) return;
  renderHeader();
  renderCompat();
  renderNotice();
  renderList();
}

/* ---------------- refresh ---------------- */
function refreshAll(force, forceKey, done) {
  if (S.refreshing) {
    S.queued = true;
    S.queuedForce = S.queuedForce || !!force;
    if (forceKey) S.queuedKey = forceKey;
    if (done) S.queuedDone.push(done);
    return;
  }
  S.refreshing = true;
  renderCheckButton();
  api("get_state").then(function(st) {
    S.st = st;
    S.offline = false;
    S.noticeClosed = false;
    // 首屏先吃上次的额度快照，网络请求之后再逐卡替换
    var cache = st.quota_cache || {};
    Object.keys(cache).forEach(function(k) {
      var prev = S.quota[k];
      var prevTs = prev && prev.fetched_at ? Number(prev.fetched_at) : 0;
      var cacheTs = cache[k] && cache[k].fetched_at ? Number(cache[k].fetched_at) : 0;
      if (!prev || cacheTs > prevTs) S.quota[k] = cache[k];
    });
    renderAll();
    return loadAllQuotas(displayProfiles(), !!force, forceKey).then(function() {
      S.lastRefresh = Date.now();
      renderAll();
    });
  }).catch(function(e) {
    S.offline = true;
    renderNotice();
    var now = Date.now();
    if (now - S.lastErrToast > 60000) {
      S.lastErrToast = now;
      pushToast(t("t_refresh_fail", {e: errText(e)}), "bad");
    }
  }).finally(function() {
    S.refreshing = false;
    renderCheckButton();
    var callbacks = S.queuedDone; S.queuedDone = [];
    if (S.queued) {
      var f = S.queuedForce, k = S.queuedKey;
      S.queued = false; S.queuedForce = false; S.queuedKey = null;
      refreshAll(f, k, function() {
        if (done) done();
        callbacks.forEach(function(cb) { cb(); });
      });
    } else {
      if (done) done();
      callbacks.forEach(function(cb) { cb(); });
    }
  });
}

function loadAllQuotas(list, force, forceKey) {
  var i = 0;
  function worker() {
    if (i >= list.length) return Promise.resolve();
    var p = list[i++];
    if (p.error) return Promise.resolve().then(worker);
    return loadQuota(p, force || p.key === forceKey).then(worker, worker);
  }
  var ws = [];
  var n = Math.min(2, Math.max(1, list.length));
  for (var k = 0; k < n; k++) ws.push(worker());
  return Promise.all(ws);
}

function loadQuota(p, force) {
  var seq = (S.quotaSeq[p.key] || 0) + 1;
  S.quotaSeq[p.key] = seq;
  return api("fetch_quota", { key: p.key, force: !!force }).then(function(q) {
    if (S.quotaSeq[p.key] !== seq) return; // 旧请求晚到，丢弃
    S.quota[p.key] = q;
    patchCard(p.key);
    return api("quota_history", { key: p.key }).then(function(h) {
      if (S.quotaSeq[p.key] !== seq) return;
      S.history[p.key] = h;
      patchCard(p.key);
    }).catch(function() {});
  }).catch(function(e) {
    if (S.quotaSeq[p.key] !== seq) return;
    S.quota[p.key] = { ok: false, code: "network", transient: true, error: errText(e), fetched_at: Date.now() / 1000 };
    patchCard(p.key);
  });
}

/* ---------------- claim ---------------- */
function doClaim(key, planId, planName) {
  if (claimActive()) { pushToast(t("claim_busy"), "warn"); return; }
  if (!planId) { openClient(); return; }
  S.claim = { status: "preparing", planId: planId, planName: planName || "", key: key };
  renderAll();
  api("claim_plan", { key: key, planId: planId, planName: planName || "" }).then(function(r) {
    if (!r || r.ok === false) {
      S.claim = null; renderAll();
      var rmsg = (r && r.code === "rate_limited_hold" && r.until)
        ? t("claim_rate_hold", {time: fmtClock(r.until)})
        : ((r && r.error) || t("claim_fail", {e: "?"}));
      pushToast(rmsg, "bad");
      return;
    }
    pollClaimState();
  }).catch(function(e) {
    S.claim = null; renderAll();
    pushToast(t("claim_fail", {e: errText(e)}), "bad");
  });
}

function pollClaimState() {
  if (S.claimTimer) clearInterval(S.claimTimer);
  var started = Date.now();
  var messageShown = false;
  var waitToasted = false;
  var finished = false;
  function finish(success, msg, type) {
    if (finished) return;
    finished = true;
    if (S.claimTimer) { clearInterval(S.claimTimer); S.claimTimer = null; }
    var ck = S.claim && S.claim.key;
    var pid = S.claim && S.claim.planId;
    // 成功时先本地乐观移除活动：不能等 get_state 往返，否则按钮会重新出现一瞬间
    if (success && ck && pid && S.st && S.st.benefits && S.st.benefits[ck]) {
      var b = S.st.benefits[ck];
      b.campaigns = (b.campaigns || []).filter(function(c) { return c.plan_id !== pid; });
      b.count = b.campaigns.length;
      delete S.quota[ck];
      S.quotaSeq[ck] = (S.quotaSeq[ck] || 0) + 1;
    }
    S.claim = null;
    renderAll();
    if (success) {
      pushToast(msg, type || "ok");
      refreshAll(false, ck, null);
    } else {
      pushToast(msg, type || "bad");
    }
  }
  function tick() {
    if (finished) return;
    api("claim_state").then(function(s) {
      if (finished || !s || s.status === "idle") return;
      if (s.status === "success") {
        finish(true, t("claim_ok", {p: s.planName || "?", t: s.effectiveAt ? fmtT2(s.effectiveAt) : "—"}));
        return;
      }
      // 服务端说今天已领过：活动从卡片移除，权益已生效，不算失败
      if (s.status === "already_claimed") {
        finish(true, t("claim_already"));
        return;
      }
      // 活动未开放：提示等待自动复查
      if (s.status === "not_eligible") {
        finish(false, t("claim_not_eligible"), "warn");
        return;
      }
      if (s.status === "failed") {
        var fmsg = s.holdUntil
          ? t("claim_rate_hold", {time: fmtClock(s.holdUntil)})
          : t("claim_fail", {e: localizeErr(s.message || "?")});
        finish(false, fmsg);
        return;
      }
      // 进入等待验证：提示一次（验证页会复用，用户只需切回已打开的那一页）
      if (s.status === "waiting_captcha" && !waitToasted) {
        waitToasted = true;
        pushToast(t("claim_wait"), "warn");
      }
      S.claim = { status: s.status, planId: s.planId || (S.claim && S.claim.planId), planName: s.planName || (S.claim && S.claim.planName), key: S.claim && S.claim.key, captchaUrl: s.captchaUrl };
      renderAll();
    }).catch(function() {});
    var elapsed = Date.now() - started;
    if (!messageShown && elapsed > 240000) {
      messageShown = true;
      pushToast(t("claim_bg"), "warn");
      if (S.claimTimer) { clearInterval(S.claimTimer); S.claimTimer = setInterval(tick, 5000); }
    }
    if (elapsed > 900000) finish(false, t("claim_timeout"));
  }
  tick();
  S.claimTimer = setInterval(tick, 1500);
}

/* ---------------- settings ---------------- */
function settingsBody(patch) {
  var body = {
    minutes: Number(el("autoCheckSel").value),
    notifyEnabled: !!el("notifyTgl").checked,
    hotSwitch: !!el("hotTgl").checked,
    safeMode: !!el("safeModeTgl").checked,
    lang: LANG,
    closeAction: el("closeActionSel").value,
    startMinimized: !!el("startMinTgl").checked,
    quotaNotify: !!el("quotaNotifyTgl").checked,
    autoBackup: !!el("autoBackupTgl").checked,
    updateNotify: !!el("updateNotifyTgl").checked
  };
  if (S.st && S.st.settings) body.zcodePath = el("zcPath").value.trim();
  if (patch) Object.keys(patch).forEach(function(k) { body[k] = patch[k]; });
  return body;
}
function syncForm(force) {
  if (!S.st) return;
  var s = S.st.settings || {};
  var ae = document.activeElement;
  if (force || ae !== el("autoCheckSel")) el("autoCheckSel").value = String(s.auto_check_minutes !== undefined ? s.auto_check_minutes : 15);
  el("notifyTgl").checked = s.notify_enabled !== false;
  el("hotTgl").checked = !!s.hot_switch;
  el("safeModeTgl").checked = !!s.safe_mode;
  syncModeExclusivity();
  el("quotaNotifyTgl").checked = s.quota_notify !== false;
  el("autoBackupTgl").checked = s.auto_backup !== false;
  el("updateNotifyTgl").checked = s.update_notify !== false;
  el("startMinTgl").checked = !!s.start_minimized;
  if (force || ae !== el("closeActionSel")) el("closeActionSel").value = s.close_action || "tray";
  if (force || ae !== el("zcPath")) el("zcPath").value = s.zcode_path || "";
  if (force || ae !== el("langSel")) el("langSel").value = LANG;
  el("autoStartTgl").checked = !!S.st.autostart;
  el("cfgVer").textContent = "v" + (S.st.version || "?");
  /* 版本只在设置页显示（顶部不弹条）：未验证只是信息，不是故障
     zcode_version 可能带四段（PowerShell ProductVersion 原文），显示截断为 x.y.z */
  var cp = S.st.compat || {};
  var vtxt = "";
  if (cp.zcode_version) {
    // PowerShell 的 ProductVersion 是四段（3.17.2.9661），版本语义只到 x.y.z
    vtxt = "ZCode v" + String(cp.zcode_version).split(".").slice(0, 3).join(".");
    if (cp.version_status && cp.version_status !== "match") {
      vtxt += "（" + t("zcode_unverified") + "，" + t("zcode_verified", {v: cp.verified_version || "?"}) + "）";
    }
  }
  el("zcodeVer").textContent = vtxt;
}

/* 严格模式要求客户端完全重新初始化，所以与热切换互斥。
   后端会静默忽略热切换（identity.rs: want_hot && !strict_requested），
   这里必须把这个事实摆到界面上，而不是让用户以为热切换还开着。 */
function syncModeExclusivity() {
  var strict = !!el("safeModeTgl").checked;
  var hotBox = el("hotTgl");
  var hotWrap = el("hotTglWrap");
  var hotHint = el("hotHint");
  // 严格模式开启时不允许热切换
  hotBox.disabled = strict;
  if (hotWrap) hotWrap.classList.toggle("tgl-disabled", strict);
  if (hotHint) {
    hotHint.textContent = strict ? t("hot_blocked_by_strict") : t("hot_hint");
    hotHint.classList.toggle("warn", strict);
  }
  // 反向：热切换开着时，提示开严格模式会关闭它（不是禁用，允许用户主动切换策略）
  var safeHint = el("safeHint");
  if (safeHint && !strict && hotBox.checked) {
    safeHint.textContent = t("strict_overrides_hot");
    safeHint.classList.add("warn");
  } else if (safeHint) {
    safeHint.textContent = t("safe_hint");
    safeHint.classList.remove("warn");
  }
}
function saveSettings(patch, quiet) {
  return api("set_settings", settingsBody(patch)).then(function(r) {
    if (!r || r.ok === false) throw new Error((r && r.error) || "save failed");
    if (S.st && r.settings) S.st.settings = r.settings;
    if (S.st) S.st.autostart = !!el("autoStartTgl").checked;
    if (!quiet) pushToast(t("t_settings_saved"), "ok");
    syncForm(false);
    renderAll();
    return r;
  }).catch(function(e) {
    pushToast(t("t_save_fail", {e: errText(e)}), "bad");
    syncForm(true);
    throw e;
  });
}

/* ---------------- actions ---------------- */
function doCapture() {
  if (S.busyKey) return;
  S.busyKey = "__capture__";
  api("capture_profile", { name: null }).then(function(r) {
    if (r && r.ok) {
      pushToast(t("t_saved", {x: r.label}), "ok");
      refreshAll(false, r.name, null);
    } else pushToast((r && r.error) || "failed", "bad");
  }).catch(function(e) { pushToast(errText(e), "bad"); })
    .finally(function() { S.busyKey = null; renderAll(); });
}

function doSwitch(key) {
  if (S.busyKey) return;
  if (claimActive()) { pushToast(t("claim_busy"), "warn"); return; }
  var p = profileByKey(key);
  if (!p) return;
  var hot = !!(S.st.settings && S.st.settings.hot_switch);
  var body = t("switch_body", {
    from: S.st.current_label ? displayLabel(S.st.current_label) : "—",
    to: displayLabel(p.label),
    mode: hot ? t("switch_hot") : t("switch_cold")
  });
  if (p.jwt_expired) body += "\n" + t("switch_expired");
  askConfirm(t("switch_title"), body).then(function(ok) {
    if (!ok) return;
    S.busyKey = key; renderAll();
    api("switch_profile", { key: key, hot: hot }).then(function(r) {
      if (r && r.ok) {
        // mode 是后端明确的字符串（cold/hot/strict），不再靠 hot/safe 键的存在与否猜
        if (r.mode === "hot") {
          S.notice = { text: t("hot_notice", {name: displayLabel(p.label)}), label: t("restart_client"), act: "restart" };
          pushToast(t("switched_hot"), "ok");
        } else if (r.mode === "strict") {
          pushToast(r.relaunched ? t("switched_strict") : t("switched_nore"), r.relaunched ? "ok" : "warn");
        } else {
          pushToast(r.relaunched ? t("switched_re") : t("switched_nore"), r.relaunched ? "ok" : "warn");
        }
        refreshAll(false, key, null);
      } else {
        pushToast(t("switch_fail", {e: (r && r.error) || "?"}), "bad");
      }
    }).catch(function(e) { pushToast(t("switch_fail", {e: errText(e)}), "bad"); })
      .finally(function() { S.busyKey = null; renderAll(); });
  });
}
function doDelete(key) {
  if (claimActive() && S.claim && S.claim.key === key) { pushToast(t("claim_busy"), "warn"); return; }
  var p = profileByKey(key);
  if (!p) return;
  askConfirm(t("delete"), t("delete_body", {name: displayLabel(p.label)}) || ("删除「" + displayLabel(p.label) + "」？"), t("delete")).then(function(ok) {
    if (!ok) return;
    api("delete_profile", { key: key }).then(function(r) {
      if (!r || r.ok === false) { pushToast((r && r.error) || "failed", "bad"); return; }
      var undo = r.trash ? {
        label: t("t_undo"),
        onClick: function() {
          api("restore_profile", { trash: r.trash }).then(function(rr) {
            if (rr && rr.ok) { pushToast(t("t_restored", {x: rr.key}), "ok"); refreshAll(false); }
            else pushToast((rr && rr.error) || "failed", "bad");
          }).catch(function(e) { pushToast(errText(e), "bad"); });
        }
      } : null;
      pushToast(t("t_deleted"), "ok", undo);
      refreshAll(false);
    }).catch(function(e) { pushToast(errText(e), "bad"); });
  });
}
function doRename(key) {
  var p = profileByKey(key);
  if (!p) return;
  S.renameKey = key;
  el("renameInput").value = p.label || "";
  openModal("renameModal", "#renameInput");
  setTimeout(function() { try { el("renameInput").select(); } catch(e) {} }, 60);
}
function submitRename() {
  var v = el("renameInput").value.trim();
  if (!v || !S.renameKey) { hideModal("renameModal"); return; }
  var key = S.renameKey;
  api("rename_profile", { key: key, label: v }).then(function(r) {
    hideModal("renameModal");
    if (r && r.ok) { pushToast(t("t_rename_saved", {x: v}), "ok"); refreshAll(false, null, null); }
    else pushToast(t("t_rename_fail", {e: (r && r.error) || "?"}), "bad");
  }).catch(function(e) { hideModal("renameModal"); pushToast(t("t_rename_fail", {e: errText(e)}), "bad"); });
}
function setFilter(f) {
  S.filter = f;
  document.querySelectorAll("#filterChips .fchip").forEach(function(b) {
    b.classList.toggle("on", b.getAttribute("data-filter") === f);
  });
  renderList();
}
function togglePin(key) {
  if (S.pins[key]) delete S.pins[key]; else S.pins[key] = true;
  savePins();
  renderList();
}
function doTags(key) {
  var p = profileByKey(key);
  if (!p) return;
  S.tagKey = key;
  el("tagInput").value = (p.tags || []).join(", ");
  openModal("tagModal", "#tagInput");
  setTimeout(function() { try { el("tagInput").focus(); } catch(e) {} }, 60);
}
function submitTags() {
  if (!S.tagKey) { hideModal("tagModal"); return; }
  var key = S.tagKey;
  var tags = el("tagInput").value.split(",").map(function(s) { return s.trim(); }).filter(Boolean);
  api("set_profile_tags", { key: key, tags: tags }).then(function(r) {
    hideModal("tagModal");
    if (!r || r.ok === false) { pushToast(t("tags_fail", {e: (r && r.error) || "?"}), "bad"); return; }
    var p = profileByKey(key);
    if (p) p.tags = r.tags || [];
    pushToast(t("tags_saved"), "ok");
    renderList();
  }).catch(function(e) { hideModal("tagModal"); pushToast(t("tags_fail", {e: errText(e)}), "bad"); });
}
function doKill() {
  askConfirm(t("kill"), t("kill_confirm") || "", t("kill")).then(function(ok) {
    if (!ok) return;
    api("kill_zcode_client").then(function(r) {
      if (r && r.ok) { pushToast(t("t_closed"), "ok"); refreshAll(false); }
      else pushToast(t("t_close_fail", {e: (r && r.error) || "?"}), "bad");
    }).catch(function(e) { pushToast(t("t_close_fail", {e: errText(e)}), "bad"); });
  });
}
function openClient() {
  api("open_zcode_client").then(function(r) {
    if (!r || r.ok === false) pushToast((r && r.error) || t("t_open_client_fail"), "bad");
  }).catch(function(e) { pushToast(t("t_open_client_fail") + " " + errText(e), "bad"); });
}
function restartZcode() {
  api("kill_zcode_client").catch(function() {}).then(function() {
    return api("open_zcode_client");
  }).then(function(r) {
    if (r && r.ok) { S.notice = null; renderAll(); pushToast(t("switched_re"), "ok"); refreshAll(false); }
    else pushToast(t("t_restart_fail", {e: (r && r.error) || "?"}), "bad");
  }).catch(function(e) { pushToast(t("t_restart_fail", {e: errText(e)}), "bad"); });
}

/* ---------------- benefit checks ---------------- */
function pollCheckState() {
  if (S.checkTimer) clearInterval(S.checkTimer);
  S.checkTimer = setInterval(function() {
    api("check_state").then(function(s) {
      S.checkProgress = { done: s.done || 0, total: s.total || 0 };
      if (s.checking) S.checking = true;
      renderCheckButton();
      if (!s.checking) { clearInterval(S.checkTimer); S.checkTimer = null; }
    }).catch(function() {});
  }, 700);
}
function doCheckAll() {
  if (S.checking) return;
  S.checking = true;
  S.checkProgress = { done: 0, total: (S.st && S.st.profiles.length) || 1 };
  renderCheckButton();
  pollCheckState();
  api("check_all_benefits").then(function(r) {
    if (!r || r.ok === false) { pushToast((r && r.error) || t("t_one_fail"), "bad"); return; }
    if (r.total_campaigns === 0) {
      if (r.failed > 0) pushToast(t("t_check_partial", {ok: r.checked_ok, all: r.accounts, f: r.failed}), "warn");
      else pushToast(t("t_check_done0", {ok: r.checked_ok, all: r.accounts}), "ok");
    } else pushToast(t("t_check_done", {w: r.accounts_with_benefits, all: r.accounts, n: r.total_campaigns}), "warn");
    refreshAll(false);
  }).catch(function(e) { pushToast(errText(e), "bad"); })
    .finally(function() { S.checking = false; if (S.checkTimer) { clearInterval(S.checkTimer); S.checkTimer = null; } renderCheckButton(); });
}
function checkOne(key) {
  if (S.checking) return;
  S.checking = true; renderCheckButton();
  api("check_benefits", { key: key }).then(function(r) {
    if (r && r.ok && r.count > 0) pushToast(t("t_one_has", {n: r.count}), "warn");
    else if (r && r.ok) pushToast(t("t_one_none"), "ok");
    else if (r && r.transient) pushToast(t("t_one_transient"), "warn");
    else pushToast((r && r.error) || t("t_one_fail"), "bad");
    refreshAll(false);
  }).catch(function(e) { pushToast(errText(e), "bad"); })
    .finally(function() { S.checking = false; renderCheckButton(); });
}

/* ---------------- OAuth ---------------- */
function resetOauthUi() {
  el("oauthStatus").textContent = "";
  el("oauthCountdown").textContent = "";
  el("oauthReopen").hidden = true;
  el("oauthCopy").hidden = true;
  el("oauthRetry").hidden = true;
  el("oauthProviders").hidden = false;
}
function doAdd() {
  if (S.oauthActive) { openModal("addModal", "#oauthProviders button"); return; }
  resetOauthUi();
  openModal("addModal", "#oauthProviders button");
}
function startOauth(provider) {
  S.oauthProvider = provider;
  S.oauthActive = true;
  el("oauthProviders").hidden = true;
  el("oauthStatus").innerHTML = '<span class="spin-mini"></span> ' + esc(t("opening", {p: provider === "bigmodel" ? "BigModel" : "Z.AI"}));
  el("oauthRetry").hidden = true;
  api("oauth_start", { provider: provider }).then(function(r) {
    if (!r || r.ok === false) {
      S.oauthActive = false;
      el("oauthStatus").textContent = t("oauth_fail", {e: (r && r.error) || "?"});
      el("oauthRetry").hidden = false;
      return;
    }
    if (r.already) {
      S.oauthState = r.status;
      el("oauthStatus").textContent = t("oauth_already");
    }
    pollOauth();
  }).catch(function(e) {
    S.oauthActive = false;
    el("oauthStatus").textContent = t("oauth_fail", {e: errText(e)});
    el("oauthRetry").hidden = false;
  });
}
function pollOauth() {
  if (S.oauthTimer) clearInterval(S.oauthTimer);
  var gen = (S.oauthPollGen || 0) + 1;
  S.oauthPollGen = gen;
  function tick() {
    if (gen !== S.oauthPollGen) return;
    api("oauth_status").then(function(s) {
      if (gen !== S.oauthPollGen) return;
      if (!s || s.status === "idle") {
        if (S.oauthTimer) { clearInterval(S.oauthTimer); S.oauthTimer = null; }
        return;
      }
      S.oauthState = s;
      if (s.status === "pending") {
        el("oauthStatus").textContent = t("oauth_pending");
        el("oauthReopen").hidden = false;
        el("oauthCopy").hidden = !s.authorize_url;
        el("oauthRetry").hidden = true;
        var started = s.started_at ? new Date(s.started_at).getTime() : Date.now();
        var left = Math.max(0, 600 - Math.floor((Date.now() - started) / 1000));
        el("oauthCountdown").textContent = left > 0 ? t("oauth_countdown", {t: Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0")}) : "";
      } else if (s.status === "ready") {
        S.oauthActive = false;
        if (S.oauthTimer) { clearInterval(S.oauthTimer); S.oauthTimer = null; }
        el("oauthStatus").innerHTML = '<span class="ok-text">' + esc(t("oauth_ready", {l: s.label || ""})) + (s.provider ? " · " + esc(s.provider) : "") + '</span>';
        el("oauthCountdown").textContent = "";
        el("oauthReopen").hidden = true;
        el("oauthCopy").hidden = true;
        el("oauthRetry").hidden = true;
        if (s.warning) pushToast(s.warning, "bad"); else pushToast(t("t_saved", {x: s.label || ""}), "ok");
        setTimeout(function() { if (gen !== S.oauthPollGen) return; hideModal("addModal"); refreshAll(false, s.name || null, null); }, 900);
      } else if (s.status === "failed") {
        S.oauthActive = false;
        if (S.oauthTimer) { clearInterval(S.oauthTimer); S.oauthTimer = null; }
        el("oauthStatus").textContent = t("oauth_fail", {e: s.error === "timeout" ? t("oauth_timeout") : localizeErr(s.error || "?")});
        el("oauthCountdown").textContent = "";
        el("oauthReopen").hidden = !s.authorize_url;
        el("oauthCopy").hidden = !s.authorize_url;
        el("oauthRetry").hidden = false;
      }
    }).catch(function() {});
  }
  tick();
  S.oauthTimer = setInterval(tick, 2000);
}
function closeAddModal(cancel) {
  if (cancel && S.oauthActive) api("oauth_cancel").catch(function() {});
  S.oauthActive = false;
  S.oauthPollGen = (S.oauthPollGen || 0) + 1;
  if (S.oauthTimer) { clearInterval(S.oauthTimer); S.oauthTimer = null; }
  hideModal("addModal");
}

/* ---------------- backup ---------------- */
function showBak() {
  el("bakStatus").textContent = "";
  el("bakActions").hidden = true;
  el("bakPwd").value = "";
  el("impPwd").value = "";
  el("bakPreview").hidden = true;
  el("bakPreview").innerHTML = "";
  S.pendingImport = null;
  openModal("bakModal", "#bakPwd");
}
function doExport() {
  var pwd = el("bakPwd").value;
  if (!pwd || pwd.length < 6) { pushToast(t("t_pwd_short"), "bad"); return; }
  el("bakStatus").textContent = "…";
  api("export_bundle", { password: pwd }).then(function(r) {
    if (!r || r.ok === false) { el("bakStatus").textContent = t("export_fail", {e: (r && r.error) || "?"}); return; }
    S.exportPath = r.path || null;
    el("bakStatus").textContent = t("exported", {n: r.accounts || 0}) + (r.path ? " · " + t("t_export_path", {p: r.path}) : "");
    el("bakActions").hidden = !r.path;
    pushToast(t("exported", {n: r.accounts}), "ok");
  }).catch(function(e) { el("bakStatus").textContent = t("export_fail", {e: errText(e)}); });
}
function previewImport() {
  var p = el("impPath").value.trim().replace(/^"|"$/g, "");
  var pwd = el("impPwd").value;
  if (!p || !pwd) { pushToast(t("t_fill_both"), "bad"); return; }
  el("bakStatus").textContent = "…";
  el("bakPreview").hidden = true;
  api("inspect_bundle", { path: p, password: pwd }).then(function(r) {
    if (!r || r.ok === false) { el("bakStatus").textContent = t("import_preview_fail", {e: (r && r.error) || "?"}); return; }
    if (!r.count) { el("bakStatus").textContent = t("import_none"); return; }
    S.pendingImport = { path: p, password: pwd };
    var newN = (r.accounts || []).filter(function(a) { return a.has_token && !a.duplicate; }).length;
    var rows = (r.accounts || []).map(function(a) {
      var badge = !a.has_token ? '<span class="tag expired">' + esc(t("preview_invalid")) + '</span>'
        : a.duplicate ? '<span class="tag warn">' + esc(t("preview_dup")) + '</span>'
        : '<span class="tag cur">' + esc(t("preview_new")) + '</span>';
      var rl = a.needs_relogin ? '<span class="tag expired">' + esc(t("preview_relogin")) + '</span>' : "";
      return '<div class="preview-row"><span class="preview-name">' + esc(a.label || "?") + '</span>' + badge + rl + '</div>';
    }).join("");
    var box = el("bakPreview");
    box.innerHTML = '<div class="preview-sum">' + esc(t("import_preview_hint", {n: newN, d: r.duplicates, r: r.relogin})) + '</div>'
      + rows + '<div class="field-hint">' + esc(t("import_confirm_hint")) + '</div>'
      + '<button class="camp-btn" data-action="bak-import-confirm">' + esc(t("import_confirm")) + '</button>';
    box.hidden = false;
    el("bakStatus").textContent = "";
  }).catch(function(e) { el("bakStatus").textContent = t("import_preview_fail", {e: errText(e)}); });
}
function confirmImport() {
  var pi = S.pendingImport;
  if (!pi) return;
  el("bakStatus").textContent = "…";
  api("import_bundle", { path: pi.path, password: pi.password }).then(function(r) {
    if (!r || r.ok === false) { el("bakStatus").textContent = t("import_fail", {e: (r && r.error) || "?"}); return; }
    var parts = [t("import_done", {n: r.added})];
    if (r.skipped) parts.push(t("import_skipped", {n: r.skipped}));
    if (r.relogin) parts.push(t("import_relogin", {n: r.relogin}));
    el("bakStatus").textContent = parts.join(" · ");
    el("bakPreview").hidden = true;
    S.pendingImport = null;
    pushToast(t("import_done", {n: r.added}), "ok");
    refreshAll(false);
  }).catch(function(e) { el("bakStatus").textContent = t("import_fail", {e: errText(e)}); });
}
function bakBrowse() {
  invoke("plugin:dialog|open", { options: { multiple: false, directory: false, filters: [{ name: "ZCode Hub backup", extensions: ["zhb"] }] } })
    .then(function(p) { if (p) el("impPath").value = Array.isArray(p) ? p[0] : p; })
    .catch(function(e) { pushToast(errText(e), "bad"); });
}
function cfgBrowseExe() {
  invoke("plugin:dialog|open", { options: { multiple: false, filters: [{ name: "ZCode", extensions: ["exe"] }] } })
    .then(function(p) { if (p) el("zcPath").value = Array.isArray(p) ? p[0] : p; })
    .catch(function(e) { pushToast(errText(e), "bad"); });
}
function backupNow() {
  api("backup_now").then(function(r) {
    if (r && r.ok) {
      pushToast(t("backup_done", {n: r.profiles || 0}), "ok", {
        label: t("open_backup_dir"),
        onClick: function() { openBackupDir(false); }
      });
      loadBackupInfo();
    } else pushToast(t("backup_fail", {e: (r && r.error) || "?"}), "bad");
  }).catch(function(e) { pushToast(t("backup_fail", {e: errText(e)}), "bad"); });
}
function loadBackupInfo() {
  var txt = el("backupInfoTxt");
  if (!txt) return;
  api("get_backup_status").then(function(r) {
    if (!r || r.ok === false) { txt.textContent = ""; return; }
    var label = r.count ? t("backup_info", {n: r.count}) : t("backup_info_none");
    if (r.count && r.latest_at) label += " · " + t("backup_last", {t: fmtT2(r.latest_at)});
    txt.textContent = label;
  }).catch(function() { txt.textContent = ""; });
}
/* 恢复备份：先列出全部备份（时间 + 账号数 + 完整性），由用户选具体一份，
   不再只有「最近一份」。恢复成功后后端会清空额度/福利缓存，这里重新拉取状态。 */
function restoreBackup() {
  api("list_backups").then(function(r) {
    if (!r || r.ok === false) { pushToast(t("restore_fail", {e: (r && r.error) || "?"}), "bad"); return; }
    var items = r.items || [];
    if (!items.length) { pushToast(t("restore_none"), "warn"); return; }
    var box = el("restoreList");
    box.innerHTML = items.map(function(it) {
      var when = it.created_at ? fmtT2(it.created_at) : it.name;
      var badge = it.verified
        ? '<span class="tag cur">' + esc(t("backup_verified")) + '</span>'
        : '<span class="tag expired">' + esc(t("backup_broken")) + '</span>';
      var accounts = '<span class="num">' + esc(t("backup_accounts", {n: it.profiles})) + '</span>';
      return '<div class="history-row backup-row">'
        + '<span class="history-plan">' + esc(when) + '<span class="mut num"> · ' + esc(it.name) + '</span></span>'
        + accounts + badge
        + '<button class="camp-btn" data-action="restore-pick" data-name="' + esc(it.name) + '" data-ok="' + (it.verified ? "1" : "0") + '"'
        + (it.verified ? "" : " disabled")
        + '>' + esc(t("restore_pick_btn")) + '</button>'
        + '</div>';
    }).join("");
    openModal("restoreModal", '[data-action="restore-close"]');
  }).catch(function(e) { pushToast(t("restore_fail", {e: errText(e)}), "bad"); });
}
function restorePick(name) {
  if (!name) return;
  askConfirm(t("restore_confirm_title"), t("restore_confirm_body"), t("restore_confirm_title")).then(function(ok) {
    if (!ok) return;
    api("restore_backup", { name: name }).then(function(r) {
      if (!r || r.ok === false) {
        // 后端完整性校验失败时给出明确原因，而不是通用错误
        var msg = (r && r.error) || "?";
        pushToast(t("restore_bad", {e: localizeErr(msg)}), "bad");
        return;
      }
      hideModal("restoreModal");
      if (r.warning) pushToast(t("restore_warn", {e: r.warning}), "warn");
      else pushToast(t("restore_done", {n: r.restored || 0}), "ok");
      // 恢复会替换账号库并清空缓存：清掉前端这份额度/福利快照再拉
      S.quota = {}; S.history = {}; S.quotaSeq = {}; S.claim = null;
      loadBackupInfo();
      refreshAll(false);
    }).catch(function(e) { pushToast(t("restore_fail", {e: errText(e)}), "bad"); });
  });
}
function openBackupDir(showToast) {
  api("open_backup_dir").then(function(r) {
    if (!r || r.ok === false) { pushToast(t("backup_open_fail", {e: (r && r.error) || "?"}), "bad"); return; }
    if (showToast) pushToast(t("backup_open_toast"), "ok");
    loadBackupInfo();
  }).catch(function(e) { pushToast(t("backup_open_fail", {e: errText(e)}), "bad"); });
}
function saveDialog(defaultPath, name, ext) {
  return invoke("plugin:dialog|save", { options: { defaultPath: defaultPath, filters: [{ name: name, extensions: [ext] }] } })
    .then(function(p) { return Array.isArray(p) ? p[0] : p; });
}
function exportDiagnostics() {
  saveDialog("zcode-hub-diagnostics.json", "JSON", "json").then(function(p) {
    if (!p) return;
    return api("export_diagnostics", { path: p }).then(function(r) {
      if (r && r.ok) pushToast(t("diag_done"), "ok");
      else pushToast(t("diag_fail", {e: (r && r.error) || "?"}), "bad");
    });
  }).catch(function(e) { pushToast(t("diag_fail", {e: errText(e)}), "bad"); });
}
function exportHistory() {
  saveDialog("zcode-hub-claim-history.json", "JSON", "json").then(function(p) {
    if (!p) return;
    return api("export_claim_history", { path: p }).then(function(r) {
      if (r && r.ok) pushToast(t("history_export_done", {n: r.count || 0}), "ok");
      else pushToast(t("history_export_fail", {e: (r && r.error) || "?"}), "bad");
    });
  }).catch(function(e) { pushToast(t("history_export_fail", {e: errText(e)}), "bad"); });
}

/* ---------------- settings modal / update / history ---------------- */
function showCfg() {
  if (S.st) syncForm(true);
  loadBackupInfo();
  openModal("cfgModal", '[data-action="cfg-checkupdate"]');
  api("get_state").then(function(st) {
    S.st = st; syncForm(true); renderAll();
    if (st.update_available && st.update_available.latest) {
      el("updTxt").innerHTML = esc(t("update_banner", {v: st.update_available.latest})) + ' '
        + '<button class="linkbtn" data-action="install-update">' + esc(t("install_upd")) + '</button>';
    }
  }).catch(function() {});
}
function doCheckUpdate() {
  var tt = el("updTxt");
  tt.textContent = t("checking_upd");
  api("check_update").then(function(r) {
    if (!r || !r.ok) { tt.textContent = t("upd_fail", {e: (r && r.error) || "?"}); return; }
    if (r.up_to_date) { tt.textContent = t("upd_latest", {v: r.current}); return; }
    tt.innerHTML = esc(t("upd_found", {v: r.latest})) + ' '
      + '<button class="linkbtn" data-action="install-update">' + esc(t("install_upd")) + '</button> · '
      + '<button class="linkbtn" data-action="open-repo" data-url="https://github.com/Ebonyhtx/zcode-hub">' + esc(t("upd_go")) + '</button>';
    pushToast(t("upd_found", {v: r.latest}), "warn");
  }).catch(function(e) { tt.textContent = t("upd_fail", {e: errText(e)}); });
}
function installUpdate() {
  askConfirm(t("update_confirm_title"), t("update_confirm"), t("install_upd")).then(function(ok) {
    if (!ok) return;
    var tt = el("updTxt");
    tt.textContent = t("upd_installing");
    var timer = setInterval(function() {
      api("update_progress").then(function(p) {
        if (p && p.total > 0) tt.textContent = t("updating_pct", {p: Math.min(100, Math.round(p.downloaded / p.total * 100))});
        else if (p && p.downloaded > 0) tt.textContent = t("updating");
      }).catch(function() {});
    }, 500);
    api("install_update").then(function(r) {
      clearInterval(timer);
      if (r && r.up_to_date) tt.textContent = t("upd_latest", {v: r.current || ""});
    }).catch(function(e) { clearInterval(timer); tt.textContent = t("install_fail", {e: errText(e)}); });
  });
}
function showHistory() {
  api("claim_history").then(function(r) {
    var box = el("historyList");
    var items = (r && r.items) || [];
    if (!items.length) { box.innerHTML = '<div class="empty small">' + esc(t("no_claim_history")) + '</div>'; }
    else {
      box.innerHTML = items.map(function(it) {
        return '<div class="history-row"><span class="history-plan">' + esc(it.plan || "?") + '</span>'
          + '<span class="num">' + esc(fmtT2(it.ts)) + '</span>'
          + '<span class="chip neutral">' + esc(t("plan_pending", {t: fmtT2(it.effectiveAt)})) + '</span></div>';
      }).join("");
    }
    openModal("historyModal", '[data-action="history-close"]');
  }).catch(function(e) { pushToast(t("t_claim_history_fail", {e: errText(e)}), "bad"); });
}

/* ---------------- language ---------------- */
function applyLang() {
  document.documentElement.lang = LANG === "zh" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach(function(node) { node.textContent = t(node.getAttribute("data-i18n")); });
  document.querySelectorAll("[data-i18n-ph]").forEach(function(node) { node.placeholder = t(node.getAttribute("data-i18n-ph")); });
  document.querySelectorAll("[data-i18n-aria]").forEach(function(node) {
    var label = t(node.getAttribute("data-i18n-aria"));
    node.setAttribute("aria-label", label);
    node.title = label;
  });
  ["autoCheckSel", "sortSel", "closeActionSel"].forEach(function(id) {
    var sel = el(id);
    if (sel) Array.prototype.forEach.call(sel.options, function(o) { o.textContent = t(o.getAttribute("data-i18n")); });
  });
  var ls = el("langSel");
  if (ls) ls.value = LANG;
  // data-i18n 把提示重置成原文了，互斥说明要重新套上
  syncModeExclusivity();
  if (S.st) { renderAll(); }
}
function setLang(l) {
  LANG = l;
  try { localStorage.setItem("hub-lang", l); } catch(e) {}
  applyLang();
  if (S.st) saveSettings({ lang: l }, true).catch(function() {});
}

/* titlebar drag: 不依赖 data-tauri-drag-region，避免按钮点击被当成拖拽 */
document.addEventListener("mousedown", function(e) {
  if (e.button !== 0) return;
  var bar = e.target.closest(".tbar");
  if (!bar) return;
  if (e.target.closest("button, select, input")) return;
  if (e.detail >= 2) return;
  invoke("win_start_drag").catch(function() {});
});
document.addEventListener("dblclick", function(e) {
  if (!e.target.closest(".tbar")) return;
  if (e.target.closest("button, select, input")) return;
  invoke("win_toggle_maximize").catch(function() {});
});

/* ---------------- event wiring ---------------- */
document.addEventListener("click", function(e) {
  var elt = e.target.closest("[data-action]");
  if (!elt) return;
  var a = elt.getAttribute("data-action");
  var key = elt.getAttribute("data-key");
  switch (a) {
    case "theme": toggleTheme(); break;
    case "cfg": showCfg(); break;
    case "min": invoke("win_minimize").catch(function() {}); break;
    case "max": invoke("win_toggle_maximize").catch(function() {}); break;
    case "hide": invoke("win_hide").catch(function() {}); break;
    case "add": doAdd(); break;
    case "capture": doCapture(); break;
    case "bak": showBak(); break;
    case "checkall": doCheckAll(); break;
    case "refresh": doRefreshQuota(); break;
    case "prov": startOauth(elt.getAttribute("data-provider")); break;
    case "add-close": closeAddModal(true); break;
    case "oauth-reopen": api("oauth_open").catch(function(e) { pushToast(errText(e), "bad"); }); break;
    case "oauth-copy":
      var u = S.oauthState && S.oauthState.authorize_url;
      if (u && navigator.clipboard) navigator.clipboard.writeText(u).then(function() { pushToast(t("copied"), "ok"); }).catch(function() { pushToast(t("copy_fail"), "bad"); });
      else pushToast(t("copy_fail"), "bad");
      break;
    case "oauth-retry": startOauth(S.oauthProvider || "zai"); break;
    case "cfg-close": hideModal("cfgModal"); break;
    case "cfg-checkupdate": doCheckUpdate(); break;
    case "install-update": installUpdate(); break;
    case "open-repo": invoke("open_url", { url: elt.getAttribute("data-url") || "https://github.com/Ebonyhtx/zcode-hub" }).catch(function() {}); break;
    case "open-site": invoke("open_url", { url: "https://zcode.z.ai" }).catch(function() {}); break;
    case "cfg-savepath":
      saveSettings({ zcodePath: el("zcPath").value.trim() }, true).then(function() { pushToast(t("t_path_saved"), "ok"); }).catch(function() {});
      break;
    case "cfg-browse": cfgBrowseExe(); break;
    case "cfg-opendata": invoke("open_data_dir").catch(function() {}); break;
    case "cfg-openzdata": invoke("open_zcode_data_dir").catch(function() {}); break;
    case "cfg-kill": doKill(); break;
    case "cfg-history": showHistory(); break;
    case "cfg-backup": backupNow(); break;
    case "cfg-openbackup": openBackupDir(true); break;
    case "cfg-restorebackup": restoreBackup(); break;
    case "restore-pick": restorePick(elt.getAttribute("data-name")); break;
    case "restore-close": hideModal("restoreModal"); break;
    case "cfg-diag": exportDiagnostics(); break;
    case "bak-export": doExport(); break;
    case "bak-import": previewImport(); break;
    case "bak-import-confirm": confirmImport(); break;
    case "bak-browse": bakBrowse(); break;
    case "bak-reveal": if (S.exportPath) invoke("reveal_file", { path: S.exportPath }).catch(function(e) { pushToast(errText(e), "bad"); }); break;
    case "bak-close": hideModal("bakModal"); break;
    case "history-close": hideModal("historyModal"); break;
    case "history-export": exportHistory(); break;
    case "filter": setFilter(elt.getAttribute("data-filter") || "all"); break;
    case "confirm-ok": resolveConfirm(true); break;
    case "confirm-cancel": resolveConfirm(false); break;
    case "rename-ok": submitRename(); break;
    case "rename-cancel": hideModal("renameModal"); break;
    case "tags-ok": submitTags(); break;
    case "tags-cancel": hideModal("tagModal"); break;
    case "pin": togglePin(key); break;
    case "tags": doTags(key); break;
    case "refresh-profile": refreshProfile(key); break;
    case "foldhead": case "foldchev":
      var fp = profileByKey(key);
      if (fp) setFold(key, !isFolded(fp));
      break;
    case "foldall": foldAll(true); break;
    case "unfoldall": foldAll(false); break;
    case "switch": doSwitch(key); break;
    case "move-up": moveProfile(key, -1); break;
    case "move-down": moveProfile(key, 1); break;
    case "del": doDelete(key); break;
    case "rename": doRename(key); break;
    case "checkone": checkOne(key); break;
    case "retry-quota":
      var rp = profileByKey(key);
      if (rp) loadQuota(rp, true);
      break;
    case "relogin": doAdd(); if (elt.getAttribute("data-provider")) { openModal("addModal", "#oauthProviders button"); startOauth(elt.getAttribute("data-provider")); } break;
    case "claim": doClaim(key, elt.getAttribute("data-plan"), elt.getAttribute("data-plan-name")); break;
    case "claim-reopen": api("open_claim_captcha").catch(function(e) { pushToast(errText(e), "bad"); }); break;
    case "notice-action":
      var act = elt.getAttribute("data-act");
      if (act === "restart") restartZcode();
      else if (act === "retry") refreshAll(true, null, null);
      else if (act === "open-claim-captcha") api("open_claim_captcha").catch(function(e) { pushToast(errText(e), "bad"); });
      else if (act === "relogin") doAdd();
      break;
    case "notice-close": S.notice = null; S.noticeClosed = true; renderNotice(); break;
    case "compat-details": el("compatNotes").hidden = !el("compatNotes").hidden; break;
  }
});

document.addEventListener("input", function(e) {
  if (e.target && e.target.id === "acctSearch") {
    S.query = e.target.value;
    renderList();
  }
});

document.addEventListener("change", function(e) {
  var id = e.target.id;
  if (id === "autoCheckSel") saveSettings({ minutes: Number(e.target.value) }, true).catch(function() {});
  else if (id === "notifyTgl") saveSettings({ notifyEnabled: !!e.target.checked }, true).then(function() {
    pushToast(e.target.checked ? t("t_notify_on") : t("t_notify_off"), "ok");
  }).catch(function() {});
  else if (id === "autoStartTgl") {
    var want = !!e.target.checked;
    api("set_autostart", { enable: want }).then(function(r) {
      if (!r || !r.ok) { e.target.checked = !want; pushToast((r && r.error) || t("t_autostart_fail", {e: "?"}), "bad"); }
      else { if (S.st) S.st.autostart = !!r.enabled; pushToast(r.enabled ? t("t_autostart_on") : t("t_autostart_off"), "ok"); }
    }).catch(function(err) { e.target.checked = !want; pushToast(t("t_autostart_fail", {e: errText(err)}), "bad"); });
  }
  else if (id === "startMinTgl") saveSettings({ startMinimized: !!e.target.checked }, true).catch(function() {});
  else if (id === "closeActionSel") saveSettings({ closeAction: e.target.value }, true).catch(function() {});
  else if (id === "hotTgl") { saveSettings({ hotSwitch: !!e.target.checked }, true).then(syncModeExclusivity).catch(function() {}); }
  else if (id === "safeModeTgl") { saveSettings({ safeMode: !!e.target.checked }, true).then(syncModeExclusivity).catch(function() {}); }
  else if (id === "quotaNotifyTgl") saveSettings({ quotaNotify: !!e.target.checked }, true).catch(function() {});
  else if (id === "autoBackupTgl") saveSettings({ autoBackup: !!e.target.checked }, true).catch(function() {});
  else if (id === "updateNotifyTgl") saveSettings({ updateNotify: !!e.target.checked }, true).catch(function() {});
  else if (id === "langSel") setLang(e.target.value);
  else if (id === "sortSel") {
    S.sort = e.target.value;
    if (S.sort === "manual") ensureOrder();
    try { localStorage.setItem("hub-sort", S.sort); } catch(e2) {}
    renderAll();
  }
});

document.addEventListener("keydown", function(e) {
  if (e.key === "Escape") { closeTopModal(); return; }
  if (e.key === "Tab") {
    var m = topModal();
    if (!m) return;
    var f = Array.prototype.slice.call(m.querySelectorAll("button, input, select, textarea, a[href]")).filter(function(x) { return !x.disabled && x.offsetParent !== null; });
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
});

/* drag & drop import: WebView may expose file.path; otherwise use the browse button */
(function() {
  var dz = el("impDrop");
  if (!dz) return;
  ["dragenter", "dragover"].forEach(function(n) { dz.addEventListener(n, function(e) { e.preventDefault(); dz.classList.add("over"); }); });
  ["dragleave", "drop"].forEach(function(n) { dz.addEventListener(n, function(e) { e.preventDefault(); dz.classList.remove("over"); }); });
  dz.addEventListener("drop", function(e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f && f.path) { el("impPath").value = f.path; }
    else if (f && f.name) { el("impDrop").textContent = f.name + " — " + t("drop_hint"); }
  });
})();

/* 未捕获异常/资源加载失败上报后端 crash.log（同一错误 1 分钟只报一次，避免死循环刷盘）。
   后端只记消息与来源文件名，不记录界面数据。 */
var _errReported = {};
function reportFrontendError(message, source, stack) {
  var msg = String(message == null ? "" : message).slice(0, 500);
  var key = msg + "@" + String(source || "");
  var now = Date.now();
  if (_errReported[key] && now - _errReported[key] < 60000) return;
  _errReported[key] = now;
  try {
    invoke("report_frontend_error", { message: msg, source: source || "", stack: String(stack || "").slice(0, 1500) }).catch(function() {});
  } catch(e) {}
}
window.addEventListener("error", function(e) {
  if (e && e.target && e.target !== window && (e.target.src || e.target.href)) {
    reportFrontendError("资源加载失败: " + (e.target.src || e.target.href), e.target.tagName || "");
    return;
  }
  reportFrontendError((e && e.message) || "script error", (e && e.filename) || "", (e && e.error && e.error.stack) || "");
});
window.addEventListener("unhandledrejection", function(e) {
  var r = e && e.reason;
  reportFrontendError("unhandledrejection: " + ((r && (r.message || r.error)) || String(r || "?")), "", (r && r.stack) || "");
});

/* ---------------- boot ---------------- */
window.__hubRefresh = function() { refreshAll(false, null, null); };
applyLang();
applyTheme((function() { try { return localStorage.getItem("hub-theme") || "system"; } catch(e) { return "system"; } })());
if (window.matchMedia) {
  try {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function() {
      if (S.theme === "system") applyTheme("system");
    });
  } catch(e) {}
}
(function tryStart() {
  if (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke) {
    refreshAll(false, null, function() {
      api("claim_state").then(function(s) {
        if (s && ["preparing", "waiting_captcha", "claiming"].indexOf(s.status) >= 0) {
          S.claim = { status: s.status, planId: s.planId, planName: s.planName, key: s.key, captchaUrl: s.captchaUrl };
          renderAll();
          pollClaimState();
        }
      }).catch(function() {});
    });
    setInterval(function() { if (!document.hidden) refreshAll(false, null, null); }, 60000);
    document.addEventListener("visibilitychange", function() {
      if (!document.hidden && Date.now() - S.lastRefresh > 5000) refreshAll(false, null, null);
    });
  } else setTimeout(tryStart, 200);
})();
