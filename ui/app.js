/* ZCode Hub app — CSP-safe (no inline handlers), zh/en i18n */
"use strict";

/* ---------------- i18n ---------------- */
var I18N = {
  zh: {
    checking: "检测中", running: "ZCode 运行中", not_running: "未运行",
    capture: "📦 保存当前登录", add: "👤 添加账号", backup: "🗄 备份 / 导入", kill: "⏻ 关闭 ZCode",
    auto_check: "🎁 自动检测福利", notify: "🔔 通知", off: "关闭", min5: "每 5 分钟", min15: "每 15 分钟", min30: "每 30 分钟", min60: "每 60 分钟",
    check_all: "🔍 检测全部账号", checking_dots: "⏳ 检测中…", last_check: "上次", never_checked: "未自动检测",
    accounts: "Accounts · 账号库", n_accounts: " 个账号", connecting: "正在连接…", no_accounts: "暂无账号 · 点上方「添加账号」登录，或「保存当前登录」收编现有登录",
    unknown: "未知", current: "当前", expired: "已过期", not_checked: "🔎 未检测", ben_none: "✓ 无待领福利", ben_has: "🎁 {n} 个待领福利", ben_fail: "⚠ 检测失败: {e}",
    claim: "去领取", use_now: "✓ 当前使用中", switch_to: "⇄ 切换到此账号", del_title: "删除存档", fold_all: "全部收起", expand_all: "全部展开", mini_title: "只检测这个账号的福利",
    no_quota: "暂无额度数据", quota_fail: "获取失败", used_up: "已用完", remain: " 剩余", total: "总 ", used: " · 已用 ", expires: " 到期",
    exp_soon: "⏰ {h} 小时后到期", exp_lt1h: "⏰ 不到 1 小时后到期", exptag_tip: "有额度将在 24 小时内到期",
    week_plan: "周末福利", base_plan: "基础套餐", other_plan: "其他",
    add_title: "添加账号", add_sub: "选择账号类型，浏览器完成官方登录后自动存入账号库。",
    zai_name: "Z.AI 账号", zai_desc: "chat.z.ai · Start Plan / Coding Plan",
    bm_name: "BigModel 账号", bm_desc: "bigmodel.cn · 智谱个人 / 团队套餐",
    opening: "正在打开 {p} 官方登录页…", oauth_ok: "✓ 登录成功：{l}", oauth_fail: "✗ 失败: {e}", reopen: "↻ 重新打开登录页", cancel: "取消",
    cfg_title: "设置 / 关于", about: "关于", about_line: " · 非官方多账号管理工具", check_upd: "🔍 检查更新", repo: "GitHub 仓库",
    zcode_sec: "ZCode", client_path: "客户端路径", path_ph: "例：C:\\Program Files\\ZCode\\ZCode.exe（留空自动探测）", save: "保存",
    datadir: "数据目录", open_hub_data: "打开 Hub 数据", open_zdata: "打开 ZCode 数据",
    sys_sec: "系统", autostart: "开机自启", autostart_hint: "写入启动文件夹快捷方式",
    hot: "热切换（实验）", hot_hint: "不重启客户端直接换号，失败自动回退",
    hot_note: "热切换不重启客户端：套餐与额度立即按新账号生效，但左下角账号名来自客户端本地缓存，需重启 ZCode 才会更新。",
    lang: "语言",
    bak_title: "备份 / 导入账号库", bak_sub: "备份文件用口令加密（PBKDF2 + AES-256-GCM），可在任何电脑导入恢复；口令丢失无法找回。",
    export_to: "导出到桌面", bak_ph: "设置口令（≥6 位）", export_btn: "导出 .zhb",
    import_from: "从文件导入", imp_path_ph: "粘贴 .zhb 文件完整路径", imp_pwd_ph: "备份口令", import_btn: "导入",
    close: "关闭",
    t_saved: "已保存: {x}", t_deleted: "已删除", t_settings_saved: "已保存设置", t_notify_on: "已开启系统通知", t_notify_off: "已关闭系统通知",
    t_autostart_on: "已开启开机自启", t_autostart_off: "已关闭开机自启", t_autostart_fail: "设置失败",
    t_path_saved: "ZCode 路径已保存（留空 = 自动探测）",
    t_detected_new: "🎁 检测到新的可领福利（{n} 项），打开 ZCode 客户端领取",
    t_check_done0: "检测完成：{ok}/{all} 个账号正常，均无待领福利",
    t_check_done: "检测完成：{w}/{all} 个账号有 🎁{n} 项福利待领（打开 ZCode 客户端领取）",
    t_check_fail: "检测失败", t_refresh_fail: "刷新失败: {e}",
    t_one_has: "🎁 该账号有 {n} 项待领福利", t_one_none: "该账号暂无待领福利", t_one_fail: "检测失败",
    t_switched_hot: "已热切换（客户端未重启）", t_switched_re: "已切换并重启 ZCode", t_switched_nore: "凭据已切换，ZCode 未自动重启，请手动打开",
    t_switch_fail: "切换失败", t_close_fail: "无法关闭 ZCode（可能仍在托盘运行），请手动退出后重试",
    t_bak_saved: "备份完成（{n} 个账号）→ 桌面", t_pwd_short: "口令至少 6 位", t_fill_both: "先填文件路径和口令",
    t_imp_done: "导入完成：新增 {n} 个账号", t_upd_latest: "已是最新（v{v}）", t_upd_found: "🆕 发现新版本 v{v}", t_upd_checking: "检查中…",
    t_upd_fail: "检查失败: {e}",
    c_switch: "切换到该账号？\n{mode}\n（正在运行的任务会中断）", c_switch_hot: "热切换：客户端不重启，直接更换登录身份。", c_switch_cold: "ZCode 将自动关闭并重启。",
    c_del: "确定删除这个账号存档？\n（不影响 ZCode 客户端当前登录）", c_kill: "关闭 ZCode 客户端？",
    install_upd: "⬇ 立即更新并重启", upd_go: "前往下载",
  },
  en: {
    checking: "Checking", running: "ZCode running", not_running: "Not running",
    capture: "📦 Save current login", add: "👤 Add account", backup: "🗄 Backup / Import", kill: "⏻ Close ZCode",
    auto_check: "🎁 Auto benefit check", notify: "🔔 Notify", off: "Off", min5: "Every 5 min", min15: "Every 15 min", min30: "Every 30 min", min60: "Every 60 min",
    check_all: "🔍 Check all accounts", checking_dots: "⏳ Checking…", last_check: "Last", never_checked: "Not checked yet",
    accounts: "Accounts", n_accounts: " accounts", connecting: "Connecting…", no_accounts: "No accounts yet · use \"Add account\" or \"Save current login\"",
    unknown: "Unknown", current: "Current", expired: "Expired", not_checked: "🔎 Not checked", ben_none: "✓ Nothing to claim", ben_has: "🎁 {n} claimable", ben_fail: "⚠ Check failed: {e}",
    claim: "Claim", use_now: "✓ In use", switch_to: "⇄ Switch to this", del_title: "Delete snapshot", fold_all: "Collapse all", expand_all: "Expand all", mini_title: "Check this account only",
    no_quota: "No quota data", quota_fail: "Fetch failed", used_up: "Used up", remain: " left", total: "Total ", used: " · used ", expires: " expires",
    exp_soon: "⏰ expires in {h}h", exp_lt1h: "⏰ expires in <1h", exptag_tip: "Some quota expires within 24h",
    week_plan: "Weekend bonus", base_plan: "Base plan", other_plan: "Other",
    add_title: "Add account", add_sub: "Pick a provider, finish official login in browser, saved automatically.",
    zai_name: "Z.AI account", zai_desc: "chat.z.ai · Start Plan / Coding Plan",
    bm_name: "BigModel account", bm_desc: "bigmodel.cn · Zhipu individual / team plans",
    opening: "Opening {p} official login…", oauth_ok: "✓ Signed in: {l}", oauth_fail: "✗ Failed: {e}", reopen: "↻ Reopen login page", cancel: "Cancel",
    cfg_title: "Settings / About", about: "About", about_line: " · unofficial multi-account manager", check_upd: "🔍 Check updates", repo: "GitHub repo",
    zcode_sec: "ZCode", client_path: "Client path", path_ph: "e.g. C:\\Program Files\\ZCode\\ZCode.exe (empty = auto-detect)", save: "Save",
    datadir: "Data dirs", open_hub_data: "Hub data", open_zdata: "ZCode data",
    sys_sec: "System", autostart: "Launch at startup", autostart_hint: "Startup-folder shortcut",
    hot: "Hot switch (exp.)", hot_hint: "Switch identity without restarting; falls back on failure",
    hot_note: "Hot switch keeps the client running: plan & quota apply to the new account immediately, but the account name at the client's bottom-left comes from its local cache and only updates after restarting ZCode.",
    lang: "Language",
    bak_title: "Backup / Import accounts", bak_sub: "Bundles are password-encrypted (PBKDF2 + AES-256-GCM) and portable; lost password = lost backup.",
    export_to: "Export to Desktop", bak_ph: "Set password (≥6 chars)", export_btn: "Export .zhb",
    import_from: "Import from file", imp_path_ph: "Full path to .zhb file", imp_pwd_ph: "Backup password", import_btn: "Import",
    close: "Close",
    t_saved: "Saved: {x}", t_deleted: "Deleted", t_settings_saved: "Settings saved", t_notify_on: "Notifications on", t_notify_off: "Notifications off",
    t_autostart_on: "Autostart enabled", t_autostart_off: "Autostart disabled", t_autostart_fail: "Failed to set",
    t_path_saved: "ZCode path saved (empty = auto-detect)",
    t_detected_new: "🎁 New claimable benefits detected ({n}) — open ZCode client to claim",
    t_check_done0: "Check done: {ok}/{all} accounts fine, nothing to claim",
    t_check_done: "Check done: {w}/{all} accounts have 🎁{n} claimable (claim in ZCode client)",
    t_check_fail: "Check failed", t_refresh_fail: "Refresh failed: {e}",
    t_one_has: "🎁 This account has {n} claimable", t_one_none: "Nothing to claim for this account", t_one_fail: "Check failed",
    t_switched_hot: "Hot-switched (client not restarted)", t_switched_re: "Switched, ZCode restarted", t_switched_nore: "Credentials switched — start ZCode manually",
    t_switch_fail: "Switch failed", t_close_fail: "Cannot close ZCode (may be in tray). Quit it manually and retry",
    t_bak_saved: "Backup saved ({n} accounts) → Desktop", t_pwd_short: "Password must be ≥6 chars", t_fill_both: "Fill in path and password first",
    t_imp_done: "Imported: {n} added", t_upd_latest: "Up to date (v{v})", t_upd_found: "🆕 New version v{v} available", t_upd_checking: "Checking…",
    t_upd_fail: "Check failed: {e}",
    c_switch: "Switch to this account?\n{mode}\n(Running tasks will be interrupted)", c_switch_hot: "Hot switch: client keeps running, identity swapped in place.", c_switch_cold: "ZCode will close and restart.",
    c_del: "Delete this account snapshot?\n(ZCode's current login is not affected)", c_kill: "Close ZCode client?",
    install_upd: "⬇ Update & restart now", upd_go: "Download",
  }
};
var LANG = (function() { try { return localStorage.getItem("hub-lang") || ((navigator.language || "zh").indexOf("zh") === 0 ? "zh" : "en"); } catch(e) { return "zh"; } })();
function t(key, vars) {
  var s = (I18N[LANG] && I18N[LANG][key]) || I18N.zh[key] || key;
  if (vars) Object.keys(vars).forEach(function(k) { s = s.replace("{" + k + "}", vars[k]); });
  return s;
}
function applyLang() {
  document.documentElement.lang = LANG === "zh" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach(function(el) { el.textContent = t(el.getAttribute("data-i18n")); });
  document.querySelectorAll("[data-i18n-ph]").forEach(function(el) { el.placeholder = t(el.getAttribute("data-i18n-ph")); });
  var sel = document.getElementById("autoCheckSel");
  if (sel) Array.prototype.forEach.call(sel.options, function(o) { o.textContent = t(o.getAttribute("data-i18n")); });
  var ls = document.getElementById("langSel");
  if (ls) ls.value = LANG;
  var empty = document.getElementById("acctList");
  if (empty && !empty.children.length) { /* re-render happens on refresh */ }
  if (window.__lastState) refresh();
}
function setLang(l) { LANG = l; try { localStorage.setItem("hub-lang", l); } catch(e) {} applyLang(); }

/* ---------------- basics ---------------- */
function invoke(cmd, args) {
  if (window.__TAURI_INTERNALS__) return window.__TAURI_INTERNALS__.invoke(cmd, args || {});
  return Promise.reject("Tauri not ready");
}
function esc(s) { return String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/'/g,"&#39;").replace(/"/g,"&quot;"); }
function fmtT2(v){ if(v==null) return "?";
  var ms = Number(v) < 1e12 ? Number(v)*1000 : Number(v);
  var d = new Date(ms), p = function(n){return String(n).padStart(2,"0");};
  return (d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes()); }
function fmtQ(n){ n=Number(n)||0; var a=Math.abs(n);
  if (LANG === "zh") {
    if(a>=1e8) return (n/1e8).toFixed(a>=1e9?1:2).replace(/\.?0+$/,"")+" 亿";
    if(a>=1e4) return (n/1e4).toFixed(a>=1e6?0:1).replace(/\.0$/,"")+" 万";
    return String(n);
  }
  if(a>=1e9) return (n/1e9).toFixed(2).replace(/\.?0+$/,"")+"B";
  if(a>=1e6) return (n/1e6).toFixed(1).replace(/\.0$/,"")+"M";
  if(a>=1e3) return (n/1e3).toFixed(1).replace(/\.0$/,"")+"K";
  return String(n); }
function pushToast(msg, kind) {
  var box = document.getElementById("toasts");
  var el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg; box.appendChild(el);
  setTimeout(function() { el.style.opacity = "0"; el.style.transition = ".3s"; setTimeout(function(){ el.remove(); }, 320); }, 5200);
}

/* ---------------- theme ---------------- */
function applyTheme(t) {
  document.body.setAttribute("data-theme", t);
  document.documentElement.style.colorScheme = t;
  var b = document.getElementById("themeBtn");
  if (b) b.textContent = t === "light" ? "🌙" : "☀️";
}
function toggleTheme() {
  var cur = document.body.getAttribute("data-theme") === "light" ? "dark" : "light";
  try { localStorage.setItem("hub-theme", cur); } catch(e) {}
  applyTheme(cur);
}
applyTheme((function(){ try { return localStorage.getItem("hub-theme") || "light"; } catch(e) { return "light"; } })());

/* ---------------- window controls & drag ---------------- */
function winMin() { invoke("win_minimize"); }
function winMax() { invoke("win_toggle_maximize"); }
function winHide() { invoke("win_hide"); }
document.addEventListener("mousedown", function(e) {
  if (e.button !== 0) return;
  var bar = e.target.closest(".tbar");
  if (!bar) return;
  if (e.target.closest("button") || e.target.closest("select") || e.target.closest("input")) return;
  if (e.detail >= 2) return;
  invoke("win_start_drag").catch(function(){});
});
document.addEventListener("dblclick", function(e) {
  if (!e.target.closest(".tbar")) return;
  if (e.target.closest("button") || e.target.closest("select") || e.target.closest("input")) return;
  invoke("win_toggle_maximize").catch(function(){});
});

/* ---------------- cards ---------------- */
function provMeta(p) {
  if (p === "bigmodel") return { cls: "bm", tag: "BigModel", tagCls: "bm", ch: "M" };
  if (p === "zai") return { cls: "zai", tag: "Z.AI", tagCls: "zai", ch: "Z" };
  return { cls: "q", tag: t("unknown"), tagCls: "unk", ch: "?" };
}
function planTag(plans, planId) {
  if (!Array.isArray(plans) || !planId) return "";
  var p = plans.filter(function(x){ return x.plan_id === planId; })[0];
  var nm = ((p && p.name) || "") + " " + planId;
  if (/weekend|build|-wk\d/i.test(nm)) return t("week_plan");
  if (/start.?plan/i.test(nm)) return t("base_plan");
  return (p && p.name) || "";
}
/* 即将到期：剩余额度 >0 且 24h 内到期时高亮；≤6h 升级为红色 */
var EXPIRE_SOON_H = 24, EXPIRE_URGENT_H = 6;
function bucketAvail(b) { return Number(b.available_units !== undefined ? b.available_units : b.remaining_units || 0); }
function bucketRemainH(b) {
  var exp = Number(b.expires_at || b.period_end || 0);
  if (!exp) return null;
  if (exp < 1e12) exp *= 1000;
  return (exp - Date.now()) / 3600000;
}
function soonestExpireH(balances) {
  var m = null;
  (balances || []).forEach(function (b) {
    if (bucketAvail(b) <= 0) return;
    var h = bucketRemainH(b);
    if (h !== null && h <= EXPIRE_SOON_H && (m === null || h < m)) m = h;
  });
  return m;
}
function renderBuckets(balances, plans) {
  if (!Array.isArray(balances) || !balances.length) return '<div style="font-size:12px;padding:4px 0;color:var(--faint)">' + esc(t("no_quota")) + '</div>';
  var groups = {}, order = [];
  balances.forEach(function(b) {
    var key = planTag(plans, b.plan_id) || t("other_plan");
    if (!groups[key]) { groups[key] = []; order.push(key); }
    groups[key].push(b);
  });
  var wk = order.indexOf(t("week_plan"));
  if (wk > 0) { order.splice(wk, 1); order.unshift(t("week_plan")); }
  return order.map(function(key) {
    var rows = groups[key].map(function(b) {
      var name = b.show_name || b.model || "?";
      var avail = bucketAvail(b);
      var total = Number(b.total_units || 0); var used = Number(b.used_units || 0);
      var exp = b.expires_at || b.period_end;
      var pct = total > 0 ? Math.round(avail/total*100) : 0;
      var done = avail <= 0; var cls = done ? "done" : (pct < 10 ? "bad" : (pct < 40 ? "warn" : "ok"));
      var remainH = done ? null : bucketRemainH(b);
      var expTxt = exp ? fmtT2(exp) + esc(t("expires")) : "";
      if (remainH !== null && remainH <= EXPIRE_SOON_H) {
        var lbl = remainH < 1 ? esc(t("exp_lt1h")) : esc(t("exp_soon", { h: Math.ceil(remainH) }));
        expTxt = '<span class="expsoon' + (remainH <= EXPIRE_URGENT_H ? ' expbad' : '') + '" title="' + esc(fmtT2(exp)) + '">' + lbl + '</span>';
      }
      return '<div class="brow"><div class="brow-top"><span class="brow-model">'+esc(name)+'</span><span class="brow-nums num">'+ (done?esc(t("used_up")):fmtQ(avail)+esc(t("remain"))) +'</span><span class="brow-pct num" style="color:'+(done?'var(--faint)':pct<10?'var(--bad)':pct<40?'var(--acc2)':'var(--ok)')+'">'+pct+'%</span></div><div class="bar"><i class="'+cls+'" style="width:'+(done?100:pct)+'%"></i></div><div class="brow-sub"><span>'+esc(t("total"))+fmtQ(total)+(used?esc(t("used"))+fmtQ(used):'')+'</span><span class="num">'+expTxt+'</span></div></div>';
    }).join("");
    var week = key === t("week_plan") ? " week" : "";
    return '<div class="pgroup"><div class="plabel'+week+'">'+esc(key)+'</div>'+rows+'</div>';
  }).join("");
}
var prevCounts = {};
function renderBenefitState(b) {
  if (!b) return '<div class="bstate unk">' + esc(t("not_checked")) + '</div>';
  var when = b.checked_at ? ' <span class="whn num">· '+fmtT2(b.checked_at)+'</span>' : "";
  if (b.ok === false) return '<div class="bstate bad">'+esc(t("ben_fail", {e: b.error || "?"}))+'</div>';
  if (!b.count) return '<div class="bstate none">'+esc(t("ben_none"))+when+'</div>';
  var rows = '<div class="campaigns">' + (b.campaigns || []).map(function(c) {
    var detail = c.detail ? ' <span>(' + esc(c.detail) + ')</span>' : "";
    return '<div class="camp"><div class="camp-info"><b>'+esc(c.title)+'</b><span>'+esc(c.grant)+' Token'+detail+'</span></div><button class="camp-btn" data-action="claim">'+esc(t("claim"))+'</button></div>';
  }).join("") + '</div>';
  return '<div class="bstate has">'+esc(t("ben_has", {n: b.count}))+when+'</div>' + rows;
}
function foldState() { try { return JSON.parse(localStorage.getItem("hub-fold") || "{}"); } catch(e) { return {}; } }
function setFold(key, v) {
  var f = foldState(); f[key] = v;
  try { localStorage.setItem("hub-fold", JSON.stringify(f)); } catch(e) {}
  refresh();
}
function isFolded(p) {
  var f = foldState();
  if (f[p.key] !== undefined) return f[p.key];
  return !p.is_current; // 默认：当前账号展开，其余收起
}
function foldAll(v) {
  var st = window.__lastState;
  var f = foldState();
  (st ? st.profiles : []).forEach(function(p) { f[p.key] = v; });
  try { localStorage.setItem("hub-fold", JSON.stringify(f)); } catch(e) {}
  refresh();
}
function cardHtml(p, quotaData, benefitData) {
  var m = provMeta(p.provider);
  var chips = '<span class="chip '+m.cls+'">'+m.ch+'</span>';
  var tags = (p.is_current ? '<span class="tag cur">'+esc(t("current"))+'</span>' : '')
    + (p.provider ? '<span class="tag '+m.tagCls+'">'+esc(m.tag)+'</span>' : '')
    + (p.jwt_expired ? '<span class="tag expired">⚠ '+esc(t("expired"))+'</span>' : '');
  var balances = [], plans = [];
  if (quotaData && quotaData.ok) { var d = quotaData.data; if (d && d.data) { balances = d.data.balances || []; plans = d.data.plans || []; } }
  var expH = (quotaData && quotaData.ok) ? soonestExpireH(balances) : null;
  var buckets = quotaData && quotaData.ok ? renderBuckets(balances, plans)
    : '<div style="font-size:11.5px;color:var(--bad);padding:2px 0">'+esc(quotaData && quotaData.error || t("quota_fail"))+'</div>';
  var benefit = renderBenefitState(benefitData);
  var foot = p.is_current
    ? '<span class="curmark">'+esc(t("use_now"))+'</span>'
    : '<button class="switch-btn" data-action="switch" data-key="'+esc(p.key)+'">'+esc(t("switch_to"))+'</button>';
  var folded = isFolded(p);
  var benCount = (benefitData && benefitData.ok) ? (benefitData.count || 0) : 0;
  return '<div class="acct'+(p.is_current?' cur':'')+(folded?' folded':'')+'"><div class="acct-head" data-action="foldhead" data-key="'+esc(p.key)+'">'+chips
    +'<span class="acct-name">'+esc(p.label)+'</span>'+tags
    +(folded && benCount > 0 ? '<span class="tag hasben">🎁'+benCount+'</span>' : '')
    +(folded && expH !== null ? '<span class="tag exptag'+(expH <= EXPIRE_URGENT_H ? ' expbad' : '')+'" title="'+esc(t("exptag_tip"))+'">⏰</span>' : '')
    +'<button class="chev" title="'+esc(t("mini_title"))+'" data-action="foldchev" data-key="'+esc(p.key)+'">▾</button>'
    +'<button class="acct-x" title="'+esc(t("del_title"))+'" data-action="del" data-key="'+esc(p.key)+'">✕</button></div>'
    +'<div class="acct-body'+(folded?' folded':'')+'">'+buckets+'<div class="bfoot">'+benefit
    +'<button class="mini-check" title="'+esc(t("mini_title"))+'" data-action="checkone" data-key="'+esc(p.key)+'">🔍</button>'+foot+'</div></div></div>';
}

/* ---------------- refresh ---------------- */
var refreshing = false;
window.__lastState = null;
function refresh(done, force) {
  if (refreshing) { if (done) done(); return; }
  refreshing = true;
  invoke("get_state").then(function(st) {
    window.__lastState = st;
    document.getElementById("runDot").className = "dot" + (st.zcode_running ? " on" : "");
    document.getElementById("runText").textContent = st.zcode_running ? t("running") : t("not_running");
    document.getElementById("profCount").textContent = st.profiles.length + t("n_accounts");
    var sel = document.getElementById("autoCheckSel");
    var mins = st.settings && st.settings.auto_check_minutes !== undefined ? st.settings.auto_check_minutes : 15;
    if (document.activeElement !== sel && String(sel.value) !== String(mins)) sel.value = String(mins);
    document.getElementById("notifyTgl").checked = !(st.settings && st.settings.notify_enabled === false);
    document.getElementById("lastCheckTxt").textContent = st.last_check ? t("last_check") + " " + fmtT2(st.last_check) : t("never_checked");
    var bens = st.benefits || {};
    Object.keys(bens).forEach(function(k) {
      var c = bens[k] && bens[k].ok ? (bens[k].count || 0) : 0;
      if (prevCounts[k] !== undefined && c > prevCounts[k] && c > 0) pushToast(t("t_detected_new", {n: c}), "ok");
      prevCounts[k] = c;
    });
    var list = st.profiles.slice().sort(function(a,b){ return (b.is_current?1:0)-(a.is_current?1:0); });
    if (!list.length) list = [{ key: "__current__", label: st.current_label, is_current: true, provider: st.current_provider }];
    Promise.all(list.map(function(p) {
      return invoke("fetch_quota", { key: p.key, force: !!force }).catch(function(e) { return { ok: false, error: String(e) }; })
        .then(function(q) { return cardHtml(p, q, bens[p.key]); });
    })).then(function(cards) {
      document.getElementById("acctList").innerHTML = cards.join("") || '<div class="empty"><div class="big">◈</div><p>'+esc(t("no_accounts"))+'</p></div>';
      refreshing = false; if (done) done();
    });
  }).catch(function(e) { refreshing = false; if (done) done(); pushToast(t("t_refresh_fail", {e: String(e)}), "bad"); });
}

/* ---------------- settings & actions ---------------- */
function setAutoCheck() {
  invoke("set_settings", { minutes: Number(document.getElementById("autoCheckSel").value), notifyEnabled: document.getElementById("notifyTgl").checked }).then(function() {
    pushToast(t("t_settings_saved"), "ok"); refresh();
  }).catch(function(e) { pushToast(String(e), "bad"); });
}
function setNotify(v) {
  invoke("set_settings", { minutes: Number(document.getElementById("autoCheckSel").value), notifyEnabled: !!v }).then(function() {
    pushToast(v ? t("t_notify_on") : t("t_notify_off"), "ok");
  }).catch(function(e) { pushToast(String(e), "bad"); });
}
function doCheck() {
  var btn = document.getElementById("chkBtn");
  btn.disabled = true; btn.textContent = t("checking_dots");
  invoke("check_all_benefits").then(function(r) {
    btn.disabled = false; btn.textContent = t("check_all");
    if (!r.ok) { pushToast(t("t_check_fail"), "bad"); return; }
    if (r.total_campaigns === 0) pushToast(t("t_check_done0", {ok: r.checked_ok, all: r.accounts}), "ok");
    else pushToast(t("t_check_done", {w: r.accounts_with_benefits, all: r.accounts, n: r.total_campaigns}), "warn");
    refresh();
  }).catch(function(e) {
    btn.disabled = false; btn.textContent = t("check_all");
    pushToast(String(e), "bad");
  });
}
function checkOne(key, btn) {
  if (btn.disabled) return;
  var old = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spin-mini"></span>';
  invoke("check_benefits", { key: key }).then(function(r) {
    if (r.ok && r.count > 0) pushToast(t("t_one_has", {n: r.count}), "warn");
    else if (r.ok) pushToast(t("t_one_none"), "ok");
    else pushToast(t("t_one_fail"), "bad");
  }).catch(function(e) { pushToast(String(e), "bad"); })
  .finally(function() { btn.disabled = false; btn.innerHTML = old; refresh(); });
}
function doCapture() { invoke("capture_profile", { name: null }).then(function(r) { if (r.ok) { pushToast(t("t_saved", {x: r.label}), "ok"); refresh(); } else pushToast(r.error, "bad"); }); }
function doSwitch(key) {
  var hot = document.getElementById("hotTgl") && document.getElementById("hotTgl").checked;
  var mode = hot ? t("c_switch_hot") : t("c_switch_cold");
  if (!confirm(t("c_switch", {mode: mode}))) return;
  invoke("switch_profile", { key: key, hot: !!hot }).then(function(r) {
    if (r.ok) {
      if (r.hot) pushToast(t("t_switched_hot"), "ok");
      else pushToast(r.relaunched ? t("t_switched_re") : t("t_switched_nore"), r.relaunched ? "ok" : "warn");
      refresh();
    } else pushToast(r.error || t("t_switch_fail"), "bad");
  });
}
function doDelete(key) { if (!confirm(t("c_del"))) return; invoke("delete_profile", { key: key }).then(function() { pushToast(t("t_deleted"), "ok"); refresh(); }); }
function doKill() { if (!confirm(t("c_kill"))) return; invoke("kill_zcode_client").then(function() { refresh(); }); }
function doOpenClient() { invoke("open_zcode_client"); }

/* ---------------- oauth modal ---------------- */
var oauthTimer = null;
function pollOauthStatus() {
  if (oauthTimer) clearInterval(oauthTimer);
  oauthTimer = setInterval(function() {
    invoke("oauth_status").then(function(s) {
      var st = document.getElementById("oauthStatus");
      if (s.status === "ready") {
        clearInterval(oauthTimer); oauthTimer = null;
        document.getElementById("oauthReopen").style.display = "none";
        st.innerHTML = '<span style="color:var(--ok)">' + esc(t("oauth_ok", {l: s.label || ""})) + (s.provider ? "（" + esc(s.provider) + "）" : "") + '</span>';
        if (s.warning) pushToast("⚠ " + s.warning, "bad"); else pushToast(t("t_saved", {x: s.label}), "ok");
        setTimeout(function() { closeAddModal(); refresh(); }, s.warning ? 2500 : 900);
      } else if (s.status === "failed") {
        clearInterval(oauthTimer); oauthTimer = null;
        document.getElementById("oauthReopen").style.display = "none";
        st.innerHTML = '<span style="color:var(--bad)">' + esc(t("oauth_fail", {e: s.error || "?"})) + '</span>';
      } else if (s.status === "pending") {
        document.getElementById("oauthReopen").style.display = "block";
      }
    }).catch(function() {});
  }, 2000);
}
function doAdd(provider) {
  if (!provider) { document.getElementById("addModal").style.display = "flex"; document.getElementById("oauthStatus").textContent = ""; return; }
  document.getElementById("oauthStatus").innerHTML = '<span class="spin-mini"></span> ' + esc(t("opening", {p: provider === "bigmodel" ? "BigModel" : "Z.AI"}));
  invoke("oauth_start", { provider: provider }).then(function(r) {
    if (r && r.ok === false) document.getElementById("oauthStatus").textContent = (r.error || "failed") + " · " + t("reopen");
    pollOauthStatus();
  }).catch(function(e) { document.getElementById("oauthStatus").textContent = String(e); });
}
function closeAddModal() {
  document.getElementById("addModal").style.display = "none";
  document.getElementById("oauthReopen").style.display = "none";
  if (oauthTimer) { clearInterval(oauthTimer); oauthTimer = null; }
}
function oauthOpen() { invoke("oauth_open").catch(function(e) { pushToast(String(e), "bad"); }); }

/* ---------------- backup modal ---------------- */
function showBak() { document.getElementById("bakModal").style.display = "flex"; document.getElementById("bakStatus").textContent = ""; }
function doExport() {
  var pwd = document.getElementById("bakPwd").value;
  if (!pwd || pwd.length < 6) { pushToast(t("t_pwd_short"), "bad"); return; }
  document.getElementById("bakStatus").textContent = "…";
  invoke("export_bundle", { password: pwd }).then(function(r) {
    document.getElementById("bakStatus").textContent = r.ok ? "✓ " + r.path : "✗ " + (r.error || "failed");
    if (r.ok) pushToast(t("t_bak_saved", {n: r.accounts}), "ok");
  }).catch(function(e) { document.getElementById("bakStatus").textContent = String(e); });
}
function doImport() {
  var p = document.getElementById("impPath").value.trim().replace(/^"|"$/g, "");
  var pwd = document.getElementById("impPwd").value;
  if (!p || !pwd) { pushToast(t("t_fill_both"), "bad"); return; }
  document.getElementById("bakStatus").textContent = "…";
  invoke("import_bundle", { path: p, password: pwd }).then(function(r) {
    if (r.ok) {
      document.getElementById("bakStatus").textContent = "✓ +" + r.added + " / -" + r.skipped;
      pushToast(t("t_imp_done", {n: r.added}), "ok"); refresh();
    } else document.getElementById("bakStatus").textContent = "✗ " + (r.error || "failed");
  }).catch(function(e) { document.getElementById("bakStatus").textContent = String(e); });
}

/* ---------------- settings/about modal ---------------- */
function showCfg() {
  invoke("get_state").then(function(st) {
    window.__lastState = st;
    document.getElementById("cfgVer").textContent = "v" + (st.version || "?");
    document.getElementById("autoStartTgl").checked = !!st.autostart;
    document.getElementById("hotTgl").checked = !!(st.settings && st.settings.hot_switch);
    var zp = st.settings && st.settings.zcode_path ? st.settings.zcode_path : "";
    if (document.activeElement !== document.getElementById("zcPath")) document.getElementById("zcPath").value = zp;
    document.getElementById("updTxt").textContent = "";
    document.getElementById("cfgModal").style.display = "flex";
  });
}
function saveZcPath() {
  var p = document.getElementById("zcPath").value.trim();
  invoke("set_settings", { minutes: Number(document.getElementById("autoCheckSel").value), zcodePath: p }).then(function(r) {
    if (r && r.ok === false) { pushToast(r.error, "bad"); return; }
    pushToast(t("t_path_saved"), "ok");
  }).catch(function(e) { pushToast(String(e), "bad"); });
}
function setAutoStart(v) {
  invoke("set_autostart", { enable: !!v }).then(function(r) {
    pushToast(r.ok ? (r.enabled ? t("t_autostart_on") : t("t_autostart_off")) : t("t_autostart_fail"), r.ok ? "ok" : "bad");
  }).catch(function(e) { pushToast(String(e), "bad"); });
}
function setHot(v) {
  invoke("set_settings", { minutes: Number(document.getElementById("autoCheckSel").value), hotSwitch: !!v }).then(function() {
    pushToast(t("t_settings_saved"), "ok");
  }).catch(function(e) { pushToast(String(e), "bad"); });
}
function doCheckUpdate() {
  var tt = document.getElementById("updTxt");
  tt.textContent = t("t_upd_checking");
  invoke("check_update").then(function(r) {
    if (!r.ok) { tt.textContent = t("t_upd_fail", {e: r.error || "?"}); return; }
    if (!r.latest) { tt.textContent = r.note || t("t_upd_latest", {v: r.current}); return; }
    if (r.up_to_date) tt.textContent = t("t_upd_latest", {v: r.current});
    else {
      tt.innerHTML = esc(t("t_upd_found", {v: r.latest}))
        + ' <a href="#" data-action="install-update" style="color:var(--ok)">' + esc(t("install_upd")) + '</a>'
        + ' · <a href="#" data-action="open-repo" style="color:var(--zai)">' + esc(t("upd_go")) + '</a>';
      pushToast(t("t_upd_found", {v: r.latest}), "warn");
    }
  }).catch(function(e) { tt.textContent = String(e); });
}
function installUpdate() {
  var tt = document.getElementById("updTxt");
  tt.textContent = "⬇ …";
  invoke("install_update").then(function(r) {
    if (r && r.up_to_date) tt.textContent = t("t_upd_latest", {v: r.current || ""});
  }).catch(function(e) { tt.textContent = String(e); });
}
function openUrl(u) { invoke("open_url", { url: u }); }

/* ---------------- event delegation (CSP-safe: no inline handlers) ---------------- */
document.addEventListener("click", function(e) {
  var el = e.target.closest("[data-action]");
  if (!el) return;
  var a = el.getAttribute("data-action");
  var key = el.getAttribute("data-key");
  switch (a) {
    case "theme": toggleTheme(); break;
    case "cfg": showCfg(); break;
    case "min": winMin(); break;
    case "max": winMax(); break;
    case "hide": winHide(); break;
    case "capture": doCapture(); break;
    case "add": doAdd(); break;
    case "bak": showBak(); break;
    case "kill": doKill(); break;
    case "checkall": doCheck(); break;
    case "prov": doAdd(el.getAttribute("data-provider")); break;
    case "oauth-reopen": oauthOpen(); break;
    case "add-cancel": closeAddModal(); break;
    case "bak-export": doExport(); break;
    case "bak-import": doImport(); break;
    case "bak-close": document.getElementById("bakModal").style.display = "none"; break;
    case "cfg-checkupdate": doCheckUpdate(); break;
    case "install-update": e.preventDefault(); installUpdate(); break;
    case "open-repo": e.preventDefault(); openUrl(el.getAttribute("data-url") || "https://github.com/Ebonyhtx/zcode-hub"); break;
    case "cfg-savepath": saveZcPath(); break;
    case "cfg-opendata": invoke("open_data_dir"); break;
    case "cfg-openzdata": invoke("open_zcode_data_dir"); break;
    case "cfg-close": document.getElementById("cfgModal").style.display = "none"; break;
    case "foldhead": case "foldchev": setFold(key, !isFolded({key: key})); break;
    case "foldall": foldAll(true); break;
    case "unfoldall": foldAll(false); break;
    case "switch": doSwitch(key); break;
    case "del": doDelete(key); break;
    case "checkone": checkOne(key, el); break;
    case "claim": doOpenClient(); break;
  }
});
document.addEventListener("change", function(e) {
  var id = e.target.id;
  if (id === "autoCheckSel") setAutoCheck();
  else if (id === "notifyTgl") setNotify(e.target.checked);
  else if (id === "autoStartTgl") setAutoStart(e.target.checked);
  else if (id === "hotTgl") setHot(e.target.checked);
  else if (id === "langSel") setLang(e.target.value);
});
document.addEventListener("keydown", function(e) { if (e.key === "Escape") { closeAddModal(); document.getElementById("cfgModal").style.display = "none"; document.getElementById("bakModal").style.display = "none"; } });

/* ---------------- boot ---------------- */
applyLang();
(function tryStart() {
  if (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke) { refresh(); setInterval(function(){ refresh(); }, 60000); }
  else setTimeout(tryStart, 200);
})();
