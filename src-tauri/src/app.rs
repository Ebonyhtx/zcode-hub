use serde_json::{json, Value};
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

use crate::benefits::{check_benefits_many, load_benefits_once, LAST_CHECK, BENEFITS};
use crate::client::{compat_report, launch_zcode_process, zcode_exe_path, zcode_running};
use crate::crypto::{decrypt_value, read_snapshot_checked};
use crate::formats::{self, read_json, write_json};
use crate::identity::{account_label, cred_fingerprint, jwt_expired, profile_label, ProfileInfo};
use crate::platform;
use crate::profiles::all_profile_keys;
use crate::quota::{load_quota_cache_once, QUOTA_CACHE};
use crate::settings::{load_settings, ui_lang, SETTINGS};
use crate::system::autostart_enabled;
use crate::util::{config_path, cred_path, profiles_dir, safe_key};
use crate::window::save_window_state;

// 托盘提示：当前账号 + 待领福利数（自动检测后也会刷新，窗口关闭时同样可见）
pub(crate) fn update_tray_tooltip() {
    let label = if cred_path().exists() {
        read_json(&cred_path()).map(|c| account_label(&c)).unwrap_or("?".into())
    } else { "(未登录)".into() };
    update_tray_tooltip_with(&label);
}

pub(crate) fn update_tray_tooltip_with(label: &str) {
    let Some(h) = APP_HANDLE.lock().unwrap().clone() else { return };
    let Some(tray) = h.tray_by_id("main") else { return };
    let n: u64 = BENEFITS.lock().unwrap().as_ref()
        .map(|m| m.values().filter(|v| v.get("ok").and_then(|b| b.as_bool()) != Some(false))
            .filter_map(|v| v.get("count").and_then(|c| c.as_u64())).sum())
        .unwrap_or(0);
    let en = ui_lang() == "en";
    let label = if label == "(未登录)" { if en { "(not signed in)" } else { "(未登录)" } } else { label };
    let tip = if n > 0 {
        if en { format!("ZCode Hub — current: {} · {} claimable", label, n) }
        else { format!("ZCode Hub — 当前: {} · 🎁 {} 项待领", label, n) }
    } else if en {
        format!("ZCode Hub — current: {}", label)
    } else {
        format!("ZCode Hub — 当前: {}", label)
    };
    let _ = tray.set_tooltip(Some(tip));
}

#[tauri::command(async)]
pub(crate) fn get_state() -> serde_json::Value {
    load_benefits_once();
    load_quota_cache_once();
    let cur = cred_path();
    let live = read_json(&cur).ok();
    let current_logged_in = live.as_ref()
        .map(|c| c.get(formats::FIELD_TOKEN).and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false))
        .unwrap_or(false);
    let cur_label = live.as_ref().map(account_label).unwrap_or("(未登录)".into());
    let dec = |s: &str| decrypt_value(s).ok();
    let cur_provider = live.as_ref().and_then(|c| formats::active_provider_with(c, &dec)).unwrap_or_default();
    let cur_fp = live.as_ref().and_then(cred_fingerprint);
    let mut profiles = Vec::new();
    let pd = profiles_dir();
    if pd.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&pd).map(|rd| rd.filter_map(|e| e.ok()).collect()).unwrap_or_default();
        entries.sort_by_key(|a| a.file_name());
        for e in entries {
            if !e.path().is_dir() { continue; }
            let name = e.file_name().to_string_lossy().to_string();
            if safe_key(&name).is_err() { continue; }
            let meta = read_json(&e.path().join("meta.json")).ok().unwrap_or(json!({}));
            let ca = meta.get("captured_at").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
            let mut provider = meta.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match read_snapshot_checked(&e.path()) {
                Ok(pval) => {
                    if provider.is_empty() {
                        provider = formats::active_provider_with(&pval, &dec).unwrap_or_default();
                    }
                    let label = profile_label(&meta, &pval);
                    let ic = match (cur_fp.as_ref(), cred_fingerprint(&pval)) {
                        (Some(a), Some(b)) => *a == b,
                        _ => false,
                    };
                    let je = jwt_expired(&pval);
                    profiles.push(ProfileInfo { key: name, label, captured_at: ca, is_current: ic, provider, jwt_expired: je, error: None });
                }
                Err(err) => {
                    let label = meta.get("label").and_then(|v| v.as_str()).unwrap_or(&name).to_string();
                    profiles.push(ProfileInfo { key: name, label, captured_at: ca, is_current: false, provider, jwt_expired: false, error: Some(err) });
                }
            }
        }
    }
    let benefits = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    let quota_cache = {
        let g = QUOTA_CACHE.lock().unwrap();
        let mut obj = serde_json::Map::new();
        if let Some(map) = g.as_ref() {
            for (k, (_ts, v)) in map { obj.insert(k.clone(), v.clone()); }
        }
        Value::Object(obj)
    };
    update_tray_tooltip_with(&cur_label);
    let run = zcode_running();
    let (running, process_error) = match run { Ok(v) => (v, Value::Null), Err(e) => (false, json!(e)) };
    json!({ "current_label": cur_label, "current_provider": cur_provider, "current_logged_in": current_logged_in,
            "profiles": profiles, "zcode_running": running, "process_error": process_error,
            "zcode_exe": zcode_exe_path().unwrap_or_default(),
            "settings": load_settings(), "benefits": benefits, "last_check": *LAST_CHECK.lock().unwrap(),
            "quota_cache": quota_cache,
            "version": env!("CARGO_PKG_VERSION"), "autostart": autostart_enabled(), "compat": compat_report(live.as_ref()) })
}

// 全量检测所有账号福利；发现可领且通知开关开启时弹系统通知（托盘菜单与自动循环共用）
pub(crate) fn notification_payload(total: u64, accounts: u64, failed: u64, enabled: bool, force: bool, lang: &str) -> Option<(String, String)> {
    if !force && (!enabled || total == 0) { return None; }
    if total > 0 {
        Some(if lang == "en" {
            ("ZCode Hub · Benefits available".to_string(),
             format!("{} claimable across {} account(s). Open the app to claim.", total, accounts))
        } else {
            ("ZCode Hub 福利提醒".to_string(),
             format!("{} 个账号共有 {} 项福利可领取，打开应用查看", accounts, total))
        })
    } else if failed > 0 {
        Some(if lang == "en" {
            ("ZCode Hub · Check finished".to_string(),
             format!("{failed} account(s) could not be checked; the rest have nothing to claim."))
        } else {
            ("ZCode Hub 检测完成".to_string(),
             format!("{failed} 个账号暂时无法检测，其余账号暂无待领福利"))
        })
    } else {
        Some(if lang == "en" {
            ("ZCode Hub · Check finished".to_string(), "Nothing to claim right now.".to_string())
        } else {
            ("ZCode Hub 检测完成".to_string(), "当前没有待领福利".to_string())
        })
    }
}

pub(crate) fn check_all_and_notify(app: &tauri::AppHandle, force_notify: bool) -> (u64, u64) {
    let keys = all_profile_keys();
    let st = check_benefits_many(&keys);
    if st.okn > 0 { *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp()); }
    let enabled = load_settings().get("notify_enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    if let Some((title, body)) = notification_payload(st.total, st.with, st.failed, enabled, force_notify, &ui_lang()) {
        if st.total > 0 { platform::beep(); } // 只有真的有待领福利才响，避免“无结果”也吓人
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification().builder().title(title).body(body).show();
    }
    (st.okn, st.failed)
}

// 自动检测线程：每 30s 醒来按设置的周期跑一轮；连续失败按 1→2→5→10 分钟退避
pub(crate) fn auto_check_loop(app: tauri::AppHandle) {
    static COOLDOWN_UNTIL: Mutex<i64> = Mutex::new(0);
    static FAILS: Mutex<u32> = Mutex::new(0);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let minutes = load_settings().get("auto_check_minutes").and_then(|v| v.as_i64()).unwrap_or(0);
        if minutes <= 0 { continue; }
        let now = chrono::Utc::now().timestamp();
        if now < *COOLDOWN_UNTIL.lock().unwrap() { continue; }
        let due = match *LAST_CHECK.lock().unwrap() { None => true, Some(l) => now - l >= minutes * 60 - 15 };
        if !due { continue; }
        let (okn, failed) = check_all_and_notify(&app, false);
        if okn == 0 && failed > 0 {
            let streak = { let mut f = FAILS.lock().unwrap(); *f = (*f + 1).min(4); *f };
            let backoff = 60i64.saturating_mul(1i64 << streak.min(4)).min(900);
            *COOLDOWN_UNTIL.lock().unwrap() = chrono::Utc::now().timestamp() + backoff;
        } else {
            *FAILS.lock().unwrap() = 0;
            *COOLDOWN_UNTIL.lock().unwrap() = 0;
        }
    }
}

/// 关闭请求：按设置隐藏到托盘或退出；首次隐藏时发一条系统通知，避免用户以为程序已退出。
pub(crate) fn request_close(app: &tauri::AppHandle) -> bool {
    save_window_state(app);
    let action = load_settings().get("close_action").and_then(|v| v.as_str()).unwrap_or("tray").to_string();
    if action == "quit" { app.exit(0); return false; }
    if let Some(w) = app.get_webview_window("main") { let _ = w.hide(); }
    let first = load_settings().get("close_hint_shown").and_then(|v| v.as_bool()) != Some(true);
    if first {
        let mut s = load_settings();
        s["close_hint_shown"] = json!(true);
        let _ = write_json(&config_path(), &s);
        *SETTINGS.lock().unwrap() = Some(s);
        use tauri_plugin_notification::NotificationExt;
        let (title, body) = if ui_lang() == "en" {
            ("ZCode Hub is still running".to_string(),
             "It stays in the system tray. Right-click the tray icon to quit.".to_string())
        } else {
            ("ZCode Hub 仍在后台运行".to_string(),
             "已最小化到系统托盘；右键托盘图标可退出。".to_string())
        };
        let _ = app.notification().builder().title(title).body(body).show();
    }
    true
}

pub(crate) fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // 菜单固定双语：语言切换不需要重建托盘菜单，也不会出现只懂中文/只懂英文的入口
    let show = MenuItem::with_id(app, "show", "显示 ZCode Hub / Show", true, None::<&str>)?;
    let check = MenuItem::with_id(app, "check", "立即检测福利 / Check now", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "打开 ZCode / Open ZCode", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "退出 / Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &check, &open, &sep, &quit])?;

    let icon_bytes = include_bytes!("../icons/icon.png");
    let icon = tauri::image::Image::from_bytes(icon_bytes)?;

    TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("ZCode Hub")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            match event.id.as_ref() {
                "show" => {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
                "check" => {
                    let h = app.clone();
                    std::thread::spawn(move || { let _ = check_all_and_notify(&h, true); });
                }
                "open" => {
                    std::thread::spawn(|| {
                        if let Some(exe) = zcode_exe_path() { let _ = launch_zcode_process(&exe); }
                    });
                }
                "quit" => { save_window_state(app); app.exit(0); }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                let app = tray.app_handle();
                if let Some(w) = app.get_webview_window("main") {
                    match w.is_visible() {
                        Ok(true) => { let _ = w.hide(); }
                        _ => { let _ = w.show(); let _ = w.set_focus(); }
                    }
                }
            }
        })
        .build(app)?;
    Ok(())
}

pub(crate) static APP_HANDLE: Mutex<Option<tauri::AppHandle>> = Mutex::new(None);



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_payload_respects_toggle_and_manual_force() {
        // 自动检测：关闭通知或无福利 → 不提醒
        assert!(notification_payload(0, 0, 0, true, false, "zh").is_none());
        assert!(notification_payload(3, 2, 0, false, false, "zh").is_none());
        // 自动检测：有福利且开启通知 → 中英文都包含账号/数量
        let (_, zh) = notification_payload(3, 2, 0, true, false, "zh").unwrap();
        assert!(zh.contains('2') && zh.contains('3'));
        let (_, en) = notification_payload(3, 2, 0, true, false, "en").unwrap();
        assert!(en.contains("2") && en.contains("3"));
        // 手动托盘检测：即使无福利也要给结果反馈；有失败时说明失败数
        let (_, none) = notification_payload(0, 0, 0, false, true, "zh").unwrap();
        assert!(none.contains("没有"));
        let (_, fail) = notification_payload(0, 0, 2, false, true, "en").unwrap();
        assert!(fail.contains('2'));
    }

}
