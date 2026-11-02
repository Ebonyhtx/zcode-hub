use serde_json::{json, Value};
use std::sync::Mutex;

use crate::benefits::LAST_CHECK;
use crate::client::EXE_CACHE;
use crate::formats::{read_json, write_json};
use crate::util::{audit_log, config_path};

pub(crate) static SETTINGS: Mutex<Option<Value>> = Mutex::new(None);

pub(crate) fn load_settings() -> Value {
    let mut st = SETTINGS.lock().unwrap();
    if st.is_none() {
        *st = Some(read_json(&config_path()).unwrap_or(json!({
            "auto_check_minutes": 15, "notify_enabled": true, "hot_switch": false,
            "safe_mode": false, "lang": "zh", "close_action": "tray", "start_minimized": false,
            "quota_notify": true, "auto_backup": true, "update_notify": true,
            "last_backup_at": 0, "last_update_check": 0
        })));
    }
    st.clone().unwrap()
}

/// 持久化并刷新进程内缓存（设置命令、备份/更新循环共用）。
pub(crate) fn save_settings(s: &Value) -> Result<(), String> {
    write_json(&config_path(), s)?;
    *SETTINGS.lock().unwrap() = Some(s.clone());
    Ok(())
}

#[tauri::command]
pub(crate) fn get_settings() -> serde_json::Value {
    load_settings()
}

#[tauri::command(async)]
#[allow(clippy::too_many_arguments)] // Tauri 命令参数必须平铺；前端按字段名调用
pub(crate) fn set_settings(
    minutes: Option<i64>,
    notify_enabled: Option<bool>,
    zcode_path: Option<String>,
    hot_switch: Option<bool>,
    safe_mode: Option<bool>,
    lang: Option<String>,
    close_action: Option<String>,
    start_minimized: Option<bool>,
    quota_notify: Option<bool>,
    auto_backup: Option<bool>,
    update_notify: Option<bool>,
) -> serde_json::Value {
    let mut s = load_settings();
    let patch = SettingsPatch {
        minutes,
        notify_enabled,
        hot_switch,
        safe_mode,
        lang,
        close_action,
        start_minimized,
        quota_notify,
        auto_backup,
        update_notify,
    };
    let minutes_changed = apply_settings_patch(&mut s, &patch);
    // None = 未传（保持原值）；Some("") = 显式清空为自动探测
    if let Some(raw) = zcode_path {
        let zp = normalize_zcode_path(&raw);
        if zp.is_empty() {
            s["zcode_path"] = json!(null);
            *EXE_CACHE.lock().unwrap() = None;
        } else if std::path::Path::new(&zp).is_file() {
            s["zcode_path"] = json!(zp);
            *EXE_CACHE.lock().unwrap() = None;
        } else {
            return json!({"ok": false, "error": format!("路径不存在或不是文件: {}", zp)});
        }
    }
    if let Err(e) = write_json(&config_path(), &s) {
        return json!({"ok": false, "error": format!("保存设置失败: {}", e)});
    }
    audit_log(
        "settings",
        None,
        json!({
            "auto_check_minutes": s["auto_check_minutes"], "notify_enabled": s["notify_enabled"],
            "hot_switch": s["hot_switch"], "safe_mode": s["safe_mode"],
            "lang": s["lang"], "close_action": s["close_action"], "start_minimized": s["start_minimized"],
            "quota_notify": s["quota_notify"], "auto_backup": s["auto_backup"], "update_notify": s["update_notify"],
            "zcode_path_set": !s["zcode_path"].is_null()
        }),
    );
    *SETTINGS.lock().unwrap() = Some(s.clone());
    if minutes_changed {
        *LAST_CHECK.lock().unwrap() = None;
    }
    json!({"ok": true, "settings": s})
}

#[derive(Default)]
pub(crate) struct SettingsPatch {
    minutes: Option<i64>,
    notify_enabled: Option<bool>,
    hot_switch: Option<bool>,
    safe_mode: Option<bool>,
    lang: Option<String>,
    close_action: Option<String>,
    start_minimized: Option<bool>,
    quota_notify: Option<bool>,
    auto_backup: Option<bool>,
    update_notify: Option<bool>,
}

/// 纯函数：部分更新设置（None = 未传，保持原值）；返回自动检测周期是否变化。
pub(crate) fn apply_settings_patch(s: &mut Value, p: &SettingsPatch) -> bool {
    let mut minutes_changed = false;
    if let Some(m) = p.minutes {
        let m = m.clamp(0, 1440);
        if s.get("auto_check_minutes").and_then(|v| v.as_i64()) != Some(m) {
            s["auto_check_minutes"] = json!(m);
            minutes_changed = true;
        }
    }
    if let Some(n) = p.notify_enabled {
        s["notify_enabled"] = json!(n);
    }
    if let Some(h) = p.hot_switch {
        s["hot_switch"] = json!(h);
    }
    if let Some(sm) = p.safe_mode {
        s["safe_mode"] = json!(sm);
    }
    if let Some(l) = &p.lang {
        if l == "zh" || l == "en" {
            s["lang"] = json!(l);
        }
    }
    if let Some(c) = &p.close_action {
        if c == "tray" || c == "quit" {
            s["close_action"] = json!(c);
        }
    }
    if let Some(v) = p.start_minimized {
        s["start_minimized"] = json!(v);
    }
    if let Some(v) = p.quota_notify {
        s["quota_notify"] = json!(v);
    }
    if let Some(v) = p.auto_backup {
        s["auto_backup"] = json!(v);
    }
    if let Some(v) = p.update_notify {
        s["update_notify"] = json!(v);
    }
    minutes_changed
}

/// 路径输入清洗：去掉包裹引号与空白（资源管理器"复制为路径"会带引号）。
pub(crate) fn normalize_zcode_path(raw: &str) -> String {
    raw.trim().trim_matches('"').to_string()
}

pub(crate) fn ui_lang() -> String {
    load_settings()
        .get("lang")
        .and_then(|v| v.as_str())
        .unwrap_or("zh")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_patch_clamps_and_validates() {
        let mut s = json!({"auto_check_minutes": 15, "notify_enabled": true, "lang": "zh"});
        assert!(apply_settings_patch(
            &mut s,
            &SettingsPatch {
                minutes: Some(99999),
                ..Default::default()
            }
        ));
        assert_eq!(s["auto_check_minutes"], json!(1440));
        // 相同值不触发 last_check 重置
        assert!(!apply_settings_patch(
            &mut s,
            &SettingsPatch {
                minutes: Some(1440),
                ..Default::default()
            }
        ));
        assert!(apply_settings_patch(
            &mut s,
            &SettingsPatch {
                minutes: Some(-5),
                ..Default::default()
            }
        ));
        assert_eq!(s["auto_check_minutes"], json!(0));
        // 非法枚举值被忽略；缺省字段保持原值
        apply_settings_patch(
            &mut s,
            &SettingsPatch {
                lang: Some("fr".into()),
                close_action: Some("explode".into()),
                ..Default::default()
            },
        );
        assert_eq!(s["lang"], json!("zh"));
        assert!(s.get("close_action").is_none());
        apply_settings_patch(
            &mut s,
            &SettingsPatch {
                lang: Some("en".into()),
                close_action: Some("quit".into()),
                notify_enabled: Some(false),
                start_minimized: Some(true),
                quota_notify: Some(false),
                auto_backup: Some(false),
                update_notify: Some(false),
                ..Default::default()
            },
        );
        assert_eq!(s["lang"], json!("en"));
        assert_eq!(s["close_action"], json!("quit"));
        assert_eq!(s["notify_enabled"], json!(false));
        assert_eq!(s["start_minimized"], json!(true));
        assert_eq!(s["quota_notify"], json!(false));
        assert_eq!(s["auto_backup"], json!(false));
        assert_eq!(s["update_notify"], json!(false));
    }

    #[test]
    fn normalize_zcode_path_trims_wrapping_quotes() {
        assert_eq!(
            normalize_zcode_path("  \"C:\\Program Files\\ZCode\\ZCode.exe\"  "),
            "C:\\Program Files\\ZCode\\ZCode.exe"
        );
        assert_eq!(normalize_zcode_path("   "), "");
        assert_eq!(normalize_zcode_path("\"C:\\x.exe"), "C:\\x.exe");
    }
}
