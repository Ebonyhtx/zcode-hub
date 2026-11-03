use serde_json::{json, Value};
use std::path::Path;

use crate::benefits::{load_benefits_once, BENEFITS};
use crate::client::{compat_report, zcode_running};
use crate::formats::read_json;
use crate::quota::{load_quota_cache_once, QUOTA_CACHE};
use crate::settings::load_settings;
use crate::util::{app_data_dir, cred_path, opaque_key, profiles_dir, safe_key};

/// 设置脱敏：路径可能包含用户名，只报告是否设置；窗口几何/开关保持原样。
fn sanitize_settings(s: &Value) -> Value {
    let mut out = s.clone();
    if let Some(obj) = out.as_object_mut() {
        let has_path = obj.get("zcode_path").map(|v| !v.is_null()).unwrap_or(false);
        obj.remove("zcode_path");
        obj.insert("zcode_path_set".into(), json!(has_path));
    }
    out
}

fn tail_lines(path: &Path, max: usize) -> Vec<String> {
    let Ok(txt) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = txt.lines().collect();
    lines
        .iter()
        .rev()
        .take(max)
        .rev()
        .map(|s| s.to_string())
        .collect()
}

/// 脱敏诊断报告：版本/环境/兼容状态/账号与额度摘要/审计尾部。
/// 不包含 token、邮箱、展示名或真实账号目录名（统一哈希）。
pub(crate) fn build_report() -> Value {
    load_benefits_once();
    load_quota_cache_once();
    let live = read_json(&cred_path()).ok();
    let mut profiles = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if safe_key(&name).is_err() {
                continue;
            }
            let meta = read_json(&e.path().join("meta.json"))
                .ok()
                .unwrap_or(json!({}));
            let tags: Vec<String> = meta
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            profiles.push(json!({
                "key": opaque_key(&name),
                "provider": meta.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
                "has_device_mid": meta.get("device_mid").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
                "has_arms_uid": meta.get("arms_uid").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
                "tags": tags,
                "snapshot": e.path().join("credentials.snap").exists(),
            }));
        }
    }
    let benefits = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    let benefit_summary: Vec<Value> = benefits
        .iter()
        .map(|(k, v)| {
            json!({
                "key": opaque_key(k),
                "ok": v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false),
                "count": v.get("count").and_then(|c| c.as_u64()).unwrap_or(0),
            })
        })
        .collect();
    let quota = QUOTA_CACHE.lock().unwrap().clone().unwrap_or_default();
    let quota_summary: Vec<Value> = quota
        .iter()
        .map(|(k, (ts, v))| {
            json!({
                "key": opaque_key(k),
                "age_secs": chrono::Utc::now().timestamp().saturating_sub(*ts),
                "ok": v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false),
                "code": v.get("code").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let (running, process_error) = match zcode_running() {
        Ok(v) => (v, Value::Null),
        Err(e) => (false, json!(e)),
    };
    json!({
        "format": "zcode-hub-diagnostics", "version": 1,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "hub_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "settings": sanitize_settings(&load_settings()),
        "compat": compat_report(live.as_ref()),
        "zcode_running": running, "process_error": process_error,
        "profiles": profiles,
        "benefits": benefit_summary,
        "quota": quota_summary,
        "startup_log": tail_lines(&app_data_dir().join("startup.log"), 50),
        "audit_tail": tail_lines(&crate::audit::audit_path(&app_data_dir()), 100),
        "crash_log": crate::crash::tail(&crate::crash::crash_path(&app_data_dir()), 20),
    })
}

#[tauri::command(async)]
pub(crate) fn export_diagnostics(path: String) -> Value {
    let p = std::path::PathBuf::from(path);
    let body = match serde_json::to_vec_pretty(&build_report()) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": e.to_string()}),
    };
    match std::fs::write(&p, body) {
        Ok(()) => json!({"ok": true, "path": p.display().to_string()}),
        Err(e) => json!({"ok": false, "error": format!("写入失败: {}", e)}),
    }
}

/// 启动耗时基线：追加一行到 %APPDATA%/zcode-hub/startup.log，保留最近 200 行。
pub(crate) fn record_startup(elapsed_ms: u128) {
    let p = app_data_dir().join("startup.log");
    let line = json!({"ts": chrono::Utc::now().to_rfc3339(),
                      "version": env!("CARGO_PKG_VERSION"), "ms": elapsed_ms})
    .to_string();
    let mut lines = tail_lines(&p, 199);
    lines.push(line);
    let _ = std::fs::create_dir_all(app_data_dir());
    let _ = std::fs::write(&p, lines.join("\n") + "\n");
}

/// 前端上报的未捕获异常/资源加载失败（WebView 崩溃前常见线索）。
/// 只记消息与来源；`source` 经 `crash::redact_path` 压成文件名。
#[tauri::command(async)]
pub(crate) fn report_frontend_error(
    message: String,
    source: Option<String>,
    stack: Option<String>,
) -> Value {
    let source = source.unwrap_or_default();
    if message.trim().is_empty() && source.trim().is_empty() {
        return json!({"ok": false, "error": "空错误"});
    }
    let mut extra = json!({"source": crate::crash::redact_path(&source)});
    if let Some(st) = stack.filter(|s| !s.trim().is_empty()) {
        extra["stack"] = json!(crate::crash::clamp_msg(&st));
    }
    let _ = crate::crash::append(
        &crate::crash::crash_path(&app_data_dir()),
        "frontend",
        &message,
        None,
        Some(extra),
    );
    json!({"ok": true})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_settings_drops_path_but_reports_presence() {
        let s = json!({"zcode_path": "C:\\Users\\alice\\ZCode.exe", "lang": "zh"});
        let out = sanitize_settings(&s);
        assert!(out.get("zcode_path").is_none());
        assert_eq!(out["zcode_path_set"], json!(true));
        assert_eq!(out["lang"], json!("zh"));
        assert_eq!(
            sanitize_settings(&json!({"lang": "en"}))["zcode_path_set"],
            json!(false)
        );
    }
}
