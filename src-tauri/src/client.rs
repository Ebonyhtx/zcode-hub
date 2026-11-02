use serde_json::{json, Value};
use std::sync::Mutex;

use crate::formats::{self, read_json};
use crate::platform;
use crate::settings::load_settings;
use crate::util::home_v2;

// exe 路径基本不变：命中缓存 5 分钟（含“没找到”的负结果），避免没装客户端时每 30 秒拉一次 PowerShell
pub(crate) static EXE_CACHE: Mutex<Option<(i64, Option<String>)>> = Mutex::new(None);

pub(crate) static VERSION_CACHE: Mutex<Option<(i64, Option<String>)>> = Mutex::new(None);

pub(crate) const EXE_CACHE_SECS: i64 = 300;

// Hub 对客户端文件格式的知识锚定在 3.17.x；客户端 major.minor 变化即提示兼容风险
pub(crate) const SUPPORTED_CLIENT_VERSION: &str = "3.17";

/// 未检测到客户端时的请求头回退版本（必须是 x.y.z 形态）
pub(crate) const DEFAULT_CLIENT_VERSION: &str = "3.17.1";

pub(crate) fn zcode_client_version() -> Option<String> {
    let mut g = VERSION_CACHE.lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some((ts, v)) = g.as_ref() { if now - ts < 3600 { return v.clone(); } }
    let v = zcode_exe_path().and_then(|exe| platform::exe_product_version(&exe));
    *g = Some((now, v.clone()));
    v
}

pub(crate) fn client_version_supported(detected: &str) -> bool {
    let dm: Vec<&str> = detected.split('.').take(2).collect();
    let sm: Vec<&str> = SUPPORTED_CLIENT_VERSION.split('.').collect();
    dm == sm
}

// 兼容探测汇总：凭据/设置格式健康度 + 客户端版本。errors 非空 = 建议安全模式。
// live 由调用方注入（一次读取，避免 get_state 里重复读盘/解密）。
pub(crate) fn compat_report(live: Option<&Value>) -> serde_json::Value {
    let mut probe = formats::probe_credentials(live);
    let setting = read_json(&home_v2().join("setting.json")).ok();
    let ps = formats::probe_setting(setting.as_ref());
    probe.errors.extend(ps.errors);
    probe.notes.extend(ps.notes);
    let ver = zcode_client_version();
    match &ver {
        Some(v) if !client_version_supported(v) => {
            probe.errors.push(format!("客户端版本 {} 与已验证版本 {} 不同，文件格式可能已变化", v, SUPPORTED_CLIENT_VERSION));
        }
        Some(_) => {}
        None => probe.notes.push("未检测到 ZCode 客户端版本（未安装或未指定路径）".into()),
    }
    json!({"ok": probe.ok(), "errors": probe.errors, "notes": probe.notes, "zcode_version": ver,
           "installed": zcode_exe_path().is_some()})
}

pub(crate) fn http() -> &'static reqwest::blocking::Client {
    HTTP.get_or_init(reqwest::blocking::Client::new)
}

pub(crate) fn zcode_exe_path() -> Option<String> {
    let now = chrono::Utc::now().timestamp();
    {
        let g = EXE_CACHE.lock().unwrap();
        if let Some((ts, p)) = g.as_ref() {
            if now - ts < EXE_CACHE_SECS { return p.clone(); }
        }
    }
    // 用户在设置里指定的路径优先（失效则回落到自动探测，探测在 platform.rs）
    let user_path = load_settings().get("zcode_path").and_then(|v| v.as_str())
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        .filter(|p| std::path::Path::new(p).exists());
    let found = platform::detect_zcode_exe(user_path.as_deref());
    *EXE_CACHE.lock().unwrap() = Some((now, found.clone()));
    found
}

pub(crate) fn zcode_running() -> Result<bool, String> { platform::zcode_running() }

pub(crate) fn kill_zcode_process() -> Result<bool, String> { platform::kill_zcode_process() }

pub(crate) fn launch_zcode_process(exe: &str) -> bool { platform::launch_zcode_process(exe) }

// 客户端完整版本号（事件上报/接口要求 "x.y.z" 形态；失败回退兼容锚点）
pub(crate) fn client_app_version() -> String {
    zcode_client_version().map(|v| {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() >= 3 { format!("{}.{}.{}", parts[0], parts[1], parts[2]) } else { v }
    }).unwrap_or_else(|| DEFAULT_CLIENT_VERSION.to_string())
}

#[tauri::command]
pub(crate) fn open_zcode_client() -> serde_json::Value {
    let exe = zcode_exe_path().unwrap_or_default();
    if exe.is_empty() { return json!({"ok": false, "error": "未找到 ZCode 客户端，请在设置中指定路径"}); }
    json!({"ok": launch_zcode_process(&exe)})
}

#[tauri::command(async)]
pub(crate) fn kill_zcode_client() -> serde_json::Value {
    match kill_zcode_process() {
        Ok(true) => json!({"ok": true}),
        Ok(false) => json!({"ok": false, "error": "无法关闭 ZCode（可能仍在托盘运行），请手动退出"}),
        Err(e) => json!({"ok": false, "error": format!("无法确认 ZCode 进程状态：{}", e)}),
    }
}

pub(crate) static HTTP: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_version_supported_compares_major_minor() {
        assert!(client_version_supported("3.17.0"));
        assert!(client_version_supported("3.17.99"));
        assert!(!client_version_supported("3.18.0"));
        assert!(!client_version_supported("4.0"));
        assert!(!client_version_supported("3.1"));
    }

}
