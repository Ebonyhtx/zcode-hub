use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::client::http;
use crate::platform;
use crate::util::{app_data_dir, audit_log, v2_dir};

// 自启快捷方式与目录/浏览器打开收敛到 platform.rs
pub(crate) fn autostart_enabled() -> bool {
    platform::autostart_enabled()
}

#[tauri::command(async)]
pub(crate) fn set_autostart(enable: bool) -> serde_json::Value {
    match platform::set_autostart_internal(enable) {
        Ok(()) => {
            audit_log("autostart", None, json!({"enabled": enable}));
            json!({"ok": true, "enabled": autostart_enabled()})
        }
        Err(e) => json!({"ok": false, "error": e}),
    }
}

pub(crate) fn open_in_explorer(dir: &PathBuf) -> serde_json::Value {
    if !dir.exists() {
        let _ = std::fs::create_dir_all(dir);
    }
    platform::open_dir_explorer(dir);
    json!({"ok": true})
}

#[tauri::command]
pub(crate) fn open_data_dir() -> serde_json::Value {
    open_in_explorer(&app_data_dir())
}

#[tauri::command]
pub(crate) fn open_zcode_data_dir() -> serde_json::Value {
    open_in_explorer(&v2_dir())
}

// 检查更新：查 GitHub Releases 最新 tag（仓库转公开后自动生效；私有期间友好降级）
#[tauri::command(async)]
pub(crate) fn check_update() -> serde_json::Value {
    let current = env!("CARGO_PKG_VERSION");
    // 走 releases/latest/download/latest.json（CDN 静态文件，无 GitHub API 未认证限频）
    let resp = http()
        .get("https://github.com/Ebonyhtx/zcode-hub/releases/latest/download/latest.json")
        .header("User-Agent", "zcode-hub")
        .timeout(std::time::Duration::from_secs(15))
        .send();
    match resp {
        Ok(r) if r.status().is_success() => {
            let j: Value = match r.json() {
                Ok(j) => j,
                Err(e) => return json!({"ok": false, "error": e.to_string()}),
            };
            let latest = j
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_start_matches('v')
                .to_string();
            let pv = |s: &str| {
                s.split('.')
                    .map(|x| x.parse::<u64>().unwrap_or(0))
                    .collect::<Vec<u64>>()
            };
            let (a, b) = (pv(&latest), pv(current));
            let mut up_to_date = true;
            for i in 0..3 {
                let l = a.get(i).unwrap_or(&0);
                let c = b.get(i).unwrap_or(&0);
                if l > c {
                    up_to_date = false;
                    break;
                }
                if l < c {
                    up_to_date = true;
                    break;
                }
            }
            json!({"ok": true, "current": current, "latest": latest, "up_to_date": up_to_date,
                   "url": "https://github.com/Ebonyhtx/zcode-hub/releases/latest"})
        }
        Ok(r) => {
            json!({"ok": false, "error": format!("检查更新失败（HTTP {}），请稍后重试", r.status().as_u16())})
        }
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

#[tauri::command]
pub(crate) fn open_url(url: String) -> serde_json::Value {
    let valid = url::Url::parse(&url)
        .ok()
        .map(|u| u.scheme() == "https" && u.host_str().is_some())
        .unwrap_or(false);
    if !valid {
        return json!({"ok": false, "error": "仅允许有效的 https 链接"});
    }
    platform::open_in_browser(&url);
    json!({"ok": true})
}
#[tauri::command]
pub(crate) fn reveal_file(path: String) -> serde_json::Value {
    let p = std::path::PathBuf::from(path);
    if !p.exists() {
        return json!({"ok": false, "error": "文件不存在"});
    }
    platform::reveal_in_explorer(&p);
    json!({"ok": true})
}

pub(crate) static UPDATE_PROGRESS: Mutex<(u64, u64)> = Mutex::new((0, 0));

#[tauri::command]
pub(crate) fn update_progress() -> serde_json::Value {
    let (d, t) = *UPDATE_PROGRESS.lock().unwrap();
    json!({"downloaded": d, "total": t})
}

#[tauri::command]
pub(crate) async fn install_update(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| e.to_string())?;
    match update {
        Some(u) => {
            *UPDATE_PROGRESS.lock().unwrap() = (0, 0);
            let result = u
                .download_and_install(
                    |chunk, total| {
                        let mut g = UPDATE_PROGRESS.lock().unwrap();
                        g.0 = g.0.saturating_add(chunk as u64);
                        if let Some(t) = total {
                            g.1 = t;
                        }
                    },
                    || {},
                )
                .await;
            *UPDATE_PROGRESS.lock().unwrap() = (0, 0);
            match result {
                Ok(()) => {
                    app.restart();
                }
                Err(e) => Err(format!("更新下载/安装失败：{}。已保持当前版本运行", e)),
            }
        }
        None => Ok(json!({"ok": true, "up_to_date": true})),
    }
}
