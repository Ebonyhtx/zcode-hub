#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine;
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

const CRED_FILE: &str = "credentials.json";
const ENC_PREFIX: &str = "enc:v1:";

// ------------------------------------------------------------------- crypto

fn credential_secret() -> String {
    if let Ok(env) = std::env::var("ZCODE_CREDENTIAL_SECRET") {
        if !env.trim().is_empty() { return env.trim().to_string(); }
    }
    let home = dirs::home_dir().unwrap_or_default().to_string_lossy().to_string();
    let user = whoami::username();
    format!("zcode-credential-fallback:win32:{}:{}", home, user)
}

fn derive_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn decrypt_value(encrypted: &str) -> Result<String, String> {
    let payload = encrypted.strip_prefix(ENC_PREFIX).ok_or("not encrypted")?;
    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() != 3 { return Err("invalid format".into()); }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let iv = engine.decode(parts[0]).map_err(|e| e.to_string())?;
    let tag = engine.decode(parts[1]).map_err(|e| e.to_string())?;
    let ct = engine.decode(parts[2]).map_err(|e| e.to_string())?;
    let key = derive_key(&credential_secret());
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&iv);
    let mut combined = ct;
    combined.extend_from_slice(&tag);
    let plain = cipher.decrypt(nonce, combined.as_ref()).map_err(|e| e.to_string())?;
    String::from_utf8(plain).map_err(|e| e.to_string())
}

// -------------------------------------------------------------------- paths

fn v2_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".zcode").join("v2")
}
fn cred_path() -> PathBuf { v2_dir().join(CRED_FILE) }
fn profiles_dir() -> PathBuf { PathBuf::from("D:\\zcode-hub\\profiles") }

fn read_json(path: &PathBuf) -> Result<Value, String> {
    let c = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&c).map_err(|e| e.to_string())
}

fn write_json(path: &PathBuf, v: &Value) -> Result<(), String> {
    if let Some(p) = path.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
    std::fs::write(path, serde_json::to_string_pretty(v).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

// ------------------------------------------------------------- account label

fn account_label(creds: &Value) -> String {
    if let Some(raw) = creds.get("oauth:zai:user_info").and_then(|v| v.as_str()) {
        if let Ok(plain) = decrypt_value(raw) {
            if let Ok(info) = serde_json::from_str::<Value>(&plain) {
                for k in ["name", "nickname", "email", "username"] {
                    if let Some(v) = info.get(k).and_then(|v| v.as_str()) { if !v.is_empty() { return v.to_string(); } }
                }
            }
        }
    }
    if let Some(raw) = creds.get("zcodejwttoken").and_then(|v| v.as_str()) {
        if let Ok(plain) = decrypt_value(raw) {
            let parts: Vec<&str> = plain.split('.').collect();
            if parts.len() >= 2 {
                let padded = format!("{}{}", parts[1], "=".repeat((4 - parts[1].len() % 4) % 4));
                if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&padded) {
                    if let Ok(claims) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&bytes)) {
                        for k in ["name", "email", "sub"] {
                            if let Some(v) = claims.get(k).and_then(|v| v.as_str()) { return v.to_string(); }
                        }
                    }
                }
            }
        }
    }
    match creds.get("oauth:active_provider").and_then(|v| v.as_str()) {
        Some(ap) if ap.starts_with("enc:") => "(已加密账号)".into(),
        Some(ap) => ap.to_string(),
        _ => "(未知)".into(),
    }
}

// ------------------------------------------------------------------- process

fn zcode_running() -> bool {
    Command::new("tasklist").args(["/FI", "IMAGENAME eq ZCode.exe", "/NH"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("ZCode.exe")).unwrap_or(false)
}

fn zcode_exe_path() -> Option<String> {
    Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-Process ZCode -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path"])
        .output().ok()
        .and_then(|o| { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } })
}

fn kill_zcode_process() -> bool {
    Command::new("taskkill").args(["/IM", "ZCode.exe", "/T"]).output().is_ok()
}

fn launch_zcode_process(exe: &str) -> bool {
    Command::new(exe).current_dir(std::path::Path::new(exe).parent().unwrap_or(std::path::Path::new("."))).spawn().is_ok()
}

fn telemetry_device_mid() -> String {
    read_json(&v2_dir().join("telemetry-state.json")).ok()
        .and_then(|v| v.get("deviceMid").and_then(|v| v.as_str()).map(String::from)).unwrap_or_default()
}

// ------------------------------------------------------------------- structs

#[derive(serde::Serialize)]
struct ProfileInfo { key: String, label: String, captured_at: String, is_current: bool }

#[tauri::command]
fn get_state() -> serde_json::Value {
    let cur = cred_path();
    let cur_label = if cur.exists() { read_json(&cur).map(|c| account_label(&c)).unwrap_or("(err)".into()) } else { "(未登录)".into() };
    let cur_sha = std::fs::read(&cur).ok().map(|b| Sha256::digest(&b).to_vec());
    let mut profiles = Vec::new();
    let pd = profiles_dir();
    if pd.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&pd).map(|rd| rd.filter_map(|e| e.ok()).collect()).unwrap_or_default();
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        for e in entries {
            let name = e.file_name().to_string_lossy().to_string();
            let cp = e.path().join(CRED_FILE);
            if !cp.exists() { continue; }
            let label = read_json(&cp).map(|c| account_label(&c)).unwrap_or("?".into());
            let ca = read_json(&e.path().join("meta.json")).ok().and_then(|m| m.get("captured_at").and_then(|v| v.as_str()).map(String::from)).unwrap_or_default();
            let ic = std::fs::read(&cp).ok().map(|b| Sha256::digest(&b).to_vec()).map(|h| Some(h) == cur_sha).unwrap_or(false);
            profiles.push(ProfileInfo { key: name, label, captured_at: ca, is_current: ic });
        }
    }
    json!({ "current_label": cur_label, "profiles": profiles, "zcode_running": zcode_running(), "zcode_exe": zcode_exe_path().unwrap_or_default() })
}

#[tauri::command]
fn capture_profile(name: Option<String>) -> serde_json::Value {
    let src = cred_path();
    if !src.exists() { return json!({"ok": false, "error": "未找到登录凭证"}); }
    let creds = match read_json(&src) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e}) };
    let label = account_label(&creds);
    let base = name.unwrap_or_else(|| label.clone());
    let safe: String = base.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let mut fname = safe.clone();
    let mut i = 2;
    while profiles_dir().join(&fname).exists() { fname = format!("{}-{}", safe, i); i += 1; }
    let dd = profiles_dir().join(&fname);
    let _ = std::fs::create_dir_all(&dd);
    let _ = std::fs::copy(&src, dd.join(CRED_FILE));
    let _ = write_json(&dd.join("meta.json"), &json!({"label": label, "captured_at": chrono::Utc::now().to_rfc3339()}));
    json!({"ok": true, "name": fname, "label": label})
}

#[tauri::command]
fn switch_profile(key: String) -> serde_json::Value {
    let prof = profiles_dir().join(&key).join(CRED_FILE);
    if !prof.exists() { return json!({"ok": false, "error": format!("'{}' 不存在", key)}); }
    let cur = cred_path();
    let exe = zcode_exe_path();
    let was = zcode_running();
    if was { kill_zcode_process(); std::thread::sleep(std::time::Duration::from_millis(2000)); }
    if cur.exists() {
        let cl = read_json(&cur).map(|c| account_label(&c)).unwrap_or_default();
        let mut known = false;
        if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
            for e in rd.flatten() {
                let cp = e.path().join(CRED_FILE);
                if cp.exists() && read_json(&cp).map(|c| account_label(&c)) == Ok(cl.clone()) { known = true; break; }
            }
        }
        if !known {
            let auto = format!("autosave-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            let _ = std::fs::create_dir_all(profiles_dir().join(&auto));
            let _ = std::fs::copy(&cur, profiles_dir().join(&auto).join(CRED_FILE));
        }
    }
    let _ = std::fs::copy(&prof, &cur);
    let rel = if was { exe.as_ref().map(|e| launch_zcode_process(e)).unwrap_or(false) } else { false };
    json!({"ok": true, "relaunched": rel})
}

#[tauri::command]
fn delete_profile(key: String) -> serde_json::Value {
    let d = profiles_dir().join(&key);
    if d.exists() { let _ = std::fs::remove_dir_all(&d); }
    json!({"ok": true})
}

fn _get_jwt_token(key: &str) -> Result<String, String> {
    let cp = if key == "__current__" { cred_path() } else { profiles_dir().join(key).join(CRED_FILE) };
    if !cp.exists() { return Err("profile not found".into()); }
    let creds = read_json(&cp)?;
    let raw = creds.get("zcodejwttoken").and_then(|v| v.as_str()).ok_or("no jwt")?;
    decrypt_value(raw)
}

#[tauri::command]
fn fetch_quota(key: String) -> serde_json::Value {
    let token = match _get_jwt_token(&key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e}) };
    let mid = telemetry_device_mid();
    let client = reqwest::blocking::Client::new();
    match client.get("https://zcode.z.ai/api/v1/zcode-plan/billing/balance")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", &mid).header("X-Client-Language", "zh-CN")
        .header("X-ZCode-App-Version", "3.16.3")
        .timeout(std::time::Duration::from_secs(30)).send() {
        Ok(r) => match r.json::<Value>() { Ok(j) => json!({"ok": true, "data": j}), Err(e) => json!({"ok": false, "error": e.to_string()}) },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

#[tauri::command]
fn fetch_benefits(key: String) -> serde_json::Value {
    let token = match _get_jwt_token(&key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e}) };
    let mid = telemetry_device_mid();
    let client = reqwest::blocking::Client::new();
    match client.get("https://zcode.z.ai/api/v1/marketing/touch?seq=1")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", &mid).header("X-Client-Language", "zh-CN")
        .header("X-ZCode-App-Version", "3.16.3")
        .timeout(std::time::Duration::from_secs(30)).send() {
        Ok(r) => match r.json::<Value>() { Ok(j) => json!({"ok": true, "data": j}), Err(e) => json!({"ok": false, "error": e.to_string()}) },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

#[tauri::command]
fn open_zcode_client() -> serde_json::Value {
    let exe = zcode_exe_path().unwrap_or_default();
    if exe.is_empty() { return json!({"ok": false, "error": "not found"}); }
    json!({"ok": launch_zcode_process(&exe)})
}

// -------------------------------------------------------------------- tray

fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "显示 ZCode Hub", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

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
                        w.show().unwrap();
                        w.set_focus().unwrap();
                    }
                }
                "quit" => { app.exit(0); }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                let app = tray.app_handle();
                if let Some(w) = app.get_webview_window("main") {
                    if w.is_visible().unwrap() { w.hide().unwrap(); }
                    else { w.show().unwrap(); w.set_focus().unwrap(); }
                }
            }
        })
        .build(app)?;
    Ok(())
}

// -------------------------------------------------------------------- main

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            setup_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state, capture_profile, switch_profile, delete_profile,
            fetch_quota, fetch_benefits, open_zcode_client,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() { run() }
