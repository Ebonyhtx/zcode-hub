#![windows_subsystem = "windows"]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine;
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;
use std::os::windows::process::CommandExt;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

const CRED_FILE: &str = "credentials.json";

// 账号标识只允许目录名用字符；阻断 ../、绝对路径等穿越（delete/switch/fetch 都是 key 拼路径）
fn safe_key(key: &str) -> Result<(), String> {
    if key == "__current__" { return Ok(()); }
    let ok = !key.is_empty()
        && !key.starts_with('.')
        && !key.contains('\\') && !key.contains('/') && !key.contains("..") && !key.contains(':')
        && key.chars().all(|c| c.is_alphanumeric() || "-_.@".contains(c));
    if ok { Ok(()) } else { Err("非法账号标识".into()) }
}

fn denied(e: String) -> serde_json::Value { json!({"ok": false, "error": e}) }

// 账号目录名清洗：白名单字符外全部替换为下划线（capture / OAuth 建档 / 导入共用）
fn sanitize_label(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' { c } else { '_' }).collect()
}

// ---------------- 窗口几何持久化 ----------------
fn save_window_state(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        if let (Ok(pos), Ok(size)) = (w.outer_position(), w.outer_size()) {
            let mut s = load_settings();
            s["window"] = json!({"x": pos.x, "y": pos.y, "w": size.width, "h": size.height, "max": w.is_maximized().unwrap_or(false)});
            let _ = write_json(&config_path(), &s);
            *SETTINGS.lock().unwrap() = Some(s);
        }
    }
}

fn restore_window_state(app: &tauri::App) {
    if let Some(w) = app.get_webview_window("main") {
        let cfg = load_settings();
        if let Some(win) = cfg.get("window") {
            let max = win.get("max").and_then(|v| v.as_bool()).unwrap_or(false);
            if max {
                let _ = w.maximize();
            } else if let (Some(x), Some(y), Some(ww), Some(hh)) = (
                win.get("x").and_then(|v| v.as_i64()), win.get("y").and_then(|v| v.as_i64()),
                win.get("w").and_then(|v| v.as_u64()), win.get("h").and_then(|v| v.as_u64())) {
                use tauri::{PhysicalPosition, PhysicalSize};
                let _ = w.set_position(PhysicalPosition::new(x as i32, y as i32));
                let _ = w.set_size(PhysicalSize::new(ww as u32, hh as u32));
            }
        }
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---------------- 快照保护（DPAPI） ----------------
// 账号快照整包加密：随机密钥经 DPAPI 绑定当前 Windows 用户+机器。
// 快照文件被拷到别的机器/用户无法解密（区别于 ZCode 自身的可推导 fallback 方案）。
#[repr(C)]
struct DataBlob { cb: u32, pb: *mut u8 }

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(pIn: *const DataBlob, descr: *const u16, entropy: *const DataBlob, reserved: *mut std::ffi::c_void, prompt: *mut std::ffi::c_void, flags: u32, pOut: *mut DataBlob) -> i32;
    fn CryptUnprotectData(pIn: *const DataBlob, descr: *mut *mut u16, entropy: *const DataBlob, reserved: *mut std::ffi::c_void, prompt: *mut std::ffi::c_void, flags: u32, pOut: *mut DataBlob) -> i32;
}
extern "system" { fn LocalFree(h: *mut std::ffi::c_void) -> *mut std::ffi::c_void; }

const DPAPI_ENTROPY: &[u8] = b"zcode-hub-snapshots-v1";

fn dpapi_operate(plain: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    let inp = DataBlob { cb: plain.len() as u32, pb: plain.as_ptr() as *mut u8 };
    let ent = DataBlob { cb: DPAPI_ENTROPY.len() as u32, pb: DPAPI_ENTROPY.as_ptr() as *mut u8 };
    let mut out = DataBlob { cb: 0, pb: std::ptr::null_mut() };
    let ok = unsafe {
        if protect {
            CryptProtectData(&inp, std::ptr::null(), &ent, std::ptr::null_mut(), std::ptr::null_mut(), 1, &mut out)
        } else {
            CryptUnprotectData(&inp, std::ptr::null_mut(), &ent, std::ptr::null_mut(), std::ptr::null_mut(), 1, &mut out)
        }
    };
    if ok == 0 { return Err("DPAPI 调用失败".into()); }
    let v = unsafe { std::slice::from_raw_parts(out.pb, out.cb as usize).to_vec() };
    unsafe { LocalFree(out.pb as *mut std::ffi::c_void); }
    Ok(v)
}

static SNAP_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn snap_key() -> Vec<u8> {
    let mut g = SNAP_KEY.lock().unwrap();
    if let Some(k) = g.as_ref() { return k.clone(); }
    let f = app_data_dir().join("snapkey");
    let mut key: Vec<u8> = Vec::new();
    if let Ok(txt) = std::fs::read_to_string(&f) {
        if let Some(b64) = txt.trim().strip_prefix("dpapi:") {
            let engine = base64::engine::general_purpose::STANDARD;
            if let Ok(enc) = engine.decode(b64) {
                if let Ok(k) = dpapi_operate(&enc, false) { key = k; }
            }
        }
    }
    if key.len() != 32 {
        key = (0..32).map(|_| rand::random::<u8>()).collect();
        let engine = base64::engine::general_purpose::STANDARD;
        if let Ok(enc) = dpapi_operate(&key, true) {
            let _ = std::fs::create_dir_all(app_data_dir());
            let _ = std::fs::write(&f, format!("dpapi:{}", engine.encode(enc)));
        }
    }
    *g = Some(key.clone());
    key
}

const SNAP_MAGIC: &str = "ZH-SNAP1:";

fn write_snapshot(dir: &PathBuf, v: &Value) -> Result<(), String> {
    let key = snap_key();
    let plain = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let ct = cipher.encrypt(Nonce::from_slice(&iv), plain.as_ref()).map_err(|e| e.to_string())?;
    let engine = base64::engine::general_purpose::STANDARD;
    let body = format!("{}{}.{}", SNAP_MAGIC, engine.encode(iv), engine.encode(ct));
    std::fs::write(dir.join("credentials.snap"), body).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(dir.join(CRED_FILE)); // 旧格式副本不再保留
    Ok(())
}

fn read_snapshot_value(dir: &PathBuf) -> Option<Value> {
    let snap = dir.join("credentials.snap");
    if snap.exists() {
        let txt = std::fs::read_to_string(&snap).ok()?;
        let body = txt.trim().strip_prefix(SNAP_MAGIC)?;
        let engine = base64::engine::general_purpose::STANDARD;
        let mut it = body.split('.');
        let iv = engine.decode(it.next()?).ok()?;
        let ct = engine.decode(it.next()?).ok()?;
        let cipher = Aes256Gcm::new_from_slice(&snap_key()).ok()?;
        let plain = cipher.decrypt(Nonce::from_slice(&iv), ct.as_ref()).ok()?;
        serde_json::from_slice(&plain).ok()
    } else {
        let legacy = dir.join(CRED_FILE);
        if legacy.exists() {
            let v = read_json(&legacy).ok()?; // 旧格式快照读取时顺手升级为 DPAPI 加密
            let _ = write_snapshot(dir, &v);
            Some(v)
        } else { None }
    }
}

// 客户端 setting.json 的 providerFamilyDomain 必须 = 当前登录账号的家族（zai/bigmodel），
// 否则账号提供商解析第一个检查就返回 null → 模型配置显示「请登录」、套餐额度不加载。
// 交互登录时官方客户端会自己写这个字段；文件级切换/存档必须由 Hub 同步维护。
// ---------------- 设备身份跟账号走 ----------------
// 每个账号存档绑定独立 deviceMid：首次采纳当前设备的（未被其他存档占用时），
// 否则生成新的 UUID；切换时写进客户端 telemetry-state.json。
// 效果：不同账号在服务端各自呈现独立的设备标识，互不关联。
fn live_device_mid() -> Option<String> {
    let v: Value = std::fs::read_to_string(v2_dir().join("telemetry-state.json")).ok()
        .and_then(|s| serde_json::from_str(&s).ok())?;
    v.get("deviceMid").and_then(|m| m.as_str()).map(String::from).filter(|m| !m.trim().is_empty())
}

fn ensure_profile_device_mid(dir: &PathBuf, meta: &mut Value) -> String {
    if let Some(m) = meta.get("device_mid").and_then(|v| v.as_str()) {
        if !m.trim().is_empty() { return m.to_string(); }
    }
    let mut taken: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if &e.path() == dir { continue; }
            if let Ok(m) = read_json(&e.path().join("meta.json")) {
                if let Some(dm) = m.get("device_mid").and_then(|v| v.as_str()) { taken.push(dm.to_string()); }
            }
        }
    }
    let mid = match live_device_mid() {
        Some(m) if !taken.contains(&m) => m,
        _ => uuid::Uuid::new_v4().to_string(),
    };
    meta["device_mid"] = json!(mid);
    mid
}

fn write_live_device_mid(mid: &str) {
    let p = v2_dir().join("telemetry-state.json");
    let mut v: Value = std::fs::read_to_string(&p).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    if !v.is_object() { v = json!({}); }
    if v.get("deviceMid").and_then(|m| m.as_str()) == Some(mid) { return; }
    v["deviceMid"] = json!(mid);
    let _ = write_json(&p, &v);
}

// arms_uid：阿里云 RUM 遥测的用户标识，存于 %APPDATA% 下 ZCode 的 rum-electron-store/*.json 的 _arms_uid。
// 与 deviceMid 同策略：每账号独立，首次采纳当前值（未被占用时），否则生成新的。
const ARMS_DEFAULT_STORE_FILE: &str = "ZGVmYXVsdA.json";

fn new_arms_uid() -> String {
    use rand::Rng;
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..16).map(|_| ALPHABET[rng.gen::<usize>() % 36] as char).collect();
    format!("uid_{}", suffix)
}

fn arms_store_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        let base = PathBuf::from(&appdata);
        for name in ["ZCode", "zcode", "ZCode Preview", "ZCode Dev"] {
            out.push(base.join(name).join("rum-electron-store"));
        }
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if n.starts_with("zcode") {
                    let d = e.path().join("rum-electron-store");
                    if d.is_dir() && !out.contains(&d) { out.push(d); }
                }
            }
        }
    }
    out
}

fn read_live_arms_uid() -> Option<String> {
    for d in arms_store_dirs() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)).collect();
            files.sort_by_key(|p| !p.file_name().map(|n| n == ARMS_DEFAULT_STORE_FILE).unwrap_or(false));
            for f in files {
                if let Ok(s) = std::fs::read_to_string(&f) {
                    if let Ok(v) = serde_json::from_str::<Value>(&s) {
                        if let Some(u) = v.get("_arms_uid").and_then(|u| u.as_str()) {
                            if !u.trim().is_empty() { return Some(u.to_string()); }
                        }
                    }
                }
            }
        }
    }
    None
}

fn write_live_arms_uid(uid: &str) {
    let mut first_err: Option<String> = None;
    for d in arms_store_dirs() {
        let mut jsons: Vec<PathBuf> = std::fs::read_dir(&d).map(|rd| rd.flatten().map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)).collect()).unwrap_or_default();
        if jsons.is_empty() {
            let _ = std::fs::create_dir_all(&d);
            jsons.push(d.join(ARMS_DEFAULT_STORE_FILE));
        }
        for f in jsons {
            let mut v: Value = std::fs::read_to_string(&f).ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| json!({}));
            if !v.is_object() { v = json!({}); }
            if v.get("_arms_uid").and_then(|u| u.as_str()) == Some(uid) && v.get("_arms_session").is_none() { continue; }
            if let Some(obj) = v.as_object_mut() {
                obj.insert("_arms_uid".into(), json!(uid));
                obj.remove("_arms_session");
                if let Err(e) = write_json(&f, &v) { first_err.get_or_insert(e); }
            }
        }
    }
    if let Some(e) = first_err { eprintln!("arms_uid 写回失败(忽略): {}", e); }
}

fn ensure_profile_arms_uid(dir: &PathBuf, meta: &mut Value) -> String {
    if let Some(u) = meta.get("arms_uid").and_then(|v| v.as_str()) {
        if !u.trim().is_empty() { return u.to_string(); }
    }
    let mut taken: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if &e.path() == dir { continue; }
            if let Ok(m) = read_json(&e.path().join("meta.json")) {
                if let Some(u) = m.get("arms_uid").and_then(|v| v.as_str()) { taken.push(u.to_string()); }
            }
        }
    }
    let uid = match read_live_arms_uid() {
        Some(u) if !taken.contains(&u) => u,
        _ => new_arms_uid(),
    };
    meta["arms_uid"] = json!(uid);
    uid
}

fn sync_provider_family_domain(provider: &str) {
    if provider != "zai" && provider != "bigmodel" { return; }
    let p = v2_dir().join("setting.json");
    let mut s = match read_json(&p) { Ok(s) => s, Err(_) => return };
    if s.get("providerFamilyDomain").and_then(|v| v.as_str()) == Some(provider) { return; }
    s["providerFamilyDomain"] = json!(provider);
    s["providerFamilyDomainUpdatedAt"] = json!(chrono::Utc::now().timestamp_millis());
    let _ = write_json(&p, &s);
}
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

fn home_v2() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".zcode").join("v2")
}
// setting.json 的 dataBaseDir 若被用户改过，凭据等数据文件跟着走（setting.json 本身留在原处）
fn v2_dir() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let root = std::fs::read_to_string(home_v2().join("setting.json")).ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("dataBaseDir").and_then(|d| d.as_str()).map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or(base);
    root.join(".zcode").join("v2")
}
fn cred_path() -> PathBuf { v2_dir().join(CRED_FILE) }

// 标准应用数据目录：%APPDATA%\zcode-hub（换机器 / 无 D 盘也正常）
fn app_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".zcode-hub"))
        .join("zcode-hub")
}

fn profiles_dir() -> PathBuf { app_data_dir().join("profiles") }

// 旧版本把数据硬编码在 D:\zcode-hub；首次启动若新位置为空则整体迁入（不删旧文件）
fn migrate_legacy_data() {
    let old_profiles = PathBuf::from(r"D:\zcode-hub\profiles");
    let old_config = PathBuf::from(r"D:\zcode-hub\hub-config.json");
    let new_profiles = profiles_dir();
    let _ = std::fs::create_dir_all(&new_profiles);
    let empty = std::fs::read_dir(&new_profiles).map(|rd| rd.count() == 0).unwrap_or(true);
    if empty && old_profiles.exists() {
        if let Ok(rd) = std::fs::read_dir(&old_profiles) {
            for e in rd.flatten() {
                let _ = copy_dir_all(&e.path(), new_profiles.join(e.file_name()));
            }
        }
    }
    if !config_path().exists() && old_config.exists() {
        let _ = std::fs::copy(&old_config, config_path());
    }
}

fn copy_dir_all(src: &PathBuf, dst: PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let t = dst.join(e.file_name());
        if e.path().is_dir() { copy_dir_all(&e.path(), t)?; }
        else { std::fs::copy(e.path(), t)?; }
    }
    Ok(())
}

fn read_json(path: &PathBuf) -> Result<Value, String> {
    let c = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&c).map_err(|e| e.to_string())
}

fn write_json(path: &PathBuf, v: &Value) -> Result<(), String> {
    if let Some(p) = path.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
    let body = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    // 原子写：临时文件 + rename，进程被杀也不会留下半截 JSON
    let tmp = path.with_extension("hub-tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => { let _ = std::fs::remove_file(&tmp); Err(e.to_string()) }
    }
}

// ------------------------------------------------------------- account label

fn account_label(creds: &Value) -> String {
    for uk in ["oauth:zai:user_info", "oauth:bigmodel:user_info"] {
        if let Some(raw) = creds.get(uk).and_then(|v| v.as_str()) {
            if let Ok(plain) = decrypt_value(raw) {
                if let Ok(info) = serde_json::from_str::<Value>(&plain) {
                    for k in ["username", "displayName", "name", "nickname", "email"] {
                        if let Some(v) = info.get(k).and_then(|v| v.as_str()) { if !v.is_empty() { return v.to_string(); } }
                    }
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
    // CREATE_NO_WINDOW：探测命令不能闪黑框（get_state 每 60 秒被 UI 轮询调用一次）
    Command::new("tasklist").args(["/FI", "IMAGENAME eq ZCode.exe", "/NH"]).creation_flags(0x08000000).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("ZCode.exe")).unwrap_or(false)
}

// exe 路径基本不变，命中一次就缓存，避免反复拉 PowerShell
static EXE_CACHE: Mutex<Option<String>> = Mutex::new(None);
static APP_HANDLE: Mutex<Option<tauri::AppHandle>> = Mutex::new(None);
static QUOTA_CACHE: Mutex<Option<std::collections::HashMap<String, (i64, Value)>>> = Mutex::new(None);
static HTTP: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();

fn http() -> &'static reqwest::blocking::Client {
    HTTP.get_or_init(|| reqwest::blocking::Client::new())
}

fn zcode_exe_path() -> Option<String> {
    if let Some(p) = EXE_CACHE.lock().unwrap().clone() { return Some(p); }
    // 用户在设置里指定的路径优先（失效则回落到自动探测）
    if let Some(p) = load_settings().get("zcode_path").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        if std::path::Path::new(&p).exists() {
            *EXE_CACHE.lock().unwrap() = Some(p.clone());
            return Some(p);
        }
    }
    let found = Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-Process ZCode -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path"])
        .creation_flags(0x08000000)
        .output().ok()
        .and_then(|o| { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } })
        .or_else(|| {
            // 客户端未运行时按常见安装位置兜底
            let mut cands = vec![r"C:\Program Files\ZCode\ZCode.exe".to_string()];
            if let Ok(la) = std::env::var("LOCALAPPDATA") {
                cands.push(format!(r"{}\Programs\ZCode\ZCode.exe", la));
            }
            cands.into_iter().find(|c| std::path::Path::new(c).exists())
        });
    if let Some(ref p) = found { *EXE_CACHE.lock().unwrap() = Some(p.clone()); }
    found
}

fn kill_zcode_process() -> bool {
    // 先温和关闭（WM_CLOSE），不行再强制（/F），并轮询确认进程真正退出——
    // 只看 taskkill 是否执行成功不可靠（Electron 可能忽略关闭消息）
    let _ = Command::new("taskkill").args(["/IM", "ZCode.exe", "/T"]).creation_flags(0x08000000).output();
    for _ in 0..8 {
        if !zcode_running() { return true; }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    let _ = Command::new("taskkill").args(["/IM", "ZCode.exe", "/T", "/F"]).creation_flags(0x08000000).output();
    for _ in 0..15 {
        if !zcode_running() { return true; }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    false
}

fn launch_zcode_process(exe: &str) -> bool {
    // CREATE_NO_WINDOW：不给启动链上任何控制台，避免 ZCode 的 host 子进程弹出黑色日志窗口
    Command::new(exe).current_dir(std::path::Path::new(exe).parent().unwrap_or(std::path::Path::new(".")))
        .creation_flags(0x08000000).spawn().is_ok()
}

fn telemetry_device_mid() -> String {
    read_json(&v2_dir().join("telemetry-state.json")).ok()
        .and_then(|v| v.get("deviceMid").and_then(|v| v.as_str()).map(String::from)).unwrap_or_default()
}

// ------------------------------------------------------------------- structs

#[derive(serde::Serialize)]
struct ProfileInfo { key: String, label: String, captured_at: String, is_current: bool, provider: String, jwt_expired: bool }

// 令牌载荷若带 exp（部分旧格式/未来格式），本地解码判定是否已过期（30s 时钟容忍）
fn jwt_expired(creds: &Value) -> bool {
    let Some(jwt) = creds.get("zcodejwttoken").and_then(|v| v.as_str()) else { return false };
    let Some(payload) = jwt.split('.').nth(1) else { return false };
    let mut padded = payload.trim_end_matches('=').to_string();
    while padded.len() % 4 != 0 { padded.push('='); }
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes()) else { return false };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else { return false };
    let Some(exp) = v.get("exp").and_then(|e| e.as_i64()) else { return false };
    exp <= chrono::Utc::now().timestamp() + 30
}

fn startup_lnk() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_default();
    PathBuf::from(base).join(r"Microsoft\Windows\Start Menu\Programs\Startup").join("ZCode Hub.lnk")
}

fn autostart_enabled() -> bool { startup_lnk().exists() }

fn set_autostart_internal(enable: bool) -> Result<(), String> {
    let lnk = startup_lnk();
    if !enable {
        if lnk.exists() { std::fs::remove_file(&lnk).map_err(|e| e.to_string())?; }
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let script = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}');$s.TargetPath='{}';$s.WorkingDirectory='{}';$s.Save()",
        lnk.display(), exe.display(), exe.parent().map(|p| p.display().to_string()).unwrap_or_default());
    let out = Command::new("powershell").args(["-NoProfile", "-Command", &script])
        .creation_flags(0x08000000).output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err("创建自启快捷方式失败".into()); }
    Ok(())
}

#[tauri::command]
fn set_autostart(enable: bool) -> serde_json::Value {
    match set_autostart_internal(enable) {
        Ok(()) => json!({"ok": true, "enabled": autostart_enabled()}),
        Err(e) => json!({"ok": false, "error": e}),
    }
}

fn open_in_explorer(dir: &PathBuf) -> serde_json::Value {
    if !dir.exists() { let _ = std::fs::create_dir_all(dir); }
    let _ = Command::new("explorer").arg(dir).creation_flags(0x08000000).spawn();
    json!({"ok": true})
}

#[tauri::command]
fn open_data_dir() -> serde_json::Value { open_in_explorer(&app_data_dir()) }

#[tauri::command]
fn open_zcode_data_dir() -> serde_json::Value { open_in_explorer(&v2_dir()) }

// 检查更新：查 GitHub Releases 最新 tag（仓库转公开后自动生效；私有期间友好降级）
#[tauri::command]
fn check_update() -> serde_json::Value {
    let current = env!("CARGO_PKG_VERSION");
    let resp = http().get("https://api.github.com/repos/Ebonyhtx/zcode-hub/releases/latest")
        .header("User-Agent", "zcode-hub")
        .timeout(std::time::Duration::from_secs(15)).send();
    match resp {
        Ok(r) if r.status().as_u16() == 200 => {
            let j: Value = match r.json() { Ok(j) => j, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let latest = j.get("tag_name").and_then(|v| v.as_str()).unwrap_or("").trim_start_matches('v').to_string();
            let url = j.get("html_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let pv = |s: &str| s.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<u64>>();
            let (a, b) = (pv(&latest), pv(current));
            let mut up_to_date = true;
            for i in 0..3 {
                let l = a.get(i).unwrap_or(&0); let c = b.get(i).unwrap_or(&0);
                if l > c { up_to_date = false; break; }
                if l < c { up_to_date = true; break; }
            }
            json!({"ok": true, "current": current, "latest": latest, "up_to_date": up_to_date, "url": url})
        }
        Ok(r) => json!({"ok": true, "current": current, "latest": "", "up_to_date": true,
                        "note": format!("仓库当前不可公开查询（HTTP {}），转公开后可在线检查更新", r.status().as_u16())}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

#[tauri::command]
fn open_url(url: String) -> serde_json::Value {
    if !url.starts_with("https://") { return json!({"ok": false, "error": "仅允许 https 链接"}); }
    open_in_browser(&url);
    json!({"ok": true})
}

#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| e.to_string())?;
    match update {
        Some(u) => {
            let _ = u.download_and_install(|_, _| {}, || {}).await;
            app.restart();
        }
        None => Ok(json!({"ok": true, "up_to_date": true})),
    }
}

#[tauri::command]
fn get_state() -> serde_json::Value {
    let cur = cred_path();
    let cur_label = if cur.exists() { read_json(&cur).map(|c| account_label(&c)).unwrap_or("(err)".into()) } else { "(未登录)".into() };
    let cur_provider = if cur.exists() {
        read_json(&cur).ok()
            .and_then(|c| c.get("oauth:active_provider").and_then(|v| v.as_str()).map(String::from))
            .and_then(|s| decrypt_value(&s).ok())
            .unwrap_or_default()
    } else { String::new() };
    let mut profiles = Vec::new();
    let pd = profiles_dir();
    if pd.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&pd).map(|rd| rd.filter_map(|e| e.ok()).collect()).unwrap_or_default();
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        for e in entries {
            let name = e.file_name().to_string_lossy().to_string();
            let pval = read_snapshot_value(&e.path());
            if pval.is_none() { continue; }
            let label = pval.as_ref().map(|c| account_label(c)).unwrap_or("?".into());
            let meta = read_json(&e.path().join("meta.json")).ok().unwrap_or(json!({}));
            let ca = meta.get("captured_at").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
            // provider 优先取 meta.json，老存档回退到解密凭据里的 oauth:active_provider
            let mut provider = meta.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if provider.is_empty() {
                provider = pval.as_ref()
                    .and_then(|c| c.get("oauth:active_provider").and_then(|v| v.as_str()).map(String::from))
                    .and_then(|s| decrypt_value(&s).ok())
                    .unwrap_or_default();
            }
            let ic = !cur_label.starts_with('(') && label == cur_label;
            let je = pval.as_ref().map(|c| jwt_expired(c)).unwrap_or(false);
            profiles.push(ProfileInfo { key: name, label, captured_at: ca, is_current: ic, provider, jwt_expired: je });
        }
    }
    let benefits = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    if let Some(h) = APP_HANDLE.lock().unwrap().as_ref() {
        if let Some(tray) = h.tray_by_id("main") {
            let _ = tray.set_tooltip(Some(format!("ZCode Hub — 当前: {}", cur_label)));
        }
    }
    json!({ "current_label": cur_label, "current_provider": cur_provider, "profiles": profiles, "zcode_running": zcode_running(), "zcode_exe": zcode_exe_path().unwrap_or_default(),
            "settings": load_settings(), "benefits": benefits, "last_check": *LAST_CHECK.lock().unwrap(),
            "version": env!("CARGO_PKG_VERSION"), "autostart": autostart_enabled() })
}

#[tauri::command]
fn capture_profile(name: Option<String>) -> serde_json::Value {
    let src = cred_path();
    if !src.exists() { return json!({"ok": false, "error": "未找到登录凭证"}); }
    let creds = match read_json(&src) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e}) };
    let label = account_label(&creds);
    let base = name.unwrap_or_else(|| label.clone());
    let safe = sanitize_label(&base);
    let mut fname = safe.clone();
    let mut i = 2;
    while profiles_dir().join(&fname).exists() { fname = format!("{}-{}", safe, i); i += 1; }
    let dd = profiles_dir().join(&fname);
    let _ = std::fs::create_dir_all(&dd);
    let _ = write_snapshot(&dd, &creds);
    let provider = creds.get("oauth:active_provider").and_then(|v| v.as_str())
        .and_then(|s| decrypt_value(s).ok()).unwrap_or_default();
    let mut meta = json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()});
    let _mid = ensure_profile_device_mid(&dd, &mut meta);
    let _auid = ensure_profile_arms_uid(&dd, &mut meta);
    let _ = write_json(&dd.join("meta.json"), &meta);
    json!({"ok": true, "name": fname, "label": label})
}

fn hot_swap_verified(cur: &PathBuf, prof_v: &Value) -> bool {
    // 写入后回读两次校验账号身份——客户端若用内存状态覆盖写回则重试，三次失败放弃
    let label = account_label(prof_v);
    for attempt in 0..3u32 {
        if write_json(cur, prof_v).is_err() {
            std::thread::sleep(std::time::Duration::from_millis(250 * (attempt as u64 + 1)));
            continue;
        }
        if let Ok(v1) = read_json(cur) {
            if account_label(&v1) == label {
                std::thread::sleep(std::time::Duration::from_millis(150));
                if let Ok(v2) = read_json(cur) {
                    if account_label(&v2) == label { return true; }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250 * (attempt as u64 + 1)));
    }
    false
}

#[tauri::command]
fn switch_profile(key: String, hot: Option<bool>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let prof_dir = profiles_dir().join(&key);
    let prof_v = match read_snapshot_value(&prof_dir) { Some(v) => v, None => return json!({"ok": false, "error": format!("'{}' 不存在", key)}) };
    let cur = cred_path();
    let exe = zcode_exe_path();
    let was = zcode_running();
    let want_hot = hot.unwrap_or(false)
        && load_settings().get("hot_switch").and_then(|v| v.as_bool()).unwrap_or(false)
        && was;
    if want_hot {
        // 热切换：不杀客户端，直接换凭据并回读验证；验证失败自动回退重启路径
        if let Ok(cur_v) = read_json(&cur) {
            if cur_v.get("zcodejwttoken").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
                let cl = account_label(&cur_v);
                let mut known_dir: Option<PathBuf> = None;
                if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
                    for e in rd.flatten() {
                        if read_snapshot_value(&e.path()).map(|c| account_label(&c)) == Some(cl.clone()) {
                            known_dir = Some(e.path()); break;
                        }
                    }
                }
                if let Some(kd) = known_dir.as_ref() { let _ = write_snapshot(kd, &cur_v); }
                else {
                    let auto = format!("autosave-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    let _ = std::fs::create_dir_all(profiles_dir().join(&auto));
                    let _ = write_snapshot(&profiles_dir().join(&auto), &cur_v);
                    let _ = write_json(&profiles_dir().join(&auto).join("meta.json"), &json!({"label": cl, "captured_at": chrono::Utc::now().to_rfc3339()}));
                }
            }
        }
        if hot_swap_verified(&cur, &prof_v) {
            let fam = prof_v.get("oauth:active_provider").and_then(|v| v.as_str())
                .and_then(|s| decrypt_value(s).ok())
                .unwrap_or_default();
            sync_provider_family_domain(&fam);
            let mut meta = read_json(&prof_dir.join("meta.json")).ok()
                .unwrap_or_else(|| json!({"label": key, "provider": fam}));
            let mid = ensure_profile_device_mid(&prof_dir, &mut meta);
            let auid = ensure_profile_arms_uid(&prof_dir, &mut meta);
            let _ = write_json(&prof_dir.join("meta.json"), &meta);
            write_live_device_mid(&mid);
            write_live_arms_uid(&auid);
            let _ = std::fs::remove_file(v2_dir().join("coding-plan-cache.json"));
            return json!({"ok": true, "hot": true, "relaunched": false});
        }
        // 热切换失败 → 落回冷路径（杀进程 + 重启）
    }
    if was {
        // 先杀干净再动文件——绝不在客户端运行时替换凭据
        if !kill_zcode_process() {
            return json!({"ok": false, "error": "无法关闭 ZCode（可能仍在托盘运行），请手动退出 ZCode 后重试"});
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if cur.exists() {
        // 只有「完整有效的登录凭据」才值得备份；强杀瞬间可能抓到空文件/半截文件，
        // 备份那种垃圾会在账号库里出现 (未知) 空账号（2026-10-31 实际踩过）
        let cur_creds = read_json(&cur).ok();
        let valid_session = cur_creds.as_ref()
            .map(|c| c.get("zcodejwttoken").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false))
            .unwrap_or(false);
        let cl = cur_creds.as_ref().map(|c| account_label(c)).unwrap_or_default();
        let mut known_dir: Option<PathBuf> = None;
        if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
            for e in rd.flatten() {
                if read_snapshot_value(&e.path()).map(|c| account_label(&c)) == Some(cl.clone()) {
                    known_dir = Some(e.path()); break;
                }
            }
        }
        // 回写：当前登录匹配已有存档时，把客户端刷新过的最新凭据同步回该存档（token 保鲜）
        if let (Some(kd), Some(cv)) = (known_dir.as_ref(), cur_creds.as_ref()) {
            let _ = write_snapshot(kd, cv);
        }
        let known = known_dir.is_some();
        if !known && valid_session {
            let auto = format!("autosave-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            let _ = std::fs::create_dir_all(profiles_dir().join(&auto));
            if let Some(cv) = cur_creds.as_ref() { let _ = write_snapshot(&profiles_dir().join(&auto), cv); }
            let _ = write_json(&profiles_dir().join(&auto).join("meta.json"), &json!({"label": cl, "captured_at": chrono::Utc::now().to_rfc3339()}));
        }
        if valid_session {
            let _ = std::fs::copy(&cur, v2_dir().join("credentials.json.hub-backup"));
        }
    }
    if write_json(&cur, &prof_v).is_err() {
        let _ = std::fs::copy(v2_dir().join("credentials.json.hub-backup"), &cur);
        return json!({"ok": false, "error": "替换凭据文件失败，已恢复原文件"});
    }
    // 同步客户端激活家族，否则模型配置/套餐解析会因 domain 不匹配而「请登录」
    let fam = prof_v.get("oauth:active_provider").and_then(|v| v.as_str())
        .and_then(|s| decrypt_value(s).ok())
        .unwrap_or_default();
    sync_provider_family_domain(&fam);
    let mut meta = read_json(&prof_dir.join("meta.json")).ok()
        .unwrap_or_else(|| json!({"label": key, "provider": fam}));
    let mid = ensure_profile_device_mid(&prof_dir, &mut meta);
    let auid = ensure_profile_arms_uid(&prof_dir, &mut meta);
    let _ = write_json(&prof_dir.join("meta.json"), &meta);
    write_live_device_mid(&mid);
    write_live_arms_uid(&auid);
    // 客户端会读套餐缓存，切换后必须清掉避免上一账号的套餐状态残留
    let _ = std::fs::remove_file(v2_dir().join("coding-plan-cache.json"));
    // 客户端会读套餐缓存，切换后必须清掉避免上一账号的套餐状态残留
    let _ = std::fs::remove_file(v2_dir().join("coding-plan-cache.json"));
    let rel = if was { exe.as_ref().map(|e| launch_zcode_process(e)).unwrap_or(false) } else { false };
    json!({"ok": true, "relaunched": rel})
}

// ---------------- 账号库备份：口令加密导出 / 导入（.zhb） ----------------
// PBKDF2-HMAC-SHA256(120k) + AES-256-GCM；解决 DPAPI 快照换机不可解的问题：
// 导出文件凭口令即可在任何机器导入恢复账号

fn bundle_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, 120_000, &mut out);
    out
}

#[tauri::command]
fn export_bundle(password: String) -> serde_json::Value {
    if password.chars().count() < 6 { return json!({"ok": false, "error": "口令至少 6 位"}); }
    let mut accounts = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if let Some(creds) = read_snapshot_value(&e.path()) {
                if creds.get("zcodejwttoken").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
                    let meta = read_json(&e.path().join("meta.json")).ok().unwrap_or(json!({}));
                    accounts.push(json!({
                        "label": meta.get("label").and_then(|v| v.as_str()).unwrap_or(e.file_name().to_string_lossy().as_ref()),
                        "provider": meta.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
                        "credentials": creds,
                    }));
                }
            }
        }
    }
    if accounts.is_empty() { return json!({"ok": false, "error": "账号库为空"}); }
    let bundle = json!({"format": "zcode-hub-bundle", "version": 1, "exported_at": chrono::Utc::now().to_rfc3339(), "accounts": accounts});
    let plain = match serde_json::to_vec(&bundle) { Ok(p) => p, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
    let salt: [u8; 16] = rand::random();
    let iv: [u8; 12] = rand::random();
    let key = bundle_key(&password, &salt);
    let cipher = match Aes256Gcm::new_from_slice(&key) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
    let ct = match cipher.encrypt(Nonce::from_slice(&iv), plain.as_ref()) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
    let engine = base64::engine::general_purpose::STANDARD;
    let mut raw = Vec::new();
    raw.extend_from_slice(&salt); raw.extend_from_slice(&iv); raw.extend_from_slice(&ct);
    let desktop = dirs::desktop_dir().or_else(dirs::home_dir).unwrap_or_else(|| PathBuf::from("."));
    let fname = format!("zcode-hub-backup-{}.zhb", chrono::Local::now().format("%Y%m%d-%H%M%S"));
    let out = desktop.join(&fname);
    if let Err(e) = std::fs::write(&out, format!("ZHB1:{}", engine.encode(raw))) {
        return json!({"ok": false, "error": e.to_string()});
    }
    json!({"ok": true, "path": out.display().to_string(), "accounts": accounts.len()})
}

#[tauri::command]
fn import_bundle(path: String, password: String) -> serde_json::Value {
    let raw = match std::fs::read_to_string(&path) { Ok(r) => r, Err(e) => return json!({"ok": false, "error": format!("读取失败: {}", e)}) };
    let body = match raw.trim().strip_prefix("ZHB1:") { Some(b) => b, None => return json!({"ok": false, "error": "不是 ZCode Hub 备份文件"}) };
    let engine = base64::engine::general_purpose::STANDARD;
    let data = match engine.decode(body.trim()) { Ok(d) => d, Err(_) => return json!({"ok": false, "error": "文件损坏"}) };
    if data.len() < 28 + 16 { return json!({"ok": false, "error": "文件损坏"}); }
    let (salt, rest) = data.split_at(16);
    let (iv, ct) = rest.split_at(12);
    let key = bundle_key(&password, salt);
    let cipher = match Aes256Gcm::new_from_slice(&key) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
    let plain = match cipher.decrypt(Nonce::from_slice(iv), ct) { Ok(p) => p, Err(_) => return json!({"ok": false, "error": "口令错误或文件损坏"}) };
    let bundle: Value = match serde_json::from_slice(&plain) { Ok(b) => b, Err(_) => return json!({"ok": false, "error": "文件损坏"}) };
    if bundle.get("format").and_then(|v| v.as_str()) != Some("zcode-hub-bundle") {
        return json!({"ok": false, "error": "不是 ZCode Hub 备份文件"});
    }
    let mut added = 0u64; let mut skipped = 0u64;
    if let Some(list) = bundle.get("accounts").and_then(|v| v.as_array()) {
        for a in list {
            let creds = a.get("credentials").cloned().unwrap_or(json!({}));
            let has_jwt = creds.get("zcodejwttoken").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
            if !has_jwt { skipped += 1; continue; }
            let label = a.get("label").and_then(|v| v.as_str()).unwrap_or("imported").to_string();
            let provider = a.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let safe = sanitize_label(&label);
            let dir = profiles_dir().join(&safe);
            if dir.exists() { skipped += 1; continue; }
            let _ = std::fs::create_dir_all(&dir);
            if write_snapshot(&dir, &creds).is_ok() {
                let _ = write_json(&dir.join("meta.json"), &json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()}));
                added += 1;
            } else { skipped += 1; }
        }
    }
    json!({"ok": true, "added": added, "skipped": skipped})
}

#[tauri::command]
fn delete_profile(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let d = profiles_dir().join(&key);
    if d.exists() { let _ = std::fs::remove_dir_all(&d); }
    json!({"ok": true})
}

// -------------------------------------------------------------------- OAuth

use std::sync::Mutex;

static OAUTH_STATE: Mutex<Option<Value>> = Mutex::new(None);

fn set_oauth(v: Value) { *OAUTH_STATE.lock().unwrap() = Some(v); }
fn get_oauth() -> Option<Value> { OAUTH_STATE.lock().unwrap().clone() }

fn generate_poll_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

// 用系统 Shell 处理协议分发（等价于 Win+R 打开 URL），不经任何命令行解析，URL 里的 & % ? 都安全
fn open_in_browser(url: &str) {
    use std::os::windows::ffi::OsStrExt;
    fn wide(s: &str) -> Vec<u16> { std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect() }
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(hwnd: isize, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
    }
    let op = wide("open");
    let file = wide(url);
    let r = unsafe { ShellExecuteW(0, op.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 5 /* SW_SHOW */) };
    if r <= 32 {
        // ShellExecute 失败（返回 SE_ERR_* 错误码）时回退 rundll32 协议处理器
        let _ = Command::new("rundll32").args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x08000000).spawn();
    }
}

fn _oauth_worker(provider: String, poll_token: String) {
    let client = reqwest::blocking::Client::new();
    // init
    let init = client.post("https://zcode.z.ai/api/v1/oauth/cli/init")
        .header("Authorization", format!("Bearer {}", poll_token))
        .header("Content-Type", "application/json")
        .body(json!({"provider": provider}).to_string())
        .timeout(std::time::Duration::from_secs(20))
        .send();
    let init = match init { Ok(r) => r, Err(e) => { set_oauth(json!({"status":"failed","error":e.to_string()})); return; } };
    let j: Value = match init.json() { Ok(j) => j, Err(e) => { set_oauth(json!({"status":"failed","error":e.to_string()})); return; } };
    if j.get("code").and_then(|c| c.as_i64()) != Some(0) {
        set_oauth(json!({"status":"failed","error": j.get("msg").and_then(|m| m.as_str()).unwrap_or("init error")}));
        return;
    }
    let d = j.get("data").cloned().unwrap_or(json!({}));
    let authorize_url = d.get("authorize_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // 官方桌面端会用带 ? 的登录页 URL 覆盖回调参数（见 asar 内 startOAuthWithPolling）：
    //   zai      → 覆盖 redirect_uri 参数
    //   bigmodel → 覆盖 redirect 参数
    // 服务端拼接重定向时无条件下 &，裸回调值（无 query）会被拼坏成 /callback/xxx&state=... → 404。
    let authorize_url = {
        let desktop_redirect = "https://zcode.z.ai/app/oauth/login?redirect=zcode://oauth/callback&app_version=3.17.1";
        let param = if provider == "bigmodel" { "redirect" } else { "redirect_uri" };
        match url::Url::parse(&authorize_url) {
            Ok(mut u) => {
                let pairs: Vec<(String, String)> = u.query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .filter(|(k, _)| k != param && k != "redirect_uri" && k != "redirect")
                    .collect();
                {
                    let mut q = u.query_pairs_mut();
                    q.clear();
                    for (k, v) in &pairs { q.append_pair(k, v); }
                    q.append_pair(param, desktop_redirect);
                }
                u.to_string()
            }
            Err(_) => authorize_url,
        }
    };
    let flow_id = d.get("flow_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let interval = d.get("poll_interval_sec").and_then(|v| v.as_u64()).unwrap_or(2);
    let expires = d.get("expires_at").and_then(|v| v.as_f64()).unwrap_or(0.0);

    set_oauth(json!({"status":"pending","authorize_url": authorize_url}));
    open_in_browser(&authorize_url);

    let deadline = if expires > 0.0 { expires } else { 600.0 };
    loop {
        if chrono::Utc::now().timestamp() as f64 > deadline {
            set_oauth(json!({"status":"failed","error":"timeout"}));
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
        let poll = client.get(format!("https://zcode.z.ai/api/v1/oauth/cli/poll/{}", flow_id))
            .header("Authorization", format!("Bearer {}", poll_token))
            .timeout(std::time::Duration::from_secs(15))
            .send();
        let poll = match poll { Ok(r) => r, Err(_) => continue };
        let pj: Value = match poll.json() { Ok(j) => j, Err(_) => continue };
        let pd = pj.get("data").cloned().unwrap_or(json!({}));
        let status = pd.get("status").and_then(|v| v.as_str()).unwrap_or("pending");
        if status == "pending" { continue; }
        if status != "ready" {
            set_oauth(json!({"status":"failed","error": format!("login failed: {}", status)}));
            return;
        }
        let user = pd.get("user").cloned().unwrap_or(json!({}));
        // 官方 CLI 轮询响应：zai → data.zai.access_token；bigmodel → data.bigmodel.access_token(+refresh_token)
        let pdata = pd.get(&provider).cloned().unwrap_or(json!({}));
        let access_token = pdata.get("access_token").and_then(|v| v.as_str())
            .or_else(|| pdata.get("accessToken").and_then(|v| v.as_str()))
            .unwrap_or("").to_string();
        let refresh_token = pdata.get("refresh_token").and_then(|v| v.as_str())
            .or_else(|| pdata.get("refreshToken").and_then(|v| v.as_str()))
            .unwrap_or("").to_string();
        let token = pd.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // 官方 ZaiBusinessTokenResolver：poll 返回的 zai access_token 只有 1 小时寿命，
        // 必须先到 api.z.ai/api/auth/z/login 换成长效业务 token 再入库，否则切换后一小时内就报过期
        let mut warning = String::new();
        let access_token = if provider == "zai" && !access_token.is_empty() {
            match client.post("https://api.z.ai/api/auth/z/login")
                .header("Content-Type", "application/json")
                .body(json!({"token": access_token}).to_string())
                .timeout(std::time::Duration::from_secs(15))
                .send() {
                Ok(r) => match r.json::<Value>() {
                    Ok(j) => {
                        let bt = j.pointer("/data/access_token").and_then(|v| v.as_str())
                            .or_else(|| j.pointer("/data/accessToken").and_then(|v| v.as_str()))
                            .map(|s| s.trim().to_string()).unwrap_or_default();
                        if bt.is_empty() {
                            warning = "业务 token 交换失败（响应缺少 access_token），保存的是 1 小时临时 token，请重新登录".into();
                            access_token
                        } else { bt }
                    }
                    Err(e) => { warning = format!("业务 token 交换失败（{}），保存的是 1 小时临时 token", e); access_token }
                },
                Err(e) => { warning = format!("业务 token 交换失败（{}），保存的是 1 小时临时 token", e); access_token }
            }
        } else { access_token };
        let user_id = user.get("user_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let label = user.get("name").and_then(|v| v.as_str())
            .or(user.get("email").and_then(|v| v.as_str()))
            .unwrap_or(&user_id).to_string();
        let avatar = user.get("avatar").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // 客户端启动恢复会话时按规范化档案 {id,username,displayName,avatarUrl?,rawProfile} 解析，
        // 原始 poll 的 user 对象（{user_id,name,...}）缺 id/username 会被判定无效 → 未登录
        let mut pnorm = serde_json::Map::new();
        pnorm.insert("id".into(), json!(user_id));
        pnorm.insert("username".into(), json!(label));
        pnorm.insert("displayName".into(), json!(label));
        if !avatar.is_empty() { pnorm.insert("avatarUrl".into(), json!(avatar)); }
        pnorm.insert("rawProfile".into(), user.clone());
        let profile_norm = Value::Object(pnorm);

        // 官方凭据键名（见 asar oauthCredentialRepo）：oauth:{provider}:access_token|refresh_token|user_info
        // + zcodejwttoken + oauth:active_provider
        let mut encrypted = std::collections::HashMap::new();
        encrypted.insert("oauth:active_provider".to_string(), encrypt_value(&provider));
        encrypted.insert(format!("oauth:{}:access_token", provider), encrypt_value(&access_token));
        if !refresh_token.is_empty() {
            encrypted.insert(format!("oauth:{}:refresh_token", provider), encrypt_value(&refresh_token));
        }
        encrypted.insert(format!("oauth:{}:user_info", provider), encrypt_value(&profile_norm.to_string()));
        encrypted.insert("zcodejwttoken".to_string(), encrypt_value(&token));
        let safe = sanitize_label(&label);
        let prof_dir = profiles_dir().join(&safe);
        let _ = std::fs::create_dir_all(&prof_dir);
        let _ = write_snapshot(&prof_dir, &serde_json::to_value(&encrypted).unwrap_or(json!({})));
        let mut meta = json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()});
        let _mid = ensure_profile_device_mid(&prof_dir, &mut meta);
        let _auid = ensure_profile_arms_uid(&prof_dir, &mut meta);
        let _ = write_json(&prof_dir.join("meta.json"), &meta);
        sync_provider_family_domain(&provider);
        set_oauth(json!({"status":"ready","label": label, "provider": provider, "name": safe, "warning": warning}));
        return;
    }
}

fn encrypt_value(plain: &str) -> String {
    let key = derive_key(&credential_secret());
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let iv: [u8; 12] = rand::Rng::gen(&mut rand::thread_rng());
    let ct = cipher.encrypt(Nonce::from_slice(&iv), plain.as_bytes()).unwrap();
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // 布局必须与 decrypt_value 一致：IV.TAG.CT（tag 在中段，密文在末段）
    format!("{}{}.{}.{}", ENC_PREFIX,
        engine.encode(iv), engine.encode(&ct[ct.len()-16..]), engine.encode(&ct[..ct.len()-16]))
}

#[tauri::command]
fn oauth_start(provider: Option<String>) -> serde_json::Value {
    let provider = provider.unwrap_or_else(|| "zai".to_string());
    if provider != "zai" && provider != "bigmodel" {
        return json!({"ok": false, "error": format!("unknown provider: {}", provider)});
    }
    if let Some(s) = get_oauth() {
        if s.get("status").and_then(|v| v.as_str()) == Some("pending") {
            return json!({"ok": false, "error": "already pending"});
        }
    }
    set_oauth(json!({"status":"pending","provider": provider}));
    let poll_token = generate_poll_token();
    std::thread::spawn(move || { _oauth_worker(provider, poll_token); });
    json!({"ok": true})
}

#[tauri::command]
fn oauth_status() -> serde_json::Value {
    match get_oauth() {
        Some(s) => s,
        None => json!({"status": "idle"}),
    }
}

#[tauri::command]
fn oauth_open() -> serde_json::Value {
    if let Some(s) = get_oauth() {
        let url = s.get("authorize_url").and_then(|v| v.as_str()).unwrap_or("");
        if !url.is_empty() {
            open_in_browser(url);
            return json!({"ok": true});
        }
    }
    json!({"ok": false, "error": "no pending oauth"})
}

fn _get_jwt_token(key: &str) -> Result<String, String> {
    let creds = if key == "__current__" {
        read_json(&cred_path())?
    } else {
        read_snapshot_value(&profiles_dir().join(key)).ok_or("profile not found")?
    };
    let raw = creds.get("zcodejwttoken").and_then(|v| v.as_str()).ok_or("no jwt")?;
    decrypt_value(raw)
}

#[tauri::command]
fn fetch_quota(key: String, force: Option<bool>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let now = chrono::Utc::now().timestamp();
    if !force.unwrap_or(false) {
        if let Some(map) = QUOTA_CACHE.lock().unwrap().as_ref() {
            if let Some((ts, v)) = map.get(&key) { if now - ts < 90 { return v.clone(); } }
        }
    }
    let token = match _get_jwt_token(&key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e}) };
    let mid = telemetry_device_mid();
    let resp = match http().get("https://zcode.z.ai/api/v1/zcode-plan/billing/balance")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", &mid).header("X-Client-Language", "zh-CN")
        .header("X-ZCode-App-Version", "3.17.1")
        .timeout(std::time::Duration::from_secs(30)).send() {
        Ok(r) => match r.json::<Value>() { Ok(j) => json!({"ok": true, "data": j}), Err(e) => json!({"ok": false, "error": e.to_string()}) },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    QUOTA_CACHE.lock().unwrap().get_or_insert_with(Default::default).insert(key, (now, resp.clone()));
    resp
}

// 自绘标题栏的窗口控制（decorations:false 后由前端按钮调用）
#[tauri::command]
fn win_minimize(window: tauri::WebviewWindow) { let _ = window.minimize(); }

#[tauri::command]
fn win_toggle_maximize(window: tauri::WebviewWindow) {
    match window.is_maximized() { Ok(true) => { let _ = window.unmaximize(); }, Ok(_) => { let _ = window.maximize(); }, Err(_) => {} }
}

#[tauri::command]
fn win_hide(window: tauri::WebviewWindow) { let _ = window.hide(); } // 关闭键 = 隐藏到托盘

#[tauri::command]
fn win_start_drag(window: tauri::WebviewWindow) { let _ = window.start_dragging(); }

#[tauri::command]
fn open_zcode_client() -> serde_json::Value {
    let exe = zcode_exe_path().unwrap_or_default();
    if exe.is_empty() { return json!({"ok": false, "error": "not found"}); }
    json!({"ok": launch_zcode_process(&exe)})
}

// ------------------------------------------------------- settings & benefits

static SETTINGS: Mutex<Option<Value>> = Mutex::new(None);
static BENEFITS: Mutex<Option<std::collections::HashMap<String, Value>>> = Mutex::new(None);
static LAST_CHECK: Mutex<Option<i64>> = Mutex::new(None);

fn config_path() -> PathBuf { app_data_dir().join("hub-config.json") }

fn load_settings() -> Value {
    let mut st = SETTINGS.lock().unwrap();
    if st.is_none() {
        *st = Some(read_json(&config_path()).unwrap_or(json!({"auto_check_minutes": 15, "notify_enabled": true, "hot_switch": false})));
    }
    st.clone().unwrap()
}

// 官方 preview 响应 → 福利条目（纯函数，可单测）
fn parse_preview_plans(j: &Value) -> Vec<Value> {
    let mut camps = Vec::new();
    if let Some(plans) = j.pointer("/data/plans").and_then(|v| v.as_array()) {
        for p in plans {
            let name = p.get("name").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| p.get("plan_id").and_then(|v| v.as_str()).map(String::from))
                .unwrap_or_else(|| "未命名福利".into());
            let mut grant: i64 = 0;
            let mut parts: Vec<String> = Vec::new();
            if let Some(ents) = p.get("entitlements").and_then(|v| v.as_array()) {
                for e in ents {
                    let units = e.get("grant_units").and_then(|v| v.as_i64()).unwrap_or(0);
                    grant += units;
                    if let Some(sn) = e.get("show_name").and_then(|v| v.as_str()) {
                        if !sn.is_empty() { parts.push(format!("{} +{}", sn, units)); }
                    }
                }
            }
            camps.push(json!({
                "title": name,
                "grant": if grant > 0 { grant.to_string() } else { "?".to_string() },
                "detail": parts.join(" / ")
            }));
        }
    }
    camps
}

// 官方「可领取预览」：GET /api/v1/zcode-plan/billing/preview —— 客户端领取弹窗同源接口，
// 返回 data.plans[]（每个含 plan_id/name/entitlements[grant_units]）。空数组 = 当前无可领。
// 注意：429 限流存在，批量检测时逐账号间加间隔。
fn _benefits_key_result(key: &str) -> Value {
    let ts = chrono::Utc::now().timestamp();
    let token = match _get_jwt_token(key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e, "count": 0, "campaigns": [], "checked_at": ts}) };
    let client = reqwest::blocking::Client::new();
    let resp = client.get("https://zcode.z.ai/api/v1/zcode-plan/billing/preview")
        .query(&[("app_version", "3.17.1"), ("platform", "win32-x64")])
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Client-Language", "zh-CN")
        .header("X-ZCode-App-Version", "3.17.1")
        .timeout(std::time::Duration::from_secs(30)).send();
    let j: Value = match resp {
        Ok(r) => {
            if r.status().as_u16() == 429 {
                return json!({"ok": false, "error": "请求过于频繁(429)，稍后自动重试", "count": 0, "campaigns": [], "checked_at": ts});
            }
            match r.json::<Value>() { Ok(j) => j, Err(e) => return json!({"ok": false, "error": e.to_string(), "count": 0, "campaigns": [], "checked_at": ts}) }
        }
        Err(e) => return json!({"ok": false, "error": e.to_string(), "count": 0, "campaigns": [], "checked_at": ts}),
    };
    if j.get("code").and_then(|c| c.as_i64()) != Some(0) {
        let msg = j.get("msg").and_then(|m| m.as_str()).unwrap_or("preview error");
        return json!({"ok": false, "error": msg, "count": 0, "campaigns": [], "checked_at": ts});
    }
    let camps = parse_preview_plans(&j);
    json!({"ok": true, "count": camps.len(), "campaigns": camps, "checked_at": ts})
}

fn run_benefit_check_for(key: &str) -> Value {
    let result = _benefits_key_result(key);
    BENEFITS.lock().unwrap()
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(key.to_string(), result.clone());
    result
}

fn _all_profile_keys() -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            // DPAPI 加密快照（credentials.snap）或旧格式（credentials.json）都算有效存档
            let p = e.path();
            if p.join("credentials.snap").exists() || p.join(CRED_FILE).exists() {
                keys.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    keys.sort();
    if keys.is_empty() { keys.push("__current__".to_string()); }
    keys
}

#[tauri::command]
fn check_benefits(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let r = run_benefit_check_for(&key);
    json!({"ok": r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
           "count": r.get("count").and_then(|v| v.as_u64()).unwrap_or(0), "key": key})
}

#[tauri::command]
fn check_all_benefits() -> serde_json::Value {
    let keys = _all_profile_keys();
    let mut total = 0u64; let mut with = 0u64; let mut okn = 0u64;
    for (i, k) in keys.iter().enumerate() {
        if i > 0 { std::thread::sleep(std::time::Duration::from_millis(800)); } // 避开 429 限流
        let r = run_benefit_check_for(k);
        if r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) { okn += 1; }
        let c = r.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        if c > 0 { with += 1; total += c; }
    }
    *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp());
    json!({"ok": true, "accounts": keys.len(), "checked_ok": okn, "accounts_with_benefits": with, "total_campaigns": total})
}

#[tauri::command]
fn get_settings() -> serde_json::Value { load_settings() }

#[tauri::command]
fn set_settings(minutes: i64, notify_enabled: Option<bool>, zcode_path: Option<String>, hot_switch: Option<bool>) -> serde_json::Value {
    let mut s = load_settings();
    s["auto_check_minutes"] = json!(minutes.clamp(0, 1440));
    s["notify_enabled"] = json!(notify_enabled.unwrap_or(true));
    if let Some(h) = hot_switch { s["hot_switch"] = json!(h); }
    let zp = zcode_path.map(|p| p.trim().trim_matches('"').to_string()).unwrap_or_default();
    if zp.is_empty() {
        s["zcode_path"] = json!(null);
        *EXE_CACHE.lock().unwrap() = None;
    } else if std::path::Path::new(&zp).exists() {
        s["zcode_path"] = json!(zp);
        *EXE_CACHE.lock().unwrap() = None;
    } else {
        return json!({"ok": false, "error": format!("路径不存在: {}", zp)});
    }
    let _ = write_json(&config_path(), &s);
    *SETTINGS.lock().unwrap() = Some(s);
    *LAST_CHECK.lock().unwrap() = None; // 保存后立即按新周期跑一轮
    json!({"ok": true})
}

// 全量检测所有账号福利；发现可领且通知开关开启时弹系统通知（托盘菜单与自动循环共用）
fn _check_all_and_notify(app: &tauri::AppHandle) {
    let mut total = 0u64; let mut accounts = 0u64;
    for (i, k) in _all_profile_keys().into_iter().enumerate() {
        if i > 0 { std::thread::sleep(std::time::Duration::from_millis(800)); }
        let r = run_benefit_check_for(&k);
        let c = r.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        if c > 0 { accounts += 1; total += c; }
    }
    *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp());
    if total > 0 && load_settings().get("notify_enabled").and_then(|v| v.as_bool()).unwrap_or(true) {
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification().builder()
            .title("ZCode Hub 福利提醒")
            .body(format!("{} 个账号共有 {} 项福利可领取，打开应用查看", accounts, total))
            .show();
    }
}

// 自动检测线程：每 30s 醒来按设置的周期跑一轮，发现可领福利弹系统通知
fn _auto_check_loop(app: tauri::AppHandle) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let minutes = load_settings().get("auto_check_minutes").and_then(|v| v.as_i64()).unwrap_or(0);
        if minutes <= 0 { continue; }
        let now = chrono::Utc::now().timestamp();
        let due = match *LAST_CHECK.lock().unwrap() { None => true, Some(l) => now - l >= minutes * 60 - 15 };
        if !due { continue; }
        _check_all_and_notify(&app);
    }
}

// -------------------------------------------------------------------- tray

fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "显示 ZCode Hub", true, None::<&str>)?;
    let check = MenuItem::with_id(app, "check", "🔍 立即检测福利", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &check, &quit])?;

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
                "check" => {
                    let h = app.clone();
                    std::thread::spawn(move || _check_all_and_notify(&h));
                }
                "quit" => { save_window_state(app); app.exit(0); }
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
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            migrate_legacy_data();
            *APP_HANDLE.lock().unwrap() = Some(app.handle().clone());
            setup_tray(app)?;
            restore_window_state(app);
            let handle = app.handle().clone();
            std::thread::spawn(move || _auto_check_loop(handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                save_window_state(window.app_handle());
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state, capture_profile, switch_profile, delete_profile,
            fetch_quota, open_zcode_client,
            oauth_start, oauth_status, oauth_open,
            check_benefits, check_all_benefits, get_settings, set_settings,
            win_minimize, win_toggle_maximize, win_hide, win_start_drag,
            export_bundle, import_bundle,
            set_autostart, open_data_dir, open_zcode_data_dir, check_update, open_url, install_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() { run() }


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_dec_roundtrip() {
        let v = encrypt_value("测试-token-123");
        assert!(v.starts_with(ENC_PREFIX));
        assert_eq!(decrypt_value(&v).unwrap(), "测试-token-123");
    }

    #[test]
    fn enc_layout_is_iv_tag_ct() {
        // 官方布局：IV.TAG.CT —— tag 固定 16 字节在中段；改错顺序会导致存量数据全灭
        let enc = encrypt_value("abc");
        let parts: Vec<&str> = enc[ENC_PREFIX.len()..].split('.').collect();
        assert_eq!(parts.len(), 3);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        assert_eq!(engine.decode(parts[0]).unwrap().len(), 12); // nonce
        assert_eq!(engine.decode(parts[1]).unwrap().len(), 16); // tag
        assert!(engine.decode(parts[2]).unwrap().len() >= 3);   // ciphertext
    }

    #[test]
    fn safe_key_blocks_traversal() {
        assert!(safe_key("../x").is_err());
        assert!(safe_key("..").is_err());
        assert!(safe_key("a/b").is_err());
        assert!(safe_key("a").is_err());
        assert!(safe_key("a:b").is_err());
        assert!(safe_key(".hidden").is_err());
        assert!(safe_key("").is_err());
        assert!(safe_key("test-account.example-mail.com").is_ok());
        assert!(safe_key("__current__").is_ok());
    }

    #[test]
    fn jwt_expired_detects_exp_claim() {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mk = |exp: i64| -> String {
            let claims = json!({"exp": exp, "sub": "u1"});
            format!("h.{}.s", engine.encode(claims.to_string().as_bytes()))
        };
        let now = chrono::Utc::now().timestamp();
        let expired = json!({"zcodejwttoken": mk(now - 3600)});
        let fresh = json!({"zcodejwttoken": mk(now + 3600)});
        let no_exp = json!({"zcodejwttoken": format!("h.{}.s", engine.encode(json!({"sub":"u"}).to_string().as_bytes()))});
        assert!(jwt_expired(&expired));
        assert!(!jwt_expired(&fresh));
        assert!(!jwt_expired(&no_exp)); // 无 exp 不误报
    }

    #[test]
    fn bundle_kdf_deterministic_and_password_sensitive() {
        let salt = [7u8; 16];
        let a = bundle_key("password1", &salt);
        let b = bundle_key("password1", &salt);
        let c = bundle_key("password2", &salt);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parse_preview_plans_extracts_benefits() {
        let j = json!({"code": 0, "data": {"plans": [
            {"plan_id": "p1", "name": "周末福利", "entitlements": [
                {"show_name": "GLM-5.3-Flash", "grant_units": 500000000}]},
            {"plan_id": "p2", "entitlements": []},
            {"name": "  ", "plan_id": "p3"}
        ]}});
        let camps = parse_preview_plans(&j);
        assert_eq!(camps.len(), 3);
        assert_eq!(camps[0]["title"], "周末福利");
        assert_eq!(camps[0]["grant"], "500000000");
        assert_eq!(camps[0]["detail"], "GLM-5.3-Flash +500000000");
        assert_eq!(camps[1]["title"], "p2");          // 无 name → 回退 plan_id
        assert_eq!(camps[1]["grant"], "?");            // 无权益 → ?
        assert_eq!(camps[2]["title"], "p3");          // 空白 name → 回退
        // 空响应
        assert_eq!(parse_preview_plans(&json!({"code": 0})).len(), 0);
    }

    #[test]
    fn sanitize_label_whitelists_chars() {
        assert_eq!(sanitize_label("a b/c"), "a_b_c");
        assert_eq!(sanitize_label("user@mail.com"), "user@mail.com");
        assert_eq!(sanitize_label("../.."), ".._.."); // 点保留、斜杠替换
    }

    #[test]
    fn write_json_read_json_roundtrip() {
        let dir = std::env::temp_dir().join("zhb-test-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.json");
        let v = json!({"k": [1, 2, {"zh": "中文"}]});
        write_json(&p, &v).unwrap();
        assert_eq!(read_json(&p).unwrap(), v);
        // 原子写不应残留临时文件
        assert!(!dir.join("t.hub-tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hot_swap_verified_roundtrip() {
        let dir = std::env::temp_dir().join("zhb-test-hotswap");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("live.json");
        let v = json!({"zcodejwttoken": "x.y.z", "k": 1});
        assert!(hot_swap_verified(&p, &v));
        assert_eq!(read_json(&p).unwrap(), v);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_device_mid_helpers_exist() {
        // 冒烟：arms 目录推导不含空项
        let dirs = arms_store_dirs();
        assert!(dirs.iter().all(|d| d.file_name().is_some()));
    }
}