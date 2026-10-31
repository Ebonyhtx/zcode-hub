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

// 客户端 setting.json 的 providerFamilyDomain 必须 = 当前登录账号的家族（zai/bigmodel），
// 否则账号提供商解析第一个检查就返回 null → 模型配置显示「请登录」、套餐额度不加载。
// 交互登录时官方客户端会自己写这个字段；文件级切换/存档必须由 Hub 同步维护。
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

fn zcode_exe_path() -> Option<String> {
    if let Some(p) = EXE_CACHE.lock().unwrap().clone() { return Some(p); }
    let found = Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-Process ZCode -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path"])
        .creation_flags(0x08000000)
        .output().ok()
        .and_then(|o| { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } });
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
struct ProfileInfo { key: String, label: String, captured_at: String, is_current: bool, provider: String }

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
            let meta = read_json(&e.path().join("meta.json")).ok().unwrap_or(json!({}));
            let ca = meta.get("captured_at").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
            // provider 优先取 meta.json，老存档回退到解密凭据里的 oauth:active_provider
            let mut provider = meta.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if provider.is_empty() {
                provider = read_json(&cp).ok()
                    .and_then(|c| c.get("oauth:active_provider").and_then(|v| v.as_str()).map(String::from))
                    .and_then(|s| decrypt_value(&s).ok())
                    .unwrap_or_default();
            }
            let ic = std::fs::read(&cp).ok().map(|b| Sha256::digest(&b).to_vec()).map(|h| Some(h) == cur_sha).unwrap_or(false);
            profiles.push(ProfileInfo { key: name, label, captured_at: ca, is_current: ic, provider });
        }
    }
    let benefits = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    if let Some(h) = APP_HANDLE.lock().unwrap().as_ref() {
        if let Some(tray) = h.tray_by_id("main") {
            let _ = tray.set_tooltip(Some(format!("ZCode Hub — 当前: {}", cur_label)));
        }
    }
    json!({ "current_label": cur_label, "current_provider": cur_provider, "profiles": profiles, "zcode_running": zcode_running(), "zcode_exe": zcode_exe_path().unwrap_or_default(),
            "settings": load_settings(), "benefits": benefits, "last_check": *LAST_CHECK.lock().unwrap() })
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
    let provider = creds.get("oauth:active_provider").and_then(|v| v.as_str())
        .and_then(|s| decrypt_value(s).ok()).unwrap_or_default();
    let _ = write_json(&dd.join("meta.json"), &json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()}));
    json!({"ok": true, "name": fname, "label": label})
}

#[tauri::command]
fn switch_profile(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let prof = profiles_dir().join(&key).join(CRED_FILE);
    if !prof.exists() { return json!({"ok": false, "error": format!("'{}' 不存在", key)}); }
    let cur = cred_path();
    let exe = zcode_exe_path();
    let was = zcode_running();
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
        let mut known = false;
        if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
            for e in rd.flatten() {
                let cp = e.path().join(CRED_FILE);
                if cp.exists() && read_json(&cp).map(|c| account_label(&c)) == Ok(cl.clone()) { known = true; break; }
            }
        }
        if !known && valid_session {
            let auto = format!("autosave-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            let _ = std::fs::create_dir_all(profiles_dir().join(&auto));
            let _ = std::fs::copy(&cur, profiles_dir().join(&auto).join(CRED_FILE));
            let _ = write_json(&profiles_dir().join(&auto).join("meta.json"), &json!({"label": cl, "captured_at": chrono::Utc::now().to_rfc3339()}));
        }
        if valid_session {
            let _ = std::fs::copy(&cur, v2_dir().join("credentials.json.hub-backup"));
        }
    }
    if std::fs::copy(&prof, &cur).is_err() {
        let _ = std::fs::copy(v2_dir().join("credentials.json.hub-backup"), &cur);
        return json!({"ok": false, "error": "替换凭据文件失败，已恢复原文件"});
    }
    // 同步客户端激活家族，否则模型配置/套餐解析会因 domain 不匹配而「请登录」
    let fam = read_json(&cur).ok()
        .and_then(|c| c.get("oauth:active_provider").and_then(|v| v.as_str()).map(String::from))
        .and_then(|s| decrypt_value(&s).ok())
        .unwrap_or_default();
    sync_provider_family_domain(&fam);
    let rel = if was { exe.as_ref().map(|e| launch_zcode_process(e)).unwrap_or(false) } else { false };
    json!({"ok": true, "relaunched": rel})
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
        let safe: String = label.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' { c } else { '_' }).collect();
        let prof_dir = profiles_dir().join(&safe);
        let _ = std::fs::create_dir_all(&prof_dir);
        write_json(&prof_dir.join(CRED_FILE), &serde_json::to_value(&encrypted).unwrap_or(json!({}))).ok();
        let _ = write_json(&prof_dir.join("meta.json"), &json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()}));
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
    let cp = if key == "__current__" { cred_path() } else { profiles_dir().join(key).join(CRED_FILE) };
    if !cp.exists() { return Err("profile not found".into()); }
    let creds = read_json(&cp)?;
    let raw = creds.get("zcodejwttoken").and_then(|v| v.as_str()).ok_or("no jwt")?;
    decrypt_value(raw)
}

#[tauri::command]
fn fetch_quota(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let token = match _get_jwt_token(&key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e}) };
    let mid = telemetry_device_mid();
    let client = reqwest::blocking::Client::new();
    match client.get("https://zcode.z.ai/api/v1/zcode-plan/billing/balance")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", &mid).header("X-Client-Language", "zh-CN")
        .header("X-ZCode-App-Version", "3.17.1")
        .timeout(std::time::Duration::from_secs(30)).send() {
        Ok(r) => match r.json::<Value>() { Ok(j) => json!({"ok": true, "data": j}), Err(e) => json!({"ok": false, "error": e.to_string()}) },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
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

fn config_path() -> PathBuf { PathBuf::from("D:\\zcode-hub\\hub-config.json") }

fn load_settings() -> Value {
    let mut st = SETTINGS.lock().unwrap();
    if st.is_none() {
        *st = Some(read_json(&config_path()).unwrap_or(json!({"auto_check_minutes": 15, "notify_enabled": true})));
    }
    st.clone().unwrap()
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
            if e.path().join(CRED_FILE).exists() { keys.push(e.file_name().to_string_lossy().to_string()); }
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
fn set_settings(minutes: i64, notify_enabled: Option<bool>) -> serde_json::Value {
    let mut s = load_settings();
    s["auto_check_minutes"] = json!(minutes.clamp(0, 1440));
    s["notify_enabled"] = json!(notify_enabled.unwrap_or(true));
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
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            *APP_HANDLE.lock().unwrap() = Some(app.handle().clone());
            setup_tray(app)?;
            let handle = app.handle().clone();
            std::thread::spawn(move || _auto_check_loop(handle));
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
            fetch_quota, open_zcode_client,
            oauth_start, oauth_status, oauth_open,
            check_benefits, check_all_benefits, get_settings, set_settings,
            win_minimize, win_toggle_maximize, win_hide, win_start_drag,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() { run() }
