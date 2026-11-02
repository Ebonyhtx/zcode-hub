#![cfg_attr(windows, windows_subsystem = "windows")]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

mod formats;
mod audit;
mod history;
mod platform;
mod claim;
use formats::{read_json, write_json, CRED_FILE, ENC_PREFIX};

// 审计日志：只记不透明 key（哈希）与事件结果，best-effort（失败静默，不影响业务）
fn opaque_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"zcode-hub-audit:");
    h.update(key.as_bytes());
    let d = h.finalize();
    let hex: String = d.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    format!("k{}", hex)
}

fn is_opaque_key(s: &str) -> bool {
    s.len() == 17 && s.starts_with('k') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_hex16(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// 一次性迁移旧版本落盘的明文账号键（审计/福利/额度快照/历史文件名）到不透明哈希。
/// best-effort：任何一项失败都不影响启动。
fn migrate_privacy_keys() {
    // 审计日志：逐行改写 key
    let ap = audit::audit_path(&app_data_dir());
    if let Ok(txt) = std::fs::read_to_string(&ap) {
        let mut out = String::new();
        let mut changed = false;
        for line in txt.lines() {
            if let Ok(mut v) = serde_json::from_str::<Value>(line) {
                if let Some(k) = v.get("key").and_then(|x| x.as_str()).map(String::from) {
                    if !is_opaque_key(&k) && safe_key(&k).is_ok() {
                        v["key"] = json!(opaque_key(&k));
                        changed = true;
                    }
                }
                out.push_str(&serde_json::to_string(&v).unwrap_or_else(|_| line.to_string()));
            } else { out.push_str(line); }
            out.push('\n');
        }
        if changed { let _ = write_bytes_atomic(&ap, out.as_bytes()); }
    }
    // 福利缓存：{"map": {key: value}}
    let bf = benefits_file();
    if let Ok(mut v) = read_json(&bf) {
        let mut changed = false;
        if let Some(map) = v.get_mut("map").and_then(|m| m.as_object_mut()) {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if !is_opaque_key(&k) && safe_key(&k).is_ok() {
                    if let Some(val) = map.remove(&k) { map.insert(opaque_key(&k), val); changed = true; }
                }
            }
        }
        if changed { let _ = write_json(&bf, &v); }
    }
    // 额度快照：顶层 {key: {ts,resp}}
    let qc = quota_cache_path();
    if let Ok(mut v) = read_json(&qc) {
        if let Some(map) = v.as_object_mut() {
            let keys: Vec<String> = map.keys().cloned().collect();
            let mut changed = false;
            for k in keys {
                if !is_opaque_key(&k) && safe_key(&k).is_ok() {
                    if let Some(val) = map.remove(&k) { map.insert(opaque_key(&k), val); changed = true; }
                }
            }
            if changed { let _ = write_json(&qc, &v); }
        }
    }
    // 额度历史：旧文件名 = 账号 key；改为 history::key_hash
    let hd = app_data_dir().join("quota-history");
    if let Ok(rd) = std::fs::read_dir(&hd) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".jsonl") else { continue };
            if is_hex16(stem) { continue; }
            let target = hd.join(format!("{}.jsonl", history::key_hash(stem)));
            if !target.exists() { let _ = std::fs::rename(e.path(), target); }
        }
    }
}

fn audit_log(event: &str, key: Option<&str>, detail: serde_json::Value) {
    let entry = json!({"ts": chrono::Utc::now().to_rfc3339(), "event": event,
        "key": key.map(opaque_key), "detail": detail});
    let _ = audit::audit_append(&audit::audit_path(&app_data_dir()), &entry);
}

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

// 账号目录名清洗：白名单字符外全部替换为下划线（capture / OAuth 建档 / 导入共用）。
// 结果必须能通过 safe_key：连续点折叠、去掉首尾点、空值兜底、限长避免超长路径。
fn sanitize_label(s: &str) -> String {
    let mut out: String = s.trim().chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' { c } else { '_' })
        .collect();
    while out.contains("..") { out = out.replace("..", "."); }
    out = out.trim_matches('.').to_string();
    if out.is_empty() { out = "account".into(); }
    let upper = out.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4 && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.chars().nth(3).map(|c| c.is_ascii_digit()).unwrap_or(false));
    if reserved { out = format!("account-{}", out); }
    out.chars().take(64).collect()
}

// ---------------- 窗口几何持久化 ----------------
fn save_window_state(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        // 最小化时 outer_position 是 -32000 哨兵、尺寸是 160x28 —— 存下去会导致下次启动窗口跑到屏幕外
        if w.is_minimized().unwrap_or(false) { return; }
        if let (Ok(pos), Ok(size)) = (w.outer_position(), w.outer_size()) {
            if pos.x <= -10000 || pos.y <= -10000 || size.width < 400 || size.height < 400 { return; }
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
        let mut applied = false;
        if let Some(win) = cfg.get("window") {
            let max = win.get("max").and_then(|v| v.as_bool()).unwrap_or(false);
            if max {
                let _ = w.maximize();
                applied = true;
            } else if let (Some(x), Some(y), Some(ww), Some(hh)) = (
                win.get("x").and_then(|v| v.as_i64()), win.get("y").and_then(|v| v.as_i64()),
                win.get("w").and_then(|v| v.as_u64()), win.get("h").and_then(|v| v.as_u64())) {
                // 有效性校验：排除最小化哨兵（-32000）与过小/越界几何；
                // 还要确认窗口与至少一个显示器相交，副屏被拔掉时不能恢复到场外。
                let ww = ww.clamp(400, 10000) as u32;
                let hh = hh.clamp(400, 10000) as u32;
                let sane = x > -10000 && y > -10000 && x < 16384 && y < 16384;
                if sane && geometry_visible(&w, x as i32, y as i32, ww, hh) {
                    use tauri::{PhysicalPosition, PhysicalSize};
                    let _ = w.set_position(PhysicalPosition::new(x as i32, y as i32));
                    let _ = w.set_size(PhysicalSize::new(ww, hh));
                    applied = true;
                }
            }
        }
        if !applied { let _ = w.center(); }
        // 开机自启偏好：不抢前台，直接驻留托盘
        if cfg.get("start_minimized").and_then(|v| v.as_bool()).unwrap_or(false) {
            let _ = w.hide();
        } else {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

/// 窗口矩形是否与任一显示器相交（不同 DPI 下坐标均为物理像素，可与位置/尺寸直接比较）
fn geometry_visible(w: &tauri::WebviewWindow, x: i32, y: i32, ww: u32, hh: u32) -> bool {
    let Ok(monitors) = w.available_monitors() else { return false };
    if monitors.is_empty() { return true; } // 查询失败时不阻断恢复
    monitors.iter().any(|m| {
        let p = m.position();
        let s = m.size();
        let (mx1, my1) = (p.x as i64, p.y as i64);
        let (mx2, my2) = (mx1 + s.width as i64, my1 + s.height as i64);
        let (x1, y1) = (x as i64, y as i64);
        let (x2, y2) = (x1 + ww as i64, y1 + hh as i64);
        x1 < mx2 && x2 > mx1 && y1 < my2 && y2 > my1
    })
}

// ---------------- 快照保护（DPAPI） ----------------
// 账号快照整包加密：随机密钥经 DPAPI 绑定当前 Windows 用户+机器。
// 快照文件被拷到别的机器/用户无法解密（区别于 ZCode 自身的可推导 fallback 方案）。
// DPAPI 调用在 platform.rs（平台抽象第 0 期）。
static SNAP_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn snap_key() -> Result<Vec<u8>, String> {
    let mut g = SNAP_KEY.lock().unwrap();
    if let Some(k) = g.as_ref() { return Ok(k.clone()); }
    let f = app_data_dir().join("snapkey");
    // 仅「文件不存在」才允许新建密钥。已存在但读/解失败必须硬失败——
    // 旧实现会生成新密钥覆盖原文件，等于让全部账号存档永久不可解。
    if !f.exists() {
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let enc = platform::dpapi_operate(&key, true)
            .map_err(|e| format!("无法创建快照主密钥（{}），本次操作已取消", e))?;
        let engine = base64::engine::general_purpose::STANDARD;
        write_bytes_atomic(&f, format!("dpapi:{}", engine.encode(enc)).as_bytes())
            .map_err(|e| format!("快照主密钥落盘失败（{}），本次操作已取消", e))?;
        *g = Some(key.clone());
        return Ok(key);
    }
    let txt = std::fs::read_to_string(&f)
        .map_err(|e| format!("快照主密钥无法读取（{}）。为避免覆盖，已停止本次操作；请检查 %APPDATA%\\zcode-hub 权限", e))?;
    let b64 = txt.trim().strip_prefix("dpapi:")
        .ok_or("快照主密钥格式异常（缺少 dpapi: 前缀）。已停止操作以免覆盖现有密钥")?;
    let engine = base64::engine::general_purpose::STANDARD;
    let enc = engine.decode(b64)
        .map_err(|_| "快照主密钥损坏（base64 解码失败）。已停止操作以免覆盖现有密钥")?;
    let key = platform::dpapi_operate(&enc, false)
        .map_err(|_| "快照主密钥无法用当前 Windows 用户解密（可能换了用户/机器，或被安全软件拦截）。已停止操作以免覆盖现有密钥")?;
    if key.len() != 32 {
        return Err(format!("快照主密钥长度异常（{} 字节，应为 32）。已停止操作", key.len()));
    }
    *g = Some(key.clone());
    Ok(key)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(p) = path.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
    let tmp = path.with_extension(format!("hub-tmp-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => { let _ = std::fs::remove_file(&tmp); Err(e.to_string()) }
    }
}

const SNAP_MAGIC: &str = "ZH-SNAP1:";

fn write_snapshot(dir: &Path, v: &Value) -> Result<(), String> {
    let key = snap_key()?;
    let plain = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let ct = cipher.encrypt(Nonce::from_slice(&iv), plain.as_ref()).map_err(|e| e.to_string())?;
    let engine = base64::engine::general_purpose::STANDARD;
    let body = format!("{}{}.{}", SNAP_MAGIC, engine.encode(iv), engine.encode(ct));
    // 原子写：临时名带随机后缀，进程被杀也不会留下半截快照
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("credentials.hub-tmp-{}", rand::random::<u32>()));
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    match std::fs::rename(&tmp, dir.join("credentials.snap")) {
        Ok(()) => { let _ = std::fs::remove_file(dir.join(CRED_FILE)); Ok(()) } // 旧格式副本不再保留
        Err(e) => { let _ = std::fs::remove_file(&tmp); Err(e.to_string()) }
    }
}

/// 读取快照；区分「不存在」与「损坏/无法解密」，后者必须能显示给用户。
fn read_snapshot_checked(dir: &Path) -> Result<Value, String> {
    let snap = dir.join("credentials.snap");
    if snap.exists() {
        let txt = std::fs::read_to_string(&snap).map_err(|e| format!("存档读取失败: {}", e))?;
        let body = txt.trim().strip_prefix(SNAP_MAGIC).ok_or("存档格式异常（未知前缀）")?;
        let engine = base64::engine::general_purpose::STANDARD;
        let mut it = body.split('.');
        let iv = engine.decode(it.next().ok_or("存档格式异常（缺 IV）")?).map_err(|_| "存档格式异常（IV）")?;
        let ct = engine.decode(it.next().ok_or("存档格式异常（缺密文）")?).map_err(|_| "存档格式异常（密文）")?;
        if iv.len() != 12 { return Err("存档格式异常（IV 长度不是 12）".into()); }
        if ct.len() < 16 { return Err("存档格式异常（密文过短）".into()); }
        let key = snap_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
        let plain = cipher.decrypt(Nonce::from_slice(&iv), ct.as_ref())
            .map_err(|_| "存档无法解密（密钥不匹配或文件损坏）")?;
        serde_json::from_slice(&plain).map_err(|e| format!("存档 JSON 损坏: {}", e))
    } else {
        let legacy = dir.join(CRED_FILE);
        if legacy.exists() {
            let v = read_json(&legacy).map_err(|e| format!("旧格式存档读取失败: {}", e))?;
            let _ = write_snapshot(dir, &v); // 顺手升级为 DPAPI 加密
            Ok(v)
        } else {
            Err("存档不存在".into())
        }
    }
}

fn read_snapshot_value(dir: &Path) -> Option<Value> {
    read_snapshot_checked(dir).ok()
}

// 客户端 setting.json 的 providerFamilyDomain 必须 = 当前登录账号的家族（zai/bigmodel），
// 否则账号提供商解析第一个检查就返回 null → 模型配置显示「请登录」、套餐额度不加载。
// 交互登录时官方客户端会自己写这个字段；文件级切换/存档必须由 Hub 同步维护。
// ---------------- 设备身份跟账号走 ----------------
// 每个账号存档绑定独立 deviceMid：首次采纳当前设备的（未被其他存档占用时），
// 否则生成新的 UUID；切换时写进客户端 telemetry-state.json。
// 效果：不同账号在服务端各自呈现独立的设备标识，互不关联。
fn live_device_mid() -> Option<String> {
    let v = read_json(&v2_dir().join("telemetry-state.json")).ok()?;
    formats::read_device_mid(&v)
}

fn ensure_profile_device_mid(dir: &Path, meta: &mut Value, allow_live: bool) -> String {
    if let Some(m) = meta.get("device_mid").and_then(|v| v.as_str()) {
        if !m.trim().is_empty() { return m.to_string(); }
    }
    let mut taken: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if e.path().as_path() == dir { continue; }
            if let Ok(m) = read_json(&e.path().join("meta.json")) {
                if let Some(dm) = m.get("device_mid").and_then(|v| v.as_str()) { taken.push(dm.to_string()); }
            }
        }
    }
    let mid = match live_device_mid() {
        Some(m) if allow_live && !taken.contains(&m) => m,
        _ => uuid::Uuid::new_v4().to_string(),
    };
    meta["device_mid"] = json!(mid);
    mid
}

fn write_live_device_mid(mid: &str) {
    let p = v2_dir().join("telemetry-state.json");
    let mut v = read_json(&p).unwrap_or_else(|_| json!({}));
    if formats::set_device_mid(&mut v, mid) { let _ = write_json(&p, &v); }
}

// arms_uid：阿里云 RUM 遥测的用户标识，存于 %APPDATA% 下 ZCode 的 rum-electron-store/*.json 的 _arms_uid。
// 与 deviceMid 同策略：每账号独立，首次采纳当前值（未被占用时），否则生成新的。
// 目录枚举在 platform.rs（Windows 客户端专属布局）。
fn arms_store_dirs() -> Vec<PathBuf> { platform::arms_store_dirs() }

fn read_live_arms_uid() -> Option<String> {
    formats::read_arms_uid_in(&arms_store_dirs())
}

fn write_live_arms_uid(uid: &str) {
    if let Some(e) = formats::write_arms_uid_in(&arms_store_dirs(), uid) {
        eprintln!("arms_uid 写回失败(忽略): {}", e);
    }
}

fn ensure_profile_arms_uid(dir: &Path, meta: &mut Value, allow_live: bool) -> String {
    if let Some(u) = meta.get("arms_uid").and_then(|v| v.as_str()) {
        if !u.trim().is_empty() { return u.to_string(); }
    }
    let mut taken: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if e.path().as_path() == dir { continue; }
            if let Ok(m) = read_json(&e.path().join("meta.json")) {
                if let Some(u) = m.get("arms_uid").and_then(|v| v.as_str()) { taken.push(u.to_string()); }
            }
        }
    }
    let uid = match read_live_arms_uid() {
        Some(u) if allow_live && !taken.contains(&u) => u,
        _ => formats::new_arms_uid(),
    };
    meta["arms_uid"] = json!(uid);
    uid
}

fn sync_provider_family_domain(provider: &str) {
    let p = v2_dir().join("setting.json");
    let mut s = match read_json(&p) { Ok(s) => s, Err(_) => return };
    if formats::apply_provider_family_domain(&mut s, provider, chrono::Utc::now().timestamp_millis()) {
        let _ = write_json(&p, &s);
    }
}

// ------------------------------------------------------------------- crypto

fn credential_secret() -> String {
    if let Ok(env) = std::env::var("ZCODE_CREDENTIAL_SECRET") {
        if !env.trim().is_empty() { return env.trim().to_string(); }
    }
    let home = dirs::home_dir().unwrap_or_default().to_string_lossy().to_string();
    let user = whoami::username().unwrap_or_default();
    format!("zcode-credential-fallback:win32:{}:{}", home, user)
}

// 瞬时派生密钥用 Zeroizing 包裹：作用结束即清零内存；SNAP_KEY 进程级缓存是有意为之（见 DESIGN.md）
fn derive_key(secret: &str) -> zeroize::Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    zeroize::Zeroizing::new(hasher.finalize().into())
}

// 可注入变体：契约测试 / 未来密钥迁移用；enc:v1 的 IV.TAG.CT 布局是铁律 #1，不可动
fn encrypt_with(key: &[u8; 32], plain: &str) -> Result<String, String> {
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let ct = cipher.encrypt(Nonce::from_slice(&iv), plain.as_bytes()).map_err(|e| e.to_string())?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // 布局必须与 decrypt_with 一致：IV.TAG.CT（tag 在中段，密文在末段）
    Ok(format!("{}{}.{}.{}", ENC_PREFIX, engine.encode(iv), engine.encode(&ct[ct.len()-16..]), engine.encode(&ct[..ct.len()-16])))
}

fn decrypt_with(key: &[u8; 32], encrypted: &str) -> Result<String, String> {
    let payload = encrypted.strip_prefix(ENC_PREFIX).ok_or("not encrypted")?;
    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() != 3 { return Err("invalid format".into()); }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let iv = engine.decode(parts[0]).map_err(|e| e.to_string())?;
    let tag = engine.decode(parts[1]).map_err(|e| e.to_string())?;
    let ct = engine.decode(parts[2]).map_err(|e| e.to_string())?;
    // 长度必须显式校验：GenericArray::from_slice 在长度不符时会 panic，
    // 而这里读的是本地文件（可能损坏/被改），不能让启动/刷新路径崩掉。
    if iv.len() != 12 { return Err("invalid iv length".into()); }
    if tag.len() != 16 { return Err("invalid tag length".into()); }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&iv);
    let mut combined = ct;
    combined.extend_from_slice(&tag);
    let plain = cipher.decrypt(nonce, combined.as_ref()).map_err(|e| e.to_string())?;
    String::from_utf8(plain).map_err(|e| e.to_string())
}

fn decrypt_value(encrypted: &str) -> Result<String, String> {
    decrypt_with(&derive_key(&credential_secret()), encrypted)
}

// -------------------------------------------------------------------- paths

fn home_v2() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".zcode").join("v2")
}
// setting.json 的 dataBaseDir 若被用户改过，凭据等数据文件跟着走（setting.json 本身留在原处）
fn v2_dir() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let root = read_json(&home_v2().join("setting.json")).ok()
        .and_then(|v| formats::data_base_dir(&v))
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
    let old_snapkey = PathBuf::from(r"D:\zcode-hub\snapkey");
    let new_profiles = profiles_dir();
    let _ = std::fs::create_dir_all(&new_profiles);
    // 快照主密钥必须跟存档一起迁移，否则旧 profiles 永远解不开
    if !app_data_dir().join("snapkey").exists() && old_snapkey.exists() {
        let _ = std::fs::copy(&old_snapkey, app_data_dir().join("snapkey"));
    }
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
    // 瞬态回滚副本不应跨启动存在：清掉上次切换可能遗留的明文凭据副本与半截临时文件
    cleanup_transient_files();
    // 旧版本的明文账号键（邮箱/昵称）一次性改为哈希
    migrate_privacy_keys();
}

fn cleanup_transient_files() {
    let app_data = app_data_dir();
    // 应用数据根目录的临时文件（snapkey/audit/benefits/quota-cache/hub-config 的原子写残留）
    if let Ok(rd) = std::fs::read_dir(&app_data) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.contains(".hub-tmp") { let _ = std::fs::remove_file(e.path()); }
        }
    }
    let v2 = v2_dir();
    // 只有当 live 凭据仍可解析时才丢弃回滚副本；恢复失败/重启后 live 坏了，它是最后的救援。
    let live_ok = cred_path().exists() && read_json(&cred_path()).is_ok();
    if live_ok { let _ = std::fs::remove_file(v2.join("credentials.json.hub-backup")); }
    if let Ok(rd) = std::fs::read_dir(&v2) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("credentials.hub-tmp") || n.starts_with("credentials.json.hub-tmp") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    // 账号目录里被强杀留下的半截快照/元数据临时文件
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() { continue; }
            if let Ok(files) = std::fs::read_dir(e.path()) {
                for f in files.flatten() {
                    let n = f.file_name().to_string_lossy().to_string();
                    if n.contains(".hub-tmp") { let _ = std::fs::remove_file(f.path()); }
                }
            }
        }
    }
    // 额度历史目录的半截重写文件
    if let Ok(rd) = std::fs::read_dir(app_data.join("quota-history")) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().contains(".hub-tmp") { let _ = std::fs::remove_file(e.path()); }
        }
    }
    // 回收站超过 30 天自动清理，避免无限增长
    if let Ok(rd) = std::fs::read_dir(trash_dir()) {
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86400);
        for e in rd.flatten() {
            if let Ok(meta) = e.metadata() {
                if meta.modified().map(|m| m < cutoff).unwrap_or(false) {
                    let _ = if meta.is_dir() { std::fs::remove_dir_all(e.path()) } else { std::fs::remove_file(e.path()) };
                }
            }
        }
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

// ------------------------------------------------------------- account label

fn account_label(creds: &Value) -> String {
    formats::account_label_with(creds, &|s: &str| decrypt_value(s).ok())
}

// ------------------------------------------------------------------- process
// 进程探测/关闭/启动收敛到 platform.rs（Windows 实现 + 非 Windows 占位）。

fn zcode_running() -> Result<bool, String> { platform::zcode_running() }

// exe 路径基本不变：命中缓存 5 分钟（含“没找到”的负结果），避免没装客户端时每 30 秒拉一次 PowerShell
static EXE_CACHE: Mutex<Option<(i64, Option<String>)>> = Mutex::new(None);
static VERSION_CACHE: Mutex<Option<(i64, Option<String>)>> = Mutex::new(None);
const EXE_CACHE_SECS: i64 = 300;

// Hub 对客户端文件格式的知识锚定在 3.17.x；客户端 major.minor 变化即提示兼容风险
const SUPPORTED_CLIENT_VERSION: &str = "3.17";
/// 未检测到客户端时的请求头回退版本（必须是 x.y.z 形态）
const DEFAULT_CLIENT_VERSION: &str = "3.17.1";

fn zcode_client_version() -> Option<String> {
    let mut g = VERSION_CACHE.lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some((ts, v)) = g.as_ref() { if now - ts < 3600 { return v.clone(); } }
    let v = zcode_exe_path().and_then(|exe| platform::exe_product_version(&exe));
    *g = Some((now, v.clone()));
    v
}

fn client_version_supported(detected: &str) -> bool {
    let dm: Vec<&str> = detected.split('.').take(2).collect();
    let sm: Vec<&str> = SUPPORTED_CLIENT_VERSION.split('.').collect();
    dm == sm
}

// 兼容探测汇总：凭据/设置格式健康度 + 客户端版本。errors 非空 = 建议安全模式。
// live 由调用方注入（一次读取，避免 get_state 里重复读盘/解密）。
fn compat_report(live: Option<&Value>) -> serde_json::Value {
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
static APP_HANDLE: Mutex<Option<tauri::AppHandle>> = Mutex::new(None);
static QUOTA_CACHE: Mutex<Option<std::collections::HashMap<String, (i64, Value)>>> = Mutex::new(None);
static HTTP: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();

fn http() -> &'static reqwest::blocking::Client {
    HTTP.get_or_init(reqwest::blocking::Client::new)
}

fn zcode_exe_path() -> Option<String> {
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

fn kill_zcode_process() -> Result<bool, String> { platform::kill_zcode_process() }

fn launch_zcode_process(exe: &str) -> bool { platform::launch_zcode_process(exe) }

fn telemetry_device_mid() -> String {
    read_json(&v2_dir().join("telemetry-state.json")).ok()
        .and_then(|v| formats::read_device_mid(&v)).unwrap_or_default()
}

// ------------------------------------------------------------------- structs

#[derive(serde::Serialize)]
struct ProfileInfo {
    key: String, label: String, captured_at: String, is_current: bool,
    provider: String, jwt_expired: bool,
    /// 快照无法读取/解密时的具体原因（前端显示“存档异常”，不再静默消失）
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// token 明文指纹：账号身份的唯一判据（不再用可能重名的展示 label）。
fn cred_fingerprint(creds: &Value) -> Option<String> {
    let raw = creds.get(formats::FIELD_TOKEN).and_then(|v| v.as_str())?;
    // 兼容旧明文存档：enc:v1 才解密，否则把原文当作 token
    let plain = if raw.starts_with(ENC_PREFIX) { decrypt_value(raw).ok()? } else { raw.to_string() };
    if plain.trim().is_empty() { return None; }
    let mut h = Sha256::new();
    h.update(plain.as_bytes());
    let d = h.finalize();
    Some(d.iter().take(12).map(|b| format!("{:02x}", b)).collect())
}

/// 在账号库里找 live 凭据对应的存档：先比 token 指纹，指纹缺失才回退 label。
fn find_profile_dir_for_live(live: &Value) -> Option<PathBuf> {
    let fp = cred_fingerprint(live);
    let label = account_label(live);
    let mut by_label: Option<PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() { continue; }
            let Ok(v) = read_snapshot_checked(&e.path()) else { continue };
            if let (Some(a), Some(b)) = (fp.as_ref(), cred_fingerprint(&v)) {
                if *a == b { return Some(e.path()); }
            } else if by_label.is_none() && account_label(&v) == label {
                by_label = Some(e.path());
            }
        }
    }
    by_label
}

fn profile_label(meta: &Value, creds: &Value) -> String {
    meta.get("label").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty())
        .map(String::from).unwrap_or_else(|| account_label(creds))
}

fn find_profile_by_fingerprint(fp: &str) -> Option<PathBuf> {
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() { continue; }
            if let Ok(v) = read_snapshot_checked(&e.path()) {
                if cred_fingerprint(&v).as_deref() == Some(fp) { return Some(e.path()); }
            }
        }
    }
    None
}

/// 为一份凭据挑选存档目录：同账号（token 指纹相同）复用原目录；
/// 否则用清洗后的显示名，重名时追加 -2/-3，绝不静默覆盖别人的存档。
/// 返回 (目录, 目录名, 是否更新已有账号)。
fn unique_profile_dir(preferred: &str, creds: &Value) -> (PathBuf, String, bool) {
    if let Some(fp) = cred_fingerprint(creds) {
        if let Some(dir) = find_profile_by_fingerprint(&fp) {
            let name = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            return (dir, name, true);
        }
    }
    let base = sanitize_label(preferred);
    let mut name = base.clone();
    let mut i = 2;
    while profiles_dir().join(&name).exists() {
        name = format!("{}-{}", base, i);
        i += 1;
    }
    (profiles_dir().join(&name), name, false)
}

// 令牌过期判定（30s 时钟容忍）；收敛在 formats.rs，兼容明文与 enc:v1 两种存法
fn jwt_expired(creds: &Value) -> bool {
    formats::jwt_expired_with(creds, &|s: &str| decrypt_value(s).ok(), chrono::Utc::now().timestamp(), 30)
}

// 自启快捷方式与目录/浏览器打开收敛到 platform.rs
fn autostart_enabled() -> bool { platform::autostart_enabled() }

#[tauri::command(async)]
fn set_autostart(enable: bool) -> serde_json::Value {
    match platform::set_autostart_internal(enable) {
        Ok(()) => {
            audit_log("autostart", None, json!({"enabled": enable}));
            json!({"ok": true, "enabled": autostart_enabled()})
        }
        Err(e) => json!({"ok": false, "error": e}),
    }
}

fn open_in_explorer(dir: &PathBuf) -> serde_json::Value {
    if !dir.exists() { let _ = std::fs::create_dir_all(dir); }
    platform::open_dir_explorer(dir);
    json!({"ok": true})
}

#[tauri::command]
fn open_data_dir() -> serde_json::Value { open_in_explorer(&app_data_dir()) }

#[tauri::command]
fn open_zcode_data_dir() -> serde_json::Value { open_in_explorer(&v2_dir()) }

// 检查更新：查 GitHub Releases 最新 tag（仓库转公开后自动生效；私有期间友好降级）
#[tauri::command(async)]
fn check_update() -> serde_json::Value {
    let current = env!("CARGO_PKG_VERSION");
    // 走 releases/latest/download/latest.json（CDN 静态文件，无 GitHub API 未认证限频）
    let resp = http().get("https://github.com/Ebonyhtx/zcode-hub/releases/latest/download/latest.json")
        .header("User-Agent", "zcode-hub")
        .timeout(std::time::Duration::from_secs(15)).send();
    match resp {
        Ok(r) if r.status().is_success() => {
            let j: Value = match r.json() { Ok(j) => j, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let latest = j.get("version").and_then(|v| v.as_str()).unwrap_or("").trim_start_matches('v').to_string();
            let pv = |s: &str| s.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<u64>>();
            let (a, b) = (pv(&latest), pv(current));
            let mut up_to_date = true;
            for i in 0..3 {
                let l = a.get(i).unwrap_or(&0); let c = b.get(i).unwrap_or(&0);
                if l > c { up_to_date = false; break; }
                if l < c { up_to_date = true; break; }
            }
            json!({"ok": true, "current": current, "latest": latest, "up_to_date": up_to_date,
                   "url": "https://github.com/Ebonyhtx/zcode-hub/releases/latest"})
        }
        Ok(r) => json!({"ok": false, "error": format!("检查更新失败（HTTP {}），请稍后重试", r.status().as_u16())}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

#[tauri::command]
fn open_url(url: String) -> serde_json::Value {
    let valid = url::Url::parse(&url).ok()
        .map(|u| u.scheme() == "https" && u.host_str().is_some()).unwrap_or(false);
    if !valid { return json!({"ok": false, "error": "仅允许有效的 https 链接"}); }
    open_in_browser(&url);
    json!({"ok": true})
}

#[tauri::command]
fn reveal_file(path: String) -> serde_json::Value {
    let p = std::path::PathBuf::from(path);
    if !p.exists() { return json!({"ok": false, "error": "文件不存在"}); }
    platform::reveal_in_explorer(&p);
    json!({"ok": true})
}

static UPDATE_PROGRESS: Mutex<(u64, u64)> = Mutex::new((0, 0));

#[tauri::command]
fn update_progress() -> serde_json::Value {
    let (d, t) = *UPDATE_PROGRESS.lock().unwrap();
    json!({"downloaded": d, "total": t})
}

#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| e.to_string())?;
    match update {
        Some(u) => {
            *UPDATE_PROGRESS.lock().unwrap() = (0, 0);
            let result = u.download_and_install(|chunk, total| {
                let mut g = UPDATE_PROGRESS.lock().unwrap();
                g.0 = g.0.saturating_add(chunk as u64);
                if let Some(t) = total { g.1 = t; }
            }, || {}).await;
            *UPDATE_PROGRESS.lock().unwrap() = (0, 0);
            match result {
                Ok(()) => { app.restart(); }
                Err(e) => Err(format!("更新下载/安装失败：{}。已保持当前版本运行", e)),
            }
        }
        None => Ok(json!({"ok": true, "up_to_date": true})),
    }
}

// 托盘提示：当前账号 + 待领福利数（自动检测后也会刷新，窗口关闭时同样可见）
fn update_tray_tooltip() {
    let label = if cred_path().exists() {
        read_json(&cred_path()).map(|c| account_label(&c)).unwrap_or("?".into())
    } else { "(未登录)".into() };
    update_tray_tooltip_with(&label);
}

fn update_tray_tooltip_with(label: &str) {
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

fn quota_cache_path() -> PathBuf { app_data_dir().join("quota-cache.json") }

fn load_quota_cache_once() {
    let mut g = QUOTA_CACHE.lock().unwrap();
    if g.is_some() { return; }
    let mut map = std::collections::HashMap::new();
    if let Ok(v) = read_json(&quota_cache_path()) {
        let reverse = known_profile_key_map();
        if let Some(obj) = v.as_object() {
            for (k, e) in obj {
                let raw = reverse.get(k).cloned().or_else(|| {
                    if !is_opaque_key(k) && safe_key(k).is_ok() { Some(k.clone()) } else { None }
                });
                let Some(raw) = raw else { continue };
                if let (Some(ts), Some(resp)) = (e.get("ts").and_then(|x| x.as_i64()), e.get("resp")) {
                    map.insert(raw, (ts, resp.clone()));
                }
            }
        }
    }
    *g = Some(map);
}

fn persist_quota_cache() {
    let map = QUOTA_CACHE.lock().unwrap().clone().unwrap_or_default();
    let mut obj = serde_json::Map::new();
    for (k, (ts, resp)) in map { obj.insert(opaque_key(&k), json!({"ts": ts, "resp": resp})); }
    let _ = write_json(&quota_cache_path(), &Value::Object(obj));
}

#[tauri::command(async)]
fn get_state() -> serde_json::Value {
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

#[tauri::command(async)]
fn capture_profile(name: Option<String>) -> serde_json::Value {
    let src = cred_path();
    if !src.exists() { return json!({"ok": false, "error": "未找到登录凭证"}); }
    let creds = match read_json(&src) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e}) };
    let label = account_label(&creds);
    let base = name.unwrap_or_else(|| label.clone());
    let (dd, fname, updated) = unique_profile_dir(&base, &creds);
    if let Err(e) = write_snapshot(&dd, &creds) {
        if !updated { let _ = std::fs::remove_dir_all(&dd); }
        return json!({"ok": false, "error": format!("存档写入失败: {}", e)});
    }
    let provider = formats::active_provider_with(&creds, &|s: &str| decrypt_value(s).ok()).unwrap_or_default();
    let mut meta = read_json(&dd.join("meta.json")).ok().unwrap_or(json!({}));
    let keep_label = meta.get("label").and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| label.clone());
    meta["label"] = json!(if updated { keep_label } else { base.clone() });
    meta["provider"] = json!(provider);
    meta["captured_at"] = json!(chrono::Utc::now().to_rfc3339());
    let _mid = ensure_profile_device_mid(&dd, &mut meta, true);
    let _auid = ensure_profile_arms_uid(&dd, &mut meta, true);
    if let Err(e) = write_json(&dd.join("meta.json"), &meta) {
        if !updated { let _ = std::fs::remove_dir_all(&dd); }
        return json!({"ok": false, "error": format!("账号元数据写入失败: {}", e)});
    }
    audit_log("capture", Some(&fname), json!({"updated": updated}));
    json!({"ok": true, "name": fname, "label": label, "updated": updated})
}

fn hot_swap_verified(cur: &Path, target: &Value, original: Option<&Value>) -> bool {
    // 写入后回读两次，比较 token 明文指纹（不是展示名——同名账号会误判成功）。
    // 三次失败必须恢复原文件：调用方可能随后走冷切换，不能让 live 停在半切换状态。
    let expected = cred_fingerprint(target);
    let Some(expected) = expected else { return false };
    for attempt in 0..3u32 {
        if write_json(cur, target).is_err() {
            std::thread::sleep(std::time::Duration::from_millis(250 * (attempt as u64 + 1)));
            continue;
        }
        if let Ok(v1) = read_json(cur) {
            if cred_fingerprint(&v1).as_deref() == Some(expected.as_str()) {
                std::thread::sleep(std::time::Duration::from_millis(150));
                if let Ok(v2) = read_json(cur) {
                    if cred_fingerprint(&v2).as_deref() == Some(expected.as_str()) { return true; }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250 * (attempt as u64 + 1)));
    }
    if let Some(orig) = original { let _ = write_json(cur, orig); }
    false
}

/// 把当前 live 登录保鲜回其存档（按 token 指纹匹配）；找不到时自动新建 autosave。
/// 失败必须让调用方中止切换——不能在无法保全当前账号时继续写 live。
fn preserve_current_login(live: &Value) -> Result<(), String> {
    let has_token = live.get(formats::FIELD_TOKEN).and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty()).unwrap_or(false);
    if !has_token { return Ok(()); }
    if let Some(dir) = find_profile_dir_for_live(live) {
        return write_snapshot(&dir, live).map_err(|e| format!("无法保全当前登录: {}", e));
    }
    let auto = format!("autosave-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let dir = profiles_dir().join(&auto);
    write_snapshot(&dir, live).map_err(|e| format!("无法为当前登录创建存档: {}", e))?;
    let label = account_label(live);
    let provider = formats::active_provider_with(live, &|s: &str| decrypt_value(s).ok()).unwrap_or_default();
    let _ = write_json(&dir.join("meta.json"),
        &json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()}));
    Ok(())
}

fn apply_switch_identity(prof_dir: &Path, provider: &str) {
    let mut meta = read_json(&prof_dir.join("meta.json")).ok()
        .unwrap_or_else(|| json!({"label": prof_dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), "provider": provider}));
    let mid = ensure_profile_device_mid(prof_dir, &mut meta, false);
    let auid = ensure_profile_arms_uid(prof_dir, &mut meta, false);
    let _ = write_json(&prof_dir.join("meta.json"), &meta);
    write_live_device_mid(&mid);
    write_live_arms_uid(&auid);
    sync_provider_family_domain(provider);
    let _ = std::fs::remove_file(v2_dir().join("coding-plan-cache.json"));
}

fn preserve_corrupt_live(cur: &Path) {
    if cur.exists() && read_json(cur).is_err() {
        let _ = std::fs::copy(cur, v2_dir().join("credentials.json.corrupt"));
    }
}

#[tauri::command(async)]
fn switch_profile(key: String, hot: Option<bool>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let prof_dir = profiles_dir().join(&key);
    let prof_v = match read_snapshot_checked(&prof_dir) {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("读取存档失败: {}", e)}),
    };
    let cur = cred_path();
    let exe = zcode_exe_path();
    // 三态探测：探测失败不能当作“未运行”，否则可能在客户端运行时替换凭据
    let was = match zcode_running() {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("无法确认 ZCode 是否在运行（{}）。为避免在客户端运行时改凭据，已取消切换", e)}),
    };
    let want_hot = hot.unwrap_or(false)
        && load_settings().get("hot_switch").and_then(|v| v.as_bool()).unwrap_or(false)
        && was;
    let dec = |s: &str| decrypt_value(s).ok();
    let target_provider = formats::active_provider_with(&prof_v, &dec).unwrap_or_default();
    if target_provider.is_empty() {
        return json!({"ok": false, "error": "目标存档缺少有效的 provider，拒绝切换"});
    }
    let live_creds = read_json(&cur).ok();
    let live_probe_bad = live_creds.as_ref()
        .map(|v| !formats::probe_credentials(Some(v)).ok())
        .unwrap_or(false);
    let safe_requested = load_settings().get("safe_mode").and_then(|v| v.as_bool()).unwrap_or(false);

    // ---------------- 安全模式：只合并账号身份字段，保留未知字段 ----------------
    if (safe_requested || live_probe_bad) && live_creds.is_some() {
        let original = live_creds.clone().unwrap_or_else(|| json!({}));
        if let Err(e) = preserve_current_login(&original) {
            audit_log("switch", Some(&key), json!({"mode": "safe", "result": "fail", "error": "preserve_failed"}));
            return json!({"ok": false, "error": format!("{}。为避免丢失当前账号，已取消切换", e)});
        }
        let mut merged = original.clone();
        if let Err(e) = formats::merge_account_fields(&mut merged, &prof_v, &target_provider) {
            audit_log("switch", Some(&key), json!({"mode": "safe", "result": "fail", "error": e}));
            return json!({"ok": false, "error": format!("安全模式合并失败：{}", e)});
        }
        if !hot_swap_verified(&cur, &merged, Some(&original)) {
            audit_log("switch", Some(&key), json!({"mode": "safe", "result": "fail", "error": "verify_failed"}));
            return json!({"ok": false, "error": "安全模式写入验证失败，已恢复原文件"});
        }
        apply_switch_identity(&prof_dir, &target_provider);
        audit_log("switch", Some(&key), json!({"mode": "safe", "result": "ok"}));
        return json!({"ok": true, "hot": true, "safe": true, "relaunched": false});
    }

    // ---------------- 热切换：客户端不重启，失败恢复后回退冷路径 ----------------
    if want_hot {
        preserve_corrupt_live(&cur);
        if let Ok(cur_v) = read_json(&cur) {
            if let Err(e) = preserve_current_login(&cur_v) {
                return json!({"ok": false, "error": format!("{}。为避免丢失当前账号，已取消切换", e)});
            }
        }
        let original = read_json(&cur).ok();
        if hot_swap_verified(&cur, &prof_v, original.as_ref()) {
            apply_switch_identity(&prof_dir, &target_provider);
            audit_log("switch", Some(&key), json!({"mode": "hot", "result": "ok"}));
            return json!({"ok": true, "hot": true, "relaunched": false});
        }
        // 校验失败时 hot_swap_verified 已恢复原文件 → 继续冷路径
    }

    if was {
        // 先杀干净再动文件——绝不在客户端运行时替换凭据
        match kill_zcode_process() {
            Ok(true) => {}
            Ok(false) => return json!({"ok": false, "error": "无法关闭 ZCode（可能仍在托盘运行），请手动退出 ZCode 后重试"}),
            Err(e) => return json!({"ok": false, "error": format!("无法确认 ZCode 进程已退出（{}），已取消切换", e)}),
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let backup = v2_dir().join("credentials.json.hub-backup");
    preserve_corrupt_live(&cur);
    let had_backup = if cur.exists() {
        if let Ok(cur_v) = read_json(&cur) {
            if let Err(e) = preserve_current_login(&cur_v) {
                if was { let _ = exe.as_ref().map(|e| launch_zcode_process(e)); }
                return json!({"ok": false, "error": format!("{}。为避免丢失当前账号，已取消切换", e)});
            }
        }
        std::fs::copy(&cur, &backup).is_ok()
    } else { false };
    if let Err(e) = write_json(&cur, &prof_v) {
        if had_backup {
            match std::fs::copy(&backup, &cur) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&backup);
                    audit_log("switch", Some(&key), json!({"mode": "cold", "result": "fail", "error": "write_failed_restored"}));
                    return json!({"ok": false, "error": format!("替换凭据文件失败（{}），已恢复原文件", e)});
                }
                Err(e2) => {
                    audit_log("switch", Some(&key), json!({"mode": "cold", "result": "fail", "error": "restore_failed"}));
                    return json!({"ok": false, "critical": true,
                        "error": format!("替换凭据失败且恢复也失败（{} / {}）。请从“备份/导入”恢复，或重新登录 ZCode", e, e2)});
                }
            }
        }
        audit_log("switch", Some(&key), json!({"mode": "cold", "result": "fail", "error": "write_failed"}));
        return json!({"ok": false, "error": format!("替换凭据文件失败：{}", e)});
    }
    // 替换成功后回滚副本使命结束
    let _ = std::fs::remove_file(&backup);
    apply_switch_identity(&prof_dir, &target_provider);
    let rel = if was { exe.as_ref().map(|e| launch_zcode_process(e)).unwrap_or(false) } else { false };
    audit_log("switch", Some(&key), json!({"mode": "cold", "result": "ok", "relaunched": rel}));
    json!({"ok": true, "relaunched": rel})
}

// ---------------- 账号库备份：口令加密导出 / 导入（.zhb） ----------------
// PBKDF2-HMAC-SHA256(120k) + AES-256-GCM；解决 DPAPI 快照换机不可解的问题：
// 导出文件凭口令即可在任何机器导入恢复账号

fn bundle_key(password: &str, salt: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, 120_000, &mut *out);
    out
}

#[tauri::command(async)]
fn export_bundle(password: String) -> serde_json::Value {
    if password.chars().count() < 6 { return json!({"ok": false, "error": "口令至少 6 位"}); }
    let mut accounts = Vec::new();
    let mut relogin = 0u64;
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() { continue; }
            if let Some(mut creds) = read_snapshot_value(&e.path()) {
                if creds.get(formats::FIELD_TOKEN).and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
                    let meta = read_json(&e.path().join("meta.json")).ok().unwrap_or(json!({}));
                    // v2：字段密文用本机密钥解开后放进口令加密的 bundle。目标机再加密，
                    // 解决换用户名/换机器后 enc:v1 解不开的问题（bundle 自身仍是 AES-GCM）。
                    let mut plain_fields: Vec<String> = Vec::new();
                    if let Some(obj) = creds.as_object_mut() {
                        for (k, v) in obj.iter_mut() {
                            if let Some(s) = v.as_str() {
                                if s.starts_with(ENC_PREFIX) {
                                    match decrypt_value(s) {
                                        Ok(plain) => { *v = json!(plain); plain_fields.push(k.clone()); }
                                        Err(_) => { relogin += 1; }
                                    }
                                }
                            }
                        }
                    }
                    accounts.push(json!({
                        "label": meta.get("label").and_then(|v| v.as_str()).unwrap_or(e.file_name().to_string_lossy().as_ref()),
                        "provider": meta.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
                        "device_mid": meta.get("device_mid").cloned().unwrap_or(Value::Null),
                        "arms_uid": meta.get("arms_uid").cloned().unwrap_or(Value::Null),
                        "credentials": creds,
                        "plain_fields": plain_fields,
                    }));
                }
            }
        }
    }
    if accounts.is_empty() { return json!({"ok": false, "error": "账号库为空"}); }
    let bundle = json!({"format": "zcode-hub-bundle", "version": 2, "exported_at": chrono::Utc::now().to_rfc3339(), "accounts": accounts});
    let plain = match serde_json::to_vec(&bundle) { Ok(p) => p, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
    let salt: [u8; 16] = rand::random();
    let iv: [u8; 12] = rand::random();
    let key = bundle_key(&password, &salt);
    let cipher = match Aes256Gcm::new_from_slice(&key[..]) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
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
    audit_log("export", None, json!({"accounts": accounts.len(), "relogin": relogin}));
    json!({"ok": true, "path": out.display().to_string(), "accounts": accounts.len(), "needs_relogin": relogin})
}

#[tauri::command(async)]
fn import_bundle(path: String, password: String) -> serde_json::Value {
    let raw = match std::fs::read_to_string(&path) { Ok(r) => r, Err(e) => return json!({"ok": false, "error": format!("读取失败: {}", e)}) };
    let body = match raw.trim().strip_prefix("ZHB1:") { Some(b) => b, None => return json!({"ok": false, "error": "不是 ZCode Hub 备份文件"}) };
    let engine = base64::engine::general_purpose::STANDARD;
    let data = match engine.decode(body.trim()) { Ok(d) => d, Err(_) => return json!({"ok": false, "error": "文件损坏"}) };
    if data.len() < 28 + 16 { return json!({"ok": false, "error": "文件损坏"}); }
    let (salt, rest) = data.split_at(16);
    let (iv, ct) = rest.split_at(12);
    let key = bundle_key(&password, salt);
    let cipher = match Aes256Gcm::new_from_slice(&key[..]) { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
    let plain = match cipher.decrypt(Nonce::from_slice(iv), ct) { Ok(p) => p, Err(_) => return json!({"ok": false, "error": "口令错误或文件损坏"}) };
    let bundle: Value = match serde_json::from_slice(&plain) { Ok(b) => b, Err(_) => return json!({"ok": false, "error": "文件损坏"}) };
    if bundle.get("format").and_then(|v| v.as_str()) != Some("zcode-hub-bundle") {
        return json!({"ok": false, "error": "不是 ZCode Hub 备份文件"});
    }
    let version = bundle.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut added = 0u64; let mut skipped = 0u64; let mut relogin = 0u64;
    if let Some(list) = bundle.get("accounts").and_then(|v| v.as_array()) {
        for a in list {
            let mut creds = a.get("credentials").cloned().unwrap_or(json!({}));
            // v2：把导出时解开的明文字段用目标机密钥重新加密（enc:v1 布局不变）
            if version >= 2 {
                if let Some(fields) = a.get("plain_fields").and_then(|v| v.as_array()) {
                    for f in fields.iter().filter_map(|v| v.as_str()) {
                        if let Some(s) = creds.get(f).and_then(|v| v.as_str()) {
                            creds[f] = json!(encrypt_value(s));
                        }
                    }
                }
            }
            let has_jwt = creds.get(formats::FIELD_TOKEN).and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
            if !has_jwt { skipped += 1; continue; }
            // 字段解不开（v1 跨机、或 v2 导出时本机也解不开）→ 仍导入，但标记需要重新登录
            let tok = creds.get(formats::FIELD_TOKEN).and_then(|v| v.as_str()).unwrap_or("");
            if tok.starts_with(ENC_PREFIX) && decrypt_value(tok).is_err() { relogin += 1; }
            let label = a.get("label").and_then(|v| v.as_str()).unwrap_or("imported").to_string();
            let provider = a.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let (dir, _name, exists_same) = unique_profile_dir(&label, &creds);
            if exists_same { skipped += 1; continue; }
            if write_snapshot(&dir, &creds).is_err() { skipped += 1; continue; }
            let mut meta = json!({
                "label": label, "provider": provider,
                "captured_at": chrono::Utc::now().to_rfc3339(),
            });
            if let Some(mid) = a.get("device_mid").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                meta["device_mid"] = json!(mid);
            }
            if let Some(uid) = a.get("arms_uid").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                meta["arms_uid"] = json!(uid);
            }
            if meta.get("device_mid").is_none() { ensure_profile_device_mid(&dir, &mut meta, false); }
            if meta.get("arms_uid").is_none() { ensure_profile_arms_uid(&dir, &mut meta, false); }
            let _ = write_json(&dir.join("meta.json"), &meta);
            added += 1;
        }
    }
    audit_log("import", None, json!({"added": added, "skipped": skipped, "relogin": relogin}));
    json!({"ok": true, "added": added, "skipped": skipped, "relogin": relogin})
}

fn trash_dir() -> PathBuf { app_data_dir().join("trash") }

fn cleanup_profile_caches(key: &str) {
    load_benefits_once();
    load_quota_cache_once();
    if let Some(map) = QUOTA_CACHE.lock().unwrap().as_mut() { map.remove(key); }
    if let Some(map) = BENEFITS.lock().unwrap().as_mut() { map.remove(key); }
    persist_benefits();
    persist_quota_cache();
    let hp = history::history_path(&app_data_dir(), key);
    let _ = std::fs::remove_file(hp);
    let legacy = app_data_dir().join("quota-history").join(format!("{}.jsonl", key));
    let _ = std::fs::remove_file(legacy);
}

#[tauri::command(async)]
fn delete_profile(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let d = profiles_dir().join(&key);
    if !d.exists() { return json!({"ok": false, "error": "账号不存在"}); }
    let _ = std::fs::create_dir_all(trash_dir());
    let stamp = chrono::Utc::now().timestamp_millis();
    let trash_name = format!("{}-{}", key, stamp);
    let dest = trash_dir().join(&trash_name);
    match std::fs::rename(&d, &dest) {
        Ok(()) => {
            cleanup_profile_caches(&key);
            audit_log("delete", Some(&key), json!({"trash_ts": stamp}));
            json!({"ok": true, "trash": trash_name})
        }
        Err(e) => {
            audit_log("delete", Some(&key), json!({"result": "fail"}));
            json!({"ok": false, "error": format!("删除失败: {}", e)})
        }
    }
}

#[tauri::command(async)]
fn restore_profile(trash: String) -> serde_json::Value {
    // trash 名形如 <key>-<13位毫秒>；只允许安全字符，防止路径穿越
    let ok = !trash.is_empty() && !trash.starts_with('.') && !trash.contains('/') && !trash.contains('\\')
        && !trash.contains("..") && !trash.contains(':')
        && trash.chars().all(|c| c.is_alphanumeric() || "-_.@".contains(c));
    if !ok { return denied("非法回收站标识".into()); }
    let Some((key, stamp)) = trash.rsplit_once('-') else { return json!({"ok": false, "error": "回收站标识无效"}) };
    if stamp.len() < 10 || !stamp.chars().all(|c| c.is_ascii_digit()) {
        return json!({"ok": false, "error": "回收站标识无效"});
    }
    if safe_key(key).is_err() { return denied("非法账号标识".into()); }
    let src = trash_dir().join(&trash);
    if !src.exists() { return json!({"ok": false, "error": "回收站中找不到该账号（可能已过期清理）"}) };
    let dst = profiles_dir().join(key);
    if dst.exists() { return json!({"ok": false, "error": "同名账号已存在，无法撤销"}) };
    match std::fs::rename(&src, &dst) {
        Ok(()) => {
            audit_log("restore", Some(key), json!({}));
            json!({"ok": true, "key": key})
        }
        Err(e) => json!({"ok": false, "error": format!("撤销失败: {}", e)}),
    }
}

#[tauri::command(async)]
fn rename_profile(key: String, label: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let label = label.trim();
    if label.is_empty() { return json!({"ok": false, "error": "名称不能为空"}); }
    if label.chars().count() > 80 { return json!({"ok": false, "error": "名称过长（最多 80 字）"}); }
    let dir = profiles_dir().join(&key);
    if !dir.exists() { return json!({"ok": false, "error": "账号不存在"}); }
    let mut meta = read_json(&dir.join("meta.json")).ok().unwrap_or(json!({}));
    meta["label"] = json!(label);
    if let Err(e) = write_json(&dir.join("meta.json"), &meta) {
        return json!({"ok": false, "error": format!("重命名失败: {}", e)});
    }
    audit_log("rename", Some(&key), json!({}));
    json!({"ok": true, "label": label})
}

// -------------------------------------------------------------------- OAuth

use std::sync::Mutex;

static OAUTH_STATE: Mutex<Option<Value>> = Mutex::new(None);
/// 每次 oauth_start/oauth_cancel 递增；旧 worker 发现自己不是最新代次就静默退出，
/// 避免“取消后又开始”被上一轮轮询回写 ready/failed。
static OAUTH_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn set_oauth(v: Value) { *OAUTH_STATE.lock().unwrap() = Some(v); }
fn get_oauth() -> Option<Value> { OAUTH_STATE.lock().unwrap().clone() }
fn oauth_alive(gen: u64) -> bool { OAUTH_GEN.load(std::sync::atomic::Ordering::SeqCst) == gen }
fn set_oauth_if(gen: u64, v: Value) { if oauth_alive(gen) { set_oauth(v); } }

fn allowed_oauth_host(host: &str) -> bool {
    // 官方域及其子域；避免服务端换成 open.bigmodel.cn 等入口时把正常登录挡掉
    host == "z.ai" || host.ends_with(".z.ai")
        || host == "bigmodel.cn" || host.ends_with(".bigmodel.cn")
}

fn generate_poll_token() -> String {
    (0..32).map(|_| format!("{:02x}", rand::random::<u8>())).collect()
}

// 用系统 Shell 处理协议分发（等价于 Win+R 打开 URL），不经任何命令行解析，URL 里的 & % ? 都安全
fn open_in_browser(url: &str) { platform::open_in_browser(url) }

fn _oauth_worker(provider: String, poll_token: String, gen: u64) {
    let client = reqwest::blocking::Client::new();
    let fail = |msg: String| {
        // 失败态保留 authorize_url，用户可直接重开登录页而不是从头再来
        let url = get_oauth()
            .and_then(|s| s.get("authorize_url").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_default();
        set_oauth_if(gen, json!({"status":"failed","error":msg,"authorize_url":url}));
    };
    // init
    let init = client.post("https://zcode.z.ai/api/v1/oauth/cli/init")
        .header("Authorization", format!("Bearer {}", poll_token))
        .header("Content-Type", "application/json")
        .body(json!({"provider": provider}).to_string())
        .timeout(std::time::Duration::from_secs(20))
        .send();
    let init = match init { Ok(r) => r, Err(e) => return fail(e.to_string()) };
    let j: Value = match init.json() { Ok(j) => j, Err(e) => return fail(e.to_string()) };
    if j.get("code").and_then(|c| c.as_i64()) != Some(0) {
        return fail(j.get("msg").and_then(|m| m.as_str()).unwrap_or("init error").to_string());
    }
    let d = j.get("data").cloned().unwrap_or(json!({}));
    let raw_authorize_url = d.get("authorize_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // 官方桌面端会用带 ? 的登录页 URL 覆盖回调参数（见 asar 内 startOAuthWithPolling）：
    //   zai      → 覆盖 redirect_uri 参数
    //   bigmodel → 覆盖 redirect 参数
    // 服务端拼接重定向时无条件下 &，裸回调值（无 query）会被拼坏成 /callback/xxx&state=... → 404。
    let authorize_url = {
        let desktop_redirect = format!(
            "https://zcode.z.ai/app/oauth/login?redirect=zcode://oauth/callback&app_version={}",
            client_app_version());
        let param = if provider == "bigmodel" { "redirect" } else { "redirect_uri" };
        match url::Url::parse(&raw_authorize_url) {
            Ok(mut u) => {
                // 只允许官方 https 域名，避免服务端响应被篡改后交给 ShellExecute 打开本地协议
                if u.scheme() != "https" || !u.host_str().map(allowed_oauth_host).unwrap_or(false) {
                    return fail("登录页地址不在官方域名白名单内，已取消".into());
                }
                let pairs: Vec<(String, String)> = u.query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .filter(|(k, _)| k != param && k != "redirect_uri" && k != "redirect")
                    .collect();
                {
                    let mut q = u.query_pairs_mut();
                    q.clear();
                    for (k, v) in &pairs { q.append_pair(k, v); }
                    q.append_pair(param, &desktop_redirect);
                }
                u.to_string()
            }
            Err(_) => return fail("登录页地址无效，已取消".into()),
        }
    };
    let flow_id = d.get("flow_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let interval = d.get("poll_interval_sec").and_then(|v| v.as_u64()).unwrap_or(2).clamp(1, 10);
    let expires = d.get("expires_at").and_then(|v| v.as_f64()).unwrap_or(0.0);

    if !oauth_alive(gen) { return; }
    set_oauth(json!({"status":"pending","provider": provider, "authorize_url": authorize_url}));
    platform::open_in_browser(&authorize_url);

    let deadline = if expires > 0.0 { expires } else { 600.0 };
    loop {
        if !oauth_alive(gen) { return; }
        if chrono::Utc::now().timestamp() as f64 > deadline {
            return fail("timeout".into());
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
        if !oauth_alive(gen) { return; }
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
            return fail(format!("login failed: {}", status));
        }
        if !oauth_alive(gen) { return; }
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
            .unwrap_or(&user_id).trim().to_string();
        let label = if label.is_empty() { "account".to_string() } else { label };
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
        // + zcodejwttoken + oauth:active_provider（键名常量与解析逻辑收敛在 formats.rs）
        let mut encrypted = std::collections::HashMap::new();
        encrypted.insert(formats::FIELD_ACTIVE_PROVIDER.to_string(), encrypt_value(&provider));
        encrypted.insert(formats::oauth_field(&provider, "access_token"), encrypt_value(&access_token));
        if !refresh_token.is_empty() {
            encrypted.insert(formats::oauth_field(&provider, "refresh_token"), encrypt_value(&refresh_token));
        }
        encrypted.insert(formats::oauth_field(&provider, "user_info"), encrypt_value(&profile_norm.to_string()));
        encrypted.insert(formats::FIELD_TOKEN.to_string(), encrypt_value(&token));
        let encrypted_v = serde_json::to_value(&encrypted).unwrap_or(json!({}));
        if !oauth_alive(gen) { return; } // 用户已取消/已开始新流程，不再落盘
        // 同账号（token 指纹相同）→ 更新原存档；不同账号同名 → 自动加后缀，绝不覆盖
        let (prof_dir, safe, updated) = unique_profile_dir(&label, &encrypted_v);
        if let Err(e) = write_snapshot(&prof_dir, &encrypted_v) {
            if !updated { let _ = std::fs::remove_dir_all(&prof_dir); }
            return fail(format!("保存登录凭据失败: {}", e));
        }
        let mut meta = read_json(&prof_dir.join("meta.json")).ok().unwrap_or(json!({}));
        let keep = meta.get("label").and_then(|v| v.as_str()).map(String::from);
        meta["label"] = json!(if updated { keep.unwrap_or_else(|| label.clone()) } else { label.clone() });
        meta["provider"] = json!(provider);
        meta["captured_at"] = json!(chrono::Utc::now().to_rfc3339());
        let _mid = ensure_profile_device_mid(&prof_dir, &mut meta, false);
        let _auid = ensure_profile_arms_uid(&prof_dir, &mut meta, false);
        if let Err(e) = write_json(&prof_dir.join("meta.json"), &meta) {
            if !updated { let _ = std::fs::remove_dir_all(&prof_dir); }
            return fail(format!("保存账号元数据失败: {}", e));
        }
        // 注意：新增账号只写存档，不切换 live 凭据，因此绝不能改 setting.json 的 providerFamilyDomain
        set_oauth_if(gen, json!({"status":"ready","label": label, "provider": provider, "name": safe,
                                 "updated": updated, "warning": warning}));
        audit_log("oauth_add", Some(&safe), json!({"provider": provider, "updated": updated}));
        return;
    }
}

fn encrypt_value(plain: &str) -> String {
    encrypt_with(&derive_key(&credential_secret()), plain).expect("AES encrypt failed")
}

#[tauri::command]
fn oauth_start(provider: Option<String>) -> serde_json::Value {
    let provider = provider.unwrap_or_else(|| "zai".to_string());
    if provider != "zai" && provider != "bigmodel" {
        return json!({"ok": false, "error": format!("unknown provider: {}", provider)});
    }
    // 已有流程在跑：返回可恢复状态，前端继续轮询/重开登录页，而不是报裸错误
    if let Some(s) = get_oauth() {
        if s.get("status").and_then(|v| v.as_str()) == Some("pending") {
            return json!({"ok": true, "already": true, "status": s});
        }
    }
    let gen = OAUTH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    set_oauth(json!({"status":"pending","provider": provider, "started_at": chrono::Utc::now().to_rfc3339()}));
    let poll_token = generate_poll_token();
    std::thread::spawn(move || { _oauth_worker(provider, poll_token, gen); });
    json!({"ok": true})
}

#[tauri::command]
fn oauth_cancel() -> serde_json::Value {
    OAUTH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    set_oauth(json!({"status": "idle"}));
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
            let valid = url::Url::parse(url).ok()
                .map(|u| u.scheme() == "https" && u.host_str().map(allowed_oauth_host).unwrap_or(false))
                .unwrap_or(false);
            if !valid { return json!({"ok": false, "error": "登录页地址不在官方域名白名单内"}); }
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
    let raw = creds.get(formats::FIELD_TOKEN).and_then(|v| v.as_str()).ok_or("no jwt")?;
    if raw.starts_with(ENC_PREFIX) { decrypt_value(raw) } else { Ok(raw.to_string()) }
}

#[tauri::command(async)]
fn fetch_quota(key: String, force: Option<bool>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    load_quota_cache_once();
    let now = chrono::Utc::now().timestamp();
    if !force.unwrap_or(false) {
        if let Some(map) = QUOTA_CACHE.lock().unwrap().as_ref() {
            if let Some((ts, v)) = map.get(&key) {
                let ttl = if v.get("ok").and_then(|x| x.as_bool()) == Some(true) { 90 } else { 20 };
                if now - ts < ttl {
                    let mut hit = v.clone();
                    hit["cached"] = json!(true);
                    return hit;
                }
            }
        }
    }
    let token = match _get_jwt_token(&key) { Ok(t) => t, Err(e) => return json!({"ok": false, "code": "auth", "error": e}) };
    let mid = api_device_mid(&key);
    if mid.trim().is_empty() {
        return json!({"ok": false, "code": "device", "error": "账号缺少设备标识，请切换一次该账号后重试"});
    }
    let ver = client_app_version();
    let resp = match zcode_api_headers(http().get("https://zcode.z.ai/api/v1/zcode-plan/billing/balance")
        .query(&[("app_version", ver.as_str())])
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", &mid), &ver)
        .timeout(std::time::Duration::from_secs(30)).send() {
        Ok(r) => {
            let status = r.status();
            if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
                json!({"ok": false, "code": "auth", "error": "登录已过期，请重新登录该账号", "fetched_at": now})
            } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let retry = r.headers().get("retry-after").and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(60);
                json!({"ok": false, "code": "rate", "transient": true, "retry_after": retry,
                       "error": format!("请求过于频繁，{} 秒后自动重试", retry), "fetched_at": now})
            } else if !status.is_success() {
                json!({"ok": false, "code": "server", "transient": true,
                       "error": format!("服务端暂时不可用（HTTP {}）", status.as_u16()), "fetched_at": now})
            } else {
                match r.json::<Value>() {
                    Ok(j) => {
                        let code = j.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                        if code != 0 {
                            let msg = j.get("msg").and_then(|m| m.as_str()).filter(|s| !s.trim().is_empty()).unwrap_or("额度接口返回错误");
                            let transient = code == 429 || (500..=599).contains(&code);
                            json!({"ok": false, "code": if transient { "server" } else { "business" },
                                   "transient": transient, "error": msg, "fetched_at": now})
                        } else {
                            json!({"ok": true, "data": j, "fetched_at": now})
                        }
                    }
                    Err(e) => json!({"ok": false, "code": "parse", "transient": true, "error": e.to_string(), "fetched_at": now}),
                }
            }
        }
        Err(e) => json!({"ok": false, "code": "network", "transient": true, "error": e.to_string(), "fetched_at": now}),
    };
    // 成功响应落额度历史（10 分钟节流、30 天保留），供燃尽率预测；失败响应不入库
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        if let Some(sample) = history::sample_from_quota(&resp, now) {
            let hp = history::ensure_history_path(&app_data_dir(), &key);
            let _ = history::append_sample(&hp, &sample, now);
        }
    }
    let ok = resp.get("ok").and_then(|v| v.as_bool()) == Some(true);
    QUOTA_CACHE.lock().unwrap().get_or_insert_with(Default::default).insert(key, (now, resp.clone()));
    if ok { persist_quota_cache(); }
    resp
}

/// 额度历史 + 燃尽率预测（纯本地文件，无网络）
#[tauri::command(async)]
fn quota_history(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let samples = history::load_history_cached(&history::ensure_history_path(&app_data_dir(), &key));
    let forecast = history::forecast(&samples);
    json!({"ok": true, "samples": samples.len(), "points": samples, "forecast": forecast})
}

// 自绘标题栏的窗口控制（decorations:false 后由前端按钮调用）
#[tauri::command]
fn win_minimize(window: tauri::WebviewWindow) { let _ = window.minimize(); }

#[tauri::command]
fn win_toggle_maximize(window: tauri::WebviewWindow) {
    match window.is_maximized() { Ok(true) => { let _ = window.unmaximize(); }, Ok(_) => { let _ = window.maximize(); }, Err(_) => {} }
}

#[tauri::command]
fn win_hide(window: tauri::WebviewWindow) {
    request_close(window.app_handle()); // 关闭键 = 按设置隐藏到托盘或退出
}

#[tauri::command]
fn win_start_drag(window: tauri::WebviewWindow) { let _ = window.start_dragging(); }

#[tauri::command]
fn open_zcode_client() -> serde_json::Value {
    let exe = zcode_exe_path().unwrap_or_default();
    if exe.is_empty() { return json!({"ok": false, "error": "未找到 ZCode 客户端，请在设置中指定路径"}); }
    json!({"ok": launch_zcode_process(&exe)})
}

#[tauri::command(async)]
fn kill_zcode_client() -> serde_json::Value {
    match kill_zcode_process() {
        Ok(true) => json!({"ok": true}),
        Ok(false) => json!({"ok": false, "error": "无法关闭 ZCode（可能仍在托盘运行），请手动退出"}),
        Err(e) => json!({"ok": false, "error": format!("无法确认 ZCode 进程状态：{}", e)}),
    }
}

// ------------------------------------------------------- settings & benefits

static SETTINGS: Mutex<Option<Value>> = Mutex::new(None);
static BENEFITS: Mutex<Option<std::collections::HashMap<String, Value>>> = Mutex::new(None);
static LAST_CHECK: Mutex<Option<i64>> = Mutex::new(None);

fn config_path() -> PathBuf { app_data_dir().join("hub-config.json") }

fn load_settings() -> Value {
    let mut st = SETTINGS.lock().unwrap();
    if st.is_none() {
        *st = Some(read_json(&config_path()).unwrap_or(json!({
            "auto_check_minutes": 15, "notify_enabled": true, "hot_switch": false,
            "safe_mode": false, "lang": "zh", "close_action": "tray", "start_minimized": false
        })));
    }
    st.clone().unwrap()
}

// 官方 preview 响应 → 福利条目（纯函数，可单测）
fn campaigns_from_plans(plans: &[Value]) -> Vec<Value> {
    let mut camps = Vec::new();
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
            "detail": parts.join(" / "),
            "plan_id": p.get("plan_id").and_then(|v| v.as_str()).unwrap_or(""),
        }));
    }
    camps
}

#[cfg(test)]
fn parse_preview_plans(j: &Value) -> Vec<Value> {
    let plans = j.pointer("/data/plans").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    campaigns_from_plans(&plans)
}

// 官方「可领取预览」：GET /api/v1/zcode-plan/billing/preview —— 客户端领取弹窗同源接口，
// 返回 data.plans[]（每个含 plan_id/name/entitlements[grant_units]）。空数组 = 当前无可领。
// 注意：429 限流存在，批量检测时逐账号间加间隔。
// 与客户端一致的请求头（UA / X-Title / X-Platform 等）；服务端按客户端上下文做路由与风控
fn zcode_api_headers(rb: reqwest::blocking::RequestBuilder, ver: &str) -> reqwest::blocking::RequestBuilder {
    rb.header("User-Agent", format!("ZCode/{}", ver))
        .header("X-ZCode-App-Version", ver)
        .header("X-Title", "Z Code@electron")
        .header("X-Platform", "win32-x64")
        .header("X-Os-Category", "windows")
        .header("X-Client-Language", "zh-CN")
        .header("HTTP-Referer", "https://zcode.z.ai")
        .header("x-request-id", uuid::Uuid::new_v4().to_string())
}

// 客户端完整版本号（事件上报/接口要求 "x.y.z" 形态；失败回退兼容锚点）
fn client_app_version() -> String {
    zcode_client_version().map(|v| {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() >= 3 { format!("{}.{}.{}", parts[0], parts[1], parts[2]) } else { v }
    }).unwrap_or_else(|| DEFAULT_CLIENT_VERSION.to_string())
}

// 读取某账号的凭据快照（用于事件上报的 user_id）
fn cred_for_key(key: &str) -> Option<Value> {
    if key == "__current__" { read_json(&cred_path()).ok() }
    else { read_snapshot_value(&profiles_dir().join(key)) }
}

// 每账号虚拟设备标识（meta.json 的 device_mid）。非当前账号的 API 请求必须用它：
// 服务端按 账号×设备 校验，用错 deviceMid 会导致 preview 列表为空 / claim 被风控拒绝(3012)。
fn profile_device_mid(key: &str) -> Option<String> {
    if key == "__current__" { return Some(telemetry_device_mid()); }
    read_json(&profiles_dir().join(key).join("meta.json")).ok()?
        .get("device_mid").and_then(|v| v.as_str())
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
fn api_device_mid(key: &str) -> String {
    if key == "__current__" {
        let mut mid = telemetry_device_mid();
        if mid.trim().is_empty() {
            mid = uuid::Uuid::new_v4().to_string();
            write_live_device_mid(&mid);
        }
        return mid;
    }
    if let Some(mid) = profile_device_mid(key) { return mid; }
    // 非当前账号缺设备标识时生成并持久化；绝不回退到 live（那会与当前账号共享设备）
    let dir = profiles_dir().join(key);
    let mut meta = read_json(&dir.join("meta.json")).ok().unwrap_or(json!({}));
    let mid = ensure_profile_device_mid(&dir, &mut meta, false);
    let _ = write_json(&dir.join("meta.json"), &meta);
    mid
}

// 活动事件上报节流表：每账号 30 分钟最多一次（检测解锁用，见 claim.rs 模块文档）
static EVENT_REPORTS: Mutex<Option<std::collections::HashMap<String, i64>>> = Mutex::new(None);

fn maybe_report_events(key: &str, creds: &Value, mid: &str, ver: &str) {
    let now = chrono::Utc::now().timestamp();
    {
        let mut g = EVENT_REPORTS.lock().unwrap();
        let map = g.get_or_insert_with(Default::default);
        if let Some(t) = map.get(key) { if now - t < 1800 { return; } }
        map.insert(key.to_string(), now);
    }
    let Some(uid) = claim::telemetry_user_id(creds, &|s| decrypt_value(s).ok()) else { return };
    let env = claim::EventEnv::detect(ver);
    let _ = claim::report_activation_events(http(), &env, &uid, mid);
}

fn _benefits_key_result(key: &str) -> Value {
    let ts = chrono::Utc::now().timestamp();
    let token = match _get_jwt_token(key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e, "count": 0, "campaigns": [], "checked_at": ts}) };
    let mid = api_device_mid(key); // 账号自己的设备标识（见 profile_device_mid 注释）
    let ver = client_app_version();
    // 检测解锁：以用户本人账号上报 app_launch / app_daily_active（与客户端启动行为一致，30 分钟节流）
    if let Some(creds) = cred_for_key(key) { maybe_report_events(key, &creds, &mid, &ver); }
    // 主数据源：marketing/touch（客户端左下角领取横幅同源）；preview 作为兜底（可能返回其他活动）
    let marketing = claim::marketing_claim_plans(http(), &token, &mid, &ver);
    let preview = claim::preview_plans(http(), &token, &mid, &ver);
    match (&marketing, &preview) {
        (Err(me), Err(pe)) => json!({"ok": false, "transient": pe.transient,
            "error": format!("{} / {}", me, pe.msg), "count": 0, "campaigns": [], "checked_at": ts}),
        _ => {
            let mut plans: Vec<Value> = Vec::new();
            if let Ok(p) = &marketing { plans.extend(p.iter().cloned()); }
            if let Ok(p) = &preview { plans.extend(p.iter().cloned()); }
            let mut seen = std::collections::HashSet::new();
            plans.retain(|p| p.get("plan_id").and_then(|v| v.as_str())
                .map(|k| seen.insert(k.to_string())).unwrap_or(false));
            let camps = campaigns_from_plans(&plans);
            json!({"ok": true, "count": camps.len(), "campaigns": camps, "checked_at": ts})
        }
    }
}

// ---------------- 领取（验证码由用户在系统浏览器手动完成；不做自动领取） ----------------

static CLAIM_STATE: Mutex<Option<Value>> = Mutex::new(None);

fn set_claim_state(v: Value) { *CLAIM_STATE.lock().unwrap() = Some(v); }

#[tauri::command]
fn claim_state() -> Value { CLAIM_STATE.lock().unwrap().clone().unwrap_or(json!({"status":"idle"})) }

fn claim_busy() -> bool {
    let st = CLAIM_STATE.lock().unwrap().clone().unwrap_or(Value::Null);
    matches!(st.get("status").and_then(|s| s.as_str()),
        Some("preparing") | Some("activating") | Some("waiting_captcha") | Some("claiming"))
}

#[tauri::command]
fn claim_plan(key: String, plan_id: String, plan_name: Option<String>) -> Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    if plan_id.trim().is_empty() { return json!({"ok": false, "error": "缺少 plan_id，无法领取"}); }
    if claim_busy() { return json!({"ok": false, "code": "claim_busy", "error": "上一次领取仍在进行中，请稍候"}); }
    let pname = plan_name.unwrap_or_default();
    set_claim_state(json!({"status": "preparing", "key": key, "planId": plan_id, "planName": pname,
                           "updatedAt": chrono::Utc::now().timestamp()}));
    let (k, pid, pn) = (key.clone(), plan_id.clone(), pname.clone());
    std::thread::spawn(move || claim_worker(k, pid, pn));
    json!({"ok": true, "started": true})
}

/// 领取成功后先做本地乐观更新：立即去掉该活动，按钮马上消失；
/// 后台重查 marketing/touch 再校正真实状态。返回给 UI 的 success 不被网络请求阻塞。
fn optimistically_consume_benefit(key: &str, plan_id: &str) {
    let mut changed = false;
    {
        let mut g = BENEFITS.lock().unwrap();
        if let Some(map) = g.as_mut() {
            if let Some(entry) = map.get_mut(key) {
                if let Some(arr) = entry.get_mut("campaigns").and_then(|c| c.as_array_mut()) {
                    let before = arr.len();
                    arr.retain(|c| c.get("plan_id").and_then(|v| v.as_str()) != Some(plan_id));
                    if arr.len() != before {
                        entry["count"] = json!(arr.len());
                        changed = true;
                    }
                }
            }
        }
    }
    if changed { persist_benefits(); update_tray_tooltip(); }
}

fn claim_worker(key: String, plan_id: String, plan_name: String) {
    let fail = |msg: String| set_claim_state(json!({"status":"failed","message":msg,"key":key.clone(),"planName":plan_name.clone(),
        "planId": plan_id.clone(), "updatedAt": chrono::Utc::now().timestamp()}));
    let ver = client_app_version();
    let token = match _get_jwt_token(&key) { Ok(t) => t, Err(e) => return fail(e) };
    let mid = api_device_mid(&key); // 账号自己的设备标识，避免 3012 风控
    // 领取前确保激活（best-effort）；与自动检测共用 30 分钟节流，重试不会重复上报事件
    if let Some(creds) = cred_for_key(&key) {
        maybe_report_events(&key, &creds, &mid, &ver);
    }
    // 验证码（若服务端要求）：本地回环页 + 系统浏览器，用户手动完成
    let cfg = claim::fetch_captcha_config(http(), &ver).unwrap_or(json!({"enabled": false}));
    let enabled = cfg.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut param: Option<String> = None;
    let mut region: Option<String> = None;
    if enabled {
        match claim::start_captcha_flow(&cfg) {
            Ok(flow) => {
                let captcha_url = flow.url.clone();
                set_claim_state(json!({"status":"waiting_captcha","key": key, "planName": plan_name,
                    "planId": plan_id, "captchaUrl": captcha_url,
                    "updatedAt": chrono::Utc::now().timestamp()}));
                platform::open_in_browser(&flow.url);
                match claim::wait_captcha(flow) {
                    Ok(v) => {
                        param = v.get("param").and_then(|p| p.as_str()).map(String::from);
                        region = v.get("region").and_then(|r| r.as_str()).map(String::from);
                        if param.as_deref().map(|p| p.trim().is_empty()).unwrap_or(true) {
                            return fail("未取得验证码结果".into());
                        }
                    }
                    Err(e) => return fail(e),
                }
            }
            Err(e) => return fail(e),
        }
    }
    set_claim_state(json!({"status":"claiming","key": key, "planName": plan_name, "planId": plan_id,
                           "updatedAt": chrono::Utc::now().timestamp()}));
    match claim::submit_claim(http(), &token, &mid, &ver, &plan_id, param.as_deref(), region.as_deref()) {
        Ok(data) => {
            let (eff, _s, ends) = claim::claim_timing(&data);
            let name = data.pointer("/plan/name").and_then(|v| v.as_str())
                .or_else(|| data.pointer("/plan/plan_id").and_then(|v| v.as_str()))
                .map(String::from).filter(|s| !s.is_empty()).unwrap_or_else(|| plan_name.clone());
            audit_log("claim", Some(&key), json!({"plan": name, "plan_id": plan_id, "effective_at": eff}));
            // 立即失效该账号额度缓存 + 乐观移除本次活动，让 UI 马上看到成功/按钮消失
            QUOTA_CACHE.lock().unwrap().as_mut().map(|m| m.remove(&key));
            persist_quota_cache();
            optimistically_consume_benefit(&key, &plan_id);
            set_claim_state(json!({"status":"success","key": key, "planName": name, "planId": plan_id,
                                   "effectiveAt": eff, "endsAt": ends,
                                   "updatedAt": chrono::Utc::now().timestamp()}));
            // 福利重查放后台：marketing/touch 20s + preview 30s，不能阻塞成功状态回传
            let k2 = key.clone();
            std::thread::spawn(move || {
                let _ = run_benefit_check_for(&k2);
                persist_benefits();
            });
        }
        Err(e) => fail(e),
    }
}

/// 重新打开当前领取流程的验证页（用户关闭浏览器后不必重新走整个领取）
#[tauri::command]
fn open_claim_captcha() -> Value {
    let st = claim_state();
    let url = st.get("captchaUrl").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() { return json!({"ok": false, "error": "当前没有进行中的验证页"}); }
    if !platform::is_safe_open_url(url) { return json!({"ok": false, "error": "验证页地址无效"}); }
    platform::open_in_browser(url);
    json!({"ok": true})
}

/// 本地领取历史（审计日志中的 claim 事件；不含账号标识）
#[tauri::command(async)]
fn claim_history() -> Value {
    let p = audit::audit_path(&app_data_dir());
    let Ok(txt) = std::fs::read_to_string(&p) else { return json!({"ok": true, "items": []}) };
    let mut items: Vec<Value> = txt.lines().rev().filter_map(|l| {
        let v: Value = serde_json::from_str(l).ok()?;
        if v.get("event").and_then(|e| e.as_str()) != Some("claim") { return None; }
        let d = v.get("detail").cloned().unwrap_or(json!({}));
        Some(json!({"ts": v.get("ts").cloned().unwrap_or(Value::Null),
                    "plan": d.get("plan").cloned().unwrap_or(Value::Null),
                    "effectiveAt": d.get("effective_at").cloned().unwrap_or(Value::Null)}))
    }).take(50).collect();
    items.truncate(50);
    json!({"ok": true, "items": items})
}

fn benefits_file() -> PathBuf { app_data_dir().join("benefits.json") }

/// 持久化时把账号 key 哈希，避免 benefits.json 里出现邮箱/昵称。
fn persist_benefits() {
    let map = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    let mut obj = serde_json::Map::new();
    for (k, v) in map { obj.insert(opaque_key(&k), v); }
    let v = json!({"last_check": *LAST_CHECK.lock().unwrap(), "map": obj});
    let _ = write_json(&benefits_file(), &v);
}

fn known_profile_key_map() -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    m.insert(opaque_key("__current__"), "__current__".to_string());
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() { continue; }
            let k = e.file_name().to_string_lossy().to_string();
            if safe_key(&k).is_ok() { m.insert(opaque_key(&k), k); }
        }
    }
    m
}

fn load_benefits_once() {
    let mut g = BENEFITS.lock().unwrap();
    if g.is_some() { return; }
    if let Ok(v) = read_json(&benefits_file()) {
        if let Some(map) = v.get("map").and_then(|m| m.as_object()) {
            let reverse = known_profile_key_map();
            let mut loaded = std::collections::HashMap::new();
            for (hk, val) in map {
                let raw = reverse.get(hk).cloned().or_else(|| {
                    if !is_opaque_key(hk) && safe_key(hk).is_ok() { Some(hk.clone()) } else { None }
                });
                if let Some(raw) = raw { loaded.insert(raw, val.clone()); }
            }
            *g = Some(loaded);
            if let Some(lc) = v.get("last_check").and_then(|x| x.as_i64()) {
                *LAST_CHECK.lock().unwrap() = Some(lc);
            }
        }
    }
}

/// 单账号检测：只更新内存与托盘，不立刻写盘（批量调用方统一持久化一次）。
fn run_benefit_check_for(key: &str) -> Value {
    let result = _benefits_key_result(key);
    BENEFITS.lock().unwrap()
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(key.to_string(), result.clone());
    update_tray_tooltip();
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

const BENEFIT_BATCH_GAP_MS: u64 = 800;

static CHECK_STATE: Mutex<Option<(u64, u64)>> = Mutex::new(None);
static BENEFIT_BATCH_LOCK: Mutex<()> = Mutex::new(());

#[tauri::command]
fn check_state() -> serde_json::Value {
    match *CHECK_STATE.lock().unwrap() {
        Some((done, total)) => json!({"checking": true, "done": done, "total": total}),
        None => json!({"checking": false, "done": 0, "total": 0}),
    }
}

struct BatchStat { okn: u64, failed: u64, transient: u64, with: u64, total: u64 }

fn check_benefits_many(keys: &[String]) -> BatchStat {
    // 手动、托盘与自动检测可能同时触发：串行化，避免重复全量请求把 429 风险翻倍
    let _batch_guard = BENEFIT_BATCH_LOCK.lock().unwrap();
    let mut st = BatchStat { okn: 0, failed: 0, transient: 0, with: 0, total: 0 };
    *CHECK_STATE.lock().unwrap() = Some((0, keys.len() as u64));
    for (i, k) in keys.iter().enumerate() {
        if i > 0 { std::thread::sleep(std::time::Duration::from_millis(BENEFIT_BATCH_GAP_MS)); }
        let r = run_benefit_check_for(k);
        if r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            st.okn += 1;
            let c = r.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            if c > 0 { st.with += 1; st.total += c; }
        } else {
            st.failed += 1;
            if r.get("transient").and_then(|v| v.as_bool()).unwrap_or(false) { st.transient += 1; }
        }
        *CHECK_STATE.lock().unwrap() = Some(((i + 1) as u64, keys.len() as u64));
    }
    *CHECK_STATE.lock().unwrap() = None;
    persist_benefits();
    st
}

#[tauri::command(async)]
fn check_benefits(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let r = run_benefit_check_for(&key);
    persist_benefits();
    json!({"ok": r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
           "count": r.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
           "campaigns": r.get("campaigns").cloned().unwrap_or(json!([])),
           "checked_at": r.get("checked_at").cloned().unwrap_or(Value::Null),
           "transient": r.get("transient").and_then(|v| v.as_bool()).unwrap_or(false),
           "error": r.get("error").cloned().unwrap_or(Value::Null), "key": key})
}

#[tauri::command(async)]
fn check_all_benefits() -> serde_json::Value {
    let keys = _all_profile_keys();
    let st = check_benefits_many(&keys);
    // 全部失败不推进 last_check：下一轮自动检测应立即重试，而不是等一个完整周期
    if st.okn > 0 { *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp()); }
    json!({"ok": true, "accounts": keys.len(), "checked_ok": st.okn, "failed": st.failed,
           "transient": st.transient, "accounts_with_benefits": st.with, "total_campaigns": st.total})
}

#[tauri::command]
fn get_settings() -> serde_json::Value { load_settings() }

#[tauri::command(async)]
#[allow(clippy::too_many_arguments)] // Tauri 命令参数必须平铺；前端按字段名调用
fn set_settings(minutes: Option<i64>, notify_enabled: Option<bool>, zcode_path: Option<String>,
                hot_switch: Option<bool>, safe_mode: Option<bool>, lang: Option<String>,
                close_action: Option<String>, start_minimized: Option<bool>) -> serde_json::Value {
    let mut s = load_settings();
    let mut minutes_changed = false;
    if let Some(m) = minutes {
        let m = m.clamp(0, 1440);
        if s.get("auto_check_minutes").and_then(|v| v.as_i64()) != Some(m) {
            s["auto_check_minutes"] = json!(m);
            minutes_changed = true;
        }
    }
    if let Some(n) = notify_enabled { s["notify_enabled"] = json!(n); }
    if let Some(h) = hot_switch { s["hot_switch"] = json!(h); }
    if let Some(sm) = safe_mode { s["safe_mode"] = json!(sm); }
    if let Some(l) = lang {
        if l == "zh" || l == "en" { s["lang"] = json!(l); }
    }
    if let Some(c) = close_action {
        if c == "tray" || c == "quit" { s["close_action"] = json!(c); }
    }
    if let Some(v) = start_minimized { s["start_minimized"] = json!(v); }
    // None = 未传（保持原值）；Some("") = 显式清空为自动探测
    if let Some(raw) = zcode_path {
        let zp = raw.trim().trim_matches('"').to_string();
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
    audit_log("settings", None, json!({
        "auto_check_minutes": s["auto_check_minutes"], "notify_enabled": s["notify_enabled"],
        "hot_switch": s["hot_switch"], "safe_mode": s["safe_mode"],
        "lang": s["lang"], "close_action": s["close_action"], "start_minimized": s["start_minimized"],
        "zcode_path_set": !s["zcode_path"].is_null()
    }));
    *SETTINGS.lock().unwrap() = Some(s.clone());
    if minutes_changed { *LAST_CHECK.lock().unwrap() = None; }
    json!({"ok": true, "settings": s})
}

fn ui_lang() -> String {
    load_settings().get("lang").and_then(|v| v.as_str()).unwrap_or("zh").to_string()
}

// 全量检测所有账号福利；发现可领且通知开关开启时弹系统通知（托盘菜单与自动循环共用）
fn _check_all_and_notify(app: &tauri::AppHandle) -> (u64, u64) {
    let keys = _all_profile_keys();
    let st = check_benefits_many(&keys);
    if st.okn > 0 { *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp()); }
    if st.total > 0 && load_settings().get("notify_enabled").and_then(|v| v.as_bool()).unwrap_or(true) {
        platform::beep(); // 系统提示音：窗口隐藏到托盘时也能听到
        use tauri_plugin_notification::NotificationExt;
        let (title, body) = if ui_lang() == "en" {
            ("ZCode Hub · Benefits available".to_string(),
             format!("{} claimable across {} account(s). Open the app to claim.", st.total, st.with))
        } else {
            ("ZCode Hub 福利提醒".to_string(),
             format!("{} 个账号共有 {} 项福利可领取，打开应用查看", st.with, st.total))
        };
        let _ = app.notification().builder().title(title).body(body).show();
    }
    (st.okn, st.failed)
}

// 自动检测线程：每 30s 醒来按设置的周期跑一轮；连续失败按 1→2→5→10 分钟退避
fn _auto_check_loop(app: tauri::AppHandle) {
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
        let (okn, failed) = _check_all_and_notify(&app);
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

// -------------------------------------------------------------------- tray

/// 关闭请求：按设置隐藏到托盘或退出；首次隐藏时发一条系统通知，避免用户以为程序已退出。
fn request_close(app: &tauri::AppHandle) -> bool {
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

fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // 菜单固定双语：语言切换不需要重建托盘菜单，也不会出现只懂中文/只懂英文的入口
    let show = MenuItem::with_id(app, "show", "显示 ZCode Hub / Show", true, None::<&str>)?;
    let check = MenuItem::with_id(app, "check", "立即检测福利 / Check now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出 / Quit", true, None::<&str>)?;
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
                        let _ = w.show();
                        let _ = w.set_focus();
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

// -------------------------------------------------------------------- main

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
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
                let hidden = request_close(window.app_handle());
                if hidden { api.prevent_close(); }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state, capture_profile, switch_profile, delete_profile, restore_profile, rename_profile,
            fetch_quota, quota_history, open_zcode_client, kill_zcode_client,
            oauth_start, oauth_status, oauth_open, oauth_cancel,
            check_benefits, check_all_benefits, check_state, claim_plan, claim_state, open_claim_captcha, claim_history,
            get_settings, set_settings,
            win_minimize, win_toggle_maximize, win_hide, win_start_drag,
            export_bundle, import_bundle, reveal_file,
            set_autostart, open_data_dir, open_zcode_data_dir, check_update, open_url, install_update, update_progress,
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
        // 连续点折叠 + 首尾点剥离：结果必须能通过 safe_key
        assert_eq!(sanitize_label("../.."), "_");
        assert_eq!(sanitize_label("..."), "account");
        assert_eq!(sanitize_label(""), "account");
        assert_eq!(sanitize_label("CON"), "account-CON");
        assert_eq!(sanitize_label("COM1"), "account-COM1");
        for s in ["../..", "...", "", ".hidden", "a/b", "a:b", "a b"] {
            assert!(safe_key(&sanitize_label(s)).is_ok(), "sanitize 后仍非法: {:?}", s);
        }
    }

    #[test]
    fn fingerprint_is_same_for_plain_and_encrypted_token() {
        let plain = json!({ formats::FIELD_TOKEN: "same-token-value" });
        let enc = json!({ formats::FIELD_TOKEN: encrypt_value("same-token-value") });
        assert_eq!(cred_fingerprint(&plain), cred_fingerprint(&enc));
        assert!(cred_fingerprint(&json!({})).is_none());
        assert!(cred_fingerprint(&json!({ formats::FIELD_TOKEN: "" })).is_none());
    }

    #[test]
    fn decrypt_rejects_malformed_iv_and_tag() {
        // 损坏的本地文件不能让 Nonce::from_slice panic
        assert!(decrypt_with(&[0u8; 32], "enc:v1:AAAA.AAAA.AAAA").is_err());
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let iv12 = engine.encode([0u8; 12]);
        let tag16 = engine.encode([0u8; 16]);
        assert!(decrypt_with(&[0u8; 32], &format!("enc:v1:{}.AAAA.{}", iv12, tag16)).is_err());
        assert!(decrypt_with(&[0u8; 32], &format!("enc:v1:{}.{}.AAAA", iv12, tag16)).is_err());
    }

    #[test]
    fn opaque_key_is_stable_and_does_not_leak_input() {
        let a = opaque_key("user@example.com");
        assert_eq!(a, opaque_key("user@example.com"));
        assert_ne!(a, opaque_key("other@example.com"));
        assert!(!a.contains("user") && !a.contains("example"));
        assert!(a.starts_with('k'));
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
        assert!(hot_swap_verified(&p, &v, None));
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