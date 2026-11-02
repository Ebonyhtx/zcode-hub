use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::client::{kill_zcode_process, launch_zcode_process, zcode_exe_path, zcode_running};
use crate::crypto::{decrypt_value, read_snapshot_checked, read_snapshot_value, write_snapshot};

#[cfg(test)]
use crate::crypto::encrypt_value;
use crate::formats::{self, read_json, write_json, ENC_PREFIX};
use crate::platform;
use crate::settings::load_settings;
use crate::util::{audit_log, cred_path, denied, profiles_dir, safe_key, sanitize_label, v2_dir};

#[derive(serde::Serialize)]
pub(crate) struct ProfileInfo {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) captured_at: String,
    pub(crate) is_current: bool,
    pub(crate) provider: String,
    pub(crate) jwt_expired: bool,
    /// 用户自定义标签（meta.json），用于搜索/筛选。
    pub(crate) tags: Vec<String>,
    /// 快照无法读取/解密时的具体原因（前端显示“存档异常”，不再静默消失）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// token 明文指纹：账号身份的唯一判据（不再用可能重名的展示 label）。
pub(crate) fn cred_fingerprint(creds: &Value) -> Option<String> {
    let raw = creds.get(formats::FIELD_TOKEN).and_then(|v| v.as_str())?;
    // 兼容旧明文存档：enc:v1 才解密，否则把原文当作 token
    let plain = if raw.starts_with(ENC_PREFIX) {
        decrypt_value(raw).ok()?
    } else {
        raw.to_string()
    };
    if plain.trim().is_empty() {
        return None;
    }
    let mut h = Sha256::new();
    h.update(plain.as_bytes());
    let d = h.finalize();
    Some(d.iter().take(12).map(|b| format!("{:02x}", b)).collect())
}

/// 在账号库里找 live 凭据对应的存档：先比 token 指纹，指纹缺失才回退 label。
pub(crate) fn find_profile_dir_for_live(live: &Value) -> Option<PathBuf> {
    let fp = cred_fingerprint(live);
    let label = account_label(live);
    let mut by_label: Option<PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let Ok(v) = read_snapshot_checked(&e.path()) else {
                continue;
            };
            if let (Some(a), Some(b)) = (fp.as_ref(), cred_fingerprint(&v)) {
                if *a == b {
                    return Some(e.path());
                }
            } else if by_label.is_none() && account_label(&v) == label {
                by_label = Some(e.path());
            }
        }
    }
    by_label
}

pub(crate) fn profile_label(meta: &Value, creds: &Value) -> String {
    meta.get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| account_label(creds))
}

pub(crate) fn find_profile_by_fingerprint(fp: &str) -> Option<PathBuf> {
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            if let Ok(v) = read_snapshot_checked(&e.path()) {
                if cred_fingerprint(&v).as_deref() == Some(fp) {
                    return Some(e.path());
                }
            }
        }
    }
    None
}

/// 为一份凭据挑选存档目录：同账号（token 指纹相同）复用原目录；
/// 否则用清洗后的显示名，重名时追加 -2/-3，绝不静默覆盖别人的存档。
/// 返回 (目录, 目录名, 是否更新已有账号)。
pub(crate) fn unique_profile_dir(preferred: &str, creds: &Value) -> (PathBuf, String, bool) {
    if let Some(fp) = cred_fingerprint(creds) {
        if let Some(dir) = find_profile_by_fingerprint(&fp) {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
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
pub(crate) fn jwt_expired(creds: &Value) -> bool {
    formats::jwt_expired_with(
        creds,
        &|s: &str| decrypt_value(s).ok(),
        chrono::Utc::now().timestamp(),
        30,
    )
}

pub(crate) fn account_label(creds: &Value) -> String {
    formats::account_label_with(creds, &|s: &str| decrypt_value(s).ok())
}

#[tauri::command(async)]
pub(crate) fn capture_profile(name: Option<String>) -> serde_json::Value {
    let src = cred_path();
    if !src.exists() {
        return json!({"ok": false, "error": "未找到登录凭证"});
    }
    let creds = match read_json(&src) {
        Ok(c) => c,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let label = account_label(&creds);
    let base = name.unwrap_or_else(|| label.clone());
    let (dd, fname, updated) = unique_profile_dir(&base, &creds);
    if let Err(e) = write_snapshot(&dd, &creds) {
        if !updated {
            let _ = std::fs::remove_dir_all(&dd);
        }
        return json!({"ok": false, "error": format!("存档写入失败: {}", e)});
    }
    let provider =
        formats::active_provider_with(&creds, &|s: &str| decrypt_value(s).ok()).unwrap_or_default();
    let mut meta = read_json(&dd.join("meta.json")).ok().unwrap_or(json!({}));
    let keep_label = meta
        .get("label")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| label.clone());
    meta["label"] = json!(if updated { keep_label } else { base.clone() });
    meta["provider"] = json!(provider);
    meta["captured_at"] = json!(chrono::Utc::now().to_rfc3339());
    let _mid = ensure_profile_device_mid(&dd, &mut meta, true);
    let _auid = ensure_profile_arms_uid(&dd, &mut meta, true);
    if let Err(e) = write_json(&dd.join("meta.json"), &meta) {
        if !updated {
            let _ = std::fs::remove_dir_all(&dd);
        }
        return json!({"ok": false, "error": format!("账号元数据写入失败: {}", e)});
    }
    audit_log("capture", Some(&fname), json!({"updated": updated}));
    json!({"ok": true, "name": fname, "label": label, "updated": updated})
}

pub(crate) fn hot_swap_verified(cur: &Path, target: &Value, original: Option<&Value>) -> bool {
    // 写入后回读两次，比较 token 明文指纹（不是展示名——同名账号会误判成功）。
    // 三次失败必须恢复原文件：调用方可能随后走冷切换，不能让 live 停在半切换状态。
    let expected = cred_fingerprint(target);
    let Some(expected) = expected else {
        return false;
    };
    for attempt in 0..3u32 {
        if write_json(cur, target).is_err() {
            std::thread::sleep(std::time::Duration::from_millis(250 * (attempt as u64 + 1)));
            continue;
        }
        if let Ok(v1) = read_json(cur) {
            if cred_fingerprint(&v1).as_deref() == Some(expected.as_str()) {
                std::thread::sleep(std::time::Duration::from_millis(150));
                if let Ok(v2) = read_json(cur) {
                    if cred_fingerprint(&v2).as_deref() == Some(expected.as_str()) {
                        return true;
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250 * (attempt as u64 + 1)));
    }
    if let Some(orig) = original {
        let _ = write_json(cur, orig);
    }
    false
}

/// 把当前 live 登录保鲜回其存档（按 token 指纹匹配）；找不到时自动新建 autosave。
/// 失败必须让调用方中止切换——不能在无法保全当前账号时继续写 live。
pub(crate) fn preserve_current_login(live: &Value) -> Result<(), String> {
    let has_token = live
        .get(formats::FIELD_TOKEN)
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !has_token {
        return Ok(());
    }
    if let Some(dir) = find_profile_dir_for_live(live) {
        return write_snapshot(&dir, live).map_err(|e| format!("无法保全当前登录: {}", e));
    }
    let auto = format!("autosave-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let dir = profiles_dir().join(&auto);
    write_snapshot(&dir, live).map_err(|e| format!("无法为当前登录创建存档: {}", e))?;
    let label = account_label(live);
    let provider =
        formats::active_provider_with(live, &|s: &str| decrypt_value(s).ok()).unwrap_or_default();
    let _ = write_json(
        &dir.join("meta.json"),
        &json!({"label": label, "provider": provider, "captured_at": chrono::Utc::now().to_rfc3339()}),
    );
    Ok(())
}

pub(crate) fn apply_switch_identity(prof_dir: &Path, provider: &str) {
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

pub(crate) fn preserve_corrupt_live(cur: &Path) {
    if cur.exists() && read_json(cur).is_err() {
        let _ = std::fs::copy(cur, v2_dir().join("credentials.json.corrupt"));
    }
}

#[tauri::command(async)]
pub(crate) fn switch_profile(key: String, hot: Option<bool>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
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
        Err(e) => {
            return json!({"ok": false, "error": format!("无法确认 ZCode 是否在运行（{}）。为避免在客户端运行时改凭据，已取消切换", e)})
        }
    };
    let want_hot = hot.unwrap_or(false)
        && load_settings()
            .get("hot_switch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        && was;
    let dec = |s: &str| decrypt_value(s).ok();
    let target_provider = formats::active_provider_with(&prof_v, &dec).unwrap_or_default();
    if target_provider.is_empty() {
        return json!({"ok": false, "error": "目标存档缺少有效的 provider，拒绝切换"});
    }
    let live_creds = read_json(&cur).ok();
    let live_probe_bad = live_creds
        .as_ref()
        .map(|v| !formats::probe_credentials(Some(v)).ok())
        .unwrap_or(false);
    let safe_requested = load_settings()
        .get("safe_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // ---------------- 安全模式：只合并账号身份字段，保留未知字段 ----------------
    if (safe_requested || live_probe_bad) && live_creds.is_some() {
        let original = live_creds.clone().unwrap_or_else(|| json!({}));
        if let Err(e) = preserve_current_login(&original) {
            audit_log(
                "switch",
                Some(&key),
                json!({"mode": "safe", "result": "fail", "error": "preserve_failed"}),
            );
            return json!({"ok": false, "error": format!("{}。为避免丢失当前账号，已取消切换", e)});
        }
        let mut merged = original.clone();
        if let Err(e) = formats::merge_account_fields(&mut merged, &prof_v, &target_provider) {
            audit_log(
                "switch",
                Some(&key),
                json!({"mode": "safe", "result": "fail", "error": e}),
            );
            return json!({"ok": false, "error": format!("安全模式合并失败：{}", e)});
        }
        if !hot_swap_verified(&cur, &merged, Some(&original)) {
            audit_log(
                "switch",
                Some(&key),
                json!({"mode": "safe", "result": "fail", "error": "verify_failed"}),
            );
            return json!({"ok": false, "error": "安全模式写入验证失败，已恢复原文件"});
        }
        apply_switch_identity(&prof_dir, &target_provider);
        audit_log(
            "switch",
            Some(&key),
            json!({"mode": "safe", "result": "ok"}),
        );
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
            Ok(false) => {
                return json!({"ok": false, "error": "无法关闭 ZCode（可能仍在托盘运行），请手动退出 ZCode 后重试"})
            }
            Err(e) => {
                return json!({"ok": false, "error": format!("无法确认 ZCode 进程已退出（{}），已取消切换", e)})
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let backup = v2_dir().join("credentials.json.hub-backup");
    preserve_corrupt_live(&cur);
    let had_backup = if cur.exists() {
        if let Ok(cur_v) = read_json(&cur) {
            if let Err(e) = preserve_current_login(&cur_v) {
                if was {
                    let _ = exe.as_ref().map(|e| launch_zcode_process(e));
                }
                return json!({"ok": false, "error": format!("{}。为避免丢失当前账号，已取消切换", e)});
            }
        }
        std::fs::copy(&cur, &backup).is_ok()
    } else {
        false
    };
    if let Err(e) = write_json(&cur, &prof_v) {
        if had_backup {
            match std::fs::copy(&backup, &cur) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&backup);
                    audit_log(
                        "switch",
                        Some(&key),
                        json!({"mode": "cold", "result": "fail", "error": "write_failed_restored"}),
                    );
                    return json!({"ok": false, "error": format!("替换凭据文件失败（{}），已恢复原文件", e)});
                }
                Err(e2) => {
                    audit_log(
                        "switch",
                        Some(&key),
                        json!({"mode": "cold", "result": "fail", "error": "restore_failed"}),
                    );
                    return json!({"ok": false, "critical": true,
                        "error": format!("替换凭据失败且恢复也失败（{} / {}）。请从“备份/导入”恢复，或重新登录 ZCode", e, e2)});
                }
            }
        }
        audit_log(
            "switch",
            Some(&key),
            json!({"mode": "cold", "result": "fail", "error": "write_failed"}),
        );
        return json!({"ok": false, "error": format!("替换凭据文件失败：{}", e)});
    }
    // 替换成功后回滚副本使命结束
    let _ = std::fs::remove_file(&backup);
    apply_switch_identity(&prof_dir, &target_provider);
    let rel = if was {
        exe.as_ref()
            .map(|e| launch_zcode_process(e))
            .unwrap_or(false)
    } else {
        false
    };
    audit_log(
        "switch",
        Some(&key),
        json!({"mode": "cold", "result": "ok", "relaunched": rel}),
    );
    json!({"ok": true, "relaunched": rel})
}

// 客户端 setting.json 的 providerFamilyDomain 必须 = 当前登录账号的家族（zai/bigmodel），
// 否则账号提供商解析第一个检查就返回 null → 模型配置显示「请登录」、套餐额度不加载。
// 交互登录时官方客户端会自己写这个字段；文件级切换/存档必须由 Hub 同步维护。
// ---------------- 设备身份跟账号走 ----------------
// 每个账号存档绑定独立 deviceMid：首次采纳当前设备的（未被其他存档占用时），
// 否则生成新的 UUID；切换时写进客户端 telemetry-state.json。
// 效果：不同账号在服务端各自呈现独立的设备标识，互不关联。
pub(crate) fn live_device_mid() -> Option<String> {
    let v = read_json(&v2_dir().join("telemetry-state.json")).ok()?;
    formats::read_device_mid(&v)
}

pub(crate) fn ensure_profile_device_mid(dir: &Path, meta: &mut Value, allow_live: bool) -> String {
    if let Some(m) = meta.get("device_mid").and_then(|v| v.as_str()) {
        if !m.trim().is_empty() {
            return m.to_string();
        }
    }
    let mut taken: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if e.path().as_path() == dir {
                continue;
            }
            if let Ok(m) = read_json(&e.path().join("meta.json")) {
                if let Some(dm) = m.get("device_mid").and_then(|v| v.as_str()) {
                    taken.push(dm.to_string());
                }
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

pub(crate) fn write_live_device_mid(mid: &str) {
    let p = v2_dir().join("telemetry-state.json");
    let mut v = read_json(&p).unwrap_or_else(|_| json!({}));
    if formats::set_device_mid(&mut v, mid) {
        let _ = write_json(&p, &v);
    }
}

// arms_uid：阿里云 RUM 遥测的用户标识，存于 %APPDATA% 下 ZCode 的 rum-electron-store/*.json 的 _arms_uid。
// 与 deviceMid 同策略：每账号独立，首次采纳当前值（未被占用时），否则生成新的。
// 目录枚举在 platform.rs（Windows 客户端专属布局）。
pub(crate) fn arms_store_dirs() -> Vec<PathBuf> {
    platform::arms_store_dirs()
}

pub(crate) fn read_live_arms_uid() -> Option<String> {
    formats::read_arms_uid_in(&arms_store_dirs())
}

pub(crate) fn write_live_arms_uid(uid: &str) {
    if let Some(e) = formats::write_arms_uid_in(&arms_store_dirs(), uid) {
        eprintln!("arms_uid 写回失败(忽略): {}", e);
    }
}

pub(crate) fn ensure_profile_arms_uid(dir: &Path, meta: &mut Value, allow_live: bool) -> String {
    if let Some(u) = meta.get("arms_uid").and_then(|v| v.as_str()) {
        if !u.trim().is_empty() {
            return u.to_string();
        }
    }
    let mut taken: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if e.path().as_path() == dir {
                continue;
            }
            if let Ok(m) = read_json(&e.path().join("meta.json")) {
                if let Some(u) = m.get("arms_uid").and_then(|v| v.as_str()) {
                    taken.push(u.to_string());
                }
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

pub(crate) fn sync_provider_family_domain(provider: &str) {
    let p = v2_dir().join("setting.json");
    let mut s = match read_json(&p) {
        Ok(s) => s,
        Err(_) => return,
    };
    if formats::apply_provider_family_domain(
        &mut s,
        provider,
        chrono::Utc::now().timestamp_millis(),
    ) {
        let _ = write_json(&p, &s);
    }
}

pub(crate) fn telemetry_device_mid() -> String {
    read_json(&v2_dir().join("telemetry-state.json"))
        .ok()
        .and_then(|v| formats::read_device_mid(&v))
        .unwrap_or_default()
}

// 每账号虚拟设备标识（meta.json 的 device_mid）。非当前账号的 API 请求必须用它：
// 服务端按 账号×设备 校验，用错 deviceMid 会导致 preview 列表为空 / claim 被风控拒绝(3012)。
pub(crate) fn profile_device_mid(key: &str) -> Option<String> {
    if key == "__current__" {
        return Some(telemetry_device_mid());
    }
    read_json(&profiles_dir().join(key).join("meta.json"))
        .ok()?
        .get("device_mid")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn api_device_mid(key: &str) -> String {
    if key == "__current__" {
        let mut mid = telemetry_device_mid();
        if mid.trim().is_empty() {
            mid = uuid::Uuid::new_v4().to_string();
            write_live_device_mid(&mid);
        }
        return mid;
    }
    if let Some(mid) = profile_device_mid(key) {
        return mid;
    }
    // 非当前账号缺设备标识时生成并持久化；绝不回退到 live（那会与当前账号共享设备）
    let dir = profiles_dir().join(key);
    let mut meta = read_json(&dir.join("meta.json")).ok().unwrap_or(json!({}));
    let mid = ensure_profile_device_mid(&dir, &mut meta, false);
    let _ = write_json(&dir.join("meta.json"), &meta);
    mid
}

// 读取某账号的凭据快照（用于事件上报的 user_id）
pub(crate) fn cred_for_key(key: &str) -> Option<Value> {
    if key == "__current__" {
        read_json(&cred_path()).ok()
    } else {
        read_snapshot_value(&profiles_dir().join(key))
    }
}

pub(crate) fn get_jwt_token(key: &str) -> Result<String, String> {
    let creds = if key == "__current__" {
        read_json(&cred_path())?
    } else {
        read_snapshot_value(&profiles_dir().join(key)).ok_or("profile not found")?
    };
    let raw = creds
        .get(formats::FIELD_TOKEN)
        .and_then(|v| v.as_str())
        .ok_or("no jwt")?;
    if raw.starts_with(ENC_PREFIX) {
        decrypt_value(raw)
    } else {
        Ok(raw.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fingerprint_is_same_for_plain_and_encrypted_token() {
        let plain = json!({ formats::FIELD_TOKEN: "same-token-value" });
        let enc = json!({ formats::FIELD_TOKEN: encrypt_value("same-token-value") });
        assert_eq!(cred_fingerprint(&plain), cred_fingerprint(&enc));
        assert!(cred_fingerprint(&json!({})).is_none());
        assert!(cred_fingerprint(&json!({ formats::FIELD_TOKEN: "" })).is_none());
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
