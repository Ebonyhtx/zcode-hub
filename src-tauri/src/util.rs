use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::audit;
use crate::formats::{self, read_json, write_json, CRED_FILE};
use crate::history;

// 审计日志：只记不透明 key（哈希）与事件结果，best-effort（失败静默，不影响业务）
pub(crate) fn opaque_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"zcode-hub-audit:");
    h.update(key.as_bytes());
    let d = h.finalize();
    let hex: String = d.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    format!("k{}", hex)
}

pub(crate) fn is_opaque_key(s: &str) -> bool {
    s.len() == 17 && s.starts_with('k') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn is_hex16(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// 一次性迁移旧版本落盘的明文账号键（审计/福利/额度快照/历史文件名）到不透明哈希。
/// best-effort：任何一项失败都不影响启动。
pub(crate) fn migrate_privacy_keys() {
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

pub(crate) fn audit_log(event: &str, key: Option<&str>, detail: serde_json::Value) {
    let entry = json!({"ts": chrono::Utc::now().to_rfc3339(), "event": event,
        "key": key.map(opaque_key), "detail": detail});
    let _ = audit::audit_append(&audit::audit_path(&app_data_dir()), &entry);
}

// 账号标识只允许目录名用字符；阻断 ../、绝对路径等穿越（delete/switch/fetch 都是 key 拼路径）
pub(crate) fn safe_key(key: &str) -> Result<(), String> {
    if key == "__current__" { return Ok(()); }
    let ok = !key.is_empty()
        && !key.starts_with('.')
        && !key.contains('\\') && !key.contains('/') && !key.contains("..") && !key.contains(':')
        && key.chars().all(|c| c.is_alphanumeric() || "-_.@".contains(c));
    if ok { Ok(()) } else { Err("非法账号标识".into()) }
}

pub(crate) fn denied(e: String) -> serde_json::Value { json!({"ok": false, "error": e}) }

// 账号目录名清洗：白名单字符外全部替换为下划线（capture / OAuth 建档 / 导入共用）。
// 结果必须能通过 safe_key：连续点折叠、去掉首尾点、空值兜底、限长避免超长路径。
pub(crate) fn sanitize_label(s: &str) -> String {
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

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(p) = path.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
    let tmp = path.with_extension(format!("hub-tmp-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => { let _ = std::fs::remove_file(&tmp); Err(e.to_string()) }
    }
}

pub(crate) fn home_v2() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".zcode").join("v2")
}

// setting.json 的 dataBaseDir 若被用户改过，凭据等数据文件跟着走（setting.json 本身留在原处）
pub(crate) fn v2_dir() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let root = read_json(&home_v2().join("setting.json")).ok()
        .and_then(|v| formats::data_base_dir(&v))
        .map(PathBuf::from)
        .unwrap_or(base);
    root.join(".zcode").join("v2")
}

pub(crate) fn cred_path() -> PathBuf { v2_dir().join(CRED_FILE) }

// 标准应用数据目录：%APPDATA%\zcode-hub（换机器 / 无 D 盘也正常）
pub(crate) fn app_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".zcode-hub"))
        .join("zcode-hub")
}

pub(crate) fn profiles_dir() -> PathBuf { app_data_dir().join("profiles") }

// 旧版本把数据硬编码在 D:\zcode-hub；首次启动若新位置为空则整体迁入（不删旧文件）
pub(crate) fn migrate_legacy_data() {
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

pub(crate) fn cleanup_transient_files() {
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

pub(crate) fn copy_dir_all(src: &PathBuf, dst: PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let t = dst.join(e.file_name());
        if e.path().is_dir() { copy_dir_all(&e.path(), t)?; }
        else { std::fs::copy(e.path(), t)?; }
    }
    Ok(())
}

pub(crate) fn trash_dir() -> PathBuf { app_data_dir().join("trash") }

pub(crate) fn quota_cache_path() -> PathBuf { app_data_dir().join("quota-cache.json") }

pub(crate) fn benefits_file() -> PathBuf { app_data_dir().join("benefits.json") }

pub(crate) fn config_path() -> PathBuf { app_data_dir().join("hub-config.json") }

#[cfg(test)]
mod tests {
    use super::*;

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
    fn opaque_key_is_stable_and_does_not_leak_input() {
        let a = opaque_key("user@example.com");
        assert_eq!(a, opaque_key("user@example.com"));
        assert_ne!(a, opaque_key("other@example.com"));
        assert!(!a.contains("user") && !a.contains("example"));
        assert!(a.starts_with('k'));
    }

    #[test]
    fn privacy_key_format_helpers() {
        let k = opaque_key("user@example.com");
        assert!(is_opaque_key(&k));
        assert!(!is_opaque_key("user@example.com"));
        assert!(!is_opaque_key("k"));
        assert!(is_hex16("0123456789abcdef"));
        assert!(is_hex16("0123456789ABCDEF"));
        assert!(!is_hex16("0123456789abcde"));
        assert!(!is_hex16("0123456789abcdeg"));
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

}
