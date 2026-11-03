use serde_json::{json, Value};
use std::path::PathBuf;

use crate::benefits::{load_benefits_once, persist_benefits, BENEFITS};
use crate::crypto::{
    decode_bundle, decrypt_value, encode_bundle, encrypt_value, read_snapshot_checked,
    read_snapshot_value, write_snapshot,
};
use crate::formats::{self, read_json, write_json, CRED_FILE, ENC_PREFIX};
use crate::history;
use crate::identity::{
    cred_fingerprint, ensure_profile_arms_uid, ensure_profile_device_mid,
    find_profile_by_fingerprint, unique_profile_dir,
};
use crate::quota::{load_quota_cache_once, persist_quota_cache, QUOTA_CACHE};
use crate::util::{
    app_data_dir, audit_log, cred_path, denied, opaque_key, profiles_dir, safe_key, trash_dir,
};

pub(crate) fn cleanup_profile_caches(key: &str) {
    load_benefits_once();
    load_quota_cache_once();
    if let Some(map) = QUOTA_CACHE.lock().unwrap().as_mut() {
        map.remove(key);
    }
    if let Some(map) = BENEFITS.lock().unwrap().as_mut() {
        map.remove(key);
    }
    persist_benefits();
    persist_quota_cache();
    let hp = history::history_path(&app_data_dir(), key);
    let _ = std::fs::remove_file(hp);
    let legacy = app_data_dir()
        .join("quota-history")
        .join(format!("{}.jsonl", key));
    let _ = std::fs::remove_file(legacy);
}

#[tauri::command(async)]
pub(crate) fn delete_profile(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
    let d = profiles_dir().join(&key);
    if !d.exists() {
        return json!({"ok": false, "error": "账号不存在"});
    }
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
pub(crate) fn restore_profile(trash: String) -> serde_json::Value {
    let Some((key, _stamp)) = parse_trash_name(&trash) else {
        return denied("回收站标识无效".into());
    };
    let src = trash_dir().join(&trash);
    if !src.exists() {
        return json!({"ok": false, "error": "回收站中找不到该账号（可能已过期清理）"});
    };
    let dst = profiles_dir().join(key);
    if dst.exists() {
        return json!({"ok": false, "error": "同名账号已存在，无法撤销"});
    };
    match std::fs::rename(&src, &dst) {
        Ok(()) => {
            audit_log("restore", Some(key), json!({}));
            json!({"ok": true, "key": key})
        }
        Err(e) => json!({"ok": false, "error": format!("撤销失败: {}", e)}),
    }
}

/// 回收站名形如 <key>-<13位毫秒>；只允许安全字符，防止路径穿越。
pub(crate) fn parse_trash_name(trash: &str) -> Option<(&str, &str)> {
    let ok = !trash.is_empty()
        && !trash.starts_with('.')
        && !trash.contains('/')
        && !trash.contains('\\')
        && !trash.contains("..")
        && !trash.contains(':')
        && trash
            .chars()
            .all(|c| c.is_alphanumeric() || "-_.@".contains(c));
    if !ok {
        return None;
    }
    let (key, stamp) = trash.rsplit_once('-')?;
    if stamp.len() < 10 || !stamp.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if safe_key(key).is_err() {
        return None;
    }
    Some((key, stamp))
}

#[tauri::command(async)]
pub(crate) fn rename_profile(key: String, label: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
    let label = label.trim();
    if label.is_empty() {
        return json!({"ok": false, "error": "名称不能为空"});
    }
    if label.chars().count() > 80 {
        return json!({"ok": false, "error": "名称过长（最多 80 字）"});
    }
    let dir = profiles_dir().join(&key);
    if !dir.exists() {
        return json!({"ok": false, "error": "账号不存在"});
    }
    let mut meta = read_json(&dir.join("meta.json")).ok().unwrap_or(json!({}));
    meta["label"] = json!(label);
    if let Err(e) = write_json(&dir.join("meta.json"), &meta) {
        return json!({"ok": false, "error": format!("重命名失败: {}", e)});
    }
    audit_log("rename", Some(&key), json!({}));
    json!({"ok": true, "label": label})
}

/// 标签清洗：去空白、限长 16、最多 8 个、忽略大小写去重；空标签丢弃。
pub(crate) fn sanitize_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for t in tags {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        let t: String = t.chars().take(16).collect();
        let key = t.to_lowercase();
        if seen.insert(key) {
            out.push(t);
        }
        if out.len() >= 8 {
            break;
        }
    }
    out
}

#[tauri::command(async)]
pub(crate) fn set_profile_tags(key: String, tags: Vec<String>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
    let dir = profiles_dir().join(&key);
    if !dir.exists() {
        return json!({"ok": false, "error": "账号不存在"});
    }
    let tags = sanitize_tags(&tags);
    let mut meta = read_json(&dir.join("meta.json")).ok().unwrap_or(json!({}));
    meta["tags"] = json!(tags);
    if let Err(e) = write_json(&dir.join("meta.json"), &meta) {
        return json!({"ok": false, "error": format!("保存标签失败: {}", e)});
    }
    audit_log("tags", Some(&key), json!({"count": tags.len()}));
    json!({"ok": true, "tags": tags})
}

#[tauri::command(async)]
pub(crate) fn export_bundle(password: String) -> serde_json::Value {
    if password.chars().count() < 6 {
        return json!({"ok": false, "error": "口令至少 6 位"});
    }
    let mut accounts = Vec::new();
    let mut relogin = 0u64;
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            if let Some(mut creds) = read_snapshot_value(&e.path()) {
                if creds
                    .get(formats::FIELD_TOKEN)
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    let meta = read_json(&e.path().join("meta.json"))
                        .ok()
                        .unwrap_or(json!({}));
                    // v2：字段密文用本机密钥解开后放进口令加密的 bundle。目标机再加密，
                    // 解决换用户名/换机器后 enc:v1 解不开的问题（bundle 自身仍是 AES-GCM）。
                    let mut plain_fields: Vec<String> = Vec::new();
                    if let Some(obj) = creds.as_object_mut() {
                        for (k, v) in obj.iter_mut() {
                            if let Some(s) = v.as_str() {
                                if s.starts_with(ENC_PREFIX) {
                                    match decrypt_value(s) {
                                        Ok(plain) => {
                                            *v = json!(plain);
                                            plain_fields.push(k.clone());
                                        }
                                        Err(_) => {
                                            relogin += 1;
                                        }
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
                        "tags": meta.get("tags").cloned().unwrap_or(json!([])),
                        "credentials": creds,
                        "plain_fields": plain_fields,
                    }));
                }
            }
        }
    }
    if accounts.is_empty() {
        return json!({"ok": false, "error": "账号库为空"});
    }
    let bundle = json!({"format": "zcode-hub-bundle", "version": 2, "exported_at": chrono::Utc::now().to_rfc3339(), "accounts": accounts});
    let salt: [u8; 16] = rand::random();
    let iv: [u8; 12] = rand::random();
    let body = match encode_bundle(&bundle, &password, &salt, &iv) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let desktop = dirs::desktop_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    let fname = format!(
        "zcode-hub-backup-{}.zhb",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let out = desktop.join(&fname);
    if let Err(e) = std::fs::write(&out, body) {
        return json!({"ok": false, "error": e.to_string()});
    }
    audit_log(
        "export",
        None,
        json!({"accounts": accounts.len(), "relogin": relogin}),
    );
    json!({"ok": true, "path": out.display().to_string(), "accounts": accounts.len(), "needs_relogin": relogin})
}

#[tauri::command(async)]
pub(crate) fn import_bundle(path: String, password: String) -> serde_json::Value {
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => return json!({"ok": false, "error": format!("读取失败: {}", e)}),
    };
    let bundle = match decode_bundle(&raw, &password) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    if bundle.get("format").and_then(|v| v.as_str()) != Some("zcode-hub-bundle") {
        return json!({"ok": false, "error": "不是 ZCode Hub 备份文件"});
    }
    let version = bundle.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut added = 0u64;
    let mut skipped = 0u64;
    let mut relogin = 0u64;
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
            let has_jwt = creds
                .get(formats::FIELD_TOKEN)
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !has_jwt {
                skipped += 1;
                continue;
            }
            // 字段解不开（v1 跨机、或 v2 导出时本机也解不开）→ 仍导入，但标记需要重新登录
            let tok = creds
                .get(formats::FIELD_TOKEN)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if tok.starts_with(ENC_PREFIX) && decrypt_value(tok).is_err() {
                relogin += 1;
            }
            let label = a
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("imported")
                .to_string();
            let provider = a
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let (dir, _name, exists_same) = unique_profile_dir(&label, &creds);
            if exists_same {
                skipped += 1;
                continue;
            }
            if write_snapshot(&dir, &creds).is_err() {
                skipped += 1;
                continue;
            }
            let mut meta = json!({
                "label": label, "provider": provider,
                "captured_at": chrono::Utc::now().to_rfc3339(),
            });
            if let Some(mid) = a
                .get("device_mid")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                meta["device_mid"] = json!(mid);
            }
            if let Some(uid) = a
                .get("arms_uid")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                meta["arms_uid"] = json!(uid);
            }
            if let Some(tags) = a.get("tags").and_then(|v| v.as_array()) {
                let tags: Vec<String> = tags
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                meta["tags"] = json!(sanitize_tags(&tags));
            }
            if meta.get("device_mid").is_none() {
                ensure_profile_device_mid(&dir, &mut meta, false);
            }
            if meta.get("arms_uid").is_none() {
                ensure_profile_arms_uid(&dir, &mut meta, false);
            }
            let _ = write_json(&dir.join("meta.json"), &meta);
            added += 1;
        }
    }
    audit_log(
        "import",
        None,
        json!({"added": added, "skipped": skipped, "relogin": relogin}),
    );
    json!({"ok": true, "added": added, "skipped": skipped, "relogin": relogin})
}

/// 导入预览：只解密并检查，不写任何账号文件。
#[tauri::command(async)]
pub(crate) fn inspect_bundle(path: String, password: String) -> serde_json::Value {
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => return json!({"ok": false, "error": format!("读取失败: {}", e)}),
    };
    let bundle = match decode_bundle(&raw, &password) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    if bundle.get("format").and_then(|v| v.as_str()) != Some("zcode-hub-bundle") {
        return json!({"ok": false, "error": "不是 ZCode Hub 备份文件"});
    }
    let version = bundle.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut items = Vec::new();
    let (mut duplicates, mut relogin, mut invalid) = (0u64, 0u64, 0u64);
    if let Some(list) = bundle.get("accounts").and_then(|v| v.as_array()) {
        for a in list {
            let creds = a.get("credentials").cloned().unwrap_or(json!({}));
            let tok = creds
                .get(formats::FIELD_TOKEN)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let has_token = !tok.is_empty();
            if !has_token {
                invalid += 1;
            }
            let needs_relogin = tok.starts_with(ENC_PREFIX) && decrypt_value(tok).is_err();
            if needs_relogin {
                relogin += 1;
            }
            let duplicate = cred_fingerprint(&creds)
                .and_then(|fp| find_profile_by_fingerprint(&fp))
                .is_some();
            if duplicate {
                duplicates += 1;
            }
            items.push(json!({
                "label": a.get("label").and_then(|v| v.as_str()).unwrap_or("imported"),
                "provider": a.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
                "tags": a.get("tags").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
                "duplicate": duplicate,
                "needs_relogin": needs_relogin,
                "has_token": has_token,
                "has_device_mid": a.get("device_mid").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
                "has_arms_uid": a.get("arms_uid").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            }));
        }
    }
    json!({"ok": true, "version": version, "accounts": items, "count": items.len(),
           "duplicates": duplicates, "relogin": relogin, "invalid": invalid})
}

/// 用当前 live 凭据刷新某份存档（仅当它是当前登录账号时）。
///
/// 非当前账号没有可用的 live 状态——它的"最新"数据只能来自切换那一刻，
/// 所以这里明确拒绝而不是假装刷新。切换 A→B 时 A 的存档已被
/// `preserve_current_login` 刷新，这是非当前账号唯一的自愈路径。
#[tauri::command(async)]
pub(crate) fn refresh_profile(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
    let dir = profiles_dir().join(&key);
    if !dir.exists() {
        return json!({"ok": false, "error": "账号不存在"});
    }
    let live = match read_json(&cred_path()) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "当前没有可用的登录凭据，无法刷新存档"}),
    };
    let live_fp = match cred_fingerprint(&live) {
        Some(fp) => fp,
        None => return json!({"ok": false, "error": "当前登录凭据无法识别账号"}),
    };
    // 只有当前登录账号才能刷新：指纹不符说明这份存档属于别的账号
    let stored = read_snapshot_checked(&dir).ok();
    let stored_fp = stored.as_ref().and_then(cred_fingerprint);
    if stored_fp.as_deref() != Some(live_fp.as_str()) {
        return json!({"ok": false, "code": "not_current",
            "error": "只能刷新当前登录账号的存档；切换到此账号后会自动刷新"});
    }
    if let Err(e) = write_snapshot(&dir, &live) {
        return json!({"ok": false, "error": format!("刷新存档失败: {}", e)});
    }
    let mut meta = read_json(&dir.join("meta.json")).ok().unwrap_or(json!({}));
    crate::identity::stamp_snapshot_meta(&mut meta, &live);
    let _ = write_json(&dir.join("meta.json"), &meta);
    let fields = live.as_object().map(|o| o.len()).unwrap_or(0);
    audit_log("refresh", Some(&key), json!({"fields": fields}));
    json!({"ok": true, "key": key, "fields": fields})
}

pub(crate) fn known_profile_key_map() -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    m.insert(opaque_key("__current__"), "__current__".to_string());
    if let Ok(rd) = std::fs::read_dir(profiles_dir()) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let k = e.file_name().to_string_lossy().to_string();
            if safe_key(&k).is_ok() {
                m.insert(opaque_key(&k), k);
            }
        }
    }
    m
}

pub(crate) fn all_profile_keys() -> Vec<String> {
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
    if keys.is_empty() {
        keys.push("__current__".to_string());
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trash_name_blocks_traversal() {
        assert_eq!(
            parse_trash_name("user-1712345678901"),
            Some(("user", "1712345678901"))
        );
        // 账号名本身可以带连字符，时间戳取最后一段
        assert_eq!(
            parse_trash_name("autosave-20260101-120000-1712345678901")
                .unwrap()
                .0,
            "autosave-20260101-120000"
        );
        for bad in [
            "",
            "..",
            "../x-1712345678901",
            "a/b-1712345678901",
            "a\\b-1712345678901",
            ".hidden-1712345678901",
            "a:b-1712345678901",
            "user-123",
            "user-abcdefghij",
            "user-1712345678901 ",
            "-1712345678901",
        ] {
            assert!(parse_trash_name(bad).is_none(), "应拒绝: {:?}", bad);
        }
    }

    #[test]
    fn tags_are_trimmed_deduped_and_capped() {
        let input: Vec<String> = vec![
            "  工作  ".into(),
            "工作".into(),
            "Work".into(),
            "".into(),
            "a".repeat(40),
        ]
        .into_iter()
        .collect();
        let tags = sanitize_tags(&input);
        assert_eq!(tags[0], "工作");
        assert_eq!(tags[1], "Work");
        assert_eq!(tags[2].chars().count(), 16);
        assert_eq!(tags.len(), 3);
        let many: Vec<String> = (0..20).map(|i| format!("t{}", i)).collect();
        assert_eq!(sanitize_tags(&many).len(), 8);
    }
}
