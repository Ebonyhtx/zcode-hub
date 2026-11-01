//! ZCode 客户端内部文件格式（credentials.json / setting.json / telemetry-state.json /
//! rum-electron-store）的纯逻辑层 + Hub 的通用 JSON IO。
//!
//! 设计约束：
//! - 所有函数吃注入的 `&Value` / `&Path`，不读全局路径、不碰环境变量——契约测试用
//!   `tests/fixtures/*.json` 驱动，字段名改动会直接打破测试。
//! - `enc:v1:` 字段加密是 ZCode 客户端官方格式的一部分（asar oauthCredentialRepo），
//!   密钥派生公式与客户端保持一致，**不可改动**：改了客户端就读不懂 credentials.json，
//!   切换即坏。Hub 自有的整包快照加密（ZH-SNAP1）密钥经 DPAPI 绑定当前用户，
//!   与字段级加密互不干涉。详见 docs/DESIGN.md。

use base64::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

// --------------- credentials.json 官方键名（铁律 #3：键名与官方一致） ---------------

pub const CRED_FILE: &str = "credentials.json";
pub const FIELD_TOKEN: &str = "zcodejwttoken";
pub const FIELD_ACTIVE_PROVIDER: &str = "oauth:active_provider";
pub const FIELD_USER_INFO_KEYS: [&str; 2] = ["oauth:zai:user_info", "oauth:bigmodel:user_info"];
pub const PROVIDER_ZAI: &str = "zai";
pub const PROVIDER_BIGMODEL: &str = "bigmodel";
/// enc:v1 字段加密前缀（官方格式的一部分，不可改）
pub const ENC_PREFIX: &str = "enc:v1:";

pub fn oauth_field(provider: &str, kind: &str) -> String {
    format!("oauth:{}:{}", provider, kind)
}

/// 注入的解密闭包：enc:v1 密文 → 明文；解不开返回 None
pub type DecryptFn<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// 账号标签回退链：user_info(username/displayName/name/nickname/email) →
/// JWT claims(name/email/sub) → active_provider → 占位文案。
pub fn account_label_with(creds: &Value, decrypt: &DecryptFn) -> String {
    for uk in FIELD_USER_INFO_KEYS {
        if let Some(raw) = creds.get(uk).and_then(|v| v.as_str()) {
            if let Some(plain) = decrypt(raw) {
                if let Ok(info) = serde_json::from_str::<Value>(&plain) {
                    for k in ["username", "displayName", "name", "nickname", "email"] {
                        if let Some(v) = info.get(k).and_then(|v| v.as_str()) {
                            if !v.is_empty() { return v.to_string(); }
                        }
                    }
                }
            }
        }
    }
    if let Some(raw) = creds.get(FIELD_TOKEN).and_then(|v| v.as_str()) {
        if let Some(plain) = decrypt(raw) {
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
    match creds.get(FIELD_ACTIVE_PROVIDER).and_then(|v| v.as_str()) {
        Some(ap) if ap.starts_with(ENC_PREFIX) => "(已加密账号)".into(),
        Some(ap) => ap.to_string(),
        _ => "(未知)".into(),
    }
}

/// 从明文 JWT 载荷解析 exp（秒）；无 exp / 无法解码返回 None
pub fn jwt_payload_exp(jwt: &str) -> Option<i64> {
    let payload = jwt.split('.').nth(1)?;
    let mut padded = payload.trim_end_matches('=').to_string();
    while padded.len() % 4 != 0 { padded.push('='); }
    let bytes = base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes()).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("exp").and_then(|e| e.as_i64())
}

/// 本地解码判定令牌是否已过期（容忍 tolerance 秒时钟偏差）。
/// 兼容明文与 enc:v1 两种存法；无 token / 无 exp / 解不开一律返回 false（未过期）。
pub fn jwt_expired_with(creds: &Value, decrypt: &DecryptFn, now_ts: i64, tolerance_secs: i64) -> bool {
    let Some(raw) = creds.get(FIELD_TOKEN).and_then(|v| v.as_str()) else { return false };
    let jwt = if raw.starts_with(ENC_PREFIX) {
        match decrypt(raw) { Some(j) => j, None => return false }
    } else {
        raw.to_string()
    };
    match jwt_payload_exp(&jwt) {
        Some(exp) => exp <= now_ts + tolerance_secs,
        None => false,
    }
}

// --------------- setting.json ---------------

/// 同步 providerFamilyDomain；返回是否发生变更（契约：已相等时不重写时间戳）。
/// 仅接受 zai / bigmodel 两个家族。
pub fn apply_provider_family_domain(s: &mut Value, provider: &str, now_ms: i64) -> bool {
    if provider != PROVIDER_ZAI && provider != PROVIDER_BIGMODEL { return false; }
    if !s.is_object() { return false; }
    if s.get("providerFamilyDomain").and_then(|v| v.as_str()) == Some(provider) { return false; }
    s["providerFamilyDomain"] = json!(provider);
    s["providerFamilyDomainUpdatedAt"] = json!(now_ms);
    true
}

/// dataBaseDir 非空时凭据等数据文件迁往 `<dataBaseDir>/.zcode/v2`（setting.json 本身留在原处）。
pub fn data_base_dir(setting: &Value) -> Option<String> {
    setting.get("dataBaseDir").and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// --------------- telemetry-state.json ---------------

pub fn read_device_mid(v: &Value) -> Option<String> {
    v.get("deviceMid").and_then(|m| m.as_str()).map(String::from).filter(|m| !m.trim().is_empty())
}

/// 写入 deviceMid；返回是否变更（no-op 契约：相等时不写）。保留对象中其他键。
pub fn set_device_mid(v: &mut Value, mid: &str) -> bool {
    if !v.is_object() { *v = json!({}); }
    if v.get("deviceMid").and_then(|m| m.as_str()) == Some(mid) { return false; }
    v["deviceMid"] = json!(mid);
    true
}

// --------------- rum-electron-store / _arms_uid ---------------

pub const ARMS_DEFAULT_STORE_FILE: &str = "ZGVmYXVsdA.json";
pub const ARMS_UID_FIELD: &str = "_arms_uid";
pub const ARMS_SESSION_FIELD: &str = "_arms_session";

pub fn new_arms_uid() -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let suffix: String = (0..16).map(|_| ALPHABET[rand::random_range(0..36)] as char).collect();
    format!("uid_{}", suffix)
}

/// 依目录优先级（default 文件优先）读取第一个非空 _arms_uid。
pub fn read_arms_uid_in(dirs: &[PathBuf]) -> Option<String> {
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(d) {
            let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)).collect();
            files.sort_by_key(|p| !p.file_name().map(|n| n == ARMS_DEFAULT_STORE_FILE).unwrap_or(false));
            for f in files {
                if let Ok(v) = read_json(&f) {
                    if let Some(u) = v.get(ARMS_UID_FIELD).and_then(|u| u.as_str()) {
                        if !u.trim().is_empty() { return Some(u.to_string()); }
                    }
                }
            }
        }
    }
    None
}

/// 把 uid 写入目录组内所有 *.json（目录为空/不存在则创建 default 文件），
/// 同时移除 _arms_session（旧会话态）。尽力而为：返回首个写入错误，不中断其余文件。
pub fn write_arms_uid_in(dirs: &[PathBuf], uid: &str) -> Option<String> {
    let mut first_err: Option<String> = None;
    for d in dirs {
        let mut jsons: Vec<PathBuf> = std::fs::read_dir(d).map(|rd| rd.flatten().map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)).collect()).unwrap_or_default();
        if jsons.is_empty() {
            let _ = std::fs::create_dir_all(d);
            jsons.push(d.join(ARMS_DEFAULT_STORE_FILE));
        }
        for f in jsons {
            let mut v = read_json(&f).unwrap_or_else(|_| json!({}));
            if !v.is_object() { v = json!({}); }
            if v.get(ARMS_UID_FIELD).and_then(|u| u.as_str()) == Some(uid)
                && v.get(ARMS_SESSION_FIELD).is_none() { continue; }
            if let Some(obj) = v.as_object_mut() {
                obj.insert(ARMS_UID_FIELD.into(), json!(uid));
                obj.remove(ARMS_SESSION_FIELD);
                if let Err(e) = write_json(&f, &v) { first_err.get_or_insert(e); }
            }
        }
    }
    first_err
}

// --------------- 通用 JSON IO（原子写） ---------------

pub fn read_json(path: &Path) -> Result<Value, String> {
    let c = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&c).map_err(|e| e.to_string())
}

pub fn write_json(path: &Path, v: &Value) -> Result<(), String> {
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

// --------------- 契约测试（fixture 驱动，全部注入、不碰真实环境） ---------------

#[cfg(test)]
mod tests {
    use super::*;

    /// fixture 里 "PLAIN:x" 标记 → enc:v1:<b64url(x)>，模拟客户端真实写入形态
    fn enc_fixture(plain: &str) -> String {
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{}{}", ENC_PREFIX, e.encode(plain.as_bytes()))
    }
    fn materialize(v: &Value) -> Value {
        match v {
            Value::String(s) => match s.strip_prefix("PLAIN:") {
                Some(plain) => Value::String(enc_fixture(plain)),
                None => v.clone(),
            },
            Value::Array(a) => Value::Array(a.iter().map(materialize).collect()),
            Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), materialize(x))).collect()),
            other => other.clone(),
        }
    }
    /// 与 enc_fixture 对称的假解密（不涉及真实密钥）
    fn fake_decrypt(s: &str) -> Option<String> {
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        s.strip_prefix(ENC_PREFIX).and_then(|p| e.decode(p).ok())
            .and_then(|b| String::from_utf8(b).ok())
    }

    fn zai_creds() -> Value {
        materialize(&serde_json::from_str(include_str!("../tests/fixtures/credentials-zai.json")).unwrap())
    }
    fn expired_creds() -> Value {
        materialize(&serde_json::from_str(include_str!("../tests/fixtures/credentials-expired.json")).unwrap())
    }

    /// 字段名即契约：fixture 使用的键名集合变动必须显式过这道门
    #[test]
    fn fixture_field_names_are_the_contract() {
        let c = zai_creds();
        assert!(c.get(FIELD_TOKEN).is_some(), "zcodejwttoken 键名变动");
        assert!(c.get(FIELD_ACTIVE_PROVIDER).is_some(), "oauth:active_provider 键名变动");
        // fixture 是 zai 存档：user_info 键按 PROVIDER 拼接，zai 键必须在场
        assert!(c.get(FIELD_USER_INFO_KEYS[0]).is_some(), "oauth:zai:user_info 键名变动");
        assert!(FIELD_USER_INFO_KEYS.contains(&oauth_field(PROVIDER_BIGMODEL, "user_info").as_str()));
        assert!(c.get(oauth_field(PROVIDER_ZAI, "access_token")).is_some());
        assert!(c.get(oauth_field(PROVIDER_ZAI, "refresh_token")).is_some());
    }

    #[test]
    fn label_prefers_user_info_then_jwt_claims() {
        assert_eq!(account_label_with(&zai_creds(), &fake_decrypt), "demo-user");
        // 无 user_info 的存档：回退到 JWT claims
        assert_eq!(account_label_with(&expired_creds(), &fake_decrypt), "legacy-user");
    }

    #[test]
    fn label_falls_back_when_undecryptable() {
        let mut v = json!({});
        v[FIELD_ACTIVE_PROVIDER] = json!(enc_fixture("zai"));
        // 解密失败 → 加密占位
        assert_eq!(account_label_with(&v, &|_| None), "(已加密账号)");
        // 完全空结构 → 未知
        assert_eq!(account_label_with(&json!({}), &fake_decrypt), "(未知)");
    }

    fn b64url(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
    }
    fn make_jwt(claims: &str) -> String { format!("h.{}.s", b64url(claims)) }

    #[test]
    fn jwt_expired_handles_enc_plain_and_tolerance() {
        let now: i64 = 1_700_000_000;
        // enc 存法 + exp 在容忍窗口内 → 已过期
        let soon = json!({ FIELD_TOKEN: enc_fixture(&make_jwt(&format!("{{\"exp\":{}}}", now + 20))) });
        assert!(jwt_expired_with(&soon, &fake_decrypt, now, 30));
        // exp 在窗口外 → 未过期
        let fresh = json!({ FIELD_TOKEN: enc_fixture(&make_jwt(&format!("{{\"exp\":{}}}", now + 61))) });
        assert!(!jwt_expired_with(&fresh, &fake_decrypt, now, 30));
        // 明文存法（旧格式）同样可判
        let plain = json!({ FIELD_TOKEN: make_jwt("{\"exp\":9999999999}") });
        assert!(!jwt_expired_with(&plain, &fake_decrypt, now, 30));
        // 无 exp / 无 token / 解不开 → 未过期（不误报）
        let no_exp = json!({ FIELD_TOKEN: enc_fixture(&make_jwt("{\"sub\":\"x\"}")) });
        assert!(!jwt_expired_with(&no_exp, &fake_decrypt, now, 30));
        assert!(!jwt_expired_with(&json!({}), &fake_decrypt, now, 30));
        assert!(jwt_expired_with(&expired_creds(), &fake_decrypt, now, 30));
    }

    #[test]
    fn provider_family_domain_noop_and_update() {
        let fixture: Value = serde_json::from_str(include_str!("../tests/fixtures/setting-zai.json")).unwrap();
        let mut s = fixture.clone();
        // 已相等 → no-op，时间戳不动
        let before = s["providerFamilyDomainUpdatedAt"].clone();
        assert!(!apply_provider_family_domain(&mut s, PROVIDER_ZAI, 123));
        assert_eq!(s["providerFamilyDomainUpdatedAt"], before);
        // 换家族 → 双字段更新
        assert!(apply_provider_family_domain(&mut s, PROVIDER_BIGMODEL, 456));
        assert_eq!(s["providerFamilyDomain"], json!("bigmodel"));
        assert_eq!(s["providerFamilyDomainUpdatedAt"], json!(456));
        // 未知家族 → 拒绝
        assert!(!apply_provider_family_domain(&mut s, "openai", 789));
        // 非 object → 安全拒绝
        let mut bad = json!("string");
        assert!(!apply_provider_family_domain(&mut bad, PROVIDER_ZAI, 1));
    }

    #[test]
    fn data_base_dir_resolution() {
        let fixture: Value = serde_json::from_str(include_str!("../tests/fixtures/setting-zai.json")).unwrap();
        assert_eq!(data_base_dir(&fixture), Some("D:/demo/zcode-data".to_string()));
        let empty = json!({"dataBaseDir": "  "});
        assert_eq!(data_base_dir(&empty), None);
        assert_eq!(data_base_dir(&json!({})), None);
    }

    #[test]
    fn device_mid_set_preserves_other_keys() {
        let mut v: Value = serde_json::from_str(include_str!("../tests/fixtures/telemetry-state.json")).unwrap();
        assert!(set_device_mid(&mut v, "mid-demo-0002"));
        assert_eq!(v["deviceMid"], json!("mid-demo-0002"));
        assert_eq!(v["someOtherKey"], json!("kept")); // 无关键保全契约
        assert!(!set_device_mid(&mut v, "mid-demo-0002")); // no-op
        let mut junk = json!("not-an-object");
        assert!(set_device_mid(&mut junk, "m1")); // 非 object 安全重建
        assert_eq!(junk["deviceMid"], json!("m1"));
        assert_eq!(read_device_mid(&v), Some("mid-demo-0002".into()));
    }

    #[test]
    fn arms_uid_roundtrip_and_session_clear() {
        let base = std::env::temp_dir().join(format!("zhb-fmt-arms-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        let d1 = base.join("ZCode").join("rum-electron-store");
        let d2 = base.join("ZCode Preview").join("rum-electron-store");
        let _ = std::fs::remove_dir_all(&base);
        // 空目录：自动建 default 文件
        assert!(write_arms_uid_in(&[d1.clone(), d2.clone()], "uid_demo").is_none());
        assert_eq!(read_arms_uid_in(&[d1.clone(), d2.clone()]), Some("uid_demo".into()));
        let default: Value = serde_json::from_str(&std::fs::read_to_string(d1.join(ARMS_DEFAULT_STORE_FILE)).unwrap()).unwrap();
        assert_eq!(default[ARMS_UID_FIELD], json!("uid_demo"));
        assert!(default.get(ARMS_SESSION_FIELD).is_none(), "_arms_session 必须被清除");
        // 第二个目录同样写入；无关键保全
        let other: Value = serde_json::from_str(&std::fs::read_to_string(d2.join(ARMS_DEFAULT_STORE_FILE)).unwrap()).unwrap();
        assert_eq!(other[ARMS_UID_FIELD], json!("uid_demo"));
        // 已含其他键的文件：写 uid 时保全
        let f2 = d1.join("second.json");
        let _ = write_json(&f2, &json!({"keep": 1}));
        assert!(write_arms_uid_in(std::slice::from_ref(&d1), "uid_demo2").is_none());
        let second: Value = serde_json::from_str(&std::fs::read_to_string(&f2).unwrap()).unwrap();
        assert_eq!(second["keep"], json!(1));
        assert_eq!(second[ARMS_UID_FIELD], json!("uid_demo2"));
        // default 文件优先命中
        assert_eq!(read_arms_uid_in(std::slice::from_ref(&d1)), Some("uid_demo2".into()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn write_json_atomic_no_residue() {
        let dir = std::env::temp_dir().join(format!("zhb-fmt-io-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("nested").join("x.json");
        assert!(write_json(&p, &json!({"a": 1})).is_ok());
        assert_eq!(read_json(&p).unwrap()["a"], json!(1));
        assert!(!dir.join("nested").join("x.hub-tmp").exists(), "原子写不得残留临时文件");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
