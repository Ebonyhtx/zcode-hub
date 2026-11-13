use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

#[cfg(test)]
use serde_json::json;

#[cfg(test)]
use std::path::PathBuf;

use crate::formats::{read_json, CRED_FILE, ENC_PREFIX};
use crate::platform;
use crate::util::{app_data_dir, write_bytes_atomic};

// ---------------- 快照保护（DPAPI） ----------------
// 账号快照整包加密：随机密钥经 DPAPI 绑定当前 Windows 用户+机器。
// 快照文件被拷到别的机器/用户无法解密（区别于 ZCode 自身的可推导 fallback 方案）。
// DPAPI 调用在 platform.rs（平台抽象第 0 期）。
pub(crate) static SNAP_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

pub(crate) fn snap_key() -> Result<Vec<u8>, String> {
    snap_key_at(&app_data_dir().join("snapkey"), &SNAP_KEY)
}

/// 可注入路径/缓存的实现：单测用临时文件钉死「失败关闭、绝不覆盖」。
pub(crate) fn snap_key_at(f: &Path, cache: &Mutex<Option<Vec<u8>>>) -> Result<Vec<u8>, String> {
    let mut g = cache.lock().unwrap();
    if let Some(k) = g.as_ref() {
        return Ok(k.clone());
    }
    // 仅「文件不存在」才允许新建密钥。已存在但读/解失败必须硬失败——
    // 旧实现会生成新密钥覆盖原文件，等于让全部账号存档永久不可解。
    if !f.exists() {
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let enc = platform::dpapi_operate(&key, true)
            .map_err(|e| format!("无法创建快照主密钥（{}），本次操作已取消", e))?;
        write_bytes_atomic(f, encode_snap_key(&enc).as_bytes())
            .map_err(|e| format!("快照主密钥落盘失败（{}），本次操作已取消", e))?;
        *g = Some(key.clone());
        return Ok(key);
    }
    let txt = std::fs::read_to_string(f)
        .map_err(|e| format!("快照主密钥无法读取（{}）。为避免覆盖，已停止本次操作；请检查 %APPDATA%\\zcode-hub 权限", e))?;
    let enc = decode_snap_key(&txt)?;
    let key = platform::dpapi_operate(&enc, false)
        .map_err(|_| "快照主密钥无法用当前 Windows 用户解密（可能换了用户/机器，或被安全软件拦截）。已停止操作以免覆盖现有密钥")?;
    if key.len() != 32 {
        return Err(format!(
            "快照主密钥长度异常（{} 字节，应为 32）。已停止操作",
            key.len()
        ));
    }
    *g = Some(key.clone());
    Ok(key)
}

pub(crate) fn encode_snap_key(enc: &[u8]) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    format!("dpapi:{}", engine.encode(enc))
}

pub(crate) fn decode_snap_key(txt: &str) -> Result<Vec<u8>, String> {
    let b64 = txt
        .trim()
        .strip_prefix("dpapi:")
        .ok_or("快照主密钥格式异常（缺少 dpapi: 前缀）。已停止操作以免覆盖现有密钥")?;
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(b64)
        .map_err(|_| "快照主密钥损坏（base64 解码失败）。已停止操作以免覆盖现有密钥".into())
}

pub(crate) const SNAP_MAGIC: &str = "ZH-SNAP1:";

pub(crate) fn write_snapshot(dir: &Path, v: &Value) -> Result<(), String> {
    let key = snap_key()?;
    write_snapshot_with_key(dir, v, &key)
}

/// 可注入密钥的快照写入：单测固定密钥验证布局/原子写，不需要 DPAPI。
pub(crate) fn write_snapshot_with_key(dir: &Path, v: &Value, key: &[u8]) -> Result<(), String> {
    let plain = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plain.as_ref())
        .map_err(|e| e.to_string())?;
    let engine = base64::engine::general_purpose::STANDARD;
    let body = format!("{}{}.{}", SNAP_MAGIC, engine.encode(iv), engine.encode(ct));
    // 原子写：临时名带随机后缀，进程被杀也不会留下半截快照
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("credentials.hub-tmp-{}", rand::random::<u32>()));
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    match std::fs::rename(&tmp, dir.join("credentials.snap")) {
        Ok(()) => {
            let _ = std::fs::remove_file(dir.join(CRED_FILE));
            Ok(())
        } // 旧格式副本不再保留
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e.to_string())
        }
    }
}

/// 读取快照；区分「不存在」与「损坏/无法解密」，后者必须能显示给用户。
pub(crate) fn read_snapshot_checked(dir: &Path) -> Result<Value, String> {
    let snap = dir.join("credentials.snap");
    if snap.exists() {
        let key = snap_key()?;
        read_snapshot_with_key(dir, &key)
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

/// 只处理 DPAPI 快照文件（旧格式升级由 read_snapshot_checked 负责）。
pub(crate) fn read_snapshot_with_key(dir: &Path, key: &[u8]) -> Result<Value, String> {
    let snap = dir.join("credentials.snap");
    if !snap.exists() {
        return Err("存档不存在".into());
    }
    let txt = std::fs::read_to_string(&snap).map_err(|e| format!("存档读取失败: {}", e))?;
    let body = txt
        .trim()
        .strip_prefix(SNAP_MAGIC)
        .ok_or("存档格式异常（未知前缀）")?;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut it = body.split('.');
    let iv = engine
        .decode(it.next().ok_or("存档格式异常（缺 IV）")?)
        .map_err(|_| "存档格式异常（IV）")?;
    let ct = engine
        .decode(it.next().ok_or("存档格式异常（缺密文）")?)
        .map_err(|_| "存档格式异常（密文）")?;
    if iv.len() != 12 {
        return Err("存档格式异常（IV 长度不是 12）".into());
    }
    if ct.len() < 16 {
        return Err("存档格式异常（密文过短）".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), ct.as_ref())
        .map_err(|_| "存档无法解密（密钥不匹配或文件损坏）")?;
    serde_json::from_slice(&plain).map_err(|e| format!("存档 JSON 损坏: {}", e))
}

pub(crate) fn read_snapshot_value(dir: &Path) -> Option<Value> {
    read_snapshot_checked(dir).ok()
}

pub(crate) fn credential_secret() -> String {
    if let Ok(env) = std::env::var("ZCODE_CREDENTIAL_SECRET") {
        if !env.trim().is_empty() {
            return env.trim().to_string();
        }
    }
    let home = dirs::home_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let user = whoami::username().unwrap_or_default();
    format!("zcode-credential-fallback:win32:{}:{}", home, user)
}

// 瞬时派生密钥用 Zeroizing 包裹：作用结束即清零内存；SNAP_KEY 进程级缓存是有意为之（见 DESIGN.md）
pub(crate) fn derive_key(secret: &str) -> zeroize::Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    zeroize::Zeroizing::new(hasher.finalize().into())
}

// 可注入变体：契约测试 / 未来密钥迁移用；enc:v1 的 IV.TAG.CT 布局是铁律 #1，不可动
/// 生成 `iv.tag.ct`（base64url），不带前缀；v1/v2 共用同一 AES-GCM 布局。
pub(crate) fn seal_payload(key: &[u8; 32], plain: &str) -> Result<String, String> {
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plain.as_bytes())
        .map_err(|e| e.to_string())?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // 布局必须与 open_payload 一致：IV.TAG.CT（tag 在中段，密文在末段）
    Ok(format!(
        "{}.{}.{}",
        engine.encode(iv),
        engine.encode(&ct[ct.len() - 16..]),
        engine.encode(&ct[..ct.len() - 16])
    ))
}

/// 解开 `iv.tag.ct`（base64url），校验长度后 AES-GCM 解密；v1/v2 共用。
pub(crate) fn open_payload(key: &[u8; 32], payload: &str) -> Result<String, String> {
    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid format".into());
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let iv = engine.decode(parts[0]).map_err(|e| e.to_string())?;
    let tag = engine.decode(parts[1]).map_err(|e| e.to_string())?;
    let ct = engine.decode(parts[2]).map_err(|e| e.to_string())?;
    // 长度必须显式校验：GenericArray::from_slice 在长度不符时会 panic，
    // 而这里读的是本地文件（可能损坏/被改），不能让启动/刷新路径崩掉。
    if iv.len() != 12 {
        return Err("invalid iv length".into());
    }
    if tag.len() != 16 {
        return Err("invalid tag length".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&iv);
    let mut combined = ct;
    combined.extend_from_slice(&tag);
    let plain = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| e.to_string())?;
    String::from_utf8(plain).map_err(|e| e.to_string())
}

pub(crate) fn encrypt_with(key: &[u8; 32], plain: &str) -> Result<String, String> {
    Ok(format!("{}{}", ENC_PREFIX, seal_payload(key, plain)?))
}

pub(crate) fn decrypt_with(key: &[u8; 32], encrypted: &str) -> Result<String, String> {
    let payload = encrypted.strip_prefix(ENC_PREFIX).ok_or("not encrypted")?;
    open_payload(key, payload)
}

/// 可注入密钥来源的解密（测试用；生产走 [`decrypt_value`]）。
pub(crate) fn decrypt_value_with(
    encrypted: &str,
    key_for: &dyn Fn(&crate::creds_v2::V2Value) -> Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<String, String> {
    if let Some(v2) = crate::creds_v2::parse(encrypted) {
        // 指纹必须与密钥一致：防错密钥 / 错目录 / 伪造密文（v2 永不尝试弱派生密钥）
        let key = key_for(&v2).ok_or("v2 key unavailable")?;
        if crate::creds_v2::fingerprint_of(&key) != v2.fingerprint {
            return Err("v2 fingerprint mismatch".into());
        }
        return open_payload(&key, &v2.payload);
    }
    decrypt_with(&derive_key(&credential_secret()), encrypted)
}

pub(crate) fn decrypt_value(encrypted: &str) -> Result<String, String> {
    decrypt_value_with(encrypted, &|v2| match v2.source {
        crate::creds_v2::V2Source::Os => crate::creds_v2::os_key(&v2.fingerprint),
        crate::creds_v2::V2Source::Env => crate::creds_v2::env_key(),
    })
}

pub(crate) fn encrypt_value(plain: &str) -> String {
    encrypt_with(&derive_key(&credential_secret()), plain).expect("AES encrypt failed")
}

pub(crate) fn bundle_key(password: &str, salt: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, 120_000, &mut *out);
    out
}

/// 口令包加密：salt || iv || AES-GCM(ct||tag)，外层 "ZHB1:" + base64。
/// 抽成纯函数便于往返/口令错误/截断测试；随机数由调用方注入。
pub(crate) fn encode_bundle(
    bundle: &Value,
    password: &str,
    salt: &[u8; 16],
    iv: &[u8; 12],
) -> Result<String, String> {
    let plain = serde_json::to_vec(bundle).map_err(|e| e.to_string())?;
    let key = bundle_key(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(iv), plain.as_ref())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    raw.extend_from_slice(salt);
    raw.extend_from_slice(iv);
    raw.extend_from_slice(&ct);
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(format!("ZHB1:{}", engine.encode(raw)))
}

pub(crate) fn decode_bundle(raw: &str, password: &str) -> Result<Value, String> {
    let body = raw
        .trim()
        .strip_prefix("ZHB1:")
        .ok_or("不是 ZCode Hub 备份文件")?;
    let engine = base64::engine::general_purpose::STANDARD;
    let data = engine.decode(body.trim()).map_err(|_| "文件损坏")?;
    if data.len() < 28 + 16 {
        return Err("文件损坏".into());
    }
    let (salt, rest) = data.split_at(16);
    let (iv, ct) = rest.split_at(12);
    let key = bundle_key(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(iv), ct)
        .map_err(|_| "口令错误或文件损坏")?;
    serde_json::from_slice(&plain).map_err(|_| "文件损坏".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zhb-test-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

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
        assert!(engine.decode(parts[2]).unwrap().len() >= 3); // ciphertext
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
    fn bundle_kdf_deterministic_and_password_sensitive() {
        let salt = [7u8; 16];
        let a = bundle_key("password1", &salt);
        let b = bundle_key("password1", &salt);
        let c = bundle_key("password2", &salt);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn bundle_roundtrip_and_wrong_password() {
        let bundle = json!({"format": "zcode-hub-bundle", "version": 2,
                            "accounts": [{"label": "a", "credentials": {"zcodejwttoken": "t"}}]});
        let salt = [1u8; 16];
        let iv = [2u8; 12];
        let sealed = encode_bundle(&bundle, "pass123", &salt, &iv).unwrap();
        assert!(sealed.starts_with("ZHB1:"));
        assert_eq!(decode_bundle(&sealed, "pass123").unwrap(), bundle);
        assert!(decode_bundle(&sealed, "wrong-password").is_err());
        assert!(decode_bundle("ZHB1:AAAA", "pass123").is_err());
        assert!(decode_bundle("NOPE", "pass123").is_err());
        // 截断的密文应报错而不是 panic
        assert!(decode_bundle(&sealed[..sealed.len() - 8], "pass123").is_err());
    }

    #[test]
    fn snap_key_corrupt_file_is_never_overwritten() {
        // 已存在的密钥文件损坏时必须硬失败，绝不能生成新密钥覆盖（否则存档永久不可解）。
        let dir = temp_dir("snapkey-corrupt");
        let f = dir.join("snapkey");
        for bad in ["dpapi:!!!not-base64!!!", "not-dpapi:AAAA", ""] {
            std::fs::write(&f, bad).unwrap();
            let cache = std::sync::Mutex::new(None);
            assert!(snap_key_at(&f, &cache).is_err());
            assert_eq!(
                std::fs::read_to_string(&f).unwrap(),
                bad,
                "损坏的密钥文件不得被覆盖"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn snap_key_file_is_created_once_and_reused() {
        let dir = temp_dir("snapkey-create");
        let f = dir.join("snapkey");
        let cache = std::sync::Mutex::new(None);
        let k1 = snap_key_at(&f, &cache).expect("create");
        assert_eq!(k1.len(), 32);
        let raw = std::fs::read_to_string(&f).unwrap();
        assert!(raw.starts_with("dpapi:"));
        assert_eq!(snap_key_at(&f, &cache).unwrap(), k1);
        // 新进程（空缓存）也必须解出同一把密钥
        let cache2 = std::sync::Mutex::new(None);
        assert_eq!(snap_key_at(&f, &cache2).unwrap(), k1);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), raw);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_roundtrip_and_tamper_detection() {
        let dir = temp_dir("snapshot");
        let key = [9u8; 32];
        let v = json!({"zcodejwttoken": "t", "nested": {"中文": [1, 2]}});
        write_snapshot_with_key(&dir, &v, &key).unwrap();
        assert!(dir.join("credentials.snap").exists());
        assert!(!dir.join(CRED_FILE).exists(), "升级后不应保留明文凭据副本");
        assert_eq!(read_snapshot_with_key(&dir, &key).unwrap(), v);
        // 错误密钥必须失败，而不是返回空/垃圾
        assert!(read_snapshot_with_key(&dir, &[8u8; 32]).is_err());
        // 损坏的 IV/tag 长度不能 panic
        std::fs::write(
            dir.join("credentials.snap"),
            format!("{}AAAA.AAAA.AAAA", SNAP_MAGIC),
        )
        .unwrap();
        assert!(read_snapshot_with_key(&dir, &key).is_err());
        std::fs::remove_file(dir.join("credentials.snap")).unwrap();
        assert!(read_snapshot_with_key(&dir, &key).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_decrypt_routes_by_source_and_verifies_fingerprint() {
        let key = [9u8; 32];
        let fp = crate::creds_v2::fingerprint_of(&key);
        let payload = seal_payload(&key, "hello-v2").unwrap();
        let value = format!("enc:v2:os:{}:{}", fp, payload);
        let store = |_: &crate::creds_v2::V2Value| Some(zeroize::Zeroizing::new(key));
        assert_eq!(decrypt_value_with(&value, &store).unwrap(), "hello-v2");
        // env 来源同样可用（测试注入不区分来源，这里只验证路由与指纹）
        let env_value = format!("enc:v2:env:{}:{}", fp, payload);
        let env_store = |v: &crate::creds_v2::V2Value| {
            (v.source == crate::creds_v2::V2Source::Env).then_some(zeroize::Zeroizing::new(key))
        };
        assert_eq!(
            decrypt_value_with(&env_value, &env_store).unwrap(),
            "hello-v2"
        );
        // 密钥不可用（系统库拒绝/未登录）→ Err，调用方按「暂时不可读」处理
        let none = |_: &crate::creds_v2::V2Value| None;
        assert!(decrypt_value_with(&value, &none).is_err());
        // 指纹不匹配（错密钥/错目录/伪造）→ Err，绝不把猜测结果当明文
        let wrong = |_: &crate::creds_v2::V2Value| Some(zeroize::Zeroizing::new([8u8; 32]));
        assert!(decrypt_value_with(&value, &wrong).is_err());
        // 载荷被篡改 → GCM 认证失败
        let tampered = format!(
            "enc:v2:os:{}:{}.{}.{}",
            fp, "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA", "AAAA"
        );
        assert!(decrypt_value_with(&tampered, &store).is_err());
    }

    #[test]
    #[ignore] // 只在本机手动运行：读真实凭据文件做只读兼容探针
    fn probe_real_v2_credentials() {
        let path = dirs::home_dir()
            .expect("home")
            .join(".zcode/v2/credentials.json");
        let raw = std::fs::read_to_string(&path).expect("read live credentials");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        let mut ok = 0usize;
        let mut fail = 0usize;
        for (k, val) in v.as_object().expect("object") {
            if let Some(s) = val.as_str() {
                match decrypt_value(s) {
                    Ok(p) if !p.is_empty() => ok += 1,
                    Ok(_) => {
                        fail += 1;
                        println!("EMPTY {k}");
                    }
                    Err(e) => {
                        fail += 1;
                        println!("FAIL {k}: {e}");
                    }
                }
            }
        }
        println!("real credentials: ok={ok} fail={fail}");
        assert!(fail == 0, "some real fields failed to decrypt");
    }
}
