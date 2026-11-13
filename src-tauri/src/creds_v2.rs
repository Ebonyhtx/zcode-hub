//! `enc:v2:` 系统安全存储兼容层（ZCode 客户端 3.18.0 起）。
//!
//! 3.18.0 起客户端把 `credentials.json` 的字段加密从 `enc:v1:`（固定派生密钥）升级为
//! `enc:v2:<os|env>:<key-fingerprint>:<iv>.<tag>.<ct>`：随机 32 字节密钥保存在系统凭据库，
//! 文件只存密钥指纹 `sha256(key).hex[..24]`。Windows 上密钥条目由 `@napi-rs/keyring`
//! 写入 Credential Manager：
//! - service(target) = `ZCode Credential Encryption`
//! - account(UserName) = `sha256(凭据文件绝对路径).hex`
//! - 口令 = 43 字符 base64url（32 字节密钥），CredentialBlob 为 UTF-16LE
//!
//! Hub 只做**读取兼容**：解密仍按 AES-256-GCM（IV 12 / TAG 16 / 无 AAD，与 v1 同布局）。
//! 写入路径暂不变（继续写 `enc:v1:`，客户端读取时会自动迁移到 v2，见 DESIGN.md §5）。
//!
//! 密钥缓存是进程级的：成功与失败都保留到进程退出（与客户端一致——系统库拒绝授权后
//! 后台读取不应反复触发系统弹窗）。重启进程即可重试。

use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// 系统凭据库 service 名（与客户端 `systemCredentialCipher` 的 SYSTEM_SERVICE 一致）
#[cfg(windows)]
const SYSTEM_SERVICE: &str = "ZCode Credential Encryption";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V2Source {
    /// 系统凭据库（Windows Credential Manager）
    Os,
    /// 显式配置的 ZCODE_CREDENTIAL_SECRET(_FILE)
    Env,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V2Value {
    pub(crate) source: V2Source,
    /// 密钥指纹：sha256(key).hex[..24]
    pub(crate) fingerprint: String,
    /// IV.TAG.CT（base64url），与 v1 相同的 AES-GCM 布局
    pub(crate) payload: String,
}

/// 解析 `enc:v2:<os|env>:<fingerprint>:<iv>.<tag>.<ct>`；任何结构不符返回 None。
pub(crate) fn parse(value: &str) -> Option<V2Value> {
    let rest = value.strip_prefix("enc:v2:")?;
    let (source, rest) = rest.split_once(':')?;
    let source = match source {
        "os" => V2Source::Os,
        "env" => V2Source::Env,
        _ => return None,
    };
    let (fingerprint, payload) = rest.split_once(':')?;
    // 指纹固定 24 位小写 hex（客户端 KEY_FINGERPRINT_PATTERN）
    if fingerprint.len() != 24
        || !fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    if payload.is_empty() {
        return None;
    }
    Some(V2Value {
        source,
        fingerprint: fingerprint.to_string(),
        payload: payload.to_string(),
    })
}

/// 密钥指纹：sha256(key) 的 hex 前 24 位（与客户端 keyFingerprint 一致）。
pub(crate) fn fingerprint_of(key: &[u8; 32]) -> String {
    let d = Sha256::digest(key);
    d.iter().take(12).map(|b| format!("{:02x}", b)).collect()
}

/// 系统凭据库里的口令 → 32 字节密钥。
/// keyring 在 Windows 以 UTF-16LE 存口令；同时兼容按 UTF-8 写入的情形。
fn decode_key_password(blob: &[u8]) -> Option<[u8; 32]> {
    let b64 = |text: &str| -> Option<[u8; 32]> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text.trim())
            .ok()?
            .try_into()
            .ok()
    };
    if let Ok(text) = std::str::from_utf8(blob) {
        if text.chars().all(|c| c.is_ascii_graphic()) {
            if let Some(key) = b64(text) {
                return Some(key);
            }
        }
    }
    let units: Vec<u16> = blob
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16(&units).ok()?;
    b64(text.trim_end_matches('\0'))
}

#[cfg(windows)]
mod wincred {
    use windows_sys::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    /// 枚举本用户全部 generic 凭据的 (target, CredentialBlob)。
    /// 只读；调用方优先按 target 里的 service 名过滤，再用指纹精确匹配。
    pub(super) fn generic_blobs() -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut count: u32 = 0;
        let mut array: *mut *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: 标准 CredEnumerateW/CredFree 配对用法；filter 为 NULL 即枚举本用户条目。
        // 读取的是本机当前用户的凭据库，与客户端 @napi-rs/keyring 读取的是同一存储。
        unsafe {
            if CredEnumerateW(std::ptr::null(), 0, &mut count, &mut array) == 0 {
                return out;
            }
            for i in 0..count as usize {
                let entry = *array.add(i);
                if entry.is_null() {
                    continue;
                }
                let cred = &*entry;
                if cred.Type != CRED_TYPE_GENERIC {
                    continue;
                }
                // 口令是 43 字符 base64url：过滤明显无关/超长的条目
                if cred.CredentialBlobSize == 0 || cred.CredentialBlobSize > 512 {
                    continue;
                }
                if cred.CredentialBlob.is_null() {
                    continue;
                }
                let blob = std::slice::from_raw_parts(
                    cred.CredentialBlob,
                    cred.CredentialBlobSize as usize,
                );
                out.push((wide_to_string(cred.TargetName), blob.to_vec()));
            }
            CredFree(array as *const core::ffi::c_void);
        }
        out
    }

    /// CREDENTIALW 里的 PWSTR（UTF-16，NUL 结尾）→ String
    unsafe fn wide_to_string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// 口令 blob → 与指纹匹配的密钥
fn key_from_blob(blob: &[u8], fingerprint: &str) -> Option<[u8; 32]> {
    decode_key_password(blob).filter(|key| fingerprint_of(key) == fingerprint)
}

/// 系统凭据库密钥缓存：指纹 → 密钥（None 表示已确认不可用，保留到进程退出）。
static OS_KEY_CACHE: Mutex<Option<HashMap<String, Option<[u8; 32]>>>> = Mutex::new(None);

/// 按指纹从系统凭据库取 v2 密钥。找不到返回 None（并缓存失败，避免反复枚举）。
pub(crate) fn os_key(fingerprint: &str) -> Option<Zeroizing<[u8; 32]>> {
    {
        let g = OS_KEY_CACHE.lock().unwrap();
        if let Some(hit) = g.as_ref().and_then(|m| m.get(fingerprint)) {
            return hit.map(Zeroizing::new);
        }
    }
    #[cfg(windows)]
    let found: Option<[u8; 32]> = {
        let entries = wincred::generic_blobs();
        // 优先扫描 service 名匹配的条目（正常情况下只有一个 ZCode 密钥）；
        // 找不到再全量兜底一次，防 @napi-rs/keyring 未来改 target 命名
        entries
            .iter()
            .filter(|(target, _)| target.contains(SYSTEM_SERVICE))
            .find_map(|(_, blob)| key_from_blob(blob, fingerprint))
            .or_else(|| {
                entries
                    .iter()
                    .find_map(|(_, blob)| key_from_blob(blob, fingerprint))
            })
    };
    #[cfg(not(windows))]
    let found: Option<[u8; 32]> = None;
    let mut g = OS_KEY_CACHE.lock().unwrap();
    g.get_or_insert_with(HashMap::new)
        .insert(fingerprint.to_string(), found);
    found.map(Zeroizing::new)
}

/// 显式配置的 v2 密钥：`ZCODE_CREDENTIAL_SECRET` 或 `ZCODE_CREDENTIAL_SECRET_FILE`
/// （文件 32–4096 字节、按原字节读取不 trim；两者同时设置视为不可用，与客户端一致）。
/// 密钥 = sha256(secret 原文的 UTF-8 字节)，与客户端 `digest(secret)` 一致。
pub(crate) fn env_key() -> Option<Zeroizing<[u8; 32]>> {
    let value = std::env::var("ZCODE_CREDENTIAL_SECRET").ok();
    let file = std::env::var("ZCODE_CREDENTIAL_SECRET_FILE").ok();
    match (value, file) {
        (Some(_), Some(_)) => None,
        (Some(v), None) if !v.is_empty() => Some(crate::crypto::derive_key(&v)),
        (None, Some(path)) if !path.trim().is_empty() => {
            let bytes = std::fs::read(path.trim()).ok()?;
            if !(32..=4096).contains(&bytes.len()) {
                return None;
            }
            let text = String::from_utf8(bytes).ok()?;
            Some(crate::crypto::derive_key(&text))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_os_and_env_and_rejects_malformed() {
        let v = parse("enc:v2:os:66ed525b5a14d67f611de133:aa.bb.cc").expect("valid os");
        assert_eq!(v.source, V2Source::Os);
        assert_eq!(v.fingerprint, "66ed525b5a14d67f611de133");
        assert_eq!(v.payload, "aa.bb.cc");
        let v = parse("enc:v2:env:0123456789abcdef01234567:aa.bb.cc").expect("valid env");
        assert_eq!(v.source, V2Source::Env);
        // v1 / 未知来源 / 指纹长度或字符不符 / 缺载荷
        assert!(parse("enc:v1:aa.bb.cc").is_none());
        assert!(parse("enc:v2:xx:0123456789abcdef01234567:aa.bb.cc").is_none());
        assert!(parse("enc:v2:os:0123456789abcdef0123456:aa.bb.cc").is_none());
        assert!(parse("enc:v2:os:0123456789ABCDEF01234567:aa.bb.cc").is_none());
        assert!(parse("enc:v2:os:0123456789abcdef01234567:").is_none());
        assert!(parse("enc:v2:os").is_none());
        assert!(parse("plain text").is_none());
    }

    #[test]
    fn fingerprint_matches_client_algorithm() {
        // 客户端 keyFingerprint = sha256(key).hex.slice(0, 24)
        assert_eq!(fingerprint_of(&[1u8; 32]), "72cd6e8422c407fb6d098690");
        let mut key = [0u8; 32];
        key[0] = 1;
        assert_eq!(fingerprint_of(&key), "01d0fabd251fcbbe2b93b4b9");
    }

    #[test]
    fn decode_key_password_handles_utf16le_and_utf8() {
        let key = [7u8; 32];
        let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        assert_eq!(text.len(), 43);
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_key_password(&utf16), Some(key));
        assert_eq!(decode_key_password(text.as_bytes()), Some(key));
        // 不是 32 字节的 base64 或乱码 → None
        assert_eq!(decode_key_password(b"not-a-key"), None);
        assert_eq!(
            decode_key_password(b"YQ"),
            None, // "a" 的 base64url，只解出 1 字节
        );
    }

    #[test]
    fn os_key_negative_cache_is_stable() {
        // 不存在的指纹：首次枚举后缓存 None；二次调用同样返回 None 且不 panic
        let fp = "ffffffffffffffffffffffff";
        assert!(os_key(fp).is_none());
        assert!(os_key(fp).is_none());
    }
}
