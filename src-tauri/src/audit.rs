//! 本地审计日志（`audit.jsonl`，追加写 JSONL）。
//!
//! 隐私红线：只记 profile **key**（目录名），不记 label / 邮箱 / 令牌——
//! schema 上就不存在这些字段。文件仅存本机应用数据目录，best-effort 写入。
//! 超过 1MB 时保留最新一半（按行），避免无限增长。

use serde_json::Value;
use std::io::Write as _;
use std::path::{Path, PathBuf};

const AUDIT_FILE: &str = "audit.jsonl";
const AUDIT_MAX_BYTES: u64 = 1_000_000;

pub fn audit_path(app_data: &Path) -> PathBuf {
    app_data.join(AUDIT_FILE)
}

/// 单条落盘。`entry` 期望形如 `{"ts","event","key","detail"}`（见 tests 的 schema 断言）。
pub fn audit_append(path: &Path, entry: &Value) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    rotate_if_needed(path)?;
    let line = format!("{}\n", serde_json::to_string(entry).map_err(|e| e.to_string())?);
    std::fs::OpenOptions::new().create(true).append(true).open(path)
        .map_err(|e| e.to_string())?
        .write_all(line.as_bytes()).map_err(|e| e.to_string())
}

/// 超过阈值时原子地保留最新一半行。
pub fn rotate_if_needed(path: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::metadata(path) else { return Ok(()) };
    if meta.len() <= AUDIT_MAX_BYTES { return Ok(()); }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = content.lines().collect();
    let keep = &lines[lines.len() / 2..];
    let body = if keep.is_empty() { String::new() } else { format!("{}\n", keep.join("\n")) };
    let tmp = path.with_extension("hub-tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_log(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zhb-audit-{}-{}-{}", tag, std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_produces_jsonl_with_privacy_schema() {
        let d = tmp_log("append");
        let p = audit_path(&d);
        let entry = json!({"ts": "2026-11-01T00:00:00Z", "event": "switch", "key": "profile-a", "detail": {"mode": "cold"}});
        assert!(audit_append(&p, &entry).is_ok());
        assert!(audit_append(&p, &json!({"ts":"t2","event":"capture","key":"profile-b","detail":{}})).is_ok());
        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            let v: Value = serde_json::from_str(l).unwrap();
            let obj = v.as_object().unwrap();
            // schema 红线：只有这四个字段——label/邮箱/令牌没有落点
            assert_eq!(obj.len(), 4);
            for k in ["ts", "event", "key", "detail"] { assert!(obj.contains_key(k)); }
            assert!(obj.get("key").unwrap().as_str().unwrap().starts_with("profile-"));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rotate_keeps_newest_half_atomically() {
        let d = tmp_log("rotate");
        let p = audit_path(&d);
        // 600 行 × ~2.2KB ≈ 1.3MB，跨过 1MB 阈值触发轮转
        let filler = json!({"ts": "t", "event": "switch", "key": "k", "detail": {"pad": "x".repeat(2048)}});
        for _ in 0..600 { audit_append(&p, &filler).unwrap(); }
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.len() as u64 <= AUDIT_MAX_BYTES + 4096, "轮转后应显著缩小");
        assert!(after.lines().count() < 600);
        for l in after.lines() { serde_json::from_str::<Value>(l).unwrap(); } // 每行仍合法
        let _ = std::fs::remove_dir_all(&d);
    }
}
