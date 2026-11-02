//! 本地额度历史（`quota-history/<hash>.jsonl`）与燃尽率预测。
//!
//! 隐私：只含额度数字与套餐/模型标识；文件名是账号 key 的 SHA-256 前 16 位，
//! 不把邮箱/昵称写进文件名。采样节流：同账号 10 分钟内不重复记录。
//! 存储：正常路径为纯追加（O(1)），仅当文件超过 2MB 或距上次样本超过 30 天时
//! 才做一次裁剪重写。预测口径：线性外推首尾样本。

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const SAMPLE_MIN_GAP_SECS: i64 = 600;
pub const RETENTION_SECS: i64 = 30 * 86400;
/// 预测所需最短观察窗口（小时）——短于此值噪声过大
pub const MIN_WINDOW_HOURS: f64 = 2.0;
/// 超过该体积才做全量裁剪，避免每次采样都重写文件
const COMPACT_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// 账号 key → 不透明文件名（不可逆，避免邮箱/昵称落进文件系统）
pub fn key_hash(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"zcode-hub-history:");
    h.update(key.as_bytes());
    let d = h.finalize();
    d.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

fn legacy_name(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.@".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn history_path(app_data: &Path, key: &str) -> PathBuf {
    app_data
        .join("quota-history")
        .join(format!("{}.jsonl", key_hash(key)))
}

/// 兼容旧版本以账号 key 直接命名的历史文件：首次访问时改名为哈希名。
pub fn ensure_history_path(app_data: &Path, key: &str) -> PathBuf {
    let p = history_path(app_data, key);
    if !p.exists() {
        let legacy = app_data
            .join("quota-history")
            .join(format!("{}.jsonl", legacy_name(key)));
        if legacy.exists() && legacy != p {
            let _ = std::fs::rename(&legacy, &p);
        }
    }
    p
}

/// 从 fetch_quota 的成功响应里提取最小化样本；无 balances 返回 None（错误响应不入库）
pub fn sample_from_quota(resp: &Value, now: i64) -> Option<Value> {
    let balances = resp.get("data")?.get("data")?.get("balances")?.as_array()?;
    let mut out = Vec::new();
    for b in balances {
        let plan_id = b
            .get("plan_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let model = b
            .get("show_name")
            .and_then(|v| v.as_str())
            .or_else(|| b.get("model").and_then(|v| v.as_str()))
            .unwrap_or("?")
            .to_string();
        let available = b
            .get("available_units")
            .and_then(|v| v.as_f64())
            .or_else(|| b.get("remaining_units").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
        let total = b.get("total_units").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let expires_at = b
            .get("expires_at")
            .and_then(|v| v.as_i64())
            .or_else(|| b.get("period_end").and_then(|v| v.as_i64()));
        out.push(json!({"plan_id": plan_id, "model": model, "available": available, "total": total, "expires_at": expires_at}));
    }
    if out.is_empty() {
        None
    } else {
        Some(json!({"ts": now, "balances": out}))
    }
}

/// 逐行解析历史；坏行容忍跳过
pub fn load_history(path: &Path) -> Vec<(i64, Value)> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|l| {
            let v: Value = serde_json::from_str(l).ok()?;
            let ts = v.get("ts")?.as_i64()?;
            Some((ts, v))
        })
        .collect()
}

type HistoryRows = Vec<(i64, Value)>;
type HistoryCacheEntry = (u64, u64, HistoryRows);

/// 历史解析缓存：mtime + size 不变时直接复用，避免每次刷新全量解析。
/// 纯内存、进程内；文件被追加/裁剪后 mtime 变化会自动失效。
static HISTORY_CACHE: Mutex<Option<HashMap<PathBuf, HistoryCacheEntry>>> = Mutex::new(None);

pub fn load_history_cached(path: &Path) -> Vec<(i64, Value)> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let len = meta.len();
    {
        let mut g = HISTORY_CACHE.lock().unwrap();
        let cache = g.get_or_insert_with(HashMap::new);
        if let Some((m, l, rows)) = cache.get(path) {
            if *m == mtime && *l == len {
                return rows.clone();
            }
        }
    }
    let rows = load_history(path);
    HISTORY_CACHE
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(path.to_path_buf(), (mtime, len, rows.clone()));
    rows
}

/// 只读文件尾部最后一条合法样本的 ts（避免每次采样都全量解析）
fn last_sample_ts(path: &Path) -> Option<i64> {
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(8192);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).ok()?;
    buf.lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l).ok()?.get("ts")?.as_i64())
}

fn atomic_write(path: &Path, body: &str) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension(format!(
        "hub-tmp-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e.to_string())
        }
    }
}

/// 追加样本：尾部节流；仅在体积/保留期需要时裁剪。返回是否真正写入。
pub fn append_sample(path: &Path, sample: &Value, now: i64) -> Result<bool, String> {
    if sample.get("ts").and_then(|v| v.as_i64()) != Some(now) {
        return Err("sample ts mismatch".into());
    }
    let last = last_sample_ts(path);
    if let Some(last_ts) = last {
        if now - last_ts < SAMPLE_MIN_GAP_SECS {
            return Ok(false);
        }
    }
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let need_compact =
        size > COMPACT_MAX_BYTES || last.map(|t| now - t > RETENTION_SECS).unwrap_or(false);
    let line = format!(
        "{}\n",
        serde_json::to_string(sample).map_err(|e| e.to_string())?
    );
    if need_compact {
        let mut body = String::new();
        for (_, v) in load_history(path)
            .iter()
            .filter(|(ts, _)| now - ts <= RETENTION_SECS)
        {
            body += &format!("{}\n", v);
        }
        body += &line;
        atomic_write(path, &body)?;
        return Ok(true);
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(true)
}

/// 燃尽率预测：按 (plan_id, model) 分组线性外推。返回 `[{plan_id, model, days_left}]`。
/// 消耗中（速率 < 0）且剩余 > 0 才预测；回填期/未消耗/窗口过短不预测。
pub fn forecast(samples: &[(i64, Value)]) -> Vec<Value> {
    let mut groups: HashMap<(String, String), Vec<(i64, f64)>> = HashMap::new();
    for (ts, s) in samples {
        if let Some(balances) = s.get("balances").and_then(|v| v.as_array()) {
            for b in balances {
                let plan_id = b
                    .get("plan_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let model = b
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                let avail = b.get("available").and_then(|v| v.as_f64()).unwrap_or(0.0);
                groups
                    .entry((plan_id, model))
                    .or_default()
                    .push((*ts, avail));
            }
        }
    }
    let mut out = Vec::new();
    for ((plan_id, model), mut pts) in groups {
        pts.sort_by_key(|(ts, _)| *ts);
        if pts.len() < 2 {
            continue;
        }
        let (t0, a0) = pts[0];
        let (t1, a1) = *pts.last().unwrap();
        let hours = (t1 - t0) as f64 / 3600.0;
        if hours < MIN_WINDOW_HOURS {
            continue;
        }
        let rate_per_day = (a1 - a0) / hours * 24.0;
        if rate_per_day >= -1e-9 || a1 <= 0.0 {
            continue;
        }
        let days = a1 / -rate_per_day;
        if days > 3650.0 {
            continue;
        } // 消耗极慢，无提醒价值
        out.push(
            json!({"plan_id": plan_id, "model": model, "days_left": (days * 10.0).round() / 10.0}),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota_response(balances: Value) -> Value {
        json!({"ok": true, "data": {"data": {"balances": balances}}})
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zhb-hist-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn sample_extracts_minimal_fields_with_fallbacks() {
        let r = quota_response(json!([
            {"plan_id": "p1", "show_name": "glm-5.3-flash", "available_units": 816000.0, "total_units": 1200000.0, "expires_at": 123},
            {"plan_id": "p1", "model": "glm-5.3", "remaining_units": 5.0, "total_units": 10.0}
        ]));
        let s = sample_from_quota(&r, 1000).unwrap();
        assert_eq!(s["ts"], json!(1000));
        let b = s["balances"].as_array().unwrap();
        assert_eq!(b[0]["model"], json!("glm-5.3-flash"));
        assert_eq!(b[0]["available"], json!(816000.0));
        assert_eq!(b[1]["available"], json!(5.0), "remaining_units 回退");
        // 空 balances → None（不入库）
        assert!(sample_from_quota(&quota_response(json!([])), 1000).is_none());
        assert!(sample_from_quota(&json!({"ok": false, "error": "x"}), 1000).is_none());
    }

    #[test]
    fn append_throttles_and_prunes() {
        let dir = tmp_dir("append");
        let p = history_path(&dir, "user@example.com");
        let mk = |ts: i64| json!({"ts": ts, "balances": [{"plan_id": "p", "model": "m", "available": 1.0, "total": 2.0, "expires_at": null}]});
        assert!(append_sample(&p, &mk(1000), 1000).unwrap());
        assert!(!append_sample(&p, &mk(1001), 1001).unwrap()); // 间隔不足 → 跳过
        assert_eq!(load_history(&p).len(), 1);
        assert!(append_sample(
            &p,
            &mk(1000 + SAMPLE_MIN_GAP_SECS),
            1000 + SAMPLE_MIN_GAP_SECS
        )
        .unwrap());
        assert_eq!(load_history(&p).len(), 2);
        // 老样本被裁剪：写入 31 天后的样本，只有 30 天内的留下
        append_sample(
            &p,
            &mk(1000 + RETENTION_SECS + 86400),
            1000 + RETENTION_SECS + 86400,
        )
        .unwrap();
        let kept = load_history(&p);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, 1000 + RETENTION_SECS + 86400);
        // 文件名不含邮箱
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(!name.contains("user"), "历史文件名必须脱敏: {}", name);
        assert!(!name.contains("example.com"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cached_history_invalidates_after_append() {
        let dir = tmp_dir("cache");
        let p = history_path(&dir, "k");
        let mk = |ts: i64| json!({"ts": ts, "balances": [{"plan_id": "p", "model": "m", "available": 1.0, "total": 2.0}]});
        append_sample(&p, &mk(1000), 1000).unwrap();
        assert_eq!(load_history_cached(&p).len(), 1);
        append_sample(
            &p,
            &mk(1000 + SAMPLE_MIN_GAP_SECS),
            1000 + SAMPLE_MIN_GAP_SECS,
        )
        .unwrap();
        assert_eq!(
            load_history_cached(&p).len(),
            2,
            "file size 变化后缓存必须失效"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_history_is_migrated() {
        let dir = tmp_dir("legacy");
        let legacy = dir.join("quota-history").join("user@example.com.jsonl");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "{\"ts\":1000,\"balances\":[]}\n").unwrap();
        let p = ensure_history_path(&dir, "user@example.com");
        assert!(p.exists());
        assert!(!legacy.exists());
        assert_eq!(load_history(&p).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forecast_linear_and_guards() {
        let mk = |ts: i64, consuming: f64, refilling: f64| {
            (
                ts,
                json!({"ts": ts, "balances": [
                    {"plan_id": "p", "model": "consuming", "available": consuming, "total": 100.0, "expires_at": null},
                    {"plan_id": "p", "model": "refilling", "available": refilling, "total": 100.0, "expires_at": null}
                ]}),
            )
        };
        // 24 小时窗口：consuming 80 → 40，速率 -40/天 → 还剩 1 天；refilling 递增 → 跳过
        let samples = vec![mk(0, 80.0, 20.0), mk(86400, 40.0, 90.0)];
        let f = forecast(&samples);
        assert_eq!(f.len(), 1, "refilling 组速率 ≥ 0 必须跳过: {:?}", f);
        assert_eq!(f[0]["plan_id"], json!("p"));
        assert_eq!(f[0]["model"], json!("consuming"));
        assert_eq!(f[0]["days_left"], json!(1.0));
        // 窗口 < 2h → 不预测
        let short = vec![mk(0, 80.0, 20.0), mk(3600, 40.0, 25.0)];
        assert!(forecast(&short).is_empty());
        // 只有一个样本 → 不预测
        assert!(forecast(&[mk(0, 80.0, 20.0)]).is_empty());
        // 已耗尽 → 不预测
        let empty = vec![mk(0, 80.0, 20.0), mk(8 * 3600, 0.0, 90.0)];
        assert!(forecast(&empty).is_empty());
    }
}
