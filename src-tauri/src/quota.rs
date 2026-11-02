use serde_json::{json, Value};
use std::sync::Mutex;

use crate::benefits::zcode_api_headers;
use crate::client::{client_app_version, http};
use crate::formats::{read_json, write_json};
use crate::history;
use crate::identity::{api_device_mid, get_jwt_token};
use crate::profiles::known_profile_key_map;
use crate::util::{app_data_dir, denied, is_opaque_key, opaque_key, quota_cache_path, safe_key};

/// HTTP 层失败 → 统一错误对象（auth/rate/server），纯函数便于钉死分类。
pub(crate) fn quota_status_error(status: u16, retry_after: Option<u64>, now: i64) -> Value {
    if status == 401 || status == 403 {
        json!({"ok": false, "code": "auth", "error": "登录已过期，请重新登录该账号", "fetched_at": now})
    } else if status == 429 {
        let retry = retry_after.unwrap_or(60);
        json!({"ok": false, "code": "rate", "transient": true, "retry_after": retry,
               "error": format!("请求过于频繁，{} 秒后自动重试", retry), "fetched_at": now})
    } else {
        json!({"ok": false, "code": "server", "transient": true,
               "error": format!("服务端暂时不可用（HTTP {}）", status), "fetched_at": now})
    }
}

/// 业务 code 失败 → 错误对象；5xx/429 视为可重试，其余为业务错误。
pub(crate) fn quota_business_error(code: i64, msg: &str, now: i64) -> Value {
    let msg = if msg.trim().is_empty() { "额度接口返回错误" } else { msg };
    let transient = code == 429 || (500..=599).contains(&code);
    json!({"ok": false, "code": if transient { "server" } else { "business" },
           "transient": transient, "error": msg, "fetched_at": now})
}

/// 成功响应缓存 90s、失败 20s，避免同一时刻反复打接口。
pub(crate) fn quota_cache_ttl(ok: bool) -> i64 { if ok { 90 } else { 20 } }

#[tauri::command(async)]
pub(crate) fn fetch_quota(key: String, force: Option<bool>) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    load_quota_cache_once();
    let now = chrono::Utc::now().timestamp();
    if !force.unwrap_or(false) {
        if let Some(map) = QUOTA_CACHE.lock().unwrap().as_ref() {
            if let Some((ts, v)) = map.get(&key) {
                let ok = v.get("ok").and_then(|x| x.as_bool()) == Some(true);
                if now - ts < quota_cache_ttl(ok) {
                    let mut hit = v.clone();
                    hit["cached"] = json!(true);
                    return hit;
                }
            }
        }
    }
    let token = match get_jwt_token(&key) { Ok(t) => t, Err(e) => return json!({"ok": false, "code": "auth", "error": e}) };
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
            if !status.is_success() {
                let retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                quota_status_error(status.as_u16(), retry_after, now)
            } else {
                match r.json::<Value>() {
                    Ok(j) => {
                        let code = j.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                        if code != 0 {
                            let msg = j.get("msg").and_then(|m| m.as_str()).unwrap_or("");
                            quota_business_error(code, msg, now)
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
pub(crate) fn quota_history(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) { return denied(e); }
    let samples = history::load_history_cached(&history::ensure_history_path(&app_data_dir(), &key));
    let forecast = history::forecast(&samples);
    json!({"ok": true, "samples": samples.len(), "points": samples, "forecast": forecast})
}

pub(crate) fn load_quota_cache_once() {
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

pub(crate) fn persist_quota_cache() {
    let map = QUOTA_CACHE.lock().unwrap().clone().unwrap_or_default();
    let mut obj = serde_json::Map::new();
    for (k, (ts, resp)) in map { obj.insert(opaque_key(&k), json!({"ts": ts, "resp": resp})); }
    let _ = write_json(&quota_cache_path(), &Value::Object(obj));
}

pub(crate) static QUOTA_CACHE: Mutex<Option<std::collections::HashMap<String, (i64, Value)>>> = Mutex::new(None);



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_status_mapping_is_stable() {
        let now = 100;
        assert_eq!(quota_status_error(401, None, now)["code"], json!("auth"));
        assert_eq!(quota_status_error(403, None, now)["code"], json!("auth"));
        let r = quota_status_error(429, Some(7), now);
        assert_eq!(r["code"], json!("rate"));
        assert_eq!(r["retry_after"], json!(7));
        assert_eq!(r["transient"], json!(true));
        assert_eq!(quota_status_error(429, None, now)["retry_after"], json!(60));
        let s = quota_status_error(503, None, now);
        assert_eq!(s["code"], json!("server"));
        assert_eq!(s["transient"], json!(true));
        assert!(s["error"].as_str().unwrap().contains("503"));
        assert_eq!(s["fetched_at"], json!(now));
    }

    #[test]
    fn quota_business_mapping_marks_retryable_codes() {
        let b = quota_business_error(1001, "nope", 5);
        assert_eq!(b["code"], json!("business"));
        assert_eq!(b["transient"], json!(false));
        let s = quota_business_error(502, "", 5);
        assert_eq!(s["code"], json!("server"));
        assert_eq!(s["transient"], json!(true));
        assert_eq!(s["error"], json!("额度接口返回错误"));
        assert_eq!(quota_business_error(429, "slow", 5)["code"], json!("server"));
        assert_eq!(quota_cache_ttl(true), 90);
        assert_eq!(quota_cache_ttl(false), 20);
    }

}
