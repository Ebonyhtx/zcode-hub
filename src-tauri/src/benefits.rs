use serde_json::{json, Value};
use std::sync::Mutex;

use crate::app::update_tray_tooltip;
use crate::audit;
use crate::claim;
use crate::client::{client_app_version, http};
use crate::crypto::decrypt_value;
use crate::formats::{read_json, write_json};
use crate::identity::{api_device_mid, cred_for_key, get_jwt_token};
use crate::platform;
use crate::profiles::{all_profile_keys, known_profile_key_map};
use crate::quota::{persist_quota_cache, QUOTA_CACHE};
use crate::util::{app_data_dir, audit_log, benefits_file, denied, is_opaque_key, opaque_key,
                  safe_key};

// 官方 preview 响应 → 福利条目（纯函数，可单测）
pub(crate) fn campaigns_from_plans(plans: &[Value]) -> Vec<Value> {
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
pub(crate) fn parse_preview_plans(j: &Value) -> Vec<Value> {
    let plans = j.pointer("/data/plans").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    campaigns_from_plans(&plans)
}

// 官方「可领取预览」：GET /api/v1/zcode-plan/billing/preview —— 客户端领取弹窗同源接口，
// 返回 data.plans[]（每个含 plan_id/name/entitlements[grant_units]）。空数组 = 当前无可领。
// 注意：429 限流存在，批量检测时逐账号间加间隔。
// 与客户端一致的请求头（UA / X-Title / X-Platform 等）；服务端按客户端上下文做路由与风控
pub(crate) fn zcode_api_headers(rb: reqwest::blocking::RequestBuilder, ver: &str) -> reqwest::blocking::RequestBuilder {
    rb.header("User-Agent", format!("ZCode/{}", ver))
        .header("X-ZCode-App-Version", ver)
        .header("X-Title", "Z Code@electron")
        .header("X-Platform", "win32-x64")
        .header("X-Os-Category", "windows")
        .header("X-Client-Language", "zh-CN")
        .header("HTTP-Referer", "https://zcode.z.ai")
        .header("x-request-id", uuid::Uuid::new_v4().to_string())
}

pub(crate) fn maybe_report_events(key: &str, creds: &Value, mid: &str, ver: &str) {
    let now = chrono::Utc::now().timestamp();
    {
        let mut g = EVENT_REPORTS.lock().unwrap();
        let map = g.get_or_insert_with(Default::default);
        if let Some(t) = map.get(key) { if now - t < 1800 { return; } }
        map.insert(key.to_string(), now);
    }
    let Some(uid) = claim::telemetry_user_id(creds, &|s| decrypt_value(s).ok()) else { return };
    let env = claim::EventEnv::detect(ver);
    let api = claim::ClaimApi::default();
    let _ = claim::report_activation_events(http(), &api, &env, &uid, mid);
}

pub(crate) fn benefits_key_result(key: &str) -> Value {
    let ts = chrono::Utc::now().timestamp();
    let token = match get_jwt_token(key) { Ok(t) => t, Err(e) => return json!({"ok": false, "error": e, "count": 0, "campaigns": [], "checked_at": ts}) };
    let mid = api_device_mid(key); // 账号自己的设备标识（见 profile_device_mid 注释）
    let ver = client_app_version();
    // 检测解锁：以用户本人账号上报 app_launch / app_daily_active（与客户端启动行为一致，30 分钟节流）
    if let Some(creds) = cred_for_key(key) { maybe_report_events(key, &creds, &mid, &ver); }
    // 主数据源：marketing/touch（客户端左下角领取横幅同源）；preview 作为兜底（可能返回其他活动）
    let api = claim::ClaimApi::default();
    let marketing = claim::marketing_claim_plans(http(), &api, &token, &mid, &ver);
    let preview = claim::preview_plans(http(), &api, &token, &mid, &ver);
    match (&marketing, &preview) {
        (Err(me), Err(pe)) => json!({"ok": false, "transient": pe.transient,
            "error": format!("{} / {}", me, pe.msg), "count": 0, "campaigns": [], "checked_at": ts}),
        _ => {
            let plans: Vec<Value> = match (&marketing, &preview) {
                (Ok(m), Ok(p)) => merge_plan_sources(m, p),
                (Ok(m), Err(_)) => m.clone(),
                (Err(_), Ok(p)) => p.clone(),
                (Err(_), Err(_)) => Vec::new(),
            };
            let camps = campaigns_from_plans(&plans);
            json!({"ok": true, "count": camps.len(), "campaigns": camps, "checked_at": ts})
        }
    }
}

/// marketing/touch 为主、preview 兜底；按 plan_id 去重（保留首次出现）。
/// 缺 plan_id 的条目无法领取，直接丢弃。
pub(crate) fn merge_plan_sources(marketing: &[Value], preview: &[Value]) -> Vec<Value> {
    let mut plans: Vec<Value> = Vec::new();
    plans.extend(marketing.iter().cloned());
    plans.extend(preview.iter().cloned());
    let mut seen = std::collections::HashSet::new();
    plans.retain(|p| p.get("plan_id").and_then(|v| v.as_str())
        .map(|k| seen.insert(k.to_string())).unwrap_or(false));
    plans
}

// 活动事件上报节流表：每账号 30 分钟最多一次（检测解锁用，见 claim.rs 模块文档）
pub(crate) static EVENT_REPORTS: Mutex<Option<std::collections::HashMap<String, i64>>> = Mutex::new(None);

/// 持久化时把账号 key 哈希，避免 benefits.json 里出现邮箱/昵称。
pub(crate) fn persist_benefits() {
    let map = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    let mut obj = serde_json::Map::new();
    for (k, v) in map { obj.insert(opaque_key(&k), v); }
    let v = json!({"last_check": *LAST_CHECK.lock().unwrap(), "map": obj});
    let _ = write_json(&benefits_file(), &v);
}

pub(crate) fn load_benefits_once() {
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
pub(crate) fn run_benefit_check_for(key: &str) -> Value {
    let result = benefits_key_result(key);
    BENEFITS.lock().unwrap()
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(key.to_string(), result.clone());
    update_tray_tooltip();
    result
}

pub(crate) const BENEFIT_BATCH_GAP_MS: u64 = 800;

pub(crate) static CHECK_STATE: Mutex<Option<(u64, u64)>> = Mutex::new(None);

pub(crate) static BENEFIT_BATCH_LOCK: Mutex<()> = Mutex::new(());

#[tauri::command]
pub(crate) fn check_state() -> serde_json::Value {
    match *CHECK_STATE.lock().unwrap() {
        Some((done, total)) => json!({"checking": true, "done": done, "total": total}),
        None => json!({"checking": false, "done": 0, "total": 0}),
    }
}

pub(crate) struct BatchStat { pub(crate) okn: u64, pub(crate) failed: u64, pub(crate) transient: u64, pub(crate) with: u64, pub(crate) total: u64 }

pub(crate) fn check_benefits_many(keys: &[String]) -> BatchStat {
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
pub(crate) fn check_benefits(key: String) -> serde_json::Value {
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
pub(crate) fn check_all_benefits() -> serde_json::Value {
    let keys = all_profile_keys();
    let st = check_benefits_many(&keys);
    // 全部失败不推进 last_check：下一轮自动检测应立即重试，而不是等一个完整周期
    if st.okn > 0 { *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp()); }
    json!({"ok": true, "accounts": keys.len(), "checked_ok": st.okn, "failed": st.failed,
           "transient": st.transient, "accounts_with_benefits": st.with, "total_campaigns": st.total})
}

pub(crate) static CLAIM_STATE: Mutex<Option<Value>> = Mutex::new(None);

pub(crate) fn set_claim_state(v: Value) { *CLAIM_STATE.lock().unwrap() = Some(v); }

#[tauri::command]
pub(crate) fn claim_state() -> Value { CLAIM_STATE.lock().unwrap().clone().unwrap_or(json!({"status":"idle"})) }

pub(crate) fn claim_busy() -> bool {
    let st = CLAIM_STATE.lock().unwrap().clone().unwrap_or(Value::Null);
    matches!(st.get("status").and_then(|s| s.as_str()),
        Some("preparing") | Some("activating") | Some("waiting_captcha") | Some("claiming"))
}

#[tauri::command]
pub(crate) fn claim_plan(key: String, plan_id: String, plan_name: Option<String>) -> Value {
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
pub(crate) fn remove_campaign_from_entry(entry: &mut Value, plan_id: &str) -> bool {
    if let Some(arr) = entry.get_mut("campaigns").and_then(|c| c.as_array_mut()) {
        let before = arr.len();
        arr.retain(|c| c.get("plan_id").and_then(|v| v.as_str()) != Some(plan_id));
        if arr.len() != before {
            entry["count"] = json!(arr.len());
            return true;
        }
    }
    false
}

pub(crate) fn optimistically_consume_benefit(key: &str, plan_id: &str) {
    let mut changed = false;
    {
        let mut g = BENEFITS.lock().unwrap();
        if let Some(map) = g.as_mut() {
            if let Some(entry) = map.get_mut(key) { changed = remove_campaign_from_entry(entry, plan_id); }
        }
    }
    if changed { persist_benefits(); update_tray_tooltip(); }
}

pub(crate) fn claim_worker(key: String, plan_id: String, plan_name: String) {
    let fail = |msg: String| set_claim_state(json!({"status":"failed","message":msg,"key":key.clone(),"planName":plan_name.clone(),
        "planId": plan_id.clone(), "updatedAt": chrono::Utc::now().timestamp()}));
    let ver = client_app_version();
    let token = match get_jwt_token(&key) { Ok(t) => t, Err(e) => return fail(e) };
    let mid = api_device_mid(&key); // 账号自己的设备标识，避免 3012 风控
    // 领取前确保激活（best-effort）；与自动检测共用 30 分钟节流，重试不会重复上报事件
    if let Some(creds) = cred_for_key(&key) {
        maybe_report_events(&key, &creds, &mid, &ver);
    }
    // 验证码（若服务端要求）：本地回环页 + 系统浏览器，用户手动完成
    let api = claim::ClaimApi::default();
    let cfg = claim::fetch_captcha_config(http(), &api, &ver).unwrap_or(json!({"enabled": false}));
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
    match claim::submit_claim(http(), &api, &token, &mid, &ver, &plan_id, param.as_deref(), region.as_deref()) {
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
pub(crate) fn open_claim_captcha() -> Value {
    let st = claim_state();
    let url = st.get("captchaUrl").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() { return json!({"ok": false, "error": "当前没有进行中的验证页"}); }
    if !platform::is_safe_open_url(url) { return json!({"ok": false, "error": "验证页地址无效"}); }
    platform::open_in_browser(url);
    json!({"ok": true})
}

/// 本地领取历史（审计日志中的 claim 事件；不含账号标识）
#[tauri::command(async)]
pub(crate) fn claim_history() -> Value {
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

pub(crate) static BENEFITS: Mutex<Option<std::collections::HashMap<String, Value>>> = Mutex::new(None);

pub(crate) static LAST_CHECK: Mutex<Option<i64>> = Mutex::new(None);

#[cfg(test)]
mod tests {
    use super::*;

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
    fn merge_plan_sources_dedupes_by_plan_id() {
        let marketing = vec![json!({"plan_id": "p1", "name": "m1"}), json!({"plan_id": "p2"})];
        let preview = vec![json!({"plan_id": "p1", "name": "p1"}),
                           json!({"name": "no-id"}), json!({"plan_id": "p3"})];
        let merged = merge_plan_sources(&marketing, &preview);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0]["name"], json!("m1"), "重复项保留营销源");
        assert_eq!(merged[2]["plan_id"], json!("p3"));
        assert!(merge_plan_sources(&[], &[]).is_empty());
    }

    #[test]
    fn optimistic_removal_updates_campaigns_and_count() {
        let mut entry = json!({"ok": true, "count": 2, "campaigns": [
            {"plan_id": "p1", "title": "a"}, {"plan_id": "p2", "title": "b"}
        ]});
        assert!(remove_campaign_from_entry(&mut entry, "p1"));
        assert_eq!(entry["count"], json!(1));
        assert_eq!(entry["campaigns"].as_array().unwrap().len(), 1);
        assert!(!remove_campaign_from_entry(&mut entry, "missing"));
        assert_eq!(entry["count"], json!(1));
    }

}
