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
use crate::util::{
    app_data_dir, audit_log, benefits_file, denied, is_opaque_key, opaque_key, safe_key,
};

// 官方 preview 响应 → 福利条目（纯函数，可单测）
pub(crate) fn campaigns_from_plans(plans: &[Value]) -> Vec<Value> {
    let mut camps = Vec::new();
    for p in plans {
        let name = p
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
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
                    if !sn.is_empty() {
                        parts.push(format!("{} +{}", sn, units));
                    }
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
    let plans = j
        .pointer("/data/plans")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    campaigns_from_plans(&plans)
}

// 官方「可领取预览」：GET /api/v1/zcode-plan/billing/preview —— 客户端领取弹窗同源接口，
// 返回 data.plans[]（每个含 plan_id/name/entitlements[grant_units]）。空数组 = 当前无可领。
// 注意：429 限流存在，批量检测时逐账号间加间隔。
// 与客户端一致的请求头（UA / X-Title / X-Platform 等）；服务端按客户端上下文做路由与风控
pub(crate) fn zcode_api_headers(
    rb: reqwest::blocking::RequestBuilder,
    ver: &str,
) -> reqwest::blocking::RequestBuilder {
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
        if let Some(t) = map.get(key) {
            if now - t < 1800 {
                return;
            }
        }
        map.insert(key.to_string(), now);
    }
    let Some(uid) = claim::telemetry_user_id(creds, &|s| decrypt_value(s).ok()) else {
        return;
    };
    let env = claim::EventEnv::detect(ver);
    let api = claim::ClaimApi::default();
    let _ = claim::report_activation_events(http(), &api, &env, &uid, mid);
}

pub(crate) fn benefits_key_result(key: &str) -> Value {
    let ts = chrono::Utc::now().timestamp();
    let token = match get_jwt_token(key) {
        Ok(t) => t,
        Err(e) => {
            return json!({"ok": false, "error": e, "count": 0, "campaigns": [], "checked_at": ts})
        }
    };
    let mid = api_device_mid(key); // 账号自己的设备标识（见 profile_device_mid 注释）
    let ver = client_app_version();
    // 检测解锁：以用户本人账号上报 app_launch / app_daily_active（与客户端启动行为一致，30 分钟节流）
    if let Some(creds) = cred_for_key(key) {
        maybe_report_events(key, &creds, &mid, &ver);
    }
    // 主数据源：marketing/touch（客户端左下角领取横幅同源）；preview 作为兜底（可能返回其他活动）
    let api = claim::ClaimApi::default();
    let marketing = claim::marketing_claim_plans(http(), &api, &token, &mid, &ver);
    let preview = claim::preview_plans(http(), &api, &token, &mid, &ver);
    // marketing/preview 任一 429（含 Retry-After）→ 记录账号级 hold：
    // 下一轮检测在期满前零请求跳过该账号（两个源同时限流时取较大的 Retry-After，只记一次）
    let detect_rate_wait = marketing
        .as_ref()
        .err()
        .and_then(|e| e.rate_wait_ms)
        .into_iter()
        .chain(preview.as_ref().err().and_then(|e| e.rate_wait_ms))
        .max();
    if let Some(ra) = detect_rate_wait {
        record_rate_hold(key, ra, "检测被限流");
    }
    match (&marketing, &preview) {
        (Err(me), Err(pe)) => json!({"ok": false, "transient": me.transient || pe.transient,
            "error": format!("{} / {}", me, pe.msg), "count": 0, "campaigns": [], "checked_at": ts}),
        _ => {
            // 两个数据源都真实读通 → 解除该账号的限流 hold
            //（任一源仍被限流时，维持刚记录的 hold，不能被另一个源的成功冲掉）
            if marketing.is_ok() && preview.is_ok() {
                rate_hold_clear(key);
            }
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
    plans.retain(|p| {
        p.get("plan_id")
            .and_then(|v| v.as_str())
            .map(|k| seen.insert(k.to_string()))
            .unwrap_or(false)
    });
    plans
}

// 活动事件上报节流表：每账号 30 分钟最多一次（检测解锁用，见 claim.rs 模块文档）
pub(crate) static EVENT_REPORTS: Mutex<Option<std::collections::HashMap<String, i64>>> =
    Mutex::new(None);

/// 持久化时把账号 key 哈希，避免 benefits.json 里出现邮箱/昵称。
pub(crate) fn persist_benefits() {
    let map = BENEFITS.lock().unwrap().clone().unwrap_or_default();
    let mut obj = serde_json::Map::new();
    for (k, v) in map {
        obj.insert(opaque_key(&k), v);
    }
    let v = json!({"last_check": *LAST_CHECK.lock().unwrap(), "map": obj});
    let _ = write_json(&benefits_file(), &v);
}

pub(crate) fn load_benefits_once() {
    let mut g = BENEFITS.lock().unwrap();
    if g.is_some() {
        return;
    }
    if let Ok(v) = read_json(&benefits_file()) {
        if let Some(map) = v.get("map").and_then(|m| m.as_object()) {
            let reverse = known_profile_key_map();
            let mut loaded = std::collections::HashMap::new();
            for (hk, val) in map {
                let raw = reverse.get(hk).cloned().or_else(|| {
                    if !is_opaque_key(hk) && safe_key(hk).is_ok() {
                        Some(hk.clone())
                    } else {
                        None
                    }
                });
                if let Some(raw) = raw {
                    let mut val = val.clone();
                    // hold 仅存内存：重启后旧标记已无意义，剥掉避免显示过期的「限流等待中」
                    if val.get("held").and_then(|v| v.as_bool()).unwrap_or(false) {
                        val["held"] = json!(false);
                    }
                    loaded.insert(raw, val);
                }
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
    // 入口纪律：限流 hold 期内零请求，直接复答（与 magpie 插件 toClaim 复答同策略）
    let now = chrono::Utc::now().timestamp();
    if let Some((until, msg)) = rate_hold_check(key, now) {
        let held = json!({"ok": false, "held": true, "transient": true, "error": msg,
                          "until": until, "count": 0, "campaigns": [], "checked_at": now});
        // 复答也要进 BENEFITS：卡片 UI 读的是 get_state 里的福利表，
        // 不写入的话「限流等待中，HH:MM 恢复」永远不会显示
        BENEFITS
            .lock()
            .unwrap()
            .get_or_insert_with(std::collections::HashMap::new)
            .insert(key.to_string(), held.clone());
        update_tray_tooltip();
        return held;
    }
    let result = benefits_key_result(key);
    BENEFITS
        .lock()
        .unwrap()
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

pub(crate) struct BatchStat {
    pub(crate) okn: u64,
    pub(crate) failed: u64,
    pub(crate) transient: u64,
    pub(crate) with: u64,
    pub(crate) held: u64, // 限流 hold 中被跳过（零请求）的账号，不计入失败
    pub(crate) total: u64,
}

pub(crate) fn check_benefits_many(keys: &[String]) -> BatchStat {
    // 手动、托盘与自动检测可能同时触发：串行化，避免重复全量请求把 429 风险翻倍
    let _batch_guard = BENEFIT_BATCH_LOCK.lock().unwrap();
    let mut st = BatchStat {
        okn: 0,
        failed: 0,
        transient: 0,
        with: 0,
        held: 0,
        total: 0,
    };
    *CHECK_STATE.lock().unwrap() = Some((0, keys.len() as u64));
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(BENEFIT_BATCH_GAP_MS));
        }
        let r = run_benefit_check_for(k);
        if r.get("held").and_then(|v| v.as_bool()).unwrap_or(false) {
            // hold 中的账号：零请求跳过，也不计入「失败」——避免全部失败触发全局立即重试，
            // 把其他健康账号也拖进高频检测
            st.held += 1;
        } else if r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            st.okn += 1;
            let c = r.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            if c > 0 {
                st.with += 1;
                st.total += c;
            }
        } else {
            st.failed += 1;
            if r.get("transient")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                st.transient += 1;
            }
        }
        *CHECK_STATE.lock().unwrap() = Some(((i + 1) as u64, keys.len() as u64));
    }
    *CHECK_STATE.lock().unwrap() = None;
    persist_benefits();
    st
}

#[tauri::command(async)]
pub(crate) fn check_benefits(key: String) -> serde_json::Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
    let r = run_benefit_check_for(&key);
    persist_benefits();
    json!({"ok": r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
           "count": r.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
           "campaigns": r.get("campaigns").cloned().unwrap_or(json!([])),
           "checked_at": r.get("checked_at").cloned().unwrap_or(Value::Null),
           "transient": r.get("transient").and_then(|v| v.as_bool()).unwrap_or(false),
           "held": r.get("held").cloned().unwrap_or(Value::Null),
           "until": r.get("until").cloned().unwrap_or(Value::Null),
           "error": r.get("error").cloned().unwrap_or(Value::Null), "key": key})
}

#[tauri::command(async)]
pub(crate) fn check_all_benefits() -> serde_json::Value {
    let keys = all_profile_keys();
    let st = check_benefits_many(&keys);
    // 全部真实失败不推进 last_check：下一轮自动检测应立即重试，而不是等一个完整周期。
    // hold 中的账号不算失败：全员 hold 时按正常周期走（期满自动恢复，无需立即空转）。
    if st.okn > 0 || (st.held > 0 && st.failed == 0) {
        *LAST_CHECK.lock().unwrap() = Some(chrono::Utc::now().timestamp());
    }
    json!({"ok": true, "accounts": keys.len(), "checked_ok": st.okn, "failed": st.failed,
           "transient": st.transient, "held": st.held,
           "accounts_with_benefits": st.with, "total_campaigns": st.total})
}

pub(crate) static CLAIM_STATE: Mutex<Option<Value>> = Mutex::new(None);

pub(crate) fn set_claim_state(v: Value) {
    *CLAIM_STATE.lock().unwrap() = Some(v);
}

#[tauri::command]
pub(crate) fn claim_state() -> Value {
    CLAIM_STATE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or(json!({"status":"idle"}))
}

pub(crate) fn claim_busy() -> bool {
    let st = CLAIM_STATE.lock().unwrap().clone().unwrap_or(Value::Null);
    matches!(
        st.get("status").and_then(|s| s.as_str()),
        Some("preparing") | Some("activating") | Some("waiting_captcha") | Some("claiming")
    )
}

// ---------------- 账号级限流 hold（照 magpie 社区插件 rateWait 设计） ----------------
//
// 背景：magpie 插件真实事故（plugins#503）——一个账号 4 天被限流 180 次，根因是持续重试
// 本身会把限流一直续着。修复：429 后在等待期内对该账号**零请求**直接复答上次的失败结果。
//
// 入口纪律：claim_plan 与 run_benefit_check_for 发任何请求前先查 hold。
// 解除时机只有两种：等待期满自然过期；或一次真实请求成功读通后清除。
// 仅存内存（与 magpie 插件一致），重启失忆可接受；账号 key 天然区分账号，无需补充标识。

pub(crate) const RECHECK_MS: u64 = 30 * 60 * 1000; // 首次限流等待 30 分钟
pub(crate) const RATE_LIMIT_MAX_MS: u64 = 6 * 60 * 60 * 1000; // 封顶 6 小时

#[derive(Debug, Clone)]
pub(crate) struct RateHold {
    pub(crate) wait_ms: u64, // 本次等待时长（再犯时按此翻倍）
    pub(crate) until: i64,   // unix 秒
    pub(crate) message: String,
}

pub(crate) static RATE_WAIT: Mutex<Option<std::collections::HashMap<String, RateHold>>> =
    Mutex::new(None);

/// 下一次等待时长（纯函数）：优先服务端 Retry-After；否则 30 分钟起步、逐次翻倍，封顶 6h。
pub(crate) fn next_rate_wait_ms(prev_wait_ms: u64, retry_after_ms: u64) -> u64 {
    let raw = if retry_after_ms > 0 {
        retry_after_ms
    } else {
        RECHECK_MS.max(prev_wait_ms.saturating_mul(2))
    };
    raw.min(RATE_LIMIT_MAX_MS)
}

/// hold 期内返回 Some((until, message))；过期视为无 hold（条目保留用于再犯时翻倍）。
pub(crate) fn rate_hold_check(key: &str, now: i64) -> Option<(i64, String)> {
    let g = RATE_WAIT.lock().unwrap();
    let h = g.as_ref()?.get(key)?;
    if now < h.until {
        Some((h.until, h.message.clone()))
    } else {
        None
    }
}

/// 上次等待时长（用于再犯时指数翻倍）；无记录为 0。
pub(crate) fn rate_hold_prev_ms(key: &str) -> u64 {
    let g = RATE_WAIT.lock().unwrap();
    g.as_ref()
        .and_then(|m| m.get(key))
        .map(|h| h.wait_ms)
        .unwrap_or(0)
}

pub(crate) fn rate_hold_set(key: &str, wait_ms: u64, now: i64, message: String) {
    let mut g = RATE_WAIT.lock().unwrap();
    g.get_or_insert_with(Default::default).insert(
        key.to_string(),
        RateHold {
            wait_ms,
            until: now + (wait_ms / 1000) as i64,
            message,
        },
    );
}

pub(crate) fn rate_hold_clear(key: &str) {
    let mut g = RATE_WAIT.lock().unwrap();
    if let Some(map) = g.as_mut() {
        map.remove(key);
    }
}

/// 检测/领取被限流后统一记录 hold：Retry-After 优先，否则指数退避。
fn record_rate_hold(key: &str, retry_after_ms: u64, reason: &str) {
    let now = chrono::Utc::now().timestamp();
    let wait = next_rate_wait_ms(rate_hold_prev_ms(key), retry_after_ms);
    let until = now + (wait / 1000) as i64;
    let message = format!("{}，{} 前不再请求该账号", reason, fmt_hhmm(until));
    rate_hold_set(key, wait, now, message);
}

/// Unix 秒 → 本地 HH:MM（限流恢复时间展示用）
fn fmt_hhmm(unix: i64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(unix, 0)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".into())
}

/// ClaimErr → 领取终态决策（纯函数，便于单测）：
/// 返回 (CLAIM_STATE.status, 用户文案, 可选 hold 参数 (wait_ms, until, message))。
fn claim_error_outcome(
    e: &claim::ClaimErr,
    prev_wait_ms: u64,
    now: i64,
) -> (String, String, Option<(u64, i64, String)>) {
    use claim::ClaimErrKind::*;
    match e.kind {
        AlreadyClaimed => ("already_claimed".into(), "该福利今日已领取".into(), None),
        NotEligible => (
            "not_eligible".into(),
            "活动此刻未开放，稍后自动复查".into(),
            None,
        ),
        RateLimited => {
            let wait = next_rate_wait_ms(prev_wait_ms, e.rate_wait_ms.unwrap_or(0));
            let until = now + (wait / 1000) as i64;
            let message = format!("限流中：{} 前不再请求该账号", fmt_hhmm(until));
            let hold_msg = format!("领取被限流（{}），{} 前不再请求", e.msg, fmt_hhmm(until));
            ("failed".into(), message, Some((wait, until, hold_msg)))
        }
        Captcha => ("failed".into(), e.msg.clone(), None),
        Transient => (
            "failed".into(),
            format!("暂时不可用：{}，稍后自动重试", e.msg),
            None,
        ),
        Fatal => ("failed".into(), format!("领取失败：{}", e.msg), None),
    }
}

/// 按 ClaimErr.kind 落领取终态。已领/未开放是独立状态；限流进入账号级 hold。
fn settle_claim_error(key: &str, plan_id: &str, plan_name: &str, e: &claim::ClaimErr) {
    let now = chrono::Utc::now().timestamp();
    let (status, message, hold) = claim_error_outcome(e, rate_hold_prev_ms(key), now);
    if let Some((wait_ms, _until, hold_msg)) = &hold {
        rate_hold_set(key, *wait_ms, now, hold_msg.clone());
    }
    let mut st = json!({"status": status, "message": message, "key": key,
        "planName": plan_name, "planId": plan_id, "updatedAt": now});
    if let Some((_, until, _)) = &hold {
        st["holdUntil"] = json!(until); // UI 直接展示恢复时刻，避免本地化时丢时间
    }
    // 「今日已领」说明权益已生效（只是不是本次操作领的）：同样移除活动 + 失效额度缓存，
    // 但不写审计（不是本机执行的领取）
    if e.kind == claim::ClaimErrKind::AlreadyClaimed {
        QUOTA_CACHE.lock().unwrap().as_mut().map(|m| m.remove(key));
        persist_quota_cache();
        optimistically_consume_benefit(key, plan_id);
        rate_hold_clear(key); // 服务端正常应答 = 已读通
    }
    set_claim_state(st);
}

#[tauri::command]
pub(crate) fn claim_plan(key: String, plan_id: String, plan_name: Option<String>) -> Value {
    if let Err(e) = safe_key(&key) {
        return denied(e);
    }
    if plan_id.trim().is_empty() {
        return json!({"ok": false, "error": "缺少 plan_id，无法领取"});
    }
    if claim_busy() {
        return json!({"ok": false, "code": "claim_busy", "error": "上一次领取仍在进行中，请稍候"});
    }
    // 入口纪律：限流 hold 期内零请求直接拒绝（必须在任何网络路径之前）
    let now = chrono::Utc::now().timestamp();
    if let Some((until, _)) = rate_hold_check(&key, now) {
        return json!({"ok": false, "code": "rate_limited_hold", "until": until,
                      "error": format!("账号限流等待中，{} 前不再请求", fmt_hhmm(until))});
    }
    let pname = plan_name.unwrap_or_default();
    set_claim_state(
        json!({"status": "preparing", "key": key, "planId": plan_id, "planName": pname,
                           "updatedAt": chrono::Utc::now().timestamp()}),
    );
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
            if let Some(entry) = map.get_mut(key) {
                changed = remove_campaign_from_entry(entry, plan_id);
            }
        }
    }
    if changed {
        persist_benefits();
        update_tray_tooltip();
    }
}

pub(crate) fn claim_worker(key: String, plan_id: String, plan_name: String) {
    let fail = |msg: String| {
        set_claim_state(
            json!({"status":"failed","message":msg,"key":key.clone(),"planName":plan_name.clone(),
        "planId": plan_id.clone(), "updatedAt": chrono::Utc::now().timestamp()}),
        )
    };
    let ver = client_app_version();
    let token = match get_jwt_token(&key) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let mid = api_device_mid(&key); // 账号自己的设备标识，避免 3012 风控
                                    // 领取前确保激活（best-effort）；与自动检测共用 30 分钟节流，重试不会重复上报事件
    if let Some(creds) = cred_for_key(&key) {
        maybe_report_events(&key, &creds, &mid, &ver);
    }
    let api = claim::ClaimApi::default();
    set_claim_state(
        json!({"status":"claiming","key": key, "planName": plan_name, "planId": plan_id,
                           "updatedAt": chrono::Utc::now().timestamp()}),
    );
    match run_claim_flow(&key, &plan_id, &plan_name, &token, &mid, &ver, &api) {
        Ok(data) => {
            rate_hold_clear(&key); // 真实请求成功读通 → 解除账号级限流 hold
            let (eff, _s, ends) = claim::claim_timing(&data);
            let name = data
                .pointer("/plan/name")
                .and_then(|v| v.as_str())
                .or_else(|| data.pointer("/plan/plan_id").and_then(|v| v.as_str()))
                .map(String::from)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| plan_name.clone());
            audit_log(
                "claim",
                Some(&key),
                json!({"plan": name, "plan_id": plan_id, "effective_at": eff}),
            );
            // 立即失效该账号额度缓存 + 乐观移除本次活动，让 UI 马上看到成功/按钮消失
            QUOTA_CACHE.lock().unwrap().as_mut().map(|m| m.remove(&key));
            persist_quota_cache();
            optimistically_consume_benefit(&key, &plan_id);
            set_claim_state(
                json!({"status":"success","key": key, "planName": name, "planId": plan_id,
                                   "effectiveAt": eff, "endsAt": ends,
                                   "updatedAt": chrono::Utc::now().timestamp()}),
            );
            // 福利重查放后台：marketing/touch 20s + preview 30s，不能阻塞成功状态回传
            let k2 = key.clone();
            std::thread::spawn(move || {
                let _ = run_benefit_check_for(&k2);
                persist_benefits();
            });
        }
        Err(e) => settle_claim_error(&key, &plan_id, &plan_name, &e),
    }
}

/// 领取主流程：先裸领取（大多数活动无需验证码，零弹窗直接成功）；
/// 仅当服务端按需索要验证码（kind == Captcha）时才取配置、起本地回环页并弹浏览器，
/// 用户手动完成后带验证参数重领一次。重领的错误（含 429 → hold）原样向上传递。
#[allow(clippy::too_many_arguments)] // 与 claim 请求字段一一对应
fn run_claim_flow(
    key: &str,
    plan_id: &str,
    plan_name: &str,
    token: &str,
    mid: &str,
    ver: &str,
    api: &claim::ClaimApi,
) -> Result<Value, claim::ClaimErr> {
    match claim::submit_claim(http(), api, token, mid, ver, plan_id, None, None) {
        Ok(data) => Ok(data),
        Err(e) if e.kind == claim::ClaimErrKind::Captcha => {
            // 本次领取被要求验证码：取验证码配置（sceneId 等），起回环页 + 系统浏览器
            let cfg =
                claim::fetch_captcha_config(http(), api, ver).map_err(|ce| claim::ClaimErr {
                    msg: format!("需要完成验证码，但验证码配置获取失败: {}", ce),
                    code: None,
                    kind: claim::ClaimErrKind::Captcha,
                    rate_wait_ms: None,
                })?;
            run_captcha_and_claim(key, plan_id, plan_name, token, mid, ver, api, &cfg)
        }
        Err(e) => Err(e),
    }
}

/// Captcha 分支：等用户完成验证码，再带验证参数重领一次。
#[allow(clippy::too_many_arguments)] // 与 claim 请求字段一一对应
fn run_captcha_and_claim(
    key: &str,
    plan_id: &str,
    plan_name: &str,
    token: &str,
    mid: &str,
    ver: &str,
    api: &claim::ClaimApi,
    cfg: &Value,
) -> Result<Value, claim::ClaimErr> {
    let captcha_err = |msg: String| claim::ClaimErr {
        msg,
        code: None,
        kind: claim::ClaimErrKind::Captcha,
        rate_wait_ms: None,
    };
    // 复用同一验证页：页面还在轮询（心跳新鲜）时不再新开标签页，
    // 由页面自己进入下一轮验证；页面已关闭才新开一页。
    let (captcha_url, reused) = claim::captcha_begin(cfg).map_err(captcha_err)?;
    set_claim_state(
        json!({"status":"waiting_captcha","key": key, "planName": plan_name,
        "planId": plan_id, "captchaUrl": captcha_url,
        "updatedAt": chrono::Utc::now().timestamp()}),
    );
    if !reused {
        platform::open_in_browser(&captcha_url);
    }
    let v = claim::captcha_round().map_err(captcha_err)?;
    let param = v
        .get("param")
        .and_then(|p| p.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(param) = param else {
        return Err(captcha_err("未取得验证码结果".into()));
    };
    let region = v
        .get("region")
        .and_then(|r| r.as_str())
        .map(|s| s.trim().to_string());
    // 重领：back to claiming；每次提交都生成新的 x-request-id（submit_claim 内部）
    set_claim_state(
        json!({"status":"claiming","key": key, "planName": plan_name, "planId": plan_id,
                           "updatedAt": chrono::Utc::now().timestamp()}),
    );
    claim::submit_claim(
        http(),
        api,
        token,
        mid,
        ver,
        plan_id,
        Some(&param),
        region.as_deref(),
    )
}

/// 重新打开当前领取流程的验证页（用户关闭浏览器后不必重新走整个领取）
#[tauri::command]
pub(crate) fn open_claim_captcha() -> Value {
    let st = claim_state();
    let url = st.get("captchaUrl").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() {
        return json!({"ok": false, "error": "当前没有进行中的验证页"});
    }
    if !platform::is_safe_open_url(url) {
        return json!({"ok": false, "error": "验证页地址无效"});
    }
    platform::open_in_browser(url);
    json!({"ok": true})
}

/// 本地领取历史（审计日志中的 claim 事件；不含账号标识）
fn claim_items_from_text(txt: &str, limit: usize) -> Vec<Value> {
    txt.lines()
        .rev()
        .filter_map(|l| {
            let v: Value = serde_json::from_str(l).ok()?;
            if v.get("event").and_then(|e| e.as_str()) != Some("claim") {
                return None;
            }
            let d = v.get("detail").cloned().unwrap_or(json!({}));
            Some(json!({"ts": v.get("ts").cloned().unwrap_or(Value::Null),
                    "plan": d.get("plan").cloned().unwrap_or(Value::Null),
                    "effectiveAt": d.get("effective_at").cloned().unwrap_or(Value::Null)}))
        })
        .take(limit)
        .collect()
}

pub(crate) fn claim_items(limit: usize) -> Vec<Value> {
    let p = audit::audit_path(&app_data_dir());
    std::fs::read_to_string(&p)
        .map(|txt| claim_items_from_text(&txt, limit))
        .unwrap_or_default()
}

#[tauri::command(async)]
pub(crate) fn claim_history() -> Value {
    json!({"ok": true, "items": claim_items(50)})
}

/// 导出全部领取记录（JSON，不含账号标识），用于对账/留存。
#[tauri::command(async)]
pub(crate) fn export_claim_history(path: String) -> Value {
    let items = claim_items(10_000);
    let body = json!({"format": "zcode-hub-claim-history", "version": 1,
                      "exported_at": chrono::Utc::now().to_rfc3339(), "items": items});
    match serde_json::to_vec_pretty(&body) {
        Ok(bytes) => match std::fs::write(&path, bytes) {
            Ok(()) => json!({"ok": true, "path": path, "count": items.len()}),
            Err(e) => json!({"ok": false, "error": format!("写入失败: {}", e)}),
        },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

pub(crate) static BENEFITS: Mutex<Option<std::collections::HashMap<String, Value>>> =
    Mutex::new(None);

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
        assert_eq!(camps[1]["title"], "p2"); // 无 name → 回退 plan_id
        assert_eq!(camps[1]["grant"], "?"); // 无权益 → ?
        assert_eq!(camps[2]["title"], "p3"); // 空白 name → 回退
                                             // 空响应
        assert_eq!(parse_preview_plans(&json!({"code": 0})).len(), 0);
    }

    #[test]
    fn merge_plan_sources_dedupes_by_plan_id() {
        let marketing = vec![
            json!({"plan_id": "p1", "name": "m1"}),
            json!({"plan_id": "p2"}),
        ];
        let preview = vec![
            json!({"plan_id": "p1", "name": "p1"}),
            json!({"name": "no-id"}),
            json!({"plan_id": "p3"}),
        ];
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

    #[test]
    fn claim_history_export_reads_claim_events_newest_first() {
        let txt = concat!(
            r#"{"ts":"t1","event":"claim","detail":{"plan":"A","effective_at":1}}"#,
            "\n",
            r#"{"ts":"t2","event":"switch","detail":{}}"#,
            "\n",
            r#"{"ts":"t3","event":"claim","detail":{"plan":"B","effective_at":2}}"#,
            "\n",
        );
        let items = claim_items_from_text(txt, 10);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["plan"], json!("B"));
        assert_eq!(items[1]["plan"], json!("A"));
        assert_eq!(claim_items_from_text(txt, 1).len(), 1);
        assert!(claim_items_from_text("not json", 10).is_empty());
    }

    #[test]
    fn next_rate_wait_doubles_caps_and_prefers_retry_after() {
        // 首次限流：30 分钟起步
        assert_eq!(next_rate_wait_ms(0, 0), RECHECK_MS);
        // 无 Retry-After：逐次翻倍
        assert_eq!(next_rate_wait_ms(RECHECK_MS, 0), RECHECK_MS * 2);
        assert_eq!(next_rate_wait_ms(RECHECK_MS * 2, 0), RECHECK_MS * 4);
        // 封顶 6 小时（含溢出安全的极大值）
        assert_eq!(next_rate_wait_ms(RATE_LIMIT_MAX_MS, 0), RATE_LIMIT_MAX_MS);
        assert_eq!(next_rate_wait_ms(u64::MAX / 2, 0), RATE_LIMIT_MAX_MS);
        // Retry-After 优先
        assert_eq!(next_rate_wait_ms(0, 90_000), 90_000);
        assert_eq!(next_rate_wait_ms(RECHECK_MS * 4, 45_000), 45_000);
        // Retry-After 超过封顶也要封顶
        assert_eq!(
            next_rate_wait_ms(0, 100 * 60 * 60 * 1000),
            RATE_LIMIT_MAX_MS
        );
        // Retry-After 为 0 视同缺失
        assert_eq!(next_rate_wait_ms(RECHECK_MS, 0), RECHECK_MS * 2);
    }

    #[test]
    fn rate_hold_blocks_until_expiry_and_survives_for_escalation() {
        const K: &str = "unit-test-hold-key";
        rate_hold_clear(K);
        assert!(rate_hold_check(K, 1_000).is_none());
        assert_eq!(rate_hold_prev_ms(K), 0);
        rate_hold_set(K, 60_000, 1_000, "等待中".into());
        // 等待期内命中：零请求语义由调用方在 check 之后立即 return 保证
        let (until, msg) = rate_hold_check(K, 1_059).expect("held within window");
        assert_eq!(until, 1_000 + 60);
        assert_eq!(msg, "等待中");
        // 期满自然解除（无需手动清除入口）
        assert!(rate_hold_check(K, 1_000 + 60).is_none());
        // 条目保留：再犯时按上次等待翻倍
        assert_eq!(rate_hold_prev_ms(K), 60_000);
        rate_hold_clear(K);
        assert_eq!(rate_hold_prev_ms(K), 0);
        assert!(rate_hold_check(K, 1_060).is_none());
    }

    #[test]
    fn claim_plan_entry_rejects_held_account_without_requests() {
        const K: &str = "hold-entry-gate@example.com";
        rate_hold_clear(K);
        rate_hold_set(
            K,
            60_000,
            chrono::Utc::now().timestamp(),
            "检测被限流".into(),
        );
        // 入口纪律：hold 期内 claim_plan 直接拒绝，不进入 preparing、不 spawn 网络线程
        let r = claim_plan(K.to_string(), "p1".into(), None);
        assert_eq!(r["ok"], json!(false));
        assert_eq!(r["code"], json!("rate_limited_hold"));
        assert!(r["until"].as_i64().is_some());
        assert_ne!(claim_state()["status"], json!("preparing"));
        rate_hold_clear(K);
    }

    #[test]
    fn benefit_check_gate_answers_from_memory_without_network() {
        // run_benefit_check_for 的 hold 闸门必须在任何网络路径之前：
        // 假 key 若真走到 get_jwt_token 会得到不含 held 的错误结果，此断言即失败
        const K: &str = "hold-check-gate@example.com";
        rate_hold_clear(K);
        rate_hold_set(
            K,
            60_000,
            chrono::Utc::now().timestamp(),
            "检测被限流，12:34 前不再请求该账号".into(),
        );
        let r = run_benefit_check_for(K);
        assert_eq!(r["held"], json!(true));
        assert_eq!(r["ok"], json!(false));
        assert_eq!(r["error"], json!("检测被限流，12:34 前不再请求该账号"));
        assert!(r["until"].as_i64().is_some());
        // 复答进 BENEFITS：卡片 UI 才能显示「限流等待中」
        let entry = BENEFITS
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default()
            .get(K)
            .cloned()
            .unwrap_or(json!(null));
        assert_eq!(entry["held"], json!(true));
        rate_hold_clear(K);
        BENEFITS.lock().unwrap().as_mut().map(|m| m.remove(K));
    }

    #[test]
    fn claim_error_outcome_maps_each_kind_to_terminal_state() {
        use crate::claim::{ClaimErr, ClaimErrKind};
        let now = 1_800_000_000_i64;
        let e = |kind, msg: &str, ra: Option<u64>| ClaimErr {
            msg: msg.into(),
            code: None,
            kind,
            rate_wait_ms: ra,
        };
        // 已领 → 独立状态，不是失败
        let (st, msg, hold) =
            claim_error_outcome(&e(ClaimErrKind::AlreadyClaimed, "x", None), 0, now);
        assert_eq!(st, "already_claimed");
        assert!(hold.is_none());
        assert!(msg.contains("已领取"));
        // 未开放 → 独立状态
        let (st, msg, hold) = claim_error_outcome(&e(ClaimErrKind::NotEligible, "x", None), 0, now);
        assert_eq!(st, "not_eligible");
        assert!(hold.is_none());
        assert!(msg.contains("未开放"));
        // 限流 → failed + hold 参数（Retry-After 优先）
        let (st, _msg, hold) = claim_error_outcome(
            &e(ClaimErrKind::RateLimited, "too fast", Some(120_000)),
            0,
            now,
        );
        assert_eq!(st, "failed");
        let (wait, until, _hm) = hold.expect("rate limited sets hold");
        assert_eq!(wait, 120_000);
        assert_eq!(until, now + 120);
        // 限流无 Retry-After → 30 分钟起步；再犯翻倍
        let (_, _, hold) =
            claim_error_outcome(&e(ClaimErrKind::RateLimited, "429", Some(0)), 0, now);
        assert_eq!(hold.unwrap().0, RECHECK_MS);
        let (_, _, hold) =
            claim_error_outcome(&e(ClaimErrKind::RateLimited, "429", None), RECHECK_MS, now);
        assert_eq!(hold.unwrap().0, RECHECK_MS * 2);
        // 其余 kind → failed，无 hold
        for (kind, expect_msg) in [
            (ClaimErrKind::Captcha, "验证码超时"),
            (ClaimErrKind::Transient, "网络断开"),
            (ClaimErrKind::Fatal, "token 无效"),
        ] {
            let (st, msg, hold) = claim_error_outcome(&e(kind, expect_msg, None), 0, now);
            assert_eq!(st, "failed");
            assert!(hold.is_none());
            assert!(msg.contains(expect_msg));
        }
    }
}
