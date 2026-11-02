//! 福利领取流程。2026-11-02 用户拍板放宽边界后新增：
//! - 允许以用户本人账号上报 `app_launch` / `app_daily_active`（检测解锁，与官方客户端启动行为一致）
//! - 允许人工完成阿里云验证码后一键领取
//!
//! 仍然禁止：自动/定时领取、验证码绕过自动化、批量刷取。见 docs/DESIGN.md §4。
//!
//! 实现对齐 zcode-switch（pjpv/zcode-switch，MIT）已验证的接口序列：
//! event/report × 2 → billing/preview → （用户完成验证码）→ billing/claim。

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

pub const EVENT_REPORT_URL: &str = "https://zcode.z.ai/api/v1/event/report";
pub const BILLING_PREVIEW_URL: &str = "https://zcode.z.ai/api/v1/zcode-plan/billing/preview";
pub const BILLING_CLAIM_URL: &str = "https://zcode.z.ai/api/v1/zcode-plan/billing/claim";
pub const CLIENT_CONFIGS_URL: &str = "https://zcode.z.ai/api/v1/client/configs";
pub const ACTIVATION_EVENTS: [&str; 2] = ["app_launch", "app_daily_active"];
const SCREEN_RESOLUTION_FALLBACK: &str = "2560x1440";
const CAPTCHA_TIMEOUT_SECS: u64 = 150;

/// 上报事件所需的环境信息（注入以便测试；真实值由 platform 提供）
#[derive(Debug, Clone)]
pub struct EventEnv {
    pub app_version: String,
    pub timezone: String,
    pub os_version: String,
    pub screen_resolution: String,
}

impl EventEnv {
    pub fn detect(app_version: &str) -> Self {
        EventEnv {
            app_version: app_version.to_string(),
            timezone: crate::platform::client_timezone(),
            os_version: crate::platform::os_version().unwrap_or_default(),
            screen_resolution: crate::platform::screen_resolution()
                .unwrap_or_else(|| SCREEN_RESOLUTION_FALLBACK.to_string()),
        }
    }
}

/// 活动事件体（纯函数，字段与客户端/参考实现一致）
pub fn activation_event_body(element: &str, event_id: &str, user_id: &str, mid: &str, env: &EventEnv) -> Value {
    json!({
        "event_id": event_id,
        "client_timezone": env.timezone,
        "client_language": "zh-CN",
        "element_name": element,
        "event_region": "app",
        "event_type": "view",
        "event_text": "",
        "event_extra_detail": {},
        "user_id": user_id,
        "screen_resolution": env.screen_resolution,
        "app_version": env.app_version,
        "device_os_category": std::env::consts::OS,
        "device_os_version": env.os_version,
        "device_mid": mid,
        "mac_id": "",
        "marketing_params": "{}",
    })
}

/// 从凭据快照解析 user_id（用于事件上报）：取当前 provider 的 user_info 的 id/user_id
pub fn telemetry_user_id(creds: &Value, decrypt: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let provider = creds.get("oauth:active_provider").and_then(|v| v.as_str())
        .and_then(decrypt)
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "zai".to_string());
    let raw = creds.get(format!("oauth:{}:user_info", provider))?.as_str()?;
    let plain = decrypt(raw)?;
    let info: Value = serde_json::from_str(&plain).ok()?;
    ["id", "user_id"].iter()
        .filter_map(|k| info.get(k).and_then(|v| v.as_str()))
        .map(str::trim).find(|s| !s.is_empty())
        .map(String::from)
}

/// 上报两条激活事件；返回首个错误（尽力而为：调用方通常忽略错误继续 preview）
pub fn report_activation_events(
    client: &reqwest::blocking::Client,
    env: &EventEnv,
    user_id: &str,
    mid: &str,
) -> Result<(), String> {
    for element in ACTIVATION_EVENTS {
        let body = activation_event_body(element, &uuid::Uuid::new_v4().to_string(), user_id, mid, env);
        let resp = client.post(EVENT_REPORT_URL)
            .header("Content-Type", "application/json")
            .header("User-Agent", format!("ZCode/{}", env.app_version))
            .timeout(Duration::from_secs(10))
            .json(&body)
            .send()
            .map_err(|e| format!("事件上报失败: {}", e))?;
        let j = resp.json::<Value>().map_err(|e| format!("事件上报响应异常: {}", e))?;
        let code = j.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        if code != 0 {
            return Err(format!("事件上报失败: code {}", code));
        }
    }
    Ok(())
}

/// preview 响应分类（纯函数）：code!=0 → 业务错误；缺 data 字段 → 协议/身份异常。
/// 注意：客户端对「缺 data」按错误处理（manual_claim_preview_missing_data），
/// 因此这里绝不能再把它当成「无待领福利」，否则会给出误导性的 ✓。
pub fn parse_preview_response(j: &Value) -> Result<Vec<Value>, String> {
    let code = j.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = j.get("msg").and_then(|m| m.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("preview error");
        return Err(msg.to_string());
    }
    match j.get("data") {
        Some(d) if d.is_object() => Ok(d.get("plans").and_then(|p| p.as_array()).cloned().unwrap_or_default()),
        _ => Err("接口未返回体验套餐数据（客户端版本或账号状态可能已变化）".into()),
    }
}

/// GET billing/preview 的 `data.plans` 原文
pub fn preview_plans(
    client: &reqwest::blocking::Client,
    token: &str,
    mid: &str,
    app_version: &str,
) -> Result<Vec<Value>, String> {
    let req = client.get(BILLING_PREVIEW_URL)
        .query(&[("app_version", app_version), ("platform", "win32-x64")])
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", mid)
        .header("User-Agent", format!("ZCode/{}", app_version))
        .header("X-ZCode-App-Version", app_version)
        .header("X-Title", "Z Code@electron")
        .header("X-Platform", "win32-x64")
        .header("X-Os-Category", "windows")
        .header("X-Client-Language", "zh-CN")
        .header("HTTP-Referer", "https://zcode.z.ai")
        .header("x-request-id", uuid::Uuid::new_v4().to_string())
        .timeout(Duration::from_secs(30));
    let j: Value = req.send().map_err(|e| e.to_string())?
        .json().map_err(|e| e.to_string())?;
    parse_preview_response(&j)
}

/// 客户端 captcha 配置（/api/v1/client/configs → data.configs.captcha）
pub fn fetch_captcha_config(client: &reqwest::blocking::Client, app_version: &str) -> Result<Value, String> {
    let j: Value = client.get(CLIENT_CONFIGS_URL)
        .header("User-Agent", format!("ZCode/{}", app_version))
        .header("X-ZCode-App-Version", app_version)
        .header("X-Title", "Z Code@electron")
        .header("X-Platform", "win32-x64")
        .header("X-Os-Category", "windows")
        .header("X-Client-Language", "zh-CN")
        .timeout(Duration::from_secs(20))
        .send().map_err(|e| e.to_string())?
        .json().map_err(|e| e.to_string())?;
    if j.get("code").and_then(|c| c.as_i64()) != Some(0) {
        return Err("captcha 配置不可用".into());
    }
    Ok(j.pointer("/data/configs/captcha").cloned().unwrap_or(Value::Null))
}

/// POST billing/claim；成功返回 data（含 plan.entitlements[].effective_at 等）
pub fn submit_claim(
    client: &reqwest::blocking::Client,
    token: &str,
    mid: &str,
    app_version: &str,
    plan_id: &str,
    captcha_param: Option<&str>,
    captcha_region: Option<&str>,
) -> Result<Value, String> {
    let mut req = client.post(BILLING_CLAIM_URL)
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Device-Mid", mid)
        .header("Content-Type", "application/json")
        .header("User-Agent", format!("ZCode/{}", app_version))
        .header("X-ZCode-App-Version", app_version)
        .header("X-Title", "Z Code@electron")
        .header("X-Platform", "win32-x64")
        .header("X-Os-Category", "windows")
        .header("X-Client-Language", "zh-CN")
        .header("HTTP-Referer", "https://zcode.z.ai")
        .header("x-request-id", uuid::Uuid::new_v4().to_string())
        .timeout(Duration::from_secs(25));
    if let Some(p) = captcha_param.filter(|p| !p.trim().is_empty()) {
        req = req.header("X-Aliyun-Captcha-Verify-Param", p.trim());
    }
    if let Some(r) = captcha_region.filter(|r| !r.trim().is_empty()) {
        req = req.header("X-Aliyun-Captcha-Verify-Region", r.trim());
    }
    let j: Value = req.json(&json!({"plan_id": plan_id}))
        .send().map_err(|e| e.to_string())?
        .json().map_err(|e| e.to_string())?;
    let code = j.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = j.get("msg").and_then(|m| m.as_str()).map(str::trim)
            .filter(|s| !s.is_empty()).unwrap_or("领取失败");
        return Err(format!("{}（code {}）", msg, code));
    }
    Ok(j.get("data").cloned().unwrap_or(Value::Null))
}

/// 领取结果里的生效/到期时间（Unix 秒）
pub fn claim_timing(data: &Value) -> (Option<i64>, Option<i64>, Option<i64>) {
    let ent_eff = data.pointer("/plan/entitlements").and_then(|e| e.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.get("effective_at").and_then(|v| v.as_i64()))
            .filter(|t| *t > 0).max()).unwrap_or(None);
    let starts = data.pointer("/plan/starts_at").and_then(|v| v.as_i64());
    let ends = data.pointer("/plan/ends_at").and_then(|v| v.as_i64());
    (ent_eff, starts, ends)
}

// ---------------- 验证码：本地回环页 + 系统浏览器（不污染应用 CSP） ----------------

/// 启动一次性验证码页：`http://127.0.0.1:<port>/<nonce>/` 加载阿里云 SDK，
/// 验证通过后把参数 POST 回 `/result`，由主流程取回。超时 150s。
pub struct CaptchaFlow {
    pub url: String,
    rx: std::sync::mpsc::Receiver<Value>,
}

pub fn start_captcha_flow(cfg: &Value) -> Result<CaptchaFlow, String> {
    let scene_id = cfg.get("sceneId").or_else(|| cfg.get("scene_id"))
        .and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if scene_id.is_empty() {
        return Err("验证码配置缺少 SceneId".into());
    }
    let prefix = cfg.get("prefix").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let region = cfg.get("region").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let nonce: String = (0..24).map(|_| "0123456789abcdef".as_bytes()[rand::random_range(0..16)] as char).collect();
    let html = captcha_html(&scene_id, &prefix, &region, &nonce);
    let (tx, rx) = std::sync::mpsc::channel::<Value>();
    let url = format!("http://127.0.0.1:{}/{}/", port, nonce);

    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(CAPTCHA_TIMEOUT_SECS);
        let ok = tx.clone();
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 8192];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let first = req.lines().next().unwrap_or("");
                    if first.starts_with(&format!("GET /{}/", nonce)) || first == format!("GET /{}", nonce) {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            html.len(), html);
                        let _ = stream.write_all(resp.as_bytes());
                    } else if first.starts_with(&format!("POST /{}/result", nonce)) {
                        let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
                        let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}");
                        let _ = stream.flush();
                        let _ = ok.send(v);
                        return;
                    } else {
                        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(60));
                }
                Err(_) => break,
            }
        }
    });

    Ok(CaptchaFlow { url, rx })
}

/// 等待用户完成验证（最多 150s）；返回 {param, region}
pub fn wait_captcha(flow: CaptchaFlow) -> Result<Value, String> {
    flow.rx.recv_timeout(Duration::from_secs(CAPTCHA_TIMEOUT_SECS + 5))
        .map_err(|_| "验证码超时未完成（请重试）".to_string())
}

fn captcha_html(scene_id: &str, prefix: &str, region: &str, nonce: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('\'', "\\'");
    format!(r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>ZCode Hub · 领取验证</title>
<style>
html,body{{background:#0c0d13;color:#d8d8e6;font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif;margin:0}}
.wrap{{max-width:420px;margin:0 auto;padding:48px 24px}}
h3{{font-size:16px;margin:0 0 8px}}#st{{color:#9aa1b2;font-size:12px;min-height:18px}}
#cap-holder{{margin:28px 0}}#cap-btn{{background:#a16207;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:14px;cursor:pointer}}
#cap-btn[hidden]{{display:none}}#det{{color:#6b7280;font-size:11px;word-break:break-all}}
</style></head><body><div class="wrap">
<h3>ZCode Hub · 福利领取</h3>
<div id="st">正在准备验证码…</div>
<div id="cap-holder"></div>
<button id="cap-btn" hidden>开始验证</button>
<div id="det"></div>
<script>
var SCENE_ID='{scene}', PREFIX='{prefix}', REGION='{region}', NONCE='{nonce}';
var st=document.getElementById('st'), det=document.getElementById('det'), btn=document.getElementById('cap-btn');
var submitted=false;
function say(t){{st.textContent=t}}
function post(p){{ if(submitted||!p) return; submitted=true; say('验证通过，正在领取…');
  fetch('/'+NONCE+'/result',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{param:p,region:REGION}})}})
    .then(function(){{say('已提交，请返回 ZCode Hub')}}).catch(function(e){{det.textContent=String(e)}}); }}
var s=document.createElement('script'); s.src='https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js';
s.onload=function(){{ window.AliyunCaptchaConfig={{region:REGION,prefix:PREFIX}};
  window.initAliyunCaptcha({{ SceneId:SCENE_ID, mode:'popup', language:'zh-CN', showErrorTip:false,
    element:'#cap-holder', button:'#cap-btn',
    getInstance:function(ins){{ if(ins&&typeof ins.startTracelessVerification==='function'){{
        ins.startTracelessVerification();
        setTimeout(function(){{ if(!submitted){{ say('如未自动通过，请点击下方按钮完成验证'); btn.hidden=false; }} }},8000);
      }} else {{ btn.hidden=false; say('请点击下方按钮完成验证'); }} }},
    success:function(p){{ post(typeof p==='string'?p:(p&&p.captchaVerifyParam)); }},
    fail:function(p){{ say('验证未通过，请重试'); det.textContent=JSON.stringify(p||'').slice(0,200); }},
    onError:function(p){{ say('验证异常，请重试'); det.textContent=JSON.stringify(p||'').slice(0,200); }} }}); }};
s.onerror=function(){{ say('验证码组件加载失败，请检查网络后刷新'); }};
document.body.appendChild(s);
btn.addEventListener('click', function(){{ say('请在弹窗中完成验证'); }});
</script></div></body></html>"#,
        scene = esc(scene_id), prefix = esc(prefix), region = esc(region), nonce = esc(nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> EventEnv {
        EventEnv {
            app_version: "3.17.1".into(),
            timezone: "Asia/Shanghai".into(),
            os_version: "10.0.19045".into(),
            screen_resolution: "2560x1440".into(),
        }
    }

    #[test]
    fn activation_body_matches_client_shape() {
        let b = activation_event_body("app_launch", "e1", "u1", "mid1", &env());
        assert_eq!(b["element_name"], json!("app_launch"));
        assert_eq!(b["event_region"], json!("app"));
        assert_eq!(b["event_type"], json!("view"));
        assert_eq!(b["user_id"], json!("u1"));
        assert_eq!(b["device_mid"], json!("mid1"));
        assert_eq!(b["app_version"], json!("3.17.1"));
        assert_eq!(b["client_language"], json!("zh-CN"));
        assert_eq!(b["marketing_params"], json!("{}"));
        assert!(b["event_id"].as_str().is_some());
    }

    #[test]
    fn telemetry_user_id_prefers_id_then_user_id() {
        let decrypt = |s: &str| s.strip_prefix("enc:").map(String::from);
        let creds = json!({
            "oauth:active_provider": "enc:bigmodel",
            "oauth:bigmodel:user_info": "enc:{\"id\":\"u-1\",\"user_id\":\"u-2\"}"
        });
        assert_eq!(telemetry_user_id(&creds, &decrypt), Some("u-1".into()));
        let creds2 = json!({
            "oauth:active_provider": "enc:zai",
            "oauth:zai:user_info": "enc:{\"user_id\":\"u-2\"}"
        });
        assert_eq!(telemetry_user_id(&creds2, &decrypt), Some("u-2".into()));
        assert_eq!(telemetry_user_id(&json!({}), &decrypt), None);
    }

    #[test]
    fn claim_timing_reads_entitlement_effective_at() {
        let data = json!({
            "server_time": 1793620633,
            "plan": {"starts_at": 1793620633, "ends_at": 1793667600,
                     "entitlements": [
                        {"show_name": "GLM-5.3-Flash", "effective_at": 1793631600},
                        {"show_name": "GLM-5.3", "effective_at": 1793635200}
                     ]}
        });
        let (eff, starts, ends) = claim_timing(&data);
        assert_eq!(eff, Some(1793635200));
        assert_eq!(starts, Some(1793620633));
        assert_eq!(ends, Some(1793667600));
        // effective_at=0 视为立即生效，不作为「最晚生效时间」
        let data0 = json!({"plan": {"entitlements": [{"effective_at": 0}, {"effective_at": 1793631600}]}});
        assert_eq!(claim_timing(&data0).0, Some(1793631600));
    }

    #[test]
    fn preview_missing_data_is_error_not_empty_benefits() {
        // 服务端返回 code 0 但没有 data 字段：必须判为检测失败（客户端同样按错误处理）
        assert!(parse_preview_response(&json!({"code": 0, "msg": "", "logid": "x"})).is_err());
        // data 存在且 plans 为空：正常，确实没有可领项
        assert_eq!(parse_preview_response(&json!({"code": 0, "data": {"plans": []}})).unwrap().len(), 0);
        // 业务错误码带 msg
        assert_eq!(
            parse_preview_response(&json!({"code": 40001, "msg": "token invalid"})).unwrap_err(),
            "token invalid");
        // data 非对象同样是协议异常
        assert!(parse_preview_response(&json!({"code": 0, "data": null})).is_err());
        // 正常可领项
        let plans = parse_preview_response(&json!({"code": 0, "data": {"plans": [
            {"plan_id": "p1", "name": "体验套餐", "entitlements": [{"show_name": "GLM-5.3-Flash", "grant_units": 300000000}]}
        ]}})).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0]["plan_id"], json!("p1"));
    }

    #[test]
    fn captcha_html_embeds_sdk_and_nonce() {
        let h = captcha_html("scene1", "no8xfe", "cn", "abc123");
        assert!(h.contains("https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"));
        assert!(h.contains("SCENE_ID='scene1'"));
        assert!(h.contains("NONCE='abc123'"));
        assert!(h.contains("startTracelessVerification"));
        assert!(h.contains("NONCE+'/result'"));
    }
}
