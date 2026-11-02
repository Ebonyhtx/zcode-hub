use serde_json::{json, Value};
use std::sync::Mutex;

use crate::client::client_app_version;
use crate::crypto::{encrypt_value, write_snapshot};
use crate::formats::{self, read_json, write_json};
use crate::identity::{ensure_profile_arms_uid, ensure_profile_device_mid, unique_profile_dir};
use crate::platform;
use crate::util::audit_log;

pub(crate) static OAUTH_STATE: Mutex<Option<Value>> = Mutex::new(None);

/// 每次 oauth_start/oauth_cancel 递增；旧 worker 发现自己不是最新代次就静默退出，
/// 避免“取消后又开始”被上一轮轮询回写 ready/failed。
pub(crate) static OAUTH_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn set_oauth(v: Value) { *OAUTH_STATE.lock().unwrap() = Some(v); }

pub(crate) fn get_oauth() -> Option<Value> { OAUTH_STATE.lock().unwrap().clone() }

pub(crate) fn oauth_alive(gen: u64) -> bool { OAUTH_GEN.load(std::sync::atomic::Ordering::SeqCst) == gen }

pub(crate) fn set_oauth_if(gen: u64, v: Value) { if oauth_alive(gen) { set_oauth(v); } }

pub(crate) fn allowed_oauth_host(host: &str) -> bool {
    // 官方域及其子域；避免服务端换成 open.bigmodel.cn 等入口时把正常登录挡掉
    host == "z.ai" || host.ends_with(".z.ai")
        || host == "bigmodel.cn" || host.ends_with(".bigmodel.cn")
}

pub(crate) fn generate_poll_token() -> String {
    (0..32).map(|_| format!("{:02x}", rand::random::<u8>())).collect()
}

// 用系统 Shell 处理协议分发（等价于 Win+R 打开 URL），不经任何命令行解析，URL 里的 & % ? 都安全
pub(crate) fn open_in_browser(url: &str) { platform::open_in_browser(url) }

pub(crate) fn oauth_worker(provider: String, poll_token: String, gen: u64) {
    let client = reqwest::blocking::Client::new();
    let fail = |msg: String| {
        // 失败态保留 authorize_url，用户可直接重开登录页而不是从头再来
        let url = get_oauth()
            .and_then(|s| s.get("authorize_url").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_default();
        set_oauth_if(gen, json!({"status":"failed","error":msg,"authorize_url":url}));
    };
    // init
    let init = client.post("https://zcode.z.ai/api/v1/oauth/cli/init")
        .header("Authorization", format!("Bearer {}", poll_token))
        .header("Content-Type", "application/json")
        .body(json!({"provider": provider}).to_string())
        .timeout(std::time::Duration::from_secs(20))
        .send();
    let init = match init { Ok(r) => r, Err(e) => return fail(e.to_string()) };
    let j: Value = match init.json() { Ok(j) => j, Err(e) => return fail(e.to_string()) };
    if j.get("code").and_then(|c| c.as_i64()) != Some(0) {
        return fail(j.get("msg").and_then(|m| m.as_str()).unwrap_or("init error").to_string());
    }
    let d = j.get("data").cloned().unwrap_or(json!({}));
    let raw_authorize_url = d.get("authorize_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // 官方桌面端会用带 ? 的登录页 URL 覆盖回调参数（见 asar 内 startOAuthWithPolling）：
    //   zai      → 覆盖 redirect_uri 参数
    //   bigmodel → 覆盖 redirect 参数
    // 服务端拼接重定向时无条件下 &，裸回调值（无 query）会被拼坏成 /callback/xxx&state=... → 404。
    let authorize_url = {
        let desktop_redirect = format!(
            "https://zcode.z.ai/app/oauth/login?redirect=zcode://oauth/callback&app_version={}",
            client_app_version());
        let param = if provider == "bigmodel" { "redirect" } else { "redirect_uri" };
        match url::Url::parse(&raw_authorize_url) {
            Ok(mut u) => {
                // 只允许官方 https 域名，避免服务端响应被篡改后交给 ShellExecute 打开本地协议
                if u.scheme() != "https" || !u.host_str().map(allowed_oauth_host).unwrap_or(false) {
                    return fail("登录页地址不在官方域名白名单内，已取消".into());
                }
                let pairs: Vec<(String, String)> = u.query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .filter(|(k, _)| k != param && k != "redirect_uri" && k != "redirect")
                    .collect();
                {
                    let mut q = u.query_pairs_mut();
                    q.clear();
                    for (k, v) in &pairs { q.append_pair(k, v); }
                    q.append_pair(param, &desktop_redirect);
                }
                u.to_string()
            }
            Err(_) => return fail("登录页地址无效，已取消".into()),
        }
    };
    let flow_id = d.get("flow_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let interval = d.get("poll_interval_sec").and_then(|v| v.as_u64()).unwrap_or(2).clamp(1, 10);
    let expires = d.get("expires_at").and_then(|v| v.as_f64()).unwrap_or(0.0);

    if !oauth_alive(gen) { return; }
    set_oauth(json!({"status":"pending","provider": provider, "authorize_url": authorize_url}));
    platform::open_in_browser(&authorize_url);

    let deadline = if expires > 0.0 { expires } else { 600.0 };
    loop {
        if !oauth_alive(gen) { return; }
        if chrono::Utc::now().timestamp() as f64 > deadline {
            return fail("timeout".into());
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
        if !oauth_alive(gen) { return; }
        let poll = client.get(format!("https://zcode.z.ai/api/v1/oauth/cli/poll/{}", flow_id))
            .header("Authorization", format!("Bearer {}", poll_token))
            .timeout(std::time::Duration::from_secs(15))
            .send();
        let poll = match poll { Ok(r) => r, Err(_) => continue };
        let pj: Value = match poll.json() { Ok(j) => j, Err(_) => continue };
        let pd = pj.get("data").cloned().unwrap_or(json!({}));
        let status = pd.get("status").and_then(|v| v.as_str()).unwrap_or("pending");
        if status == "pending" { continue; }
        if status != "ready" {
            return fail(format!("login failed: {}", status));
        }
        if !oauth_alive(gen) { return; }
        let user = pd.get("user").cloned().unwrap_or(json!({}));
        // 官方 CLI 轮询响应：zai → data.zai.access_token；bigmodel → data.bigmodel.access_token(+refresh_token)
        let pdata = pd.get(&provider).cloned().unwrap_or(json!({}));
        let access_token = pdata.get("access_token").and_then(|v| v.as_str())
            .or_else(|| pdata.get("accessToken").and_then(|v| v.as_str()))
            .unwrap_or("").to_string();
        let refresh_token = pdata.get("refresh_token").and_then(|v| v.as_str())
            .or_else(|| pdata.get("refreshToken").and_then(|v| v.as_str()))
            .unwrap_or("").to_string();
        let token = pd.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // 官方 ZaiBusinessTokenResolver：poll 返回的 zai access_token 只有 1 小时寿命，
        // 必须先到 api.z.ai/api/auth/z/login 换成长效业务 token 再入库，否则切换后一小时内就报过期
        let mut warning = String::new();
        let access_token = if provider == "zai" && !access_token.is_empty() {
            match client.post("https://api.z.ai/api/auth/z/login")
                .header("Content-Type", "application/json")
                .body(json!({"token": access_token}).to_string())
                .timeout(std::time::Duration::from_secs(15))
                .send() {
                Ok(r) => match r.json::<Value>() {
                    Ok(j) => {
                        let bt = j.pointer("/data/access_token").and_then(|v| v.as_str())
                            .or_else(|| j.pointer("/data/accessToken").and_then(|v| v.as_str()))
                            .map(|s| s.trim().to_string()).unwrap_or_default();
                        if bt.is_empty() {
                            warning = "业务 token 交换失败（响应缺少 access_token），保存的是 1 小时临时 token，请重新登录".into();
                            access_token
                        } else { bt }
                    }
                    Err(e) => { warning = format!("业务 token 交换失败（{}），保存的是 1 小时临时 token", e); access_token }
                },
                Err(e) => { warning = format!("业务 token 交换失败（{}），保存的是 1 小时临时 token", e); access_token }
            }
        } else { access_token };
        let user_id = user.get("user_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let label = user.get("name").and_then(|v| v.as_str())
            .or(user.get("email").and_then(|v| v.as_str()))
            .unwrap_or(&user_id).trim().to_string();
        let label = if label.is_empty() { "account".to_string() } else { label };
        let avatar = user.get("avatar").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // 客户端启动恢复会话时按规范化档案 {id,username,displayName,avatarUrl?,rawProfile} 解析，
        // 原始 poll 的 user 对象（{user_id,name,...}）缺 id/username 会被判定无效 → 未登录
        let mut pnorm = serde_json::Map::new();
        pnorm.insert("id".into(), json!(user_id));
        pnorm.insert("username".into(), json!(label));
        pnorm.insert("displayName".into(), json!(label));
        if !avatar.is_empty() { pnorm.insert("avatarUrl".into(), json!(avatar)); }
        pnorm.insert("rawProfile".into(), user.clone());
        let profile_norm = Value::Object(pnorm);

        // 官方凭据键名（见 asar oauthCredentialRepo）：oauth:{provider}:access_token|refresh_token|user_info
        // + zcodejwttoken + oauth:active_provider（键名常量与解析逻辑收敛在 formats.rs）
        let mut encrypted = std::collections::HashMap::new();
        encrypted.insert(formats::FIELD_ACTIVE_PROVIDER.to_string(), encrypt_value(&provider));
        encrypted.insert(formats::oauth_field(&provider, "access_token"), encrypt_value(&access_token));
        if !refresh_token.is_empty() {
            encrypted.insert(formats::oauth_field(&provider, "refresh_token"), encrypt_value(&refresh_token));
        }
        encrypted.insert(formats::oauth_field(&provider, "user_info"), encrypt_value(&profile_norm.to_string()));
        encrypted.insert(formats::FIELD_TOKEN.to_string(), encrypt_value(&token));
        let encrypted_v = serde_json::to_value(&encrypted).unwrap_or(json!({}));
        if !oauth_alive(gen) { return; } // 用户已取消/已开始新流程，不再落盘
        // 同账号（token 指纹相同）→ 更新原存档；不同账号同名 → 自动加后缀，绝不覆盖
        let (prof_dir, safe, updated) = unique_profile_dir(&label, &encrypted_v);
        if let Err(e) = write_snapshot(&prof_dir, &encrypted_v) {
            if !updated { let _ = std::fs::remove_dir_all(&prof_dir); }
            return fail(format!("保存登录凭据失败: {}", e));
        }
        let mut meta = read_json(&prof_dir.join("meta.json")).ok().unwrap_or(json!({}));
        let keep = meta.get("label").and_then(|v| v.as_str()).map(String::from);
        meta["label"] = json!(if updated { keep.unwrap_or_else(|| label.clone()) } else { label.clone() });
        meta["provider"] = json!(provider);
        meta["captured_at"] = json!(chrono::Utc::now().to_rfc3339());
        let _mid = ensure_profile_device_mid(&prof_dir, &mut meta, false);
        let _auid = ensure_profile_arms_uid(&prof_dir, &mut meta, false);
        if let Err(e) = write_json(&prof_dir.join("meta.json"), &meta) {
            if !updated { let _ = std::fs::remove_dir_all(&prof_dir); }
            return fail(format!("保存账号元数据失败: {}", e));
        }
        // 注意：新增账号只写存档，不切换 live 凭据，因此绝不能改 setting.json 的 providerFamilyDomain
        set_oauth_if(gen, json!({"status":"ready","label": label, "provider": provider, "name": safe,
                                 "updated": updated, "warning": warning}));
        audit_log("oauth_add", Some(&safe), json!({"provider": provider, "updated": updated}));
        return;
    }
}

#[tauri::command]
pub(crate) fn oauth_start(provider: Option<String>) -> serde_json::Value {
    let provider = provider.unwrap_or_else(|| "zai".to_string());
    if provider != "zai" && provider != "bigmodel" {
        return json!({"ok": false, "error": format!("unknown provider: {}", provider)});
    }
    // 已有流程在跑：返回可恢复状态，前端继续轮询/重开登录页，而不是报裸错误
    if let Some(s) = get_oauth() {
        if s.get("status").and_then(|v| v.as_str()) == Some("pending") {
            return json!({"ok": true, "already": true, "status": s});
        }
    }
    let gen = OAUTH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    set_oauth(json!({"status":"pending","provider": provider, "started_at": chrono::Utc::now().to_rfc3339()}));
    let poll_token = generate_poll_token();
    std::thread::spawn(move || { oauth_worker(provider, poll_token, gen); });
    json!({"ok": true})
}

#[tauri::command]
pub(crate) fn oauth_cancel() -> serde_json::Value {
    OAUTH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    set_oauth(json!({"status": "idle"}));
    json!({"ok": true})
}

#[tauri::command]
pub(crate) fn oauth_status() -> serde_json::Value {
    match get_oauth() {
        Some(s) => s,
        None => json!({"status": "idle"}),
    }
}

#[tauri::command]
pub(crate) fn oauth_open() -> serde_json::Value {
    if let Some(s) = get_oauth() {
        let url = s.get("authorize_url").and_then(|v| v.as_str()).unwrap_or("");
        if !url.is_empty() {
            let valid = url::Url::parse(url).ok()
                .map(|u| u.scheme() == "https" && u.host_str().map(allowed_oauth_host).unwrap_or(false))
                .unwrap_or(false);
            if !valid { return json!({"ok": false, "error": "登录页地址不在官方域名白名单内"}); }
            open_in_browser(url);
            return json!({"ok": true});
        }
    }
    json!({"ok": false, "error": "no pending oauth"})
}
