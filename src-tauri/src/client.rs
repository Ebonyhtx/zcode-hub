use serde_json::{json, Value};
use std::sync::Mutex;

use crate::formats::{self, read_json};
use crate::platform;
use crate::settings::load_settings;
use crate::util::home_v2;

// exe 路径基本不变：命中缓存 5 分钟（含“没找到”的负结果），避免没装客户端时每 30 秒拉一次 PowerShell
pub(crate) static EXE_CACHE: Mutex<Option<(i64, Option<String>)>> = Mutex::new(None);

pub(crate) static VERSION_CACHE: Mutex<Option<(i64, Option<String>)>> = Mutex::new(None);

pub(crate) const EXE_CACHE_SECS: i64 = 300;

// Hub 的格式知识锚定在这个版本上；它只用于**展示与提示**，不是切换的门禁。
// 真正的判据是 formats::probe_credentials 的结构探测：客户端加字段不算问题，
// 改结构才会被探测抓到。升级客户端后按 CONTRIBUTING 的清单复核并更新此常量。
pub(crate) const VERIFIED_CLIENT_VERSION: &str = "3.17.2";

/// 未检测到客户端时的请求头回退版本（必须是 x.y.z 形态）
pub(crate) const DEFAULT_CLIENT_VERSION: &str = "3.17.2";

pub(crate) fn zcode_client_version() -> Option<String> {
    let mut g = VERSION_CACHE.lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some((ts, v)) = g.as_ref() {
        if now - ts < 3600 {
            return v.clone();
        }
    }
    let v = zcode_exe_path().and_then(|exe| platform::exe_product_version(&exe));
    *g = Some((now, v.clone()));
    v
}

/// 客户端版本相对「已验证版本」的关系。只做信息用途，不参与切换决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionStatus {
    /// major.minor 完全一致（补丁号不同也算，例如 3.17.2 vs 3.17.0）
    Match,
    /// 客户端比你验证过的更新（可能是刚升级）
    Newer,
    /// 客户端比你验证过的更旧
    Older,
    /// 任一侧无法解析
    Unknown,
}

fn parse_version(v: &str) -> Option<Vec<u64>> {
    let parts: Vec<u64> = v
        .trim()
        .split('.')
        .map(|p| p.trim().parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

/// 按数字段比较，不按字符串（`3.9` < `3.10`，字符串比较会反过来）。
/// 只比 major.minor；补丁号差异视为 Match——同一 minor 内的补丁不改变文件格式。
pub(crate) fn version_status(detected: &str, verified: &str) -> VersionStatus {
    let (Some(d), Some(v)) = (parse_version(detected), parse_version(verified)) else {
        return VersionStatus::Unknown;
    };
    let mm = |a: &[u64]| (a[0], a.get(1).copied().unwrap_or(0));
    let (dm, vm) = (mm(&d), mm(&v));
    if dm == vm {
        VersionStatus::Match
    } else if dm > vm {
        VersionStatus::Newer
    } else {
        VersionStatus::Older
    }
}

/// 兼容探测汇总：凭据/设置格式健康度 + 客户端版本。
///
/// `errors` 只放**结构性异常**（缺必需键、不可解析）——这些才该红；
/// 版本差异进 `notes`，属于信息性提示，不阻止切换。
// `live` 由调用方注入（一次读取，避免 get_state 里重复读盘/解密）。
pub(crate) fn compat_report(live: Option<&Value>) -> serde_json::Value {
    let mut probe = formats::probe_credentials(live);
    let setting = read_json(&home_v2().join("setting.json")).ok();
    let ps = formats::probe_setting(setting.as_ref());
    probe.errors.extend(ps.errors);
    probe.notes.extend(ps.notes);
    let ver = zcode_client_version();
    let status = match &ver {
        Some(v) => version_status(v, VERIFIED_CLIENT_VERSION),
        None => VersionStatus::Unknown,
    };
    match (&ver, status) {
        (Some(v), VersionStatus::Newer) => probe.notes.push(format!(
            "客户端版本 {} 高于已验证的 {}（信息性提示：文件结构仍由格式探测把关）",
            v, VERIFIED_CLIENT_VERSION
        )),
        (Some(v), VersionStatus::Older) => probe.notes.push(format!(
            "客户端版本 {} 低于已验证的 {}",
            v, VERIFIED_CLIENT_VERSION
        )),
        (None, _) => probe
            .notes
            .push("未检测到 ZCode 客户端版本（未安装或未指定路径）".into()),
        _ => {}
    }
    json!({"ok": probe.ok(), "errors": probe.errors, "notes": probe.notes,
           "zcode_version": ver, "verified_version": VERIFIED_CLIENT_VERSION,
           "version_status": format!("{:?}", status).to_lowercase(),
           "installed": zcode_exe_path().is_some()})
}

pub(crate) fn http() -> &'static reqwest::blocking::Client {
    HTTP.get_or_init(reqwest::blocking::Client::new)
}

pub(crate) fn zcode_exe_path() -> Option<String> {
    let now = chrono::Utc::now().timestamp();
    {
        let g = EXE_CACHE.lock().unwrap();
        if let Some((ts, p)) = g.as_ref() {
            if now - ts < EXE_CACHE_SECS {
                return p.clone();
            }
        }
    }
    // 用户在设置里指定的路径优先（失效则回落到自动探测，探测在 platform.rs）
    let user_path = load_settings()
        .get("zcode_path")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .filter(|p| std::path::Path::new(p).exists());
    let found = platform::detect_zcode_exe(user_path.as_deref());
    *EXE_CACHE.lock().unwrap() = Some((now, found.clone()));
    found
}

pub(crate) fn zcode_running() -> Result<bool, String> {
    platform::zcode_running()
}

pub(crate) fn kill_zcode_process() -> Result<bool, String> {
    platform::kill_zcode_process()
}

pub(crate) fn launch_zcode_process(exe: &str) -> bool {
    platform::launch_zcode_process(exe)
}

// 客户端完整版本号（事件上报/接口要求 "x.y.z" 形态；失败回退兼容锚点）
pub(crate) fn client_app_version() -> String {
    zcode_client_version()
        .map(|v| {
            let parts: Vec<&str> = v.split('.').collect();
            if parts.len() >= 3 {
                format!("{}.{}.{}", parts[0], parts[1], parts[2])
            } else {
                v
            }
        })
        .unwrap_or_else(|| DEFAULT_CLIENT_VERSION.to_string())
}

#[tauri::command]
pub(crate) fn open_zcode_client() -> serde_json::Value {
    let exe = zcode_exe_path().unwrap_or_default();
    if exe.is_empty() {
        return json!({"ok": false, "error": "未找到 ZCode 客户端，请在设置中指定路径"});
    }
    json!({"ok": launch_zcode_process(&exe)})
}

#[tauri::command(async)]
pub(crate) fn kill_zcode_client() -> serde_json::Value {
    match kill_zcode_process() {
        Ok(true) => json!({"ok": true}),
        Ok(false) => {
            json!({"ok": false, "error": "无法关闭 ZCode（可能仍在托盘运行），请手动退出"})
        }
        Err(e) => json!({"ok": false, "error": format!("无法确认 ZCode 进程状态：{}", e)}),
    }
}

pub(crate) static HTTP: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_status_compares_numerically_on_major_minor() {
        use VersionStatus::*;
        // 补丁号差异不算差异：同一 minor 内的补丁不改变文件格式
        assert_eq!(version_status("3.17.2", "3.17.0"), Match);
        assert_eq!(version_status("3.17.99", "3.17.2"), Match);
        assert_eq!(version_status("3.17", "3.17.2"), Match);
        // 客户端更新
        assert_eq!(version_status("3.18.0", "3.17.2"), Newer);
        assert_eq!(version_status("4.0.0", "3.99.9"), Newer);
        // 客户端更旧
        assert_eq!(version_status("3.16.5", "3.17.2"), Older);
        assert_eq!(version_status("2.0", "3.17.2"), Older);
        // 数字比较而非字符串：3.9 < 3.10
        assert_eq!(version_status("3.9.0", "3.10.0"), Older);
        assert_eq!(version_status("3.10.0", "3.9.0"), Newer);
        // 缺 minor 视为 0
        assert_eq!(version_status("3", "3.0.4"), Match);
        // 解析失败
        assert_eq!(version_status("", "3.17.2"), Unknown);
        assert_eq!(version_status("abc", "3.17.2"), Unknown);
        assert_eq!(version_status("3.x.1", "3.17.2"), Unknown);
    }

    /// 版本差异只做提示，绝不进 errors——与机器上装了什么无关。
    /// （旧版这个用例断言"notes 里没有'版本'字样"，在没装客户端的 CI runner 上必挂：
    /// 那种情况下会加一条"未检测到 ZCode 客户端版本"。这里改为断言真正的不变量。）
    #[test]
    fn version_mismatch_is_a_note_not_an_error() {
        let v = json!({"zcodejwttoken": "enc:v1:a.b.c"});
        let report = compat_report(Some(&v));
        let errors = report["errors"].as_array().unwrap();
        assert!(
            errors.is_empty(),
            "版本与未知字段都不该产生 error: {:?}",
            errors
        );
        assert_eq!(report["verified_version"], json!(VERIFIED_CLIENT_VERSION));
        let st = report["version_status"].as_str().unwrap();
        assert!(
            ["match", "newer", "older", "unknown"].contains(&st),
            "意外状态: {}",
            st
        );
        // 若检测到版本，state 必须与 version_status 判定一致
        match report["zcode_version"].as_str() {
            Some(detected) => {
                let expect = format!("{:?}", version_status(detected, VERIFIED_CLIENT_VERSION))
                    .to_lowercase();
                assert_eq!(st, expect);
            }
            None => assert_eq!(st, "unknown"),
        }
    }
}
