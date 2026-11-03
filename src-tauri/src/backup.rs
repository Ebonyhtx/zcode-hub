use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::benefits::{load_benefits_once, persist_benefits, BENEFITS, LAST_CHECK};
use crate::formats::{read_json, write_json};
use crate::platform;
use crate::quota::{load_quota_cache_once, persist_quota_cache, QUOTA_CACHE};
use crate::settings::{load_settings, save_settings};
use crate::util::{app_data_dir, audit_log, config_path, copy_dir_all, profiles_dir};

/// 自动备份间隔：24 小时；保留最近 7 份（可在设置里改 auto_backup / backup_keep）。
const BACKUP_INTERVAL_SECS: i64 = 24 * 3600;
const DEFAULT_KEEP: usize = 7;

static BACKUP_LOCK: Mutex<()> = Mutex::new(());

fn backup_root() -> PathBuf {
    app_data_dir().join("backups")
}

/// 备份根目录（不存在时创建），供「打开备份目录」命令使用。
pub(crate) fn ensure_backup_root() -> PathBuf {
    let root = backup_root();
    let _ = std::fs::create_dir_all(&root);
    root
}

/// 现有备份数量 + 最近一次时间，用于设置页展示。
pub(crate) fn backup_status() -> Value {
    let root = backup_root();
    let dirs = backup_dirs(&root);
    let latest = dirs
        .last()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string());
    let latest_at = dirs
        .last()
        .and_then(|d| read_json(&d.join("manifest.json")).ok())
        .and_then(|m| {
            m.get("created_at")
                .and_then(|v| v.as_str())
                .map(String::from)
        });
    json!({"ok": true, "count": dirs.len(), "latest": latest,
           "latest_at": latest_at, "path": root.display().to_string()})
}

/// 完整性判定：manifest 记录的账号数与实际账号目录数不一致时，说明备份可能被中断截断。
/// 实际少于记录 → 判为不完整（拒绝恢复，避免用残缺备份覆盖账号库）；
/// 实际多于记录 → 只是多出目录，可恢复但给出提示。
pub(crate) fn verify_counts(
    manifest_profiles: Option<u64>,
    actual: usize,
) -> (bool, Option<String>) {
    if actual == 0 {
        return (false, Some("备份里没有账号目录".into()));
    }
    match manifest_profiles {
        Some(n) if actual < n as usize => (
            false,
            Some(format!(
                "备份不完整：清单记录 {} 个账号，实际只有 {}",
                n, actual
            )),
        ),
        Some(n) if actual > n as usize => (
            true,
            Some(format!("备份含清单外目录：清单 {} 个，实际 {}", n, actual)),
        ),
        _ => (true, None),
    }
}

fn count_profile_dirs(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0)
}

/// 单份备份的展示条目：目录名 + manifest 元数据 + 完整性。
pub(crate) fn backup_entry(dir: &Path) -> Value {
    let manifest = read_json(&dir.join("manifest.json"))
        .ok()
        .unwrap_or(json!({}));
    let manifest_profiles = manifest.get("profiles").and_then(|v| v.as_u64());
    let actual = count_profile_dirs(&dir.join("profiles"));
    let (ok, warning) = verify_counts(manifest_profiles, actual);
    json!({
        "name": dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        "created_at": manifest.get("created_at").cloned().unwrap_or(Value::Null),
        "hub_version": manifest.get("hub_version").cloned().unwrap_or(Value::Null),
        "profiles": actual,
        "manifest_profiles": manifest_profiles,
        "verified": ok,
        "warning": warning,
    })
}

/// 全部备份条目，最新在前（目录名是时间戳，字典序即时间序）。
pub(crate) fn list_backups(root: &Path) -> Vec<Value> {
    let mut entries: Vec<Value> = backup_dirs(root).iter().map(|d| backup_entry(d)).collect();
    entries.reverse();
    entries
}

/// 解析要恢复的备份：None = 最新一份；Some(name) 必须是备份根目录下的直接子目录。
pub(crate) fn resolve_backup(root: &Path, name: Option<&str>) -> Result<PathBuf, String> {
    let mut dirs = backup_dirs(root);
    let Some(name) = name.map(str::trim).filter(|s| !s.is_empty()) else {
        return dirs.pop().ok_or_else(|| "没有可恢复的备份".to_string());
    };
    let valid_name = !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "-_".contains(c));
    if !valid_name {
        return Err("备份标识无效".into());
    }
    dirs.into_iter()
        .find(|d| d.file_name().map(|n| n == name).unwrap_or(false))
        .ok_or_else(|| "找不到该备份（可能已被清理）".to_string())
}

/// 恢复指定备份（默认最新一份）。先把当前账号库复制到临时目录，再做一份安全备份，
/// 然后用备份替换 profiles；失败时回滚到原目录。
#[tauri::command(async)]
pub(crate) fn restore_backup(name: Option<String>) -> Value {
    let _guard = BACKUP_LOCK.lock().unwrap();
    let root = backup_root();
    let target = match resolve_backup(&root, name.as_deref()) {
        Ok(t) => t,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let src = target.join("profiles");
    if !src.is_dir() {
        return json!({"ok": false, "error": "备份缺少 profiles 目录"});
    }
    // 恢复前校验完整性：残缺备份绝不覆盖账号库（见 verify_counts）
    let entry = backup_entry(&target);
    let manifest_profiles = entry.get("manifest_profiles").and_then(|v| v.as_u64());
    let (verified, warning) = verify_counts(manifest_profiles, count_profile_dirs(&src));
    if !verified {
        return json!({"ok": false, "error": warning.unwrap_or_else(|| "备份校验失败".into()),
                       "backup": target.file_name().map(|n| n.to_string_lossy().to_string())});
    }
    let dest = profiles_dir();
    let tmp = app_data_dir().join(format!("profiles.restore-tmp-{}", rand::random::<u32>()));
    if let Err(e) = copy_dir_all(&src, tmp.clone()) {
        let _ = std::fs::remove_dir_all(&tmp);
        return json!({"ok": false, "error": format!("读取备份失败: {}", e)});
    }
    // 安全备份当前状态；失败不阻断恢复（临时副本已经就绪）。
    let _ = create_backup_inner();
    let old = app_data_dir().join(format!(
        "profiles.restore-old-{}",
        chrono::Utc::now().timestamp_millis()
    ));
    let had_dest = dest.exists();
    if had_dest {
        if let Err(e) = std::fs::rename(&dest, &old) {
            let _ = std::fs::remove_dir_all(&tmp);
            return json!({"ok": false, "error": format!("暂存当前账号库失败: {}", e)});
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        if had_dest {
            let _ = std::fs::rename(&old, &dest);
        }
        let _ = std::fs::remove_dir_all(&tmp);
        return json!({"ok": false, "error": format!("替换账号库失败: {}", e)});
    }
    if had_dest {
        let _ = std::fs::remove_dir_all(&old);
    }
    let restored = count_profile_dirs(&dest);
    // 旧额度/福利缓存指向恢复前的账号集合，留着会让卡片显示已不存在的账号额度
    let cleared = clear_account_caches();
    audit_log(
        "restore_backup",
        None,
        json!({"backup": target.file_name().map(|n| n.to_string_lossy().to_string()),
               "accounts": restored, "caches_cleared": cleared}),
    );
    json!({"ok": true, "restored": restored,
           "backup": target.file_name().map(|n| n.to_string_lossy().to_string()),
           "warning": warning, "caches_cleared": cleared})
}

/// 恢复后清空额度/福利的内存与落盘缓存，返回清掉的条目数。
pub(crate) fn clear_account_caches() -> usize {
    load_quota_cache_once();
    load_benefits_once();
    let qn = {
        let mut g = QUOTA_CACHE.lock().unwrap();
        let n = g.as_ref().map(|m| m.len()).unwrap_or(0);
        *g = Some(Default::default());
        n
    };
    let bn = {
        let mut g = BENEFITS.lock().unwrap();
        let n = g.as_ref().map(|m| m.len()).unwrap_or(0);
        *g = Some(Default::default());
        n
    };
    *LAST_CHECK.lock().unwrap() = None;
    persist_quota_cache();
    persist_benefits();
    qn + bn
}

#[tauri::command(async)]
pub(crate) fn list_backups_cmd() -> Value {
    json!({"ok": true, "items": list_backups(&backup_root())})
}

#[tauri::command(async)]
pub(crate) fn open_backup_dir() -> Value {
    let root = ensure_backup_root();
    platform::open_dir_explorer(&root);
    json!({"ok": true, "path": root.display().to_string()})
}

#[tauri::command(async)]
pub(crate) fn get_backup_status() -> Value {
    backup_status()
}

/// 是否到期：从未备份过也算到期。
pub(crate) fn backup_due(last: i64, now: i64, interval_secs: i64) -> bool {
    last <= 0 || now.saturating_sub(last) >= interval_secs
}

fn backup_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_dir())
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs
}

/// 只保留最新 keep 份，返回删除数量。目录名是时间戳，字典序即时间序。
pub(crate) fn prune_backups(root: &Path, keep: usize) -> usize {
    let dirs = backup_dirs(root);
    let keep = keep.max(1);
    if dirs.len() <= keep {
        return 0;
    }
    let mut removed = 0;
    for d in dirs.iter().take(dirs.len() - keep) {
        if std::fs::remove_dir_all(d).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// 立即做一份本地备份：profiles（DPAPI 快照，换机不可用）+ 设置副本 + manifest。
/// 这是本机恢复点，不是跨机迁移包；跨机请继续用手动 .zhb 导出。
pub(crate) fn create_backup() -> Value {
    let _guard = BACKUP_LOCK.lock().unwrap();
    create_backup_inner()
}

fn create_backup_inner() -> Value {
    let src = profiles_dir();
    if !src.exists() {
        return json!({"ok": false, "error": "账号库为空，跳过备份"});
    }
    let root = backup_root();
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let dest = root.join(&stamp);
    if let Err(e) = std::fs::create_dir_all(&dest) {
        return json!({"ok": false, "error": format!("创建备份目录失败: {}", e)});
    }
    let fail = |msg: String| {
        let _ = std::fs::remove_dir_all(&dest);
        json!({"ok": false, "error": msg})
    };
    if let Err(e) = copy_dir_all(&src, dest.join("profiles")) {
        return fail(format!("复制账号库失败: {}", e));
    }
    let cfg = config_path();
    if cfg.exists() {
        if let Err(e) = std::fs::copy(&cfg, dest.join("hub-config.json")) {
            return fail(format!("复制设置失败: {}", e));
        }
    }
    let profiles = std::fs::read_dir(&src)
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);
    let manifest = json!({
        "format": "zcode-hub-local-backup", "version": 1,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "hub_version": env!("CARGO_PKG_VERSION"),
        "profiles": profiles,
    });
    if let Err(e) = write_json(&dest.join("manifest.json"), &manifest) {
        return fail(format!("写入备份清单失败: {}", e));
    }
    let keep = load_settings()
        .get("backup_keep")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_KEEP as i64)
        .clamp(1, 30) as usize;
    let removed = prune_backups(&root, keep);
    let mut s = load_settings();
    s["last_backup_at"] = json!(chrono::Utc::now().timestamp());
    let _ = save_settings(&s);
    json!({"ok": true, "path": dest.display().to_string(), "profiles": profiles,
           "kept": keep, "removed": removed})
}

/// 自动备份入口：关闭开关或未到期时直接跳过（best-effort）。
pub(crate) fn run_backup_if_due() -> Value {
    let s = load_settings();
    if !s
        .get("auto_backup")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        return json!({"ok": true, "skipped": "disabled"});
    }
    let now = chrono::Utc::now().timestamp();
    let last = s
        .get("last_backup_at")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if !backup_due(last, now, BACKUP_INTERVAL_SECS) {
        return json!({"ok": true, "skipped": "not_due"});
    }
    create_backup()
}

#[tauri::command(async)]
pub(crate) fn backup_now() -> Value {
    create_backup()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zhb-backup-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn backup_due_logic() {
        assert!(backup_due(0, 100, 3600));
        assert!(!backup_due(100, 100, 3600));
        assert!(backup_due(100, 3701, 3600));
        assert!(!backup_due(100, 3699, 3600));
    }

    #[test]
    fn prune_keeps_newest_backups() {
        let root = tmp("prune");
        for name in [
            "20260101-000001",
            "20260102-000001",
            "20260103-000001",
            "20260104-000001",
        ] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        assert_eq!(prune_backups(&root, 2), 2);
        let left: Vec<String> = backup_dirs(&root)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, vec!["20260103-000001", "20260104-000001"]);
        assert_eq!(prune_backups(&root, 5), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_counts_rejects_truncated_backups() {
        // 无清单：只要能读到账号目录就允许恢复
        assert_eq!(verify_counts(None, 2), (true, None));
        // 数量一致
        assert_eq!(verify_counts(Some(3), 3), (true, None));
        // 实际更少 → 不完整，拒绝恢复（关键防线：残缺备份不能覆盖账号库）
        let (ok, warning) = verify_counts(Some(3), 2);
        assert!(!ok);
        assert!(warning.unwrap().contains('3'));
        // 实际更多 → 允许但提示
        let (ok, warning) = verify_counts(Some(1), 3);
        assert!(ok);
        assert!(warning.unwrap().contains("清单外"));
        // 空目录永远拒绝
        assert!(!verify_counts(Some(0), 0).0);
        assert!(!verify_counts(None, 0).0);
    }

    #[test]
    fn resolve_backup_defaults_to_newest_and_blocks_traversal() {
        let root = tmp("resolve");
        for name in ["20260101-000001", "20260102-000001"] {
            std::fs::create_dir_all(root.join(name).join("profiles")).unwrap();
        }
        let newest = resolve_backup(&root, None).unwrap();
        assert_eq!(newest.file_name().unwrap(), "20260102-000001");
        let picked = resolve_backup(&root, Some(" 20260101-000001 ")).unwrap();
        assert_eq!(picked.file_name().unwrap(), "20260101-000001");
        for bad in ["..", "../profiles", "a/b", "a\\b", ".hidden", "nope"] {
            assert!(
                resolve_backup(&root, Some(bad)).is_err(),
                "应拒绝: {:?}",
                bad
            );
        }
        let empty = tmp("resolve-empty");
        assert!(resolve_backup(&empty, None).is_err());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn list_backups_is_newest_first_with_metadata() {
        let root = tmp("list");
        for (name, profiles) in [("20260101-000001", 2), ("20260102-000001", 2)] {
            let d = root.join(name);
            std::fs::create_dir_all(d.join("profiles")).unwrap();
            write_json(
                &d.join("manifest.json"),
                &json!({"created_at": "2026-01-01T00:00:00Z", "profiles": profiles,
                        "hub_version": "1.10.1"}),
            )
            .unwrap();
        }
        // 第二份清单说 2 个账号但只有 1 个目录 → 不完整
        for i in 0..2 {
            std::fs::create_dir_all(
                root.join("20260101-000001")
                    .join("profiles")
                    .join(format!("p{}", i)),
            )
            .unwrap();
        }
        std::fs::create_dir_all(root.join("20260102-000001").join("profiles").join("p0")).unwrap();
        let items = list_backups(&root);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["name"], json!("20260102-000001"), "最新在前");
        assert_eq!(items[0]["profiles"], json!(1));
        assert_eq!(items[0]["verified"], json!(false));
        assert!(items[0]["warning"].as_str().unwrap().contains("不完整"));
        assert_eq!(items[1]["verified"], json!(true));
        assert_eq!(items[1]["manifest_profiles"], json!(2));
        assert_eq!(items[1]["hub_version"], json!("1.10.1"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
