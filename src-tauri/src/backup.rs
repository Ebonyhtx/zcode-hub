use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::formats::{read_json, write_json};
use crate::platform;
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

/// 恢复最近一份本地备份：先把当前账号库复制到临时目录，再做一份安全备份，
/// 然后用备份替换 profiles。失败时回滚到原目录。
#[tauri::command(async)]
pub(crate) fn restore_latest_backup() -> Value {
    let _guard = BACKUP_LOCK.lock().unwrap();
    let root = backup_root();
    let Some(target) = backup_dirs(&root).pop() else {
        return json!({"ok": false, "error": "没有可恢复的备份"});
    };
    let src = target.join("profiles");
    if !src.is_dir() {
        return json!({"ok": false, "error": "备份缺少 profiles 目录"});
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
    let restored = std::fs::read_dir(&dest)
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);
    audit_log(
        "restore_backup",
        None,
        json!({"backup": target.file_name().map(|n| n.to_string_lossy().to_string()),
               "accounts": restored}),
    );
    json!({"ok": true, "restored": restored,
           "backup": target.file_name().map(|n| n.to_string_lossy().to_string())})
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
}
