//! 崩溃与异常日志（`crash.log`）。
//!
//! 进程 panic 与前端未捕获异常都会追加到这里，用户报障时有据可查；
//! 诊断报告带最后若干条。隐私：只记消息与位置，不记令牌/邮箱/路径中的用户名
//! （路径经 `redact` 只保留文件名）。文件超过 512KB 时保留最新一半。

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const CRASH_FILE: &str = "crash.log";
const CRASH_MAX_BYTES: u64 = 512 * 1024;
/// 单条消息上限：堆栈/长错误不应把日志撑爆
const MAX_MSG_CHARS: usize = 2000;

/// panic hook 与其他写入点可能并发，串行化追加与轮转。
/// 中毒状态统一用 `lock_unpoisoned` 恢复：日志锁一旦中毒就永久失效是不可接受的。
static CRASH_LOCK: Mutex<()> = Mutex::new(());

/// 取锁并忽略中毒：崩溃日志是最后一道证据，锁状态不该成为写入障碍。
fn lock_unpoisoned() -> std::sync::MutexGuard<'static, ()> {
    CRASH_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn crash_path(app_data: &Path) -> PathBuf {
    app_data.join(CRASH_FILE)
}

/// 把绝对路径压成文件名：日志里不出现用户名/目录结构。
///
/// 不能只用 `Path::file_name()`：在 Linux/macOS 上反斜杠不是分隔符，
/// Windows 风格路径会被整串返回（用户名泄漏）。这里按两种分隔符手工切分，
/// 使脱敏行为与运行平台无关。
pub fn redact_path(p: &str) -> String {
    let trimmed = p.trim().trim_matches('"');
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| "?".into())
}

/// 截断超长消息（按字符，不切断 UTF-8）。
pub fn clamp_msg(msg: &str) -> String {
    let msg = msg.replace(['\r', '\n'], " ");
    let mut out: String = msg.trim().chars().take(MAX_MSG_CHARS).collect();
    if msg.trim().chars().count() > MAX_MSG_CHARS {
        out.push('…');
    }
    out
}

/// 超过阈值时原子地保留最新一半行。
pub fn rotate_if_needed(path: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(());
    };
    if meta.len() <= CRASH_MAX_BYTES {
        return Ok(());
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = content.lines().collect();
    let keep = &lines[lines.len() / 2..];
    let body = if keep.is_empty() {
        String::new()
    } else {
        format!("{}\n", keep.join("\n"))
    };
    let tmp = path.with_extension("log.hub-tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// 追加一条崩溃记录。`kind` 区分来源：`panic` / `frontend` / `webview`。
/// best-effort：任何 IO 失败都静默（崩溃路径上不能再制造崩溃）。
pub fn append(
    path: &Path,
    kind: &str,
    msg: &str,
    location: Option<&str>,
    extra: Option<Value>,
) -> Result<(), String> {
    // 锁中毒也必须继续写：恰好在写日志时 panic 的情况下，这里正是唯一的证据来源。
    let _guard = lock_unpoisoned();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    rotate_if_needed(path)?;
    let entry = build_entry(kind, msg, location, extra);
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?
        .write_all(format!("{}\n", entry).as_bytes())
        .map_err(|e| e.to_string())
}

/// panic 位置形如 `src\identity.rs:120:9` 或带绝对路径的前缀——只保留文件名与行号。
pub fn redact_location(loc: &str) -> String {
    let parts: Vec<&str> = loc.rsplitn(3, ':').collect();
    match parts.as_slice() {
        [line, col, rest]
            if line.chars().all(|c| c.is_ascii_digit())
                && col.chars().all(|c| c.is_ascii_digit()) =>
        {
            format!("{}:{}:{}", redact_path(rest), col, line)
        }
        _ => redact_path(loc),
    }
}

/// panic 路径专用：**绝不阻塞**。若锁已被占用（典型情况：panic 就发生在写日志过程中），
/// 退化成无轮转的裸追加——宁可日志略大，也不能在 hook 里死锁或再次 panic。
pub fn append_no_block(
    path: &Path,
    kind: &str,
    msg: &str,
    location: Option<&str>,
    extra: Option<Value>,
) {
    let body = || -> Result<(), String> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let entry = build_entry(kind, msg, location, extra);
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?
            .write_all(format!("{}\n", entry).as_bytes())
            .map_err(|e| e.to_string())
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match CRASH_LOCK.try_lock() {
            Ok(_guard) => {
                let _ = rotate_if_needed(path);
                let _ = body();
            }
            // 锁被占：正在别处写日志。跳过轮转，直接追加一行。
            Err(std::sync::TryLockError::WouldBlock) => {
                let _ = body();
            }
            Err(std::sync::TryLockError::Poisoned(e)) => {
                let _guard = e.into_inner();
                let _ = body();
            }
        }
    }));
}

/// 统一的日志行构造（`append` 与 `append_no_block` 共用，保证字段一致）。
fn build_entry(kind: &str, msg: &str, location: Option<&str>, extra: Option<Value>) -> Value {
    let mut entry = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "kind": kind,
        "msg": clamp_msg(msg),
    });
    if let Some(loc) = location.filter(|s| !s.trim().is_empty()) {
        entry["at"] = json!(redact_location(loc));
    }
    if let Some(e) = extra {
        entry["extra"] = e;
    }
    entry
}

/// 安装全局 panic hook：写入 `crash.log` 后继续调用原有 hook（默认行为不变，
/// 例如 stderr 在 debug 构建下仍然可见）。
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "非字符串 panic".to_string()
        };
        let thread = std::thread::current()
            .name()
            .map(String::from)
            .unwrap_or_else(|| "unnamed".into());
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        append_no_block(
            &crash_path(&crate::util::app_data_dir()),
            "panic",
            &msg,
            loc.as_deref(),
            Some(json!({"thread": thread})),
        );
        default_hook(info);
    }));
}

/// 读取最后 `max` 条（诊断报告用）。坏行跳过，不影响其余。
pub fn tail(path: &Path, max: usize) -> Vec<Value> {
    let Ok(txt) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = txt.lines().collect();
    lines
        .iter()
        .rev()
        .take(max)
        .rev()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_log(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zhb-crash-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_writes_jsonl_and_redacts_location() {
        let d = tmp_log("append");
        let p = crash_path(&d);
        append(
            &p,
            "panic",
            "assertion failed: `x > 0`",
            Some("C:\\Users\\alice\\zcode-hub\\src-tauri\\src\\identity.rs:120:9"),
            Some(json!({"thread": "main"})),
        )
        .unwrap();
        let txt = std::fs::read_to_string(&p).unwrap();
        let v: Value = serde_json::from_str(txt.lines().next().unwrap()).unwrap();
        assert_eq!(v["kind"], json!("panic"));
        assert_eq!(v["at"], json!("identity.rs:120:9"));
        assert!(!txt.contains("alice"), "日志不得包含用户名/路径: {}", txt);
        assert_eq!(v["extra"]["thread"], json!("main"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn panic_path_never_deadlocks_when_lock_is_held() {
        // 模拟「panic 发生在写日志过程中」：锁被别的线程占用时 panic 路径仍要落盘且不阻塞。
        // 用 lock_unpoisoned 取锁：另一个测试可能故意让锁中毒，本用例不应因此失败。
        let d = tmp_log("panichook");
        let p = crash_path(&d);
        let held = lock_unpoisoned();
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = p.clone();
        std::thread::spawn(move || {
            append_no_block(&p2, "panic", "while logging", Some("src/x.rs:1:1"), None);
            let _ = tx.send(());
        });
        // 100ms 内必须完成：正常实现走 WouldBlock 分支直接追加
        rx.recv_timeout(std::time::Duration::from_millis(500))
            .expect("panic 路径在锁被占用时不应阻塞");
        drop(held);
        let rows = tail(&p, 5);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["msg"], json!("while logging"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn poisoned_lock_still_writes() {
        let d = tmp_log("poison");
        let p = crash_path(&d);
        // 让锁中毒：持锁线程 panic
        let _ = std::panic::catch_unwind(|| {
            let _g = lock_unpoisoned();
            panic!("poison it");
        });
        append(&p, "frontend", "after poison", None, None).unwrap();
        assert_eq!(tail(&p, 5).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rotate_keeps_newest_half() {
        let d = tmp_log("rotate");
        let p = crash_path(&d);
        let filler = "x".repeat(MAX_MSG_CHARS);
        for _ in 0..400 {
            append(&p, "frontend", &filler, None, None).unwrap();
        }
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(
            after.len() as u64 <= CRASH_MAX_BYTES + 8192,
            "轮转后应显著缩小"
        );
        assert!(after.lines().count() < 400);
        // 每条仍是合法 JSON
        for l in after.lines() {
            serde_json::from_str::<Value>(l).unwrap();
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tail_reads_newest_and_skips_broken_lines() {
        let d = tmp_log("tail");
        let p = crash_path(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(&p, "{\"msg\":\"a\"}\nnot-json\n{\"msg\":\"b\"}\n").unwrap();
        let rows = tail(&p, 5);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["msg"], json!("b"), "保持时间顺序，最新在末尾");
        assert_eq!(tail(&p, 1).len(), 1);
        assert!(tail(&d.join("missing.log"), 5).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 脱敏必须与运行平台无关：Windows 风格路径在 Linux/macOS 上同样不能泄漏用户名。
    /// （CI 的 ubuntu/macOS job 曾因 `Path::file_name` 只在 Windows 切反斜杠而失败）
    #[test]
    fn redact_path_handles_both_separators_on_any_platform() {
        // Windows 风格（无论当前在哪个 OS 跑）
        assert_eq!(redact_path("D:\\x\\y\\ZCode.exe"), "ZCode.exe");
        assert_eq!(
            redact_path("C:\\Users\\alice\\zcode-hub\\src-tauri\\src\\identity.rs"),
            "identity.rs"
        );
        // POSIX 风格
        assert_eq!(redact_path("/home/alice/zcode-hub/ui/app.js"), "app.js");
        assert_eq!(redact_path("src/sub/file.rs"), "file.rs");
        // 混合分隔符与边界
        assert_eq!(redact_path("C:\\a/b\\c.txt"), "c.txt");
        assert_eq!(redact_path("  \"C:\\a\\b.exe\"  "), "b.exe");
        assert_eq!(redact_path(""), "");
        assert_eq!(redact_path("plain"), "plain");
        // 关键断言：结果里绝不出现用户名
        for p in [
            "C:\\Users\\alice\\x\\y.rs",
            "/home/alice/x/y.rs",
            "D:\\zcode-hub\\profiles\\bob\\meta.json",
        ] {
            let out = redact_path(p);
            assert!(
                !out.contains("alice")
                    && !out.contains("bob")
                    && !out.contains('\\')
                    && !out.contains('/'),
                "脱敏后仍是路径或含用户名: {:?} -> {:?}",
                p,
                out
            );
        }
    }

    #[test]
    fn clamp_and_redact_helpers() {
        assert_eq!(clamp_msg("  a\nb  "), "a b");
        assert_eq!(
            clamp_msg(&"y".repeat(MAX_MSG_CHARS + 50)).chars().count(),
            MAX_MSG_CHARS + 1
        );
        assert_eq!(redact_path("D:\\x\\y\\ZCode.exe"), "ZCode.exe");
        assert_eq!(redact_path(""), "");
        assert_eq!(redact_location("src\\identity.rs:10:4"), "identity.rs:10:4");
        assert_eq!(redact_location("plain message"), "plain message");
    }
}
