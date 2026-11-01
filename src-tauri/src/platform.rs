//! 平台抽象第 0 期：把 Windows 专属代码收敛到本模块。
//!
//! - Windows：实现原样保留（DPAPI / tasklist / taskkill / ShellExecuteW / PowerShell）。
//! - 其他平台：占位实现返回 Err/false/None，使纯逻辑（formats / history / audit / compat）
//!   能在三平台编译与测试；真移植（Linux/macOS）待真实需求信号后再做。
//! - 铁律：main.rs 不得再直接出现 CommandExt / ShellExecuteW / crypt32 等平台符号。

use std::path::PathBuf;
use std::process::Command;

/// 无窗口启动修饰：Windows 用 CREATE_NO_WINDOW，其他平台原样返回
fn no_window(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000) // CREATE_NO_WINDOW：探测/开关进程不能闪黑框
    }
    #[cfg(not(windows))]
    {
        cmd
    }
}

// ---------------- DPAPI（快照主密钥保护） ----------------

#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"zcode-hub-snapshots-v1";

pub fn dpapi_operate(plain: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct DataBlob { cb: u32, pb: *mut u8 }
        #[link(name = "crypt32")]
        extern "system" {
            fn CryptProtectData(pIn: *const DataBlob, descr: *const u16, entropy: *const DataBlob, reserved: *mut std::ffi::c_void, prompt: *mut std::ffi::c_void, flags: u32, pOut: *mut DataBlob) -> i32;
            fn CryptUnprotectData(pIn: *const DataBlob, descr: *mut *mut u16, entropy: *const DataBlob, reserved: *mut std::ffi::c_void, prompt: *mut std::ffi::c_void, flags: u32, pOut: *mut DataBlob) -> i32;
        }
        extern "system" { fn LocalFree(h: *mut std::ffi::c_void) -> *mut std::ffi::c_void; }
        let inp = DataBlob { cb: plain.len() as u32, pb: plain.as_ptr() as *mut u8 };
        let ent = DataBlob { cb: DPAPI_ENTROPY.len() as u32, pb: DPAPI_ENTROPY.as_ptr() as *mut u8 };
        let mut out = DataBlob { cb: 0, pb: std::ptr::null_mut() };
        let ok = unsafe {
            if protect {
                CryptProtectData(&inp, std::ptr::null(), &ent, std::ptr::null_mut(), std::ptr::null_mut(), 1, &mut out)
            } else {
                CryptUnprotectData(&inp, std::ptr::null_mut(), &ent, std::ptr::null_mut(), std::ptr::null_mut(), 1, &mut out)
            }
        };
        if ok == 0 { return Err("DPAPI 调用失败".into()); }
        let v = unsafe { std::slice::from_raw_parts(out.pb, out.cb as usize).to_vec() };
        unsafe { LocalFree(out.pb as *mut std::ffi::c_void); }
        Ok(v)
    }
    #[cfg(not(windows))]
    {
        let _ = (plain, protect);
        Err("此平台暂未支持快照加密（第 0 期占位）".into())
    }
}

// ---------------- 客户端进程管理 ----------------

pub fn zcode_running() -> bool {
    #[cfg(windows)]
    {
        no_window(Command::new("tasklist").args(["/FI", "IMAGENAME eq ZCode.exe", "/NH"])).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("ZCode.exe")).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn kill_zcode_process() -> bool {
    #[cfg(windows)]
    {
        // 先温和关闭（WM_CLOSE），不行再强制（/F），并轮询确认进程真正退出——
        // 只看 taskkill 是否执行成功不可靠（Electron 可能忽略关闭消息）
        let _ = no_window(Command::new("taskkill").args(["/IM", "ZCode.exe", "/T"])).output();
        for _ in 0..8 {
            if !zcode_running() { return true; }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        let _ = no_window(Command::new("taskkill").args(["/IM", "ZCode.exe", "/T", "/F"])).output();
        for _ in 0..15 {
            if !zcode_running() { return true; }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn launch_zcode_process(exe: &str) -> bool {
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW：不给启动链上任何控制台，避免 ZCode 的 host 子进程弹出黑色日志窗口
        no_window(Command::new(exe)
            .current_dir(std::path::Path::new(exe).parent().unwrap_or(std::path::Path::new("."))))
            .spawn().is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        false
    }
}

/// 自动探测客户端安装路径。`user_path` 为设置里用户指定的路径（已验证存在）。
pub fn detect_zcode_exe(user_path: Option<&str>) -> Option<String> {
    #[cfg(windows)]
    {
        if let Some(p) = user_path { return Some(p.to_string()); }
        no_window(Command::new("powershell").args(["-NoProfile", "-Command",
            "Get-Process ZCode -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path"]))
            .output().ok()
            .and_then(|o| { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } })
            .or_else(|| {
                // 客户端未运行时按常见安装位置兜底
                let mut cands = vec![r"C:\Program Files\ZCode\ZCode.exe".to_string()];
                if let Ok(la) = std::env::var("LOCALAPPDATA") {
                    cands.push(format!(r"{}\Programs\ZCode\ZCode.exe", la));
                }
                cands.into_iter().find(|c| std::path::Path::new(c).exists())
            })
    }
    #[cfg(not(windows))]
    {
        let _ = user_path;
        None
    }
}

/// 客户端 exe 的 ProductVersion（PowerShell）
pub fn exe_product_version(exe: &str) -> Option<String> {
    #[cfg(windows)]
    {
        no_window(Command::new("powershell").args(["-NoProfile", "-Command",
            &format!("(Get-Item -LiteralPath '{}').VersionInfo.ProductVersion", exe)]))
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        None
    }
}

// ---------------- Shell（资源管理器 / 浏览器） ----------------

pub fn open_dir_explorer(dir: &std::path::Path) {
    #[cfg(windows)]
    {
        let _ = no_window(Command::new("explorer").arg(dir)).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
    }
}

pub fn open_in_browser(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(hwnd: isize, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
        }
        let op: Vec<u16> = "open\0".encode_utf16().collect();
        let file: Vec<u16> = std::ffi::OsStr::new(url).encode_wide().chain(std::iter::once(0)).collect();
        let r = unsafe { ShellExecuteW(0, op.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 5 /* SW_SHOW */) };
        if r <= 32 {
            // ShellExecute 失败（返回 SE_ERR_* 错误码）时回退 rundll32 协议处理器
            let _ = no_window(Command::new("rundll32").args(["url.dll,FileProtocolHandler", url])).spawn();
        }
    }
    #[cfg(not(windows))]
    {
        let _ = url;
    }
}

// ---------------- 开机自启（启动文件夹快捷方式） ----------------

fn startup_lnk() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("APPDATA").unwrap_or_default();
        PathBuf::from(base).join(r"Microsoft\Windows\Start Menu\Programs\Startup").join("ZCode Hub.lnk")
    }
    #[cfg(not(windows))]
    {
        PathBuf::new()
    }
}

pub fn autostart_enabled() -> bool {
    #[cfg(windows)]
    {
        startup_lnk().exists()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn set_autostart_internal(enable: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let lnk = startup_lnk();
        if !enable {
            if lnk.exists() { std::fs::remove_file(&lnk).map_err(|e| e.to_string())?; }
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let script = format!(
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}');$s.TargetPath='{}';$s.WorkingDirectory='{}';$s.Save()",
            lnk.display(), exe.display(), exe.parent().map(|p| p.display().to_string()).unwrap_or_default());
        let out = no_window(Command::new("powershell").args(["-NoProfile", "-Command", &script]))
            .output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err("创建自启快捷方式失败".into()); }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = enable;
        Err("此平台暂未支持开机自启（第 0 期占位）".into())
    }
}

// ---------------- ZCode 的 Windows 数据目录布局 ----------------

/// %APPDATA% 下 ZCode 系客户端的 rum-electron-store 目录（含 Preview/Dev 变体与通配扫描）。
/// 该布局是 Windows 客户端专属；其他平台返回空（arms_uid 逻辑自然不生效）。
pub fn arms_store_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut out: Vec<PathBuf> = Vec::new();
        if let Ok(appdata) = std::env::var("APPDATA") {
            let base = PathBuf::from(&appdata);
            for name in ["ZCode", "zcode", "ZCode Preview", "ZCode Dev"] {
                out.push(base.join(name).join("rum-electron-store"));
            }
            if let Ok(rd) = std::fs::read_dir(&base) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    if n.starts_with("zcode") {
                        let d = e.path().join("rum-electron-store");
                        if d.is_dir() && !out.contains(&d) { out.push(d); }
                    }
                }
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}
