use serde_json::json;
use tauri::Manager;

use crate::app::request_close;
use crate::formats::write_json;
use crate::settings::{load_settings, SETTINGS};
use crate::util::config_path;

// ---------------- 窗口几何持久化 ----------------
pub(crate) fn save_window_state(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        // 最小化时 outer_position 是 -32000 哨兵、尺寸是 160x28 —— 存下去会导致下次启动窗口跑到屏幕外
        if w.is_minimized().unwrap_or(false) { return; }
        if let (Ok(pos), Ok(size)) = (w.outer_position(), w.outer_size()) {
            if pos.x <= -10000 || pos.y <= -10000 || size.width < 400 || size.height < 400 { return; }
            let mut s = load_settings();
            s["window"] = json!({"x": pos.x, "y": pos.y, "w": size.width, "h": size.height, "max": w.is_maximized().unwrap_or(false)});
            let _ = write_json(&config_path(), &s);
            *SETTINGS.lock().unwrap() = Some(s);
        }
    }
}

pub(crate) fn restore_window_state(app: &tauri::App) {
    if let Some(w) = app.get_webview_window("main") {
        let cfg = load_settings();
        let mut applied = false;
        if let Some(win) = cfg.get("window") {
            let max = win.get("max").and_then(|v| v.as_bool()).unwrap_or(false);
            if max {
                let _ = w.maximize();
                applied = true;
            } else if let (Some(x), Some(y), Some(ww), Some(hh)) = (
                win.get("x").and_then(|v| v.as_i64()), win.get("y").and_then(|v| v.as_i64()),
                win.get("w").and_then(|v| v.as_u64()), win.get("h").and_then(|v| v.as_u64())) {
                // 有效性校验：排除最小化哨兵（-32000）与过小/越界几何；
                // 还要确认窗口与至少一个显示器相交，副屏被拔掉时不能恢复到场外。
                let ww = ww.clamp(400, 10000) as u32;
                let hh = hh.clamp(400, 10000) as u32;
                let sane = x > -10000 && y > -10000 && x < 16384 && y < 16384;
                if sane && geometry_visible(&w, x as i32, y as i32, ww, hh) {
                    use tauri::{PhysicalPosition, PhysicalSize};
                    let _ = w.set_position(PhysicalPosition::new(x as i32, y as i32));
                    let _ = w.set_size(PhysicalSize::new(ww, hh));
                    applied = true;
                }
            }
        }
        if !applied { let _ = w.center(); }
        // 开机自启偏好：不抢前台，直接驻留托盘
        if cfg.get("start_minimized").and_then(|v| v.as_bool()).unwrap_or(false) {
            let _ = w.hide();
        } else {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

/// 窗口矩形是否与任一显示器相交（不同 DPI 下坐标均为物理像素，可与位置/尺寸直接比较）
pub(crate) fn geometry_visible(w: &tauri::WebviewWindow, x: i32, y: i32, ww: u32, hh: u32) -> bool {
    let Ok(monitors) = w.available_monitors() else { return false };
    if monitors.is_empty() { return true; } // 查询失败时不阻断恢复
    monitors.iter().any(|m| {
        let p = m.position();
        let s = m.size();
        let (mx1, my1) = (p.x as i64, p.y as i64);
        let (mx2, my2) = (mx1 + s.width as i64, my1 + s.height as i64);
        let (x1, y1) = (x as i64, y as i64);
        let (x2, y2) = (x1 + ww as i64, y1 + hh as i64);
        x1 < mx2 && x2 > mx1 && y1 < my2 && y2 > my1
    })
}

// 自绘标题栏的窗口控制（decorations:false 后由前端按钮调用）
#[tauri::command]
pub(crate) fn win_minimize(window: tauri::WebviewWindow) { let _ = window.minimize(); }

#[tauri::command]
pub(crate) fn win_toggle_maximize(window: tauri::WebviewWindow) {
    match window.is_maximized() { Ok(true) => { let _ = window.unmaximize(); }, Ok(_) => { let _ = window.maximize(); }, Err(_) => {} }
}

#[tauri::command]
pub(crate) fn win_hide(window: tauri::WebviewWindow) {
    request_close(window.app_handle()); // 关闭键 = 按设置隐藏到托盘或退出
}

#[tauri::command]
pub(crate) fn win_start_drag(window: tauri::WebviewWindow) { let _ = window.start_dragging(); }
