#![cfg_attr(windows, windows_subsystem = "windows")]

mod audit;
mod claim;
mod crash;
mod formats;
mod history;
mod platform;

mod app;
mod backup;
mod benefits;
mod client;
mod crypto;
mod diagnostics;
mod identity;
mod oauth;
mod profiles;
mod quota;
mod settings;
mod system;
mod util;
mod window;

use tauri::Manager;

pub fn run() {
    let started = std::time::Instant::now();
    crash::install_panic_hook();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            util::migrate_legacy_data();
            *app::APP_HANDLE.lock().unwrap() = Some(app.handle().clone());
            app::setup_tray(app)?;
            window::restore_window_state(app);
            diagnostics::record_startup(started.elapsed().as_millis());
            // Ctrl+Shift+Z 呼出/隐藏主窗口（注册失败时静默降级）
            {
                use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
                let _ = app
                    .global_shortcut()
                    .on_shortcut("Ctrl+Shift+Z", |app, _s, ev| {
                        if ev.state == ShortcutState::Pressed {
                            if let Some(w) = app.get_webview_window("main") {
                                let visible = w.is_visible().unwrap_or(false);
                                if visible {
                                    let _ = w.hide();
                                } else {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                        }
                    });
            }
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let _ = backup::run_backup_if_due();
            });
            let handle = app.handle().clone();
            std::thread::spawn(move || app::auto_check_loop(handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let hidden = app::request_close(window.app_handle());
                if hidden {
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app::get_state,
            identity::capture_profile,
            identity::switch_profile,
            profiles::delete_profile,
            profiles::restore_profile,
            profiles::rename_profile,
            profiles::set_profile_tags,
            profiles::inspect_bundle,
            profiles::export_bundle,
            profiles::import_bundle,
            quota::fetch_quota,
            quota::quota_history,
            client::open_zcode_client,
            client::kill_zcode_client,
            oauth::oauth_start,
            oauth::oauth_status,
            oauth::oauth_open,
            oauth::oauth_cancel,
            benefits::check_benefits,
            benefits::check_all_benefits,
            benefits::check_state,
            benefits::claim_plan,
            benefits::claim_state,
            benefits::open_claim_captcha,
            benefits::claim_history,
            benefits::export_claim_history,
            settings::get_settings,
            settings::set_settings,
            window::win_minimize,
            window::win_toggle_maximize,
            window::win_hide,
            window::win_start_drag,
            system::reveal_file,
            system::set_autostart,
            system::open_data_dir,
            system::open_zcode_data_dir,
            system::check_update,
            system::open_url,
            system::install_update,
            system::update_progress,
            backup::backup_now,
            backup::open_backup_dir,
            backup::get_backup_status,
            backup::list_backups_cmd,
            backup::restore_backup,
            diagnostics::export_diagnostics,
            diagnostics::report_frontend_error,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run()
}
