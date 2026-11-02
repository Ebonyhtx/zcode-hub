#![cfg_attr(windows, windows_subsystem = "windows")]

mod formats;
mod audit;
mod history;
mod platform;
mod claim;

mod util;
mod crypto;
mod identity;
mod profiles;
mod quota;
mod benefits;
mod settings;
mod client;
mod system;
mod window;
mod oauth;
mod app;

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            util::migrate_legacy_data();
            *app::APP_HANDLE.lock().unwrap() = Some(app.handle().clone());
            app::setup_tray(app)?;
            window::restore_window_state(app);
            let handle = app.handle().clone();
            std::thread::spawn(move || app::auto_check_loop(handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let hidden = app::request_close(window.app_handle());
                if hidden { api.prevent_close(); }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app::get_state,
            identity::capture_profile, identity::switch_profile,
            profiles::delete_profile, profiles::restore_profile, profiles::rename_profile,
            profiles::export_bundle, profiles::import_bundle,
            quota::fetch_quota, quota::quota_history,
            client::open_zcode_client, client::kill_zcode_client,
            oauth::oauth_start, oauth::oauth_status, oauth::oauth_open, oauth::oauth_cancel,
            benefits::check_benefits, benefits::check_all_benefits, benefits::check_state,
            benefits::claim_plan, benefits::claim_state, benefits::open_claim_captcha,
            benefits::claim_history,
            settings::get_settings, settings::set_settings,
            window::win_minimize, window::win_toggle_maximize, window::win_hide, window::win_start_drag,
            system::reveal_file, system::set_autostart, system::open_data_dir,
            system::open_zcode_data_dir, system::check_update, system::open_url,
            system::install_update, system::update_progress,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() { run() }
