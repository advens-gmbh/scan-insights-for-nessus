mod commands;
mod export;
mod models;
mod parser;
mod private_file;
mod state;
#[cfg(windows)]
mod window_icon;

use state::AppState;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|_app| {
            #[cfg(windows)]
            window_icon::use_resource_icons(_app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::load_nessus_file,
            commands::file_hosts,
            commands::file_sizes,
            commands::unload_file,
            commands::unload_all_files,
            commands::export_data,
            commands::save_projects,
            commands::load_projects,
            commands::save_settings,
            commands::load_settings,
            commands::save_recent_files,
            commands::load_recent_files,
            commands::open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Scan Insights for Nessus");
}
