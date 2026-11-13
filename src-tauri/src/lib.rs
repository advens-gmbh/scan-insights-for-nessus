mod api;
mod commands;
mod compare;
mod export;
mod intern;
mod views;
mod models;
mod parser;
mod private_file;
mod queries;
mod reveal;
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
            commands::file_sizes,
            commands::unload_file,
            commands::unload_all_files,
            commands::export_data,
            commands::open_export,
            commands::show_export,
            commands::save_projects,
            commands::load_projects,
            commands::save_settings,
            commands::load_settings,
            commands::save_recent_files,
            commands::load_recent_files,
            commands::open_url,
            queries::open_files,
            queries::file_host_list,
            queries::vuln_rows,
            queries::vulns_on_ip,
            queries::host_rows,
            queries::service_rows,
            queries::list_counts,
            queries::vuln_detail,
            queries::vuln_outputs,
            queries::host_detail,
            queries::service_detail,
            queries::dashboard,
            queries::topology_hosts,
            queries::compare_files,
            queries::same_scans,
            queries::run_changes,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Scan Insights for Nessus");
}
