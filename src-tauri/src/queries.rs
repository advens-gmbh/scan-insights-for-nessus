// The window's questions, answered by api.rs. Long answers go out as JSON text as they are
use tauri::State;

use crate::api;
use crate::state::AppState;
use crate::views::FileInfo;

fn respond(answer: Result<String, String>) -> Result<tauri::ipc::Response, String> {
    answer.map(tauri::ipc::Response::new)
}

#[tauri::command]
pub fn open_files(state: State<'_, AppState>) -> Vec<FileInfo> {
    api::open_files(&state)
}

#[tauri::command(async)]
pub fn file_host_list(state: State<'_, AppState>, id: String) -> Result<tauri::ipc::Response, String> {
    respond(api::file_host_list(&state, id))
}

#[tauri::command(async)]
pub fn vuln_rows(state: State<'_, AppState>, file: Option<String>) -> Result<tauri::ipc::Response, String> {
    respond(api::vuln_rows(&state, file))
}

#[tauri::command(async)]
pub fn vulns_on_ip(state: State<'_, AppState>, file: Option<String>, text: String) -> Vec<u32> {
    api::vulns_on_ip(&state, file, text)
}

#[tauri::command(async)]
pub fn host_rows(state: State<'_, AppState>, file: Option<String>) -> Result<tauri::ipc::Response, String> {
    respond(api::host_rows(&state, file))
}

#[tauri::command(async)]
pub fn service_rows(state: State<'_, AppState>, file: Option<String>) -> Result<tauri::ipc::Response, String> {
    respond(api::service_rows(&state, file))
}

#[tauri::command(async)]
pub fn list_counts(state: State<'_, AppState>) -> api::ListCounts {
    api::list_counts(&state)
}

#[tauri::command(async)]
pub fn vuln_detail(state: State<'_, AppState>, plugin_id: u32, file: Option<String>) -> Result<tauri::ipc::Response, String> {
    respond(api::vuln_detail(&state, plugin_id, file))
}

#[tauri::command(async)]
pub fn vuln_outputs(state: State<'_, AppState>, plugin_id: u32, ids: Vec<usize>) -> Result<tauri::ipc::Response, String> {
    respond(api::vuln_outputs(&state, plugin_id, ids))
}

#[tauri::command(async)]
pub fn host_detail(state: State<'_, AppState>, ip: String, file: Option<String>) -> Result<tauri::ipc::Response, String> {
    respond(api::host_detail(&state, ip, file))
}

#[tauri::command(async)]
pub fn service_detail(state: State<'_, AppState>, key: String, file: Option<String>, show_info: bool) -> Result<tauri::ipc::Response, String> {
    respond(api::service_detail(&state, key, file, show_info))
}

#[tauri::command(async)]
pub fn dashboard(state: State<'_, AppState>, show_info: bool, top_vulns: usize, top_hosts: usize, top_families: usize) -> Result<tauri::ipc::Response, String> {
    respond(api::dashboard(&state, show_info, top_vulns, top_hosts, top_families))
}

#[tauri::command(async)]
pub fn topology_hosts(state: State<'_, AppState>, plugins: Vec<u32>, files: Option<Vec<String>>) -> Result<tauri::ipc::Response, String> {
    respond(api::topology_hosts(&state, plugins, files))
}

#[tauri::command(async)]
pub fn compare_files(state: State<'_, AppState>, a: String, b: String, show_info: bool) -> Result<tauri::ipc::Response, String> {
    respond(api::compare_files(&state, a, b, show_info))
}

#[tauri::command(async)]
pub fn same_scans(state: State<'_, AppState>) -> Result<tauri::ipc::Response, String> {
    respond(api::same_scans(&state))
}

#[tauri::command(async)]
pub fn run_changes(state: State<'_, AppState>, pairs: Vec<(String, String)>, show_info: bool) -> Result<Vec<Option<api::RunChanges>>, String> {
    api::run_changes(&state, pairs, show_info)
}
