use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::export;
use crate::models::{AppSettings, ExportRequest, NessusFile, Project, RecentFile};
use crate::parser::parse_nessus_file;
use crate::private_file;
use crate::state::AppState;

// ── file loading ─────────────────────────────────────────────────────────────

// A policy-only export or an empty scan has nothing to show, so it stays out of the app
fn require_hosts(file: NessusFile) -> Result<NessusFile, String> {
    if file.hosts.is_empty() {
        return Err("This file has no scanned hosts. It may contain only a scan policy.".to_string());
    }
    Ok(file)
}// require_hosts

// the window gets first the file without its hosts. The hosts follow in pages
#[derive(Serialize)]
pub struct LoadedFile {
    id: String,
    filename: String,
    path: String,
    loaded_at: String,
    report_name: String,
    target: Option<String>,
    host_count: usize,
}// LoadedFile

// `async` keeps this off the main thread, so the window stays responsive while
// a large scan is parsed
#[tauri::command(async)]
pub fn load_nessus_file(state: State<'_, AppState>, path: String,) -> Result<LoadedFile, String> {
    let parsed = Arc::new(require_hosts(parse_nessus_file(&path)?)?);
    let mut files = state.files.lock().unwrap();
    // replace if same path already loaded
    if let Some(pos) = files.iter().position(|f| f.path == parsed.path) {
        files.remove(pos);
    }
    files.push(Arc::clone(&parsed));
    Ok(LoadedFile {
        id: parsed.id.clone(),
        filename: parsed.filename.clone(),
        path: parsed.path.clone(),
        loaded_at: parsed.loaded_at.clone(),
        report_name: parsed.report_name.clone(),
        target: parsed.target.clone(),
        host_count: parsed.hosts.len(),
    })
}// load_nessus_file

// Roughly how much one page of hosts may hold
const PAGE_BYTES: usize = 16 * 1024 * 1024;

fn host_page(file: &NessusFile, start: usize, limit: usize) -> Result<String, String> {
    let mut json = String::from("{\"hosts\":[");
    let mut next = start.min(file.hosts.len());
    while next < file.hosts.len() && (next == start || json.len() < limit) {
        if next > start {
            json.push(',');
        }
        json.push_str(&serde_json::to_string(&file.hosts[next]).map_err(|e| e.to_string())?);
        next += 1;
    }
    json.push_str(&format!("],\"next\":{next}}}"));
    Ok(json)
}// host_page

#[tauri::command(async)]
pub fn file_hosts(state: State<'_, AppState>, id: String, start: usize) -> Result<tauri::ipc::Response, String> {
    let file = state.files.lock().unwrap().iter().find(|f| f.id == id).cloned()
        .ok_or_else(|| "The file was closed while it was loading.".to_string())?;
    // already JSON, so it goes to the window as it is
    Ok(tauri::ipc::Response::new(host_page(&file, start, PAGE_BYTES)?))
}// file_hosts

#[tauri::command]
pub fn unload_file(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut files = state.files.lock().unwrap();
    files.retain(|f| f.id != id);
    Ok(())
}// unload_file

#[tauri::command]
pub fn unload_all_files(state: State<'_, AppState>) -> Result<(), String> {
    state.files.lock().unwrap().clear();
    Ok(())
}// unload_all_files

// ── export ───────────────────────────────────────────────────────────────────

#[tauri::command(async)]
pub fn export_data(state: State<'_, AppState>, req: ExportRequest,) -> Result<(), String> {
    // Snapshot the list so a long export doesn't block loading or unloading files.
    let files = state.files.lock().unwrap().clone();
    export::export(&files, &req)
}// export_data

// ── persistence ──────────────────────────────────────────────────────────────

fn app_data_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("Cannot resolve app data dir: {e}"))
}// app_data_dir

fn save_json<T: Serialize>(dir: &Path, name: &str, value: &T) -> Result<(), String> {
    private_file::create_dir_all(dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    private_file::write(dir.join(name), json).map_err(|e| e.to_string())
}// save_json

#[tauri::command]
pub fn save_projects(app: AppHandle, projects: Vec<Project>,) -> Result<(), String> {
    save_json(&app_data_dir(&app)?, "projects.json", &projects)
}// save_projects

#[tauri::command]
pub fn load_projects(app: AppHandle) -> Result<Vec<Project>, String> {
    let path = app_data_dir(&app)?.join("projects.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}// load_projects

#[tauri::command]
pub fn save_settings(app: AppHandle, settings: AppSettings) -> Result<(), String> {
    save_json(&app_data_dir(&app)?, "settings.json", &settings)
}// save_settings

#[tauri::command]
pub fn load_settings(app: AppHandle) -> Result<AppSettings, String> {
    let path = app_data_dir(&app)?.join("settings.json");
    if !path.exists() {
        return Ok(AppSettings::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}// load_settings

#[tauri::command]
pub fn save_recent_files(app: AppHandle, files: Vec<RecentFile>) -> Result<(), String> {
    // keep last 20
    let kept: Vec<_> = files.into_iter().take(20).collect();
    save_json(&app_data_dir(&app)?, "recent_files.json", &kept)
}// save_recent_files

#[tauri::command]
pub fn load_recent_files(app: AppHandle) -> Result<Vec<RecentFile>, String> {
    let path = app_data_dir(&app)?.join("recent_files.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}// load_recent_files

// ── url opener ───────────────────────────────────────────────────────────────

// URLs reach this command from scan file content (`see_also`), so they are untrusted.
// Anything but a plain http(s) URL could launch a local or network program.
fn is_web_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
    else {
        return false;
    };
    // Non-ASCII allows look-alike and reversed text, and user:pass@ can make a link
    // appear to point somewhere else, so neither can be trusted as displayed.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty()
        && !authority.contains('@')
        && url.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

#[tauri::command]
pub fn open_url(url: String) -> Result<(), String> {
    if !is_web_url(&url) {
        return Err(format!("Refusing to open a non-web link: {url}"));
    }
    open::that_detached(url).map_err(|e| e.to_string())
}// open_url

#[cfg(test)]
mod tests {
    use super::{host_page, is_web_url, require_hosts, save_json};
    use crate::parser::parse_str;
    use crate::private_file::testing::TempDir;

    #[test]
    fn saved_json_creates_its_folder_and_is_private() {
        let temp = TempDir::new();
        let dir = temp.path().join("app-data");

        save_json(&dir, "values.json", &vec![1, 2]).unwrap();

        let saved: Vec<i32> =
            serde_json::from_str(&std::fs::read_to_string(dir.join("values.json")).unwrap()).unwrap();
        assert_eq!(saved, [1, 2]);

        #[cfg(unix)]
        {
            use crate::private_file::testing::mode;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join("values.json")), 0o600);
        }
    }

    #[test]
    fn a_file_without_hosts_is_not_loaded() {
        for xml in [
            r#"<NessusClientData_v2><Policy><policyName>p</policyName></Policy></NessusClientData_v2>"#,
            r#"<NessusClientData_v2><Policy><policyName>p</policyName></Policy><Report name="r"></Report></NessusClientData_v2>"#,
        ] {
            let err = require_hosts(parse_str(xml).unwrap()).unwrap_err();
            assert!(err.contains("no scanned hosts"), "{xml}: {err}");
        }
        let scan = r#"<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.1"></ReportHost></Report></NessusClientData_v2>"#;
        assert!(require_hosts(parse_str(scan).unwrap()).is_ok());
    }

    #[test]
    fn hosts_go_out_in_pages_that_together_hold_every_host() {
        let hosts: String = (1..=50)
            .map(|n| format!(r#"<ReportHost name="10.0.0.{n}"><ReportItem port="80" svc_name="www" protocol="tcp" severity="2" pluginID="{n}" pluginName="P{n}" pluginFamily="F"><description>{}</description></ReportItem></ReportHost>"#, "x".repeat(n * 40)))
            .collect();
        let file = parse_str(&format!(r#"<NessusClientData_v2><Report name="r">{hosts}</Report></NessusClientData_v2>"#)).unwrap();

        let mut seen = Vec::new();
        let mut start = 0;
        let mut pages = 0;
        while start < file.hosts.len() {
            let page: serde_json::Value = serde_json::from_str(&host_page(&file, start, 4_000).unwrap()).unwrap();
            let got = page["hosts"].as_array().unwrap();
            assert!(!got.is_empty(), "every page moves on");
            seen.extend(got.iter().map(|h| h["ip"].as_str().unwrap().to_string()));
            start = page["next"].as_u64().unwrap() as usize;
            pages += 1;
        }
        assert!(pages > 3, "small pages split the file, got {pages}");
        assert_eq!(seen, file.hosts.iter().map(|h| h.ip.clone()).collect::<Vec<_>>());

        // a host larger than a page still comes through, alone
        let one: serde_json::Value = serde_json::from_str(&host_page(&file, 49, 10).unwrap()).unwrap();
        assert_eq!(one["hosts"].as_array().unwrap().len(), 1);
        assert_eq!(one["next"], 50);
        // past the end is an empty page, not an error
        let end: serde_json::Value = serde_json::from_str(&host_page(&file, 99, 10).unwrap()).unwrap();
        assert_eq!(end["hosts"].as_array().unwrap().len(), 0);
        assert_eq!(end["next"], 50);
    }

    #[test]
    fn accepts_plain_web_urls() {
        for url in [
            "http://example.com",
            "https://example.com/a?b=c&d=e#f",
            "HTTPS://EXAMPLE.COM/%20path",
            "https://example.com/user@host",
            "https://example.com:8443/a",
        ] {
            assert!(is_web_url(url), "{url}");
        }
    }

    #[test]
    fn rejects_anything_that_could_launch_a_program() {
        for url in [
            "",
            "calc.exe",
            r"C:\Windows\System32\calc.exe",
            r"\\attacker\share\x.exe",
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "ms-msdt:/id",
            "http://",
            "https:///etc/passwd",
            r"http:\\example.com",
            "http://a\" & calc.exe & \"",
            "http://a b",
            "http://a\nb",
            "http://user:pass@example.com/",
            "https://bank.example@evil.example/",
            "https://example.com/\u{202E}moc.elgoog",
            "https://exаmple.com/",
        ] {
            assert!(!is_web_url(url), "{url}");
        }
    }
}
