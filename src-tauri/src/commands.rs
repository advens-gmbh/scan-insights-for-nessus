use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::export;
use crate::models::{AppSettings, ExportRequest, NessusFile, Project, RecentFile};
use crate::parser::parse_nessus_file_with;
use crate::private_file;
use crate::state::AppState;
use crate::api;
use crate::views::FileInfo;

// ── file loading ─────────────────────────────────────────────────────────────

// A policy-only export or an empty scan has nothing to show, so it stays out of the app
fn require_hosts(file: NessusFile) -> Result<NessusFile, String> {
    if file.hosts.is_empty() {
        return Err("This file has no scanned hosts. It may contain only a scan policy.".to_string());
    }
    Ok(file)
}// require_hosts

// how far reading a file has got
#[derive(Serialize, Clone)]
struct LoadProgress<'a> {
    path: &'a str,
    percent: u8,
}

// why a file couldn't be opened
#[derive(Serialize, Debug, PartialEq)]
pub struct LoadError {
    kind: &'static str,
    message: String,
}// LoadError

fn load_error(kind: &'static str, message: impl Into<String>) -> LoadError {
    LoadError { kind, message: message.into() }
}// load_error

// sorts the parser's message into a kind
fn classify(message: String, size: u64) -> LoadError {
    let kind = if message.starts_with("Cannot read file") {
        "unreadable"
    } else if message.starts_with("Not a Nessus scan file") {
        "not_nessus"
    } else if message.starts_with("This is the old .nessus v1") {
        "old_format"
    } else if message.starts_with("The file is incomplete") {
        "truncated"
    } else if let Some(rest) = message.strip_prefix("XML parse error at byte ") {
        let at: u64 = rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(0);
        if at + 64 >= size { "truncated" } else { "damaged" }
    } else if message.starts_with("This file has no scanned hosts") {
        "no_hosts"
    } else {
        "other"
    };
    load_error(kind, message)
}// classify

// `async` keeps this off the main thread, so the window stays responsive while
// a large scan is parsed
#[tauri::command(async)]
pub fn load_nessus_file(app: AppHandle, state: State<'_, AppState>, path: String,) -> Result<FileInfo, LoadError> {
    let size = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(load_error("missing", e.to_string())),
        Err(e) => return Err(load_error("unreadable", e.to_string())),
    };
    let mut tell = |percent: u8| {
        let _ = app.emit("load-progress", LoadProgress { path: &path, percent });
    };
    let parsed = parse_nessus_file_with(&path, &mut tell)
        .and_then(require_hosts)
        .map_err(|m| classify(m, size))?;
    Ok(api::add_file(&state, parsed, size))
}// load_nessus_file

// the size of each file, or nothing when it isn't there any more (for the recent files list)
#[tauri::command(async)]
pub fn file_sizes(paths: Vec<String>) -> Vec<Option<u64>> {
    paths.iter().map(|p| std::fs::metadata(p).ok().filter(|m| m.is_file()).map(|m| m.len())).collect()
}// file_sizes

#[tauri::command]
pub fn unload_file(state: State<'_, AppState>, id: String) -> Result<(), String> {
    api::close_files(&state, Some(&id));
    Ok(())
}// unload_file

#[tauri::command]
pub fn unload_all_files(state: State<'_, AppState>) -> Result<(), String> {
    api::close_files(&state, None);
    Ok(())
}// unload_all_files

// ── export ───────────────────────────────────────────────────────────────────

#[tauri::command(async)]
pub fn export_data(state: State<'_, AppState>, req: ExportRequest,) -> Result<(), export::ExportError> {
    // Snapshot the list so a long export doesn't block loading or unloading files.
    let files = state.files.lock().unwrap().clone();
    export::export(&files, &req)?;
    state.exported.lock().unwrap().insert(PathBuf::from(&req.output_path));
    Ok(())
}// export_data

fn exported_file(state: &AppState, path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if state.exported.lock().unwrap().contains(&path) {
        Ok(path)
    } else {
        Err("Only exported files can be opened from here".to_string())
    }
}// exported_file

#[tauri::command]
pub fn open_export(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let path = exported_file(&state, &path)?;
    open::that_detached(path).map_err(|e| e.to_string())
}// open_export

#[tauri::command]
pub fn show_export(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let path = exported_file(&state, &path)?;
    crate::reveal::show_in_folder(&path).map_err(|e| e.to_string())
}// show_export

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
    use super::{classify, exported_file, file_sizes, is_web_url, load_error, require_hosts, save_json};
    use crate::state::AppState;
    use crate::parser::parse_str;
    use crate::private_file::testing::TempDir;

    #[test]
    fn only_files_exported_in_this_session_can_be_opened() {
        let state = AppState::default();
        state.exported.lock().unwrap().insert("C:/reports/scan-export.xlsx".into());

        assert!(exported_file(&state, "C:/reports/scan-export.xlsx").is_ok());
        assert!(exported_file(&state, "C:/Windows/System32/calc.exe").is_err());
        assert!(exported_file(&state, "").is_err());
    }

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
    fn a_failed_load_says_what_kind_of_problem_it_was() {
        let kind = |m: &str, size: u64| classify(m.to_string(), size).kind;
        assert_eq!(kind("Cannot read file: access denied", 10), "unreadable");
        assert_eq!(kind("Not a Nessus scan file: unexpected root element <html>", 10), "not_nessus");
        assert_eq!(kind("This is the old .nessus v1 format, which is not supported.", 10), "old_format");
        assert_eq!(kind("The file is incomplete: it ends before the scan data is closed", 10), "truncated");
        assert_eq!(kind("This file has no scanned hosts. It may contain only a scan policy.", 10), "no_hosts");
        // an XML error at the very end is a cut-off file, earlier it is damage
        assert_eq!(kind("XML parse error at byte 999990: unexpected end", 1_000_000), "truncated");
        assert_eq!(kind("XML parse error at byte 1200: bad name", 1_000_000), "damaged");
        assert_eq!(kind("something new", 10), "other");
        assert_eq!(classify("Cannot read file: x".into(), 1), load_error("unreadable", "Cannot read file: x"));
    }

    #[test]
    fn file_sizes_are_nothing_for_a_missing_file() {
        let temp = TempDir::new();
        let there = temp.path().join("a.nessus");
        std::fs::write(&there, "12345").unwrap();
        let sizes = file_sizes(vec![there.to_string_lossy().into(), temp.path().join("gone.nessus").to_string_lossy().into(), temp.path().to_string_lossy().into()]);
        assert_eq!(sizes, vec![Some(5), None, None]);
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

#[cfg(test)]
mod timing {
    // cargo test --release timing -- --ignored --nocapture, with SCAN set to a big .nessus file
    #[test]
    #[ignore]
    fn time_loading_steps() {
        let path = std::env::var("SCAN").unwrap();
        let t = std::time::Instant::now();
        let mut file = crate::parser::parse_nessus_file(&path).unwrap();
        println!("parse {:?}", t.elapsed());
        let t = std::time::Instant::now();
        crate::intern::Interner::default().adopt(&mut file);
        println!("adopt {:?}", t.elapsed());
        let t = std::time::Instant::now();
        let info = crate::views::file_info(&file, 0);
        println!("file info {:?} ({} hosts)", t.elapsed(), info.host_count);
        let view = crate::views::View::new(vec![std::sync::Arc::new(file)]);
        for (name, f) in [("vulns", 0), ("hosts", 1), ("services", 2)] {
            let t = std::time::Instant::now();
            let n = match f { 0 => view.vulns().list.len(), 1 => view.hosts().list.len(), _ => view.services().len() };
            println!("{name} {:?} ({n})", t.elapsed());
        }
        let t = std::time::Instant::now();
        let rows: Vec<_> = view.hosts().list.iter().map(|h| h.row(&view)).collect();
        let json = serde_json::to_string(&rows).unwrap();
        println!("host rows json {:?} {} KB", t.elapsed(), json.len() / 1000);
        let t = std::time::Instant::now();
        let rows: Vec<_> = view.vulns().list.iter().map(|v| v.row(&view)).collect();
        let json = serde_json::to_string(&rows).unwrap();
        println!("vuln rows json {:?} {} KB", t.elapsed(), json.len() / 1000);
        let json = serde_json::to_string(view.services()).unwrap();
        println!("services json {} KB", json.len() / 1000);
    }
}
