use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NessusFile {
    pub id: String,
    pub filename: String,
    pub path: String,
    pub loaded_at: String,
    pub report_name: String,
    pub target: Option<String>,   // raw target string from <Policy><Preferences><ServerPreferences>
    pub hosts: Vec<ReportHost>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportHost {
    pub name: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub os: Option<String>,
    pub mac: Option<String>,
    pub netbios: Option<String>,
    pub system_type: Option<String>,
    pub credentialed_scan: bool,
    pub host_start: Option<String>,
    pub host_end: Option<String>,
    pub alt_hostnames: Vec<String>,
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportItem {
    pub plugin_id: u32,
    pub plugin_name: String,
    pub plugin_family: String,
    pub severity: u8,
    pub port: u16,
    pub protocol: String,
    pub svc_name: String,
    pub risk_factor: String,
    pub description: String,
    pub solution: String,
    pub synopsis: Option<String>,
    pub plugin_output: Option<String>,
    pub cvss_base_score: Option<f32>,
    pub cvss3_base_score: Option<f32>,
    pub cvss4_base_score: Option<f32>,
    pub vpr_score: Option<f32>,
    pub epss_score: Option<f32>,
    pub cve: Vec<String>,
    pub cwe: Vec<String>,
    pub see_also: Vec<String>,
    pub exploit_available: bool,
    pub metasploit_available: bool,
    pub metasploit_name: Option<String>,
    pub exploit_ease: Option<String>,
    pub patch_publication_date: Option<String>,
    pub vuln_publication_date: Option<String>,
    pub script_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProjectFilePath {
    pub path: String,
    pub filename: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub file_ids: Vec<String>,
    #[serde(default)]
    pub file_paths: Vec<ProjectFilePath>,
    pub created_at: String,
    #[serde(default)]
    pub last_opened: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AppSettings {
    pub theme: String,
    pub sidebar_collapsed: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecentFile {
    pub path: String,
    pub filename: String,
    pub last_opened: String,
    #[serde(default)]
    pub report_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportRequest {
    pub file_ids: Vec<String>,
    pub severities: Vec<u8>,
    pub output_path: String,
    pub format: ExportFormat,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Xlsx,
    Nessus,
}
