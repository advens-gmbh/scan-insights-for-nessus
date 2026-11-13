use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NessusFile {
    pub id: String,
    pub filename: String,
    pub path: String,
    pub loaded_at: String,
    pub report_name: String,
    pub target: Option<String>,   // raw target string from <Policy><Preferences><ServerPreferences>
    #[serde(default)]
    pub compliance_skipped: usize,
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub os_unsupported: bool,
    pub host_start: Option<String>,
    pub host_end: Option<String>,
    pub alt_hostnames: Vec<String>,
    pub items: Vec<ReportItem>,
}

// What a plugin says about a finding. Findings with exactly the same details share one copy
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct PluginDetails {
    pub plugin_id: u32,
    pub plugin_name: String,
    pub plugin_family: String,
    pub risk_factor: String,
    pub description: String,
    pub solution: String,
    pub synopsis: Option<String>,
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
    // left out of the JSON when empty. most findings have none of these
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_maturity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exploit_frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub exploited_by_malware: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub exploited_by_nessus: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cisa_known_exploited: Option<String>, // the date CISA set for fixing it
    #[serde(default, skip_serializing_if = "is_false")]
    pub unsupported_by_vendor: bool,
    pub patch_publication_date: Option<String>,
    pub vuln_publication_date: Option<String>,
    pub script_version: Option<String>,
}// PluginDetails

// for the interner. Scores are compared by their bits, so equal details hash equally
impl Eq for PluginDetails {}

impl std::hash::Hash for PluginDetails {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        let score = |s: Option<f32>| s.map(f32::to_bits);
        self.plugin_id.hash(h);
        self.plugin_name.hash(h);
        self.plugin_family.hash(h);
        self.risk_factor.hash(h);
        self.description.hash(h);
        self.solution.hash(h);
        self.synopsis.hash(h);
        [score(self.cvss_base_score), score(self.cvss3_base_score), score(self.cvss4_base_score), score(self.vpr_score), score(self.epss_score)].hash(h);
        self.cve.hash(h);
        self.cwe.hash(h);
        self.see_also.hash(h);
        [self.exploit_available, self.metasploit_available, self.exploited_by_malware, self.exploited_by_nessus, self.unsupported_by_vendor].hash(h);
        self.metasploit_name.hash(h);
        self.exploit_ease.hash(h);
        self.exploit_maturity.hash(h);
        self.exploit_frameworks.hash(h);
        self.cisa_known_exploited.hash(h);
        self.patch_publication_date.hash(h);
        self.vuln_publication_date.hash(h);
        self.script_version.hash(h);
    }
}

// where one finding is, how severe, and what the plugin printed. The plugin's own details are reached through Deref
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportItem {
    #[serde(flatten)]
    pub details: Arc<PluginDetails>,
    pub severity: u8,
    pub port: u16,
    pub protocol: Arc<str>,
    pub svc_name: Arc<str>,
    pub plugin_output: Option<Box<str>>,
}// ReportItem

impl std::ops::Deref for ReportItem {
    type Target = PluginDetails;
    fn deref(&self) -> &PluginDetails {
        &self.details
    }
}

fn is_false(value: &bool) -> bool {
    !*value
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
