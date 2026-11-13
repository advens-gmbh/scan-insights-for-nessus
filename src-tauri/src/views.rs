// The lists the pages show are built here from the open files. This way the window never has to hold the scans
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use serde::Serialize;

use crate::models::{NessusFile, PluginDetails, ReportHost, ReportItem};

// ── severity counts ──────────────────────────────────────────────────────────

#[derive(Serialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Counts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}// Counts

impl Counts {
    pub fn add(&mut self, severity: u8) {
        *self.slot(severity) += 1;
    }

    fn remove(&mut self, severity: u8) {
        let slot = self.slot(severity);
        *slot = slot.saturating_sub(1);
    }

    fn slot(&mut self, severity: u8) -> &mut u32 {
        match severity {
            4 => &mut self.critical,
            3 => &mut self.high,
            2 => &mut self.medium,
            1 => &mut self.low,
            _ => &mut self.info,
        }
    }

    pub fn get(&self, severity: u8) -> u32 {
        match severity {
            4 => self.critical,
            3 => self.high,
            2 => self.medium,
            1 => self.low,
            _ => self.info,
        }
    }

    pub fn total(&self, show_info: bool) -> u32 {
        self.critical + self.high + self.medium + self.low + if show_info { self.info } else { 0 }
    }

    fn of<'a>(items: impl IntoIterator<Item = &'a ReportItem>) -> Self {
        let mut c = Counts::default();
        for i in items {
            c.add(i.severity);
        }
        c
    }
}

// ── times ────────────────────────────────────────────────────────────────────

// Nessus writes HOST_START as "Mon Jan  1 10:00:00 2024" in the scanner's local time.
// Milliseconds since 1970, read as local time like the window did
pub fn nessus_time(value: Option<&str>) -> Option<i64> {
    use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
    let value = value?.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.is_empty() {
        return None;
    }
    // the weekday is left out: a wrong one shouldn't lose the time
    let without_day = value.split_once(' ').map_or(value.as_str(), |(_, rest)| rest);
    if let Ok(t) = NaiveDateTime::parse_from_str(without_day, "%b %d %H:%M:%S %Y") {
        return Local.from_local_datetime(&t).earliest().map(|t| t.timestamp_millis());
    }
    DateTime::parse_from_rfc3339(&value)
        .or_else(|_| DateTime::parse_from_rfc2822(&value))
        .ok()
        .map(|t| t.timestamp_millis())
}// nessus_time

// earliest host start, and how long it ran until the latest host end
pub fn scan_window<'a>(hosts: impl IntoIterator<Item = &'a ReportHost>) -> (Option<i64>, Option<i64>) {
    let mut start: Option<i64> = None;
    let mut end: Option<i64> = None;
    for h in hosts {
        if let Some(s) = nessus_time(h.host_start.as_deref()) {
            start = Some(start.map_or(s, |x| x.min(s)));
        }
        if let Some(e) = nessus_time(h.host_end.as_deref()) {
            end = Some(end.map_or(e, |x| x.max(e)));
        }
    }
    match (start, end) {
        (Some(s), Some(e)) if e >= s => (Some(s), Some(e - s)),
        (s, _) => (s, None),
    }
}// scan_window

// ── ordering ─────────────────────────────────────────────────────────────────

fn ipv4_number(value: &str) -> Option<u64> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some(parts.iter().fold(0u64, |n, p| n * 256 + p.parse::<u64>().unwrap_or(0)))
}// ipv4_number

// IPv4 addresses numerically, then IPv6 addresses and names as text
pub fn compare_hosts(a: &str, b: &str) -> Ordering {
    match (ipv4_number(a), ipv4_number(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => compare_text(a, b),
    }
}// compare_hosts

pub fn compare_text(a: &str, b: &str) -> Ordering {
    a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| a.cmp(b))
}// compare_text

// ── what a file holds, worked out once when it opens ──────────────────────────

#[derive(Serialize, Clone, Debug)]
pub struct FileInfo {
    pub id: String,
    pub filename: String,
    pub path: String,
    pub loaded_at: String,
    pub report_name: String,
    pub target: Option<String>,
    pub compliance_skipped: usize,
    pub size: u64,
    pub host_count: usize,
    pub finding_count: usize,
    pub counts: Counts,
    pub start: Option<i64>,       // ms since 1970
    pub duration_ms: Option<i64>,
    pub credentialed: usize,      // hosts scanned with credentials
    #[serde(skip)]
    pub order: u64,               // when it was opened; files read at the same time keep this order
}// FileInfo

pub fn file_info(file: &NessusFile, size: u64) -> FileInfo {
    let (start, duration_ms) = scan_window(&file.hosts);
    FileInfo {
        id: file.id.clone(),
        filename: file.filename.clone(),
        path: file.path.clone(),
        loaded_at: file.loaded_at.clone(),
        report_name: file.report_name.clone(),
        target: file.target.clone(),
        compliance_skipped: file.compliance_skipped,
        size,
        host_count: file.hosts.len(),
        finding_count: file.hosts.iter().map(|h| h.items.len()).sum(),
        counts: Counts::of(file.hosts.iter().flat_map(|h| &h.items)),
        start,
        duration_ms,
        credentialed: file.hosts.iter().filter(|h| h.credentialed_scan).count(),
        order: 0,
    }
}// file_info

// ── a finding's place in the open files ───────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct At {
    pub file: u32,
    pub host: u32,
    pub item: u32,
}// At

// ── the merged lists for one set of files ─────────────────────────────────────

pub struct View {
    pub files: Vec<Arc<NessusFile>>,
    vulns: OnceLock<Vulns>,
    hosts: OnceLock<Hosts>,
    services: OnceLock<Vec<Service>>,
}// View

pub struct Vulns {
    pub list: Vec<Vuln>,
    pub at: HashMap<u32, usize>,
}

pub struct Hosts {
    pub list: Vec<Host>,
    pub at: HashMap<String, usize>,
}

impl View {
    pub fn new(files: Vec<Arc<NessusFile>>) -> Self {
        Self { files, vulns: OnceLock::new(), hosts: OnceLock::new(), services: OnceLock::new() }
    }

    pub fn item(&self, at: At) -> &ReportItem {
        &self.files[at.file as usize].hosts[at.host as usize].items[at.item as usize]
    }

    pub fn host_of(&self, at: At) -> &ReportHost {
        &self.files[at.file as usize].hosts[at.host as usize]
    }

    pub fn vulns(&self) -> &Vulns {
        self.vulns.get_or_init(|| build_vulns(self))
    }

    pub fn hosts(&self) -> &Hosts {
        self.hosts.get_or_init(|| build_hosts(self))
    }

    pub fn services(&self) -> &[Service] {
        self.services.get_or_init(|| build_services(self))
    }

    pub fn vuln(&self, plugin_id: u32) -> Option<&Vuln> {
        let v = self.vulns();
        v.at.get(&plugin_id).map(|&i| &v.list[i])
    }

    pub fn host(&self, ip: &str) -> Option<&Host> {
        let h = self.hosts();
        h.at.get(ip).map(|&i| &h.list[i])
    }
}

// ── vulnerabilities ──────────────────────────────────────────────────────────

pub struct Vuln {
    pub first: Arc<PluginDetails>,  // as first seen: name, family, texts, CVEs
    pub severity: u8,
    pub rated_by: Arc<PluginDetails>, // the finding with the worst rating gives the scores
    pub exploit_available: bool,
    pub metasploit_available: bool,
    pub exploited_by_malware: bool,
    pub exploited_by_nessus: bool,
    pub unsupported_by_vendor: bool,
    pub exploit_maturity: Option<String>,
    pub cisa_known_exploited: Option<String>,
    pub exploit_frameworks: Vec<String>,
    pub synopsis: Option<String>,
    pub metasploit_name: Option<String>,
    pub patch_publication_date: Option<String>,
    pub vuln_publication_date: Option<String>,
    pub affected: Vec<At>,                  // one per host + port + file
    pub file_ratings: Vec<(u32, u8)>,       // worst per file
    pub host_count: usize,
}// Vuln

fn build_vulns(view: &View) -> Vulns {
    let mut list: Vec<Vuln> = Vec::new();
    let mut at: HashMap<u32, usize> = HashMap::new();
    let mut ips: Vec<HashSet<&str>> = Vec::new();

    for (fi, file) in view.files.iter().enumerate() {
        for (hi, host) in file.hosts.iter().enumerate() {
            for (ii, item) in host.items.iter().enumerate() {
                let slot = *at.entry(item.plugin_id).or_insert_with(|| {
                    let d = &item.details;
                    list.push(Vuln {
                        first: Arc::clone(d),
                        severity: item.severity,
                        rated_by: Arc::clone(d),
                        exploit_available: false,
                        metasploit_available: false,
                        exploited_by_malware: false,
                        exploited_by_nessus: false,
                        unsupported_by_vendor: false,
                        exploit_maturity: d.exploit_maturity.clone(),
                        cisa_known_exploited: None,
                        exploit_frameworks: Vec::new(),
                        synopsis: d.synopsis.clone(),
                        metasploit_name: d.metasploit_name.clone(),
                        patch_publication_date: d.patch_publication_date.clone(),
                        vuln_publication_date: d.vuln_publication_date.clone(),
                        affected: Vec::new(),
                        file_ratings: Vec::new(),
                        host_count: 0,
                    });
                    ips.push(HashSet::new());
                    list.len() - 1
                });
                let v = &mut list[slot];
                // plugin updates can re-rate a finding between scans, so the worst rating is shown
                if item.severity > v.severity {
                    v.severity = item.severity;
                    v.rated_by = Arc::clone(&item.details);
                }
                match v.file_ratings.last_mut() {
                    Some((f, s)) if *f == fi as u32 => *s = (*s).max(item.severity),
                    _ => v.file_ratings.push((fi as u32, item.severity)),
                }
                v.exploit_available |= item.exploit_available;
                v.metasploit_available |= item.metasploit_available;
                v.exploited_by_malware |= item.exploited_by_malware;
                v.exploited_by_nessus |= item.exploited_by_nessus;
                v.unsupported_by_vendor |= item.unsupported_by_vendor;
                fill(&mut v.exploit_maturity, &item.exploit_maturity);
                fill(&mut v.cisa_known_exploited, &item.cisa_known_exploited);
                for framework in &item.exploit_frameworks {
                    if !v.exploit_frameworks.contains(framework) {
                        v.exploit_frameworks.push(framework.clone());
                    }
                }
                // an older plugin version in another file may not have these yet
                fill(&mut v.synopsis, &item.synopsis);
                fill(&mut v.metasploit_name, &item.metasploit_name);
                fill(&mut v.patch_publication_date, &item.patch_publication_date);
                fill(&mut v.vuln_publication_date, &item.vuln_publication_date);
                ips[slot].insert(&host.ip);
                v.affected.push(At { file: fi as u32, host: hi as u32, item: ii as u32 });
            }
        }
    }
    for (v, set) in list.iter_mut().zip(&ips) {
        v.host_count = set.len();
    }

    let mut order: Vec<usize> = (0..list.len()).collect();
    order.sort_by(|&a, &b| list[b].severity.cmp(&list[a].severity).then_with(|| compare_text(&list[a].first.plugin_name, &list[b].first.plugin_name)));
    let mut slots: Vec<Option<Vuln>> = list.into_iter().map(Some).collect();
    let list: Vec<Vuln> = order.into_iter().map(|i| slots[i].take().unwrap()).collect();
    let at = list.iter().enumerate().map(|(i, v)| (v.first.plugin_id, i)).collect();
    Vulns { list, at }
}// build_vulns

fn fill(target: &mut Option<String>, value: &Option<String>) {
    if target.is_none() {
        target.clone_from(value);
    }
}// fill

// a row of the Vulnerabilities table: everything but the long texts and the hosts
#[derive(Serialize)]
pub struct VulnRow<'a> {
    plugin_id: u32,
    plugin_name: &'a str,
    plugin_family: &'a str,
    severity: u8,
    risk_factor: &'a str,
    cvss2: Option<f32>,
    cvss3: Option<f32>,
    cvss4: Option<f32>,
    vpr: Option<f32>,
    epss: Option<f32>,
    exploit_available: bool,
    metasploit_available: bool,
    metasploit_name: Option<&'a str>,
    exploit_ease: Option<&'a str>,
    exploit_maturity: Option<&'a str>,
    exploit_frameworks: &'a [String],
    exploited_by_malware: bool,
    exploited_by_nessus: bool,
    cisa_known_exploited: Option<&'a str>,
    unsupported_by_vendor: bool,
    patch_publication_date: Option<&'a str>,
    vuln_publication_date: Option<&'a str>,
    cve: &'a [String],
    cwe: &'a [String],
    file_ratings: Vec<FileRating<'a>>,
    host_count: usize,
}// VulnRow

#[derive(Serialize)]
pub struct FileRating<'a> {
    file_id: &'a str,
    filename: &'a str,
    severity: u8,
}

impl Vuln {
    pub fn row<'a>(&'a self, view: &'a View) -> VulnRow<'a> {
        let r = &self.rated_by;
        VulnRow {
            plugin_id: self.first.plugin_id,
            plugin_name: &self.first.plugin_name,
            plugin_family: &self.first.plugin_family,
            severity: self.severity,
            risk_factor: &r.risk_factor,
            cvss2: r.cvss_base_score,
            cvss3: r.cvss3_base_score,
            cvss4: r.cvss4_base_score,
            vpr: r.vpr_score,
            epss: r.epss_score,
            exploit_available: self.exploit_available,
            metasploit_available: self.metasploit_available,
            metasploit_name: self.metasploit_name.as_deref(),
            exploit_ease: self.first.exploit_ease.as_deref(),
            exploit_maturity: self.exploit_maturity.as_deref(),
            exploit_frameworks: &self.exploit_frameworks,
            exploited_by_malware: self.exploited_by_malware,
            exploited_by_nessus: self.exploited_by_nessus,
            cisa_known_exploited: self.cisa_known_exploited.as_deref(),
            unsupported_by_vendor: self.unsupported_by_vendor,
            patch_publication_date: self.patch_publication_date.as_deref(),
            vuln_publication_date: self.vuln_publication_date.as_deref(),
            cve: &self.first.cve,
            cwe: &self.first.cwe,
            file_ratings: self.file_ratings.iter().map(|&(f, severity)| {
                let file = &view.files[f as usize];
                FileRating { file_id: &file.id, filename: &file.filename, severity }
            }).collect(),
            host_count: self.host_count,
        }
    }
}

// ── hosts ────────────────────────────────────────────────────────────────────

pub struct Host {
    pub props: ReportHost,          // without items: first file's, gaps filled from later ones
    pub file_ids: Vec<u32>,
    pub counts: Counts,
    pub open_ports: Vec<String>,
    pub items: Vec<At>,
    pub conflicts: Vec<&'static str>,
}// Host

fn host_props(h: &ReportHost) -> ReportHost {
    ReportHost {
        name: h.name.clone(),
        ip: h.ip.clone(),
        hostname: h.hostname.clone(),
        domain: h.domain.clone(),
        os: h.os.clone(),
        mac: h.mac.clone(),
        netbios: h.netbios.clone(),
        system_type: h.system_type.clone(),
        credentialed_scan: h.credentialed_scan,
        os_unsupported: h.os_unsupported,
        host_start: h.host_start.clone(),
        host_end: h.host_end.clone(),
        alt_hostnames: h.alt_hostnames.clone(),
        items: Vec::new(),
    }
}// host_props

fn first_mac(mac: &str) -> String {
    mac.split(['\n', ',']).next().unwrap_or("").trim().to_lowercase()
}

fn build_hosts(view: &View) -> Hosts {
    let mut list: Vec<Host> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    // per host, where each plugin + port + protocol first went in `items`
    let mut seen: Vec<HashMap<(u32, u16, &str), usize>> = Vec::new();

    for (fi, file) in view.files.iter().enumerate() {
        for (hi, host) in file.hosts.iter().enumerate() {
            let slot = match at.get(&host.ip) {
                Some(&slot) => {
                    let e = &mut list[slot];
                    let p = &mut e.props;
                    for (field, value) in [
                        (&mut p.hostname, &host.hostname),
                        (&mut p.domain, &host.domain),
                        (&mut p.os, &host.os),
                        (&mut p.system_type, &host.system_type),
                    ] {
                        fill(field, value);
                    }
                    if let (Some(a), Some(b)) = (&p.mac, &host.mac) {
                        if first_mac(a) != first_mac(b) && !e.conflicts.contains(&"MAC address") {
                            e.conflicts.push("MAC address");
                        }
                    }
                    fill(&mut p.mac, &host.mac);
                    if let (Some(a), Some(b)) = (&p.netbios, &host.netbios) {
                        if a.to_lowercase() != b.to_lowercase() && !e.conflicts.contains(&"NetBIOS name") {
                            e.conflicts.push("NetBIOS name");
                        }
                    }
                    fill(&mut p.netbios, &host.netbios);
                    p.os_unsupported |= host.os_unsupported;
                    p.credentialed_scan |= host.credentialed_scan;
                    for n in &host.alt_hostnames {
                        if !p.alt_hostnames.contains(n) {
                            p.alt_hostnames.push(n.clone());
                        }
                    }
                    if !e.file_ids.contains(&(fi as u32)) {
                        e.file_ids.push(fi as u32);
                    }
                    slot
                }
                None => {
                    list.push(Host {
                        props: host_props(host),
                        file_ids: vec![fi as u32],
                        counts: Counts::default(),
                        open_ports: Vec::new(),
                        items: Vec::new(),
                        conflicts: Vec::new(),
                    });
                    seen.push(HashMap::new());
                    at.insert(host.ip.clone(), list.len() - 1);
                    list.len() - 1
                }
            };
            add_items(view, &mut list[slot], &mut seen[slot], fi, hi, host);
        }
    }

    let mut order: Vec<usize> = (0..list.len()).collect();
    order.sort_by(|&a, &b| compare_hosts(&list[a].props.ip, &list[b].props.ip));
    let mut slots: Vec<Option<Host>> = list.into_iter().map(Some).collect();
    let list: Vec<Host> = order.into_iter().map(|i| slots[i].take().unwrap()).collect();
    let at = list.iter().enumerate().map(|(i, h)| (h.props.ip.clone(), i)).collect();
    Hosts { list, at }
}// build_hosts

// a finding already added from an earlier file isn't added again, but keeps the worst rating.
// Repeats within one file are all kept
fn add_items<'a>(view: &View, entry: &mut Host, seen: &mut HashMap<(u32, u16, &'a str), usize>, fi: usize, hi: usize, host: &'a ReportHost) {
    let mut fresh: Vec<usize> = Vec::new();
    for (ii, item) in host.items.iter().enumerate() {
        let key = (item.plugin_id, item.port, &*item.protocol);
        match seen.get(&key) {
            None => fresh.push(ii),
            Some(&slot) => {
                let old = view.item(entry.items[slot]).severity;
                if item.severity > old {
                    entry.counts.remove(old);
                    entry.counts.add(item.severity);
                    entry.items[slot] = At { file: fi as u32, host: hi as u32, item: ii as u32 };
                }
            }
        }
    }
    for ii in fresh {
        let item = &host.items[ii];
        seen.entry((item.plugin_id, item.port, &*item.protocol)).or_insert(entry.items.len());
        entry.items.push(At { file: fi as u32, host: hi as u32, item: ii as u32 });
        entry.counts.add(item.severity);
        if item.port > 0 {
            let port = format!("{}/{}", item.port, item.protocol);
            if !entry.open_ports.contains(&port) {
                entry.open_ports.push(port);
            }
        }
    }
}// add_items

// a row of the Hosts table
#[derive(Serialize)]
pub struct HostRow<'a> {
    ip: &'a str,
    hostname: Option<&'a str>,
    domain: Option<&'a str>,
    os: Option<&'a str>,
    mac: Option<&'a str>,
    netbios: Option<&'a str>,
    system_type: Option<&'a str>,
    credentialed_scan: bool,
    os_unsupported: bool,
    host_start: Option<&'a str>,
    host_end: Option<&'a str>,
    alt_hostnames: &'a [String],
    file_id: &'a str,
    filename: &'a str,
    file_ids: Vec<&'a str>,
    filenames: Vec<&'a str>,
    severity_counts: Counts,
    open_ports: &'a [String],
    conflicts: &'a [&'static str],
}// HostRow

impl Host {
    pub fn row<'a>(&'a self, view: &'a View) -> HostRow<'a> {
        let p = &self.props;
        let files: Vec<&NessusFile> = self.file_ids.iter().map(|&f| view.files[f as usize].as_ref()).collect();
        HostRow {
            ip: &p.ip,
            hostname: p.hostname.as_deref(),
            domain: p.domain.as_deref(),
            os: p.os.as_deref(),
            mac: p.mac.as_deref(),
            netbios: p.netbios.as_deref(),
            system_type: p.system_type.as_deref(),
            credentialed_scan: p.credentialed_scan,
            os_unsupported: p.os_unsupported,
            host_start: p.host_start.as_deref(),
            host_end: p.host_end.as_deref(),
            alt_hostnames: &p.alt_hostnames,
            file_id: &files[0].id,
            filename: &files[0].filename,
            file_ids: files.iter().map(|f| f.id.as_str()).collect(),
            filenames: files.iter().map(|f| f.filename.as_str()).collect(),
            severity_counts: self.counts,
            open_ports: &self.open_ports,
            conflicts: &self.conflicts,
        }
    }
}

// ── services ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Clone, Copy, Debug, PartialEq)]
pub struct CvssScore {
    pub score: f32,
    pub version: u8,
}

// CVSS v2 only counts 10.0 as critical. VPR uses the same ranges as CVSS v3
pub fn cvss_severity(score: f32, version: u8) -> u8 {
    if score >= if version == 2 { 10.0 } else { 9.0 } {
        4
    } else if score >= 7.0 {
        3
    } else if score >= 4.0 {
        2
    } else if score > 0.0 {
        1
    } else {
        0
    }
}// cvss_severity

// the score that gives the finding its severity, or else the newest version's
pub fn rated_score(d: &PluginDetails, severity: u8) -> Option<CvssScore> {
    let known: Vec<CvssScore> = [(d.cvss4_base_score, 4), (d.cvss3_base_score, 3), (d.cvss_base_score, 2)]
        .into_iter()
        .filter_map(|(s, version)| s.map(|score| CvssScore { score, version }))
        .collect();
    known.iter().find(|s| cvss_severity(s.score, s.version) == severity).or(known.first()).copied()
}// rated_score

#[derive(Serialize)]
pub struct ServiceFinding {
    pub plugin_id: u32,
    pub plugin_name: String,
    pub severity: u8,
    pub score: Option<CvssScore>,
    pub host_count: usize,
}

#[derive(Serialize)]
pub struct Service {
    pub key: String,
    pub port: u16,
    pub protocol: String,
    pub svc_names: Vec<String>,
    pub host_ips: Vec<String>,
    pub severity_counts: Counts, // counts each finding once
    pub findings: Vec<ServiceFinding>,
    pub exploit_available: bool,
}// Service

// One per port and protocol with at least one finding. Port 0 is left out
fn build_services(view: &View) -> Vec<Service> {
    struct Plugin<'a> { name: &'a str, severity: i16, score: Option<CvssScore>, ips: HashSet<&'a str> }
    struct Building<'a> { port: u16, protocol: &'a str, names: HashSet<&'a str>, ips: HashSet<&'a str>, plugins: Vec<(u32, Plugin<'a>)>, at: HashMap<u32, usize>, exploit: bool }
    let mut services: Vec<Building> = Vec::new();
    let mut at: HashMap<(u16, &str), usize> = HashMap::new();

    for file in &view.files {
        for host in &file.hosts {
            for item in &host.items {
                if item.port == 0 {
                    continue;
                }
                let slot = *at.entry((item.port, &*item.protocol)).or_insert_with(|| {
                    services.push(Building { port: item.port, protocol: &item.protocol, names: HashSet::new(), ips: HashSet::new(), plugins: Vec::new(), at: HashMap::new(), exploit: false });
                    services.len() - 1
                });
                let s = &mut services[slot];
                if !item.svc_name.is_empty() {
                    s.names.insert(&item.svc_name);
                }
                s.ips.insert(&host.ip);
                s.exploit |= item.exploit_available;
                // rated by the scans of this port only. The score comes from the finding that set the severity
                let p = *s.at.entry(item.plugin_id).or_insert_with(|| {
                    s.plugins.push((item.plugin_id, Plugin { name: &item.plugin_name, severity: -1, score: None, ips: HashSet::new() }));
                    s.plugins.len() - 1
                });
                let plugin = &mut s.plugins[p].1;
                if i16::from(item.severity) > plugin.severity {
                    plugin.severity = i16::from(item.severity);
                    plugin.score = rated_score(&item.details, item.severity);
                }
                plugin.ips.insert(&host.ip);
            }
        }
    }

    let mut list: Vec<Service> = services.into_iter().map(|s| {
        let mut findings: Vec<ServiceFinding> = s.plugins.into_iter().map(|(plugin_id, p)| ServiceFinding {
            plugin_id,
            plugin_name: p.name.to_string(),
            severity: p.severity.max(0) as u8,
            score: p.score,
            host_count: p.ips.len(),
        }).collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| compare_text(&a.plugin_name, &b.plugin_name)));
        let mut severity_counts = Counts::default();
        for f in &findings {
            severity_counts.add(f.severity);
        }
        let mut svc_names: Vec<String> = s.names.into_iter().map(str::to_string).collect();
        svc_names.sort();
        let mut host_ips: Vec<String> = s.ips.into_iter().map(str::to_string).collect();
        host_ips.sort_by(|a, b| compare_hosts(a, b));
        Service {
            key: format!("{}/{}", s.port, s.protocol),
            port: s.port,
            protocol: s.protocol.to_string(),
            svc_names,
            host_ips,
            severity_counts,
            findings,
            exploit_available: s.exploit,
        }
    }).collect();
    list.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.protocol.cmp(&b.protocol)));
    list
}// build_services

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_str;

    fn scan(name: &str, hosts: &str) -> Arc<NessusFile> {
        let mut f = parse_str(&format!(r#"<NessusClientData_v2><Report name="r">{hosts}</Report></NessusClientData_v2>"#)).unwrap();
        f.id = name.to_string();
        f.filename = format!("{name}.nessus");
        Arc::new(f)
    }

    fn item(plugin: u32, port: u16, severity: u8, extra: &str) -> String {
        format!(r#"<ReportItem port="{port}" svc_name="www" protocol="tcp" severity="{severity}" pluginID="{plugin}" pluginName="P{plugin}" pluginFamily="F">{extra}</ReportItem>"#)
    }

    fn host(ip: &str, props: &str, items: &[String]) -> String {
        format!(r#"<ReportHost name="{ip}"><HostProperties>{props}</HostProperties>{}</ReportHost>"#, items.concat())
    }

    #[test]
    fn hosts_merge_across_files_and_keep_the_worst_rating() {
        let a = scan("a", &host("10.0.0.2", r#"<tag name="mac-address">aa:bb</tag>"#, &[item(1, 80, 2, ""), item(2, 443, 1, "")]));
        let b = scan("b", &(host("10.0.0.2", r#"<tag name="mac-address">cc:dd</tag><tag name="netbios-name">PC</tag>"#, &[item(1, 80, 3, ""), item(3, 0, 0, "")]) + &host("10.0.0.10", "", &[item(1, 80, 2, "")])));
        let view = View::new(vec![a, b]);
        let hosts = view.hosts();
        assert_eq!(hosts.list.iter().map(|h| h.props.ip.as_str()).collect::<Vec<_>>(), ["10.0.0.2", "10.0.0.10"]);
        let h = view.host("10.0.0.2").unwrap();
        assert_eq!(h.counts, Counts { high: 1, low: 1, info: 1, ..Counts::default() });
        assert_eq!(h.open_ports, ["80/tcp", "443/tcp"]);
        assert_eq!(h.conflicts, ["MAC address"]);
        assert_eq!(h.props.netbios.as_deref(), Some("PC"));
        assert_eq!(h.file_ids, [0, 1]);
        assert_eq!(view.item(h.items[0]).severity, 3);
    }

    #[test]
    fn vulns_count_hosts_once_and_rate_by_the_worst_file() {
        let a = scan("a", &host("10.0.0.1", "", &[item(7, 80, 2, "<cvss3_base_score>5.0</cvss3_base_score>"), item(7, 443, 2, "<cvss3_base_score>5.0</cvss3_base_score>")]));
        let b = scan("b", &host("10.0.0.1", "", &[item(7, 80, 3, "<cvss3_base_score>7.5</cvss3_base_score><synopsis>s</synopsis>")]));
        let view = View::new(vec![a, b]);
        let v = view.vuln(7).unwrap();
        assert_eq!((v.severity, v.host_count, v.affected.len()), (3, 1, 3));
        assert_eq!(v.rated_by.cvss3_base_score, Some(7.5));
        assert_eq!(v.synopsis.as_deref(), Some("s"));
        assert_eq!(v.file_ratings, [(0, 2), (1, 3)]);
    }

    #[test]
    fn services_rate_each_plugin_on_its_own_port() {
        let a = scan("a", &(host("10.0.0.1", "", &[item(7, 80, 2, ""), item(8, 80, 4, "<cvss3_base_score>9.8</cvss3_base_score>"), item(9, 0, 0, "")]) + &host("10.0.0.2", "", &[item(7, 80, 3, "")])));
        let view = View::new(vec![a]);
        let s = view.services();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].key, "80/tcp");
        assert_eq!(s[0].host_ips, ["10.0.0.1", "10.0.0.2"]);
        assert_eq!(s[0].severity_counts, Counts { critical: 1, high: 1, ..Counts::default() });
        assert_eq!(s[0].findings[0].score, Some(CvssScore { score: 9.8, version: 3 }));
        assert_eq!(s[0].findings[1].host_count, 2);
    }

    #[test]
    fn nessus_times_and_the_scan_window() {
        let a = scan("a", &(host("10.0.0.1", r#"<tag name="HOST_START">Mon Jan  1 10:00:00 2024</tag><tag name="HOST_END">Mon Jan  1 10:30:00 2024</tag>"#, &[]) + &host("10.0.0.2", r#"<tag name="HOST_START">Mon Jan  1 09:00:00 2024</tag>"#, &[])));
        let (start, duration) = scan_window(&a.hosts);
        assert_eq!(duration, Some(90 * 60 * 1000));
        assert_eq!(start, nessus_time(Some("Mon Jan 1 09:00:00 2024")));
        assert!(nessus_time(Some("not a time")).is_none());
        // 7 Nov 2025 was a Friday
        assert_eq!(nessus_time(Some("Sat Nov  7 22:10:03 2025")), nessus_time(Some("Fri Nov 7 22:10:03 2025")));
        assert!(nessus_time(Some("Sat Nov  7 22:10:03 2025")).is_some());
    }

    #[test]
    fn hosts_sort_numerically_then_by_name() {
        let mut ips = vec!["host-b", "10.0.0.10", "fe80::1", "10.0.0.9", "Host-a"];
        ips.sort_by(|a, b| compare_hosts(a, b));
        assert_eq!(ips, ["10.0.0.9", "10.0.0.10", "fe80::1", "Host-a", "host-b"]);
    }

    #[test]
    fn rated_score_matches_the_severity() {
        let d = PluginDetails { cvss_base_score: Some(10.0), cvss3_base_score: Some(7.5), ..PluginDetails::default() };
        assert_eq!(rated_score(&d, 4), Some(CvssScore { score: 10.0, version: 2 }));
        assert_eq!(rated_score(&d, 3), Some(CvssScore { score: 7.5, version: 3 }));
        assert_eq!(rated_score(&d, 1), Some(CvssScore { score: 7.5, version: 3 }));
    }

    // ── cases carried over from the window's builder tests ──

    fn on(plugin: u32, port: u16, protocol: &str, severity: u8, extra: &str) -> String {
        format!(r#"<ReportItem port="{port}" svc_name="www" protocol="{protocol}" severity="{severity}" pluginID="{plugin}" pluginName="plugin {plugin}" pluginFamily="F">{extra}</ReportItem>"#)
    }

    type Hosts<'a> = &'a [(&'a str, Vec<String>)];

    fn files(list: &[(&str, Hosts)]) -> View {
        View::new(list.iter().map(|(id, hosts)| scan(id, &hosts.iter().map(|(ip, items)| host(ip, "", items)).collect::<String>())).collect())
    }

    #[test]
    fn a_host_keeps_the_worst_rating_but_repeats_within_one_file() {
        for severities in [vec![1u8, 4], vec![4, 1], vec![1, 4, 2]] {
            let list: Vec<(String, Vec<String>)> = severities.iter().map(|s| (format!("f{s}"), vec![on(1, 80, "tcp", *s, &format!("<plugin_output>severity {s}</plugin_output>"))])).collect();
            let view = View::new(list.iter().map(|(id, items)| scan(id, &host("10.0.0.1", "", items))).collect());
            let h = view.host("10.0.0.1").unwrap();
            assert_eq!(h.items.len(), 1);
            assert_eq!(view.item(h.items[0]).plugin_output.as_deref(), Some("severity 4"));
            assert_eq!(h.counts, Counts { critical: 1, ..Counts::default() });
        }
        let twice = vec![on(1, 80, "tcp", 2, ""), on(1, 80, "tcp", 2, "")];
        let one = files(&[("a", &[("10.0.0.1", twice.clone())])]);
        assert_eq!(one.host("10.0.0.1").unwrap().counts.medium, 2);
        let two = files(&[("a", &[("10.0.0.1", twice.clone())]), ("b", &[("10.0.0.1", twice)])]);
        assert_eq!(two.host("10.0.0.1").unwrap().items.len(), 2);
    }

    #[test]
    fn services_keep_names_protocols_and_leave_out_port_0() {
        let view = files(&[("a", &[("10.0.0.2", vec![on(1, 443, "tcp", 2, "")]), ("10.0.0.10", vec![on(2, 443, "tcp", 2, "").replace("svc_name=\"www\"", "svc_name=\"https?\"")])])]);
        let s = view.services();
        assert_eq!((s.len(), s[0].svc_names.clone(), s[0].host_ips.clone()), (1, vec!["https?".to_string(), "www".to_string()], vec!["10.0.0.2".to_string(), "10.0.0.10".to_string()]));

        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 53, "tcp", 2, ""), on(2, 53, "udp", 2, ""), on(3, 0, "tcp", 2, "")])])]);
        assert_eq!(view.services().iter().map(|s| (s.key.as_str(), s.findings.len())).collect::<Vec<_>>(), [("53/tcp", 1), ("53/udp", 1)]);
    }

    #[test]
    fn a_service_counts_a_finding_once_rated_by_its_own_port() {
        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 80, "tcp", 1, "")]), ("10.0.0.2", vec![on(1, 80, "tcp", 1, "")])]), ("b", &[("10.0.0.1", vec![on(1, 80, "tcp", 3, "")])])]);
        let s = &view.services()[0];
        assert_eq!((s.findings.len(), s.findings[0].severity, s.findings[0].host_count), (1, 3, 2));
        assert_eq!(s.severity_counts, Counts { high: 1, ..Counts::default() });

        // a newer plugin version re-rated it, but only the scan of port 23 used that version
        let view = files(&[("old", &[("10.0.0.1", vec![on(1, 2002, "tcp", 1, "<cvss_base_score>2.6</cvss_base_score>")])]), ("new", &[("10.0.0.2", vec![on(1, 23, "tcp", 2, "<cvss_base_score>5.8</cvss_base_score>")])])]);
        assert_eq!(view.services().iter().map(|s| (s.key.as_str(), s.findings[0].severity, s.findings[0].score.map(|x| x.score))).collect::<Vec<_>>(), [("23/tcp", 2, Some(5.8)), ("2002/tcp", 1, Some(2.6))]);

        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 80, "tcp", 1, "<cvss_base_score>2.6</cvss_base_score>")])]), ("b", &[("10.0.0.1", vec![on(1, 80, "tcp", 2, "<cvss_base_score>5.8</cvss_base_score>")])]), ("c", &[("10.0.0.1", vec![on(1, 80, "tcp", 1, "<cvss_base_score>2.6</cvss_base_score>")])])]);
        assert_eq!(view.services()[0].findings[0].score, Some(CvssScore { score: 5.8, version: 2 }));

        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 80, "tcp", 2, "<exploit_available>true</exploit_available>"), on(2, 80, "tcp", 2, "")])])]);
        assert!(view.services()[0].exploit_available);
    }

    #[test]
    fn a_vulnerability_merges_what_the_files_say() {
        let rated = |sev: u8, v2: &str, v3: &str| on(1, 80, "tcp", sev, &format!("<cvss_base_score>{v2}</cvss_base_score>{v3}"));
        for order in [[(1u8, "2.6", ""), (4, "10.0", "<cvss3_base_score>9.8</cvss3_base_score>")], [(4, "10.0", "<cvss3_base_score>9.8</cvss3_base_score>"), (1, "2.6", "")]] {
            let view = files(&[("a", &[("10.0.0.1", vec![rated(order[0].0, order[0].1, order[0].2)])]), ("b", &[("10.0.0.1", vec![rated(order[1].0, order[1].1, order[1].2)])])]);
            let v = view.vuln(1).unwrap();
            assert_eq!((v.severity, v.rated_by.cvss_base_score, v.rated_by.cvss3_base_score), (4, Some(10.0), Some(9.8)));
        }

        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 80, "tcp", 2, "")])]), ("b", &[("10.0.0.1", vec![on(1, 80, "tcp", 2, "<exploit_available>true</exploit_available><exploit_framework_metasploit>true</exploit_framework_metasploit><synopsis>s</synopsis><metasploit_name>m</metasploit_name><patch_publication_date>2012/01/31</patch_publication_date><vuln_publication_date>2011/08/24</vuln_publication_date>")])])]);
        let v = view.vuln(1).unwrap();
        assert!(v.exploit_available && v.metasploit_available);
        assert_eq!((v.synopsis.as_deref(), v.metasploit_name.as_deref(), v.patch_publication_date.as_deref(), v.vuln_publication_date.as_deref()), (Some("s"), Some("m"), Some("2012/01/31"), Some("2011/08/24")));

        // two ratings inside one file count as that file's worst
        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 80, "tcp", 1, ""), on(1, 443, "tcp", 3, "")])]), ("b", &[("10.0.0.1", vec![on(1, 80, "tcp", 3, "")])])]);
        assert_eq!(view.vuln(1).unwrap().file_ratings, [(0, 3), (1, 3)]);

        let view = files(&[("a", &[("10.0.0.1", vec![on(1, 80, "tcp", 2, ""), on(1, 443, "tcp", 2, "")]), ("10.0.0.2", vec![on(1, 80, "tcp", 2, "")])]), ("b", &[("10.0.0.1", vec![on(1, 80, "tcp", 2, "")])])]);
        let v = view.vuln(1).unwrap();
        assert_eq!((v.affected.len(), v.host_count), (4, 2));
    }

    #[test]
    fn host_order_has_no_trouble_with_ipv6_or_names() {
        let view = files(&[("a", &[("fe80::1", vec![]), ("10.0.0.10", vec![]), ("10.0.0.2", vec![]), ("db.example", vec![])])]);
        assert_eq!(view.hosts().list.iter().map(|h| h.props.ip.as_str()).collect::<Vec<_>>(), ["10.0.0.2", "10.0.0.10", "db.example", "fe80::1"]);
    }
}
