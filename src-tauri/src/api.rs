// what the pages ask for
use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::models::{NessusFile, ReportItem};
use crate::state::AppState;
use crate::views::{compare_hosts, compare_text, file_info, Counts, FileInfo, HostRow, View, VulnRow};

// lists for all open files
pub fn view(state: &AppState, file: Option<&str>) -> Arc<View> {
    view_of(state, file.map(|id| vec![id.to_string()]).as_deref())
}// view

// the lists for some of the open files. Ids that aren't open are left out; none left means all files
pub fn view_of(state: &AppState, ids: Option<&[String]>) -> Arc<View> {
    let files = state.files.lock().unwrap().clone();
    let picked: Vec<&str> = ids.unwrap_or(&[]).iter().map(String::as_str).filter(|id| files.iter().any(|f| f.id == *id)).collect();
    let all = picked.is_empty() || picked.len() == files.len();
    let mut key: Vec<&str> = if all { Vec::new() } else { picked.clone() };
    key.sort_unstable();
    key.dedup();
    let mut views = state.views.lock().unwrap();
    Arc::clone(views.entry(key.join(",")).or_insert_with(|| {
        Arc::new(View::new(if all { files } else { files.into_iter().filter(|f| picked.contains(&f.id.as_str())).collect() }))
    }))
}// view_of

fn json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}// json

// ── files ────────────────────────────────────────────────────────────────────

// keeps a parsed file open and shares plugin texts with other open files
pub fn add_file(state: &AppState, mut parsed: NessusFile, size: u64, order: Option<u64>) -> FileInfo {
    state.interner.lock().unwrap().adopt(&mut parsed);
    let mut info = file_info(&parsed, size);
    let parsed = Arc::new(parsed);
    {
        let mut files = state.files.lock().unwrap();
        let mut infos = state.infos.lock().unwrap();
        // replace if same path already loaded
        if let Some(pos) = files.iter().position(|f| f.path == parsed.path) {
            let old = files.remove(pos);
            infos.remove(&old.id);
        }
        let order_of = |id: &str| infos.get(id).map_or(0, |i| i.order);
        info.order = order.unwrap_or_else(|| files.iter().map(|f| order_of(&f.id)).max().unwrap_or(0) + 1);
        let at = files.iter().position(|f| order_of(&f.id) > info.order).unwrap_or(files.len());
        files.insert(at, Arc::clone(&parsed));
        infos.insert(info.id.clone(), info.clone());
        state.views.lock().unwrap().clear();
        state.memo.lock().unwrap().clear();
    }
    state.interner.lock().unwrap().prune();
    info
}// add_file

// closes one file, or all when `id` is None, and forgets what only they used
pub fn close_files(state: &AppState, id: Option<&str>) {
    let closed: Vec<Arc<NessusFile>> = {
        let mut files = state.files.lock().unwrap();
        let (closed, kept) = std::mem::take(&mut *files).into_iter().partition(|f| id.is_none_or(|id| f.id == id));
        *files = kept;
        let mut infos = state.infos.lock().unwrap();
        for f in &closed {
            infos.remove(&f.id);
        }
        state.views.lock().unwrap().clear();
        state.memo.lock().unwrap().clear();
        closed
    };
    drop(closed);
    state.interner.lock().unwrap().prune();
}// close_files


pub fn open_files(state: &AppState) -> Vec<FileInfo> {
    let infos = state.infos.lock().unwrap();
    state.files.lock().unwrap().iter().filter_map(|f| infos.get(&f.id).cloned()).collect()
}// open_files

#[derive(Serialize)]
struct BriefHost<'a> {
    ip: &'a str,
    name: &'a str,
    hostname: Option<&'a str>,
    credentialed_scan: bool,
}

// the hosts of one file, for its panel
pub fn file_host_list(state: &AppState, id: String) -> Result<String, String> {
    let file = state.files.lock().unwrap().iter().find(|f| f.id == id).cloned().ok_or("The file is not open")?;
    let mut hosts: Vec<BriefHost> = file.hosts.iter()
        .map(|h| BriefHost { ip: &h.ip, name: &h.name, hostname: h.hostname.as_deref(), credentialed_scan: h.credentialed_scan })
        .collect();
    hosts.sort_by(|a, b| compare_hosts(a.ip, b.ip));
    json(&hosts)
}// file_host_list

// ── lists ────────────────────────────────────────────────────────────────────

pub fn vuln_rows(state: &AppState, file: Option<String>) -> Result<String, String> {
    let view = view(state, file.as_deref());
    let rows: Vec<VulnRow> = view.vulns().list.iter().map(|v| v.row(&view)).collect();
    json(&rows)
}// vuln_rows

// the plugins found on a host whose address contains this text
pub fn vulns_on_ip(state: &AppState, file: Option<String>, text: String) -> Vec<u32> {
    let view = view(state, file.as_deref());
    view.vulns().list.iter()
        .filter(|v| v.affected.iter().any(|&at| view.host_of(at).ip.contains(&text)))
        .map(|v| v.first.plugin_id)
        .collect()
}// vulns_on_ip

pub fn host_rows(state: &AppState, file: Option<String>) -> Result<String, String> {
    let view = view(state, file.as_deref());
    let rows: Vec<HostRow> = view.hosts().list.iter().map(|h| h.row(&view)).collect();
    json(&rows)
}// host_rows

pub fn service_rows(state: &AppState, file: Option<String>) -> Result<String, String> {
    json(&view(state, file.as_deref()).services())
}// service_rows

#[derive(Serialize)]
pub struct ListCounts {
    vulnerabilities: usize,
    hosts: usize,
    services: usize,
    findings: Counts, // merged across files, so a finding in two scans counts once
}

// for the sidebar and the top bar
pub fn list_counts(state: &AppState) -> ListCounts {
    let view = view(state, None);
    let hosts = &view.hosts().list;
    let mut findings = Counts::default();
    for h in hosts {
        for s in 0..=4u8 {
            for _ in 0..h.counts.get(s) {
                findings.add(s);
            }
        }
    }
    ListCounts { vulnerabilities: view.vulns().list.len(), hosts: hosts.len(), services: view.services().len(), findings }
}// list_counts

// ── one finding on one host ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct FindingRow<'a> {
    plugin_id: u32,
    plugin_name: &'a str,
    plugin_family: &'a str,
    severity: u8,
    port: u16,
    protocol: &'a str,
    svc_name: &'a str,
    cvss_base_score: Option<f32>,
    cvss3_base_score: Option<f32>,
    cvss4_base_score: Option<f32>,
    exploit_available: bool,
}// FindingRow

fn finding(item: &ReportItem) -> FindingRow<'_> {
    FindingRow {
        plugin_id: item.plugin_id,
        plugin_name: &item.plugin_name,
        plugin_family: &item.plugin_family,
        severity: item.severity,
        port: item.port,
        protocol: &item.protocol,
        svc_name: &item.svc_name,
        cvss_base_score: item.cvss_base_score,
        cvss3_base_score: item.cvss3_base_score,
        cvss4_base_score: item.cvss4_base_score,
        exploit_available: item.exploit_available,
    }
}// finding

// ── a vulnerability's panel ───────────────────────────────────────────────────

#[derive(Serialize)]
struct AffectedHost<'a> {
    id: usize,
    ip: &'a str,
    port: u16,
    protocol: &'a str,
    svc_name: &'a str,
    has_output: bool,
    file_id: &'a str,
    filename: &'a str,
}

#[derive(Serialize)]
struct VulnTexts<'a> {
    description: &'a str,
    solution: &'a str,
    synopsis: Option<&'a str>,
    see_also: &'a [String],
}

#[derive(Serialize)]
struct VulnDetail<'a> {
    vuln: VulnRow<'a>,     // with one file chosen, that file's rating and details
    texts: VulnTexts<'a>,
    across: VulnRow<'a>,   // how each of all files rates it
    affected: Vec<AffectedHost<'a>>,
}

pub fn vuln_detail(state: &AppState, plugin_id: u32, file: Option<String>) -> Result<String, String> {
    let all = view(state, None);
    let scoped = view(state, file.as_deref());
    let Some(across) = all.vuln(plugin_id) else {
        return json(&None::<()>);
    };
    let (shown, shown_view) = match scoped.vuln(plugin_id) {
        Some(v) => (v, &scoped),
        None => (across, &all),
    };
    let affected = across.affected.iter().enumerate().map(|(id, &at)| {
        let item = all.item(at);
        let file = &all.files[at.file as usize];
        AffectedHost {
            id,
            ip: &all.host_of(at).ip,
            port: item.port,
            protocol: &item.protocol,
            svc_name: &item.svc_name,
            has_output: item.plugin_output.is_some(),
            file_id: &file.id,
            filename: &file.filename,
        }
    }).collect();
    json(&Some(VulnDetail {
        vuln: shown.row(shown_view),
        texts: VulnTexts {
            description: &shown.first.description,
            solution: &shown.first.solution,
            synopsis: shown.synopsis.as_deref(),
            see_also: &shown.first.see_also,
        },
        across: across.row(&all),
        affected,
    }))
}// vuln_detail

// what the plugin printed on these hosts, by the ids vuln_detail gave
pub fn vuln_outputs(state: &AppState, plugin_id: u32, ids: Vec<usize>) -> Result<String, String> {
    let all = view(state, None);
    let outputs: HashMap<usize, Option<&str>> = match all.vuln(plugin_id) {
        Some(v) => ids.iter().filter_map(|&id| v.affected.get(id).map(|&at| (id, all.item(at).plugin_output.as_deref()))).collect(),
        None => HashMap::new(),
    };
    json(&outputs)
}// vuln_outputs

// ── a host's panel ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HostDetail<'a> {
    host: HostRow<'a>,
    findings: Vec<FindingRow<'a>>, // with one file chosen, the host's findings in that file
    tcp: Vec<u16>,
    udp: Vec<u16>,
}

pub fn host_detail(state: &AppState, ip: String, file: Option<String>) -> Result<String, String> {
    let all = view(state, None);
    let scoped = view(state, file.as_deref());
    let Some(host) = all.host(&ip) else {
        return json(&None::<()>);
    };
    let (shown, shown_view) = match scoped.host(&ip) {
        Some(h) => (h, &scoped),
        None => (host, &all),
    };
    let ports = |protocol: &str| {
        let mut p: Vec<u16> = host.items.iter().map(|&at| all.item(at)).filter(|i| i.port > 0 && &*i.protocol == protocol).map(|i| i.port).collect();
        p.sort_unstable();
        p.dedup();
        p
    };
    json(&Some(HostDetail {
        host: host.row(&all),
        findings: shown.items.iter().map(|&at| finding(shown_view.item(at))).collect(),
        tcp: ports("tcp"),
        udp: ports("udp"),
    }))
}// host_detail

// ── a service's panel ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HostGroup<'a> {
    key: &'a str,
    ip: &'a str,
    hostname: Option<&'a str>,
    items: Vec<FindingRow<'a>>,
    counts: [u32; 5], // indexed by severity
    worst: u8,
}

#[derive(Serialize)]
struct ServiceDetail<'a> {
    service: &'a crate::views::Service,
    hostnames: HashMap<&'a str, Option<&'a str>>,
    host_groups: Vec<HostGroup<'a>>,
    seen_in: usize,
}

pub fn service_detail(state: &AppState, key: String, file: Option<String>, show_info: bool) -> Result<String, String> {
    let view = view(state, file.as_deref());
    let Some(service) = view.services().iter().find(|s| s.key == key) else {
        return json(&None::<()>);
    };
    let hostnames = service.host_ips.iter().filter_map(|ip| view.host(ip)).map(|h| (h.props.ip.as_str(), h.props.hostname.as_deref().or(h.props.netbios.as_deref()))).collect();
    let mut host_groups: Vec<HostGroup> = view.hosts().list.iter().filter_map(|h| {
        let mut items: Vec<&ReportItem> = h.items.iter().map(|&at| view.item(at))
            .filter(|i| i.port == service.port && *i.protocol == *service.protocol && (show_info || i.severity > 0))
            .collect();
        if items.is_empty() {
            return None;
        }
        items.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| compare_text(&a.plugin_name, &b.plugin_name)));
        let mut counts = [0u32; 5];
        for i in &items {
            counts[usize::from(i.severity.min(4))] += 1;
        }
        Some(HostGroup {
            key: &h.props.ip,
            ip: &h.props.ip,
            hostname: h.props.hostname.as_deref().or(h.props.netbios.as_deref()),
            worst: items[0].severity,
            items: items.into_iter().map(finding).collect(),
            counts,
        })
    }).collect();
    host_groups.sort_by(|a, b| {
        (0..5).rev().map(|s| b.counts[s].cmp(&a.counts[s])).find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| compare_hosts(a.ip, b.ip))
    });
    let seen_in = view.files.iter().filter(|f| f.hosts.iter().any(|h| h.items.iter().any(|i| i.port == service.port && *i.protocol == *service.protocol))).count();
    json(&Some(ServiceDetail { service, hostnames, host_groups, seen_in }))
}// service_detail

// ── Dashboard ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Family {
    family: String,
    counts: Counts,
    total: u32,
}

#[derive(Serialize)]
struct Exploits {
    findings: usize,
    metasploit: usize,
    hosts: usize,
}

#[derive(Serialize)]
struct Dashboard<'a> {
    counts: Counts,           // each finding on each host
    affected_hosts: Counts,   // hosts with at least one of each severity
    host_count: usize,
    exploits: Exploits,
    serious_count: usize,     // vulnerabilities rated High or Critical
    top_vulns: Vec<VulnRow<'a>>,
    families: Vec<Family>,
    family_count: usize,
    top_hosts: Vec<HostRow<'a>>,
}

pub fn dashboard(state: &AppState, show_info: bool, top_vulns: usize, top_hosts: usize, top_families: usize) -> Result<String, String> {
    let view = view(state, None);
    let hosts = &view.hosts().list;
    let mut counts = Counts::default();
    let mut affected = Counts::default();
    let mut exploits = Exploits { findings: 0, metasploit: 0, hosts: 0 };
    let mut families: HashMap<&str, Counts> = HashMap::new();
    for h in hosts {
        for s in 0..=4u8 {
            if h.counts.get(s) > 0 {
                affected.add(s);
            }
        }
        let mut exploitable = false;
        for &at in &h.items {
            let item = view.item(at);
            counts.add(item.severity);
            if item.exploit_available {
                exploits.findings += 1;
                exploitable = true;
            }
            if item.metasploit_available {
                exploits.metasploit += 1;
            }
            if item.severity > 0 || show_info {
                let family = if item.plugin_family.is_empty() { "Other" } else { &item.plugin_family };
                families.entry(family).or_default().add(item.severity);
            }
        }
        exploits.hosts += usize::from(exploitable);
    }

    let vulns = &view.vulns().list;
    let mut top: Vec<_> = vulns.iter().filter(|v| v.severity >= 3).collect();
    top.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| b.host_count.cmp(&a.host_count)));

    let mut families: Vec<Family> = families.into_iter()
        .map(|(family, counts)| Family { family: family.to_string(), counts, total: counts.total(true) })
        .collect();
    families.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| compare_text(&a.family, &b.family)));
    let family_count = families.len();
    families.truncate(top_families);

    // worst hosts first: by critical count, then high, and so on
    let mut ranked: Vec<_> = hosts.iter().filter(|h| show_info || h.counts.total(false) > 0).collect();
    ranked.sort_by(|a, b| (0..=4u8).rev().map(|s| b.counts.get(s).cmp(&a.counts.get(s))).find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal));

    json(&Dashboard {
        counts,
        affected_hosts: affected,
        host_count: hosts.len(),
        exploits,
        serious_count: vulns.iter().filter(|v| v.severity >= 3).count(),
        top_vulns: top.into_iter().take(top_vulns).map(|v| v.row(&view)).collect(),
        families,
        family_count,
        top_hosts: ranked.into_iter().take(top_hosts).map(|h| h.row(&view)).collect(),
    })
}// dashboard

// ── Topology ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TopologyItem<'a> {
    plugin_id: u32,
    plugin_output: Option<&'a str>,
}

#[derive(Serialize)]
struct TopologyHost<'a> {
    #[serde(flatten)]
    host: HostRow<'a>,
    items: Vec<TopologyItem<'a>>,
}

// the hosts with only the findings Topology reads: traceroutes, routes and interfaces
pub fn topology_hosts(state: &AppState, plugins: Vec<u32>, files: Option<Vec<String>>) -> Result<String, String> {
    let view = view_of(state, files.as_deref());
    let hosts: Vec<TopologyHost> = view.hosts().list.iter().map(|h| TopologyHost {
        host: h.row(&view),
        items: h.items.iter().map(|&at| view.item(at)).filter(|i| plugins.contains(&i.plugin_id))
            .map(|i| TopologyItem { plugin_id: i.plugin_id, plugin_output: i.plugin_output.as_deref() })
            .collect(),
    }).collect();
    json(&hosts)
}// topology_hosts

// ── Compare and Trends ───────────────────────────────────────────────────────

// answers that take a while, kept until the open files change
fn memo(state: &AppState, key: String, make: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
    if let Some(found) = state.memo.lock().unwrap().get(&key) {
        return Ok(found.as_str().to_owned());
    }
    let made = make()?;
    state.memo.lock().unwrap().insert(key, Arc::new(made.clone()));
    Ok(made)
}// memo

fn open_file(state: &AppState, id: &str) -> Result<Arc<NessusFile>, String> {
    state.files.lock().unwrap().iter().find(|f| f.id == id).cloned().ok_or_else(|| "The file is not open".to_string())
}

#[derive(Serialize)]
struct Comparison {
    vulns: Vec<crate::compare::VulnDelta>,
    hosts: Vec<crate::compare::HostDelta>,
}

pub fn compare_files(state: &AppState, a: String, b: String, show_info: bool) -> Result<String, String> {
    let (fa, fb) = (open_file(state, &a)?, open_file(state, &b)?);
    memo(state, format!("compare|{a}|{b}|{show_info}"), || {
        use crate::compare::{delta_by_host, delta_by_vuln, plugin_info, scan_delta};
        let delta = scan_delta(&fa, &fb);
        let info = plugin_info(&[&fa, &fb]);
        let vulns = delta_by_vuln(&delta, &info).into_iter().filter(|v| show_info || v.severity > 0).collect();
        let hosts = delta_by_host(&delta, |id| show_info || info.get(&id).is_some_and(|&(_, s)| s > 0), show_info);
        serde_json::to_string(&Comparison { vulns, hosts }).map_err(|e| e.to_string())
    })
}// compare_files

#[derive(Serialize)]
struct SamePair<'a> {
    a: &'a str,
    b: &'a str,
    reason: String,
}

// every two open files that are runs of the same scan, and why
pub fn same_scans(state: &AppState) -> Result<String, String> {
    let files = state.files.lock().unwrap().clone();
    memo(state, "same_scans".to_string(), || {
        let mut found: Vec<SamePair> = Vec::new();
        for (i, a) in files.iter().enumerate() {
            for b in &files[i + 1..] {
                if let Some(reason) = crate::compare::same_scan(a, b) {
                    found.push(SamePair { a: &a.id, b: &b.id, reason });
                }
            }
        }
        serde_json::to_string(&found).map_err(|e| e.to_string())
    })
}// same_scans

#[derive(Serialize)]
pub struct RunChanges {
    added: usize,
    fixed: usize,
}

// what came and went between each previous run and the next one
pub fn run_changes(state: &AppState, pairs: Vec<(String, String)>, show_info: bool) -> Result<Vec<Option<RunChanges>>, String> {
    Ok(pairs.iter().map(|(a, b)| {
        let (fa, fb) = (open_file(state, a).ok()?, open_file(state, b).ok()?);
        let key = format!("run|{a}|{b}|{show_info}");
        let known = state.memo.lock().unwrap().get(&key).cloned();
        let (added, fixed) = match known.and_then(|k| k.split_once(',').map(|(x, y)| (x.parse().ok(), y.parse().ok()))) {
            Some((Some(x), Some(y))) => (x, y),
            _ => {
                let (x, y) = crate::compare::run_changes(&fa, &fb, show_info);
                state.memo.lock().unwrap().insert(key, Arc::new(format!("{x},{y}")));
                (x, y)
            }
        };
        Some(RunChanges { added, fixed })
    }).collect())
}// run_changes

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_str;
    use serde_json::Value;

    // a host with this many findings of each severity, critical first; plugin ids run on from `next`
    fn host(ip: &str, counts: [u32; 5], next: &mut u32) -> String {
        let mut items = String::new();
        for (i, n) in counts.iter().enumerate() {
            for _ in 0..*n {
                *next += 1;
                items.push_str(&format!(r#"<ReportItem port="80" protocol="tcp" severity="{}" pluginID="{next}" pluginName="p{next}" pluginFamily="F"/>"#, 4 - i));
            }
        }
        format!(r#"<ReportHost name="{ip}">{items}</ReportHost>"#)
    }

    fn open(state: &AppState, id: &str, hosts: &str) {
        let mut f = parse_str(&format!(r#"<NessusClientData_v2><Report name="r">{hosts}</Report></NessusClientData_v2>"#)).unwrap();
        f.id = id.to_string();
        f.path = format!("{id}.nessus");
        add_file(state, f, 0, None);
    }

    fn top_hosts(state: &AppState, show_info: bool, limit: usize) -> Vec<String> {
        let v: Value = serde_json::from_str(&dashboard(state, show_info, 10, limit, 10).unwrap()).unwrap();
        v["top_hosts"].as_array().unwrap().iter().map(|h| h["ip"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn the_worst_hosts_come_first_by_their_worst_severity() {
        let state = AppState::default();
        let mut n = 0;
        let hosts = [("10.0.0.1", [0, 9, 9, 9, 0]), ("10.0.0.2", [1, 0, 0, 0, 0]), ("10.0.0.3", [0, 0, 0, 0, 7]), ("10.0.0.4", [1, 2, 0, 0, 0])]
            .iter().map(|(ip, c)| host(ip, *c, &mut n)).collect::<String>();
        open(&state, "a", &hosts);
        assert_eq!(top_hosts(&state, true, 10), ["10.0.0.4", "10.0.0.2", "10.0.0.1", "10.0.0.3"]);
        // hosts with only Info findings stay out while Info is hidden
        assert_eq!(top_hosts(&state, false, 10), ["10.0.0.4", "10.0.0.2", "10.0.0.1"]);
        assert_eq!(top_hosts(&state, true, 2).len(), 2);

        let state = AppState::default();
        open(&state, "b", &(host("10.0.0.7", [0, 20, 0, 0, 0], &mut n) + &host("10.0.0.8", [1, 0, 0, 0, 0], &mut n)));
        assert_eq!(top_hosts(&state, true, 10), ["10.0.0.8", "10.0.0.7"]);
    }

    #[test]
    fn the_top_vulnerabilities_are_critical_then_high_by_host_count() {
        let state = AppState::default();
        // plugin 1 high on 3 hosts, 2 critical on 3, 3 medium on 5, 4 critical on 1, 5 high on 5
        let on = |ip: &str, plugins: &[(u32, u8)]| {
            let items: String = plugins.iter().map(|(id, sev)| format!(r#"<ReportItem port="80" protocol="tcp" severity="{sev}" pluginID="{id}" pluginName="p{id}" pluginFamily="F"/>"#)).collect();
            format!(r#"<ReportHost name="{ip}">{items}</ReportHost>"#)
        };
        let hosts = [
            on("10.0.0.1", &[(1, 3), (2, 4), (3, 2), (4, 4), (5, 3)]),
            on("10.0.0.2", &[(1, 3), (2, 4), (3, 2), (5, 3)]),
            on("10.0.0.3", &[(1, 3), (2, 4), (3, 2), (5, 3)]),
            on("10.0.0.4", &[(3, 2), (5, 3)]),
            on("10.0.0.5", &[(3, 2), (5, 3)]),
        ].concat();
        open(&state, "a", &hosts);
        let top = |limit: usize| -> Vec<u64> {
            let v: Value = serde_json::from_str(&dashboard(&state, false, limit, 10, 10).unwrap()).unwrap();
            v["top_vulns"].as_array().unwrap().iter().map(|x| x["plugin_id"].as_u64().unwrap()).collect()
        };
        assert_eq!(top(10), [2, 4, 5, 1]);
        assert_eq!(top(2), [2, 4]);
    }

    #[test]
    fn files_keep_the_order_they_were_opened_in() {
        let state = AppState::default();
        let mut n = 0;
        let file = |id: &str, n: &mut u32| {
            let mut f = parse_str(&format!(r#"<NessusClientData_v2><Report name="r">{}</Report></NessusClientData_v2>"#, host("10.0.0.1", [1, 0, 0, 0, 0], n))).unwrap();
            f.id = id.to_string();
            f.path = format!("{id}.nessus");
            f
        };
        // read in the order c, a, b, but opened as a, b, c
        add_file(&state, file("c", &mut n), 0, Some(3));
        add_file(&state, file("a", &mut n), 0, Some(1));
        add_file(&state, file("b", &mut n), 0, Some(2));
        add_file(&state, file("d", &mut n), 0, None);
        assert_eq!(open_files(&state).iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["a", "b", "c", "d"]);
    }

    #[test]
    fn topology_can_show_some_of_the_files() {
        let state = AppState::default();
        let mut n = 0;
        open(&state, "a", &host("10.0.0.1", [1, 0, 0, 0, 0], &mut n));
        open(&state, "b", &host("10.0.1.1", [0, 1, 0, 0, 0], &mut n));
        open(&state, "c", &host("10.0.2.1", [0, 1, 0, 0, 0], &mut n));
        let ips = |files: Option<Vec<String>>| -> Vec<String> {
            let v: Value = serde_json::from_str(&topology_hosts(&state, vec![], files).unwrap()).unwrap();
            v.as_array().unwrap().iter().map(|h| h["ip"].as_str().unwrap().to_string()).collect()
        };
        assert_eq!(ips(None), ["10.0.0.1", "10.0.1.1", "10.0.2.1"]);
        assert_eq!(ips(Some(vec!["c".into(), "a".into()])), ["10.0.0.1", "10.0.2.1"]);
        // a file that isn't open is left out, and nothing left means all files
        assert_eq!(ips(Some(vec!["b".into(), "gone".into()])), ["10.0.1.1"]);
        assert_eq!(ips(Some(vec!["gone".into()])).len(), 3);
    }

    #[test]
    fn closing_a_file_forgets_its_lists() {
        let state = AppState::default();
        let mut n = 0;
        open(&state, "a", &host("10.0.0.1", [1, 0, 0, 0, 0], &mut n));
        open(&state, "b", &host("10.0.0.2", [0, 1, 0, 0, 0], &mut n));
        assert_eq!(list_counts(&state).hosts, 2);
        close_files(&state, Some("a"));
        assert_eq!(list_counts(&state).hosts, 1);
        assert_eq!(open_files(&state).iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["b"]);
        close_files(&state, None);
        assert_eq!(list_counts(&state).hosts, 0);
    }
}
