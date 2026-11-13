// compare two scans side by side (which machines match up, and which findings came, went or stayed)
use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::models::{NessusFile, ReportHost, ReportItem};
use crate::views::Counts;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MatchedBy {
    Mac,
    Hostname,
    Netbios,
    Ip,
}

pub struct HostPair<'a> {
    pub key: String,
    pub a: Option<&'a ReportHost>,
    pub b: Option<&'a ReportHost>,
    pub by: Option<MatchedBy>, // None when the host is only in one scan
    pub conflict: Option<String>, // why the host at the same IP in the other scan is a different machine
}

pub struct DeltaItem {
    pub plugin_id: u32,
    pub pair: usize,
}

pub struct ScanDelta<'a> {
    pub pairs: Vec<HostPair<'a>>,
    pub new: Vec<DeltaItem>,
    pub resolved: Vec<DeltaItem>,
    pub persisted: Vec<DeltaItem>,
    pub unverified: Vec<DeltaItem>, // in A, gone from B, but B can't confirm a fix
}

type Identify = fn(&ReportHost) -> Vec<String>;

fn macs(h: &ReportHost) -> Vec<String> {
    h.mac.as_deref().unwrap_or("")
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|m| m.trim().to_lowercase().replace('-', ":"))
        .filter(|m| !m.is_empty() && m != "00:00:00:00:00:00" && m != "ff:ff:ff:ff:ff:ff")
        .collect()
}

fn name_of(value: &Option<String>) -> Vec<String> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(|v| vec![v.to_lowercase()]).unwrap_or_default()
}

const IDENTIFIERS: [(MatchedBy, &str, Identify); 3] = [
    (MatchedBy::Mac, "MAC address", macs),
    (MatchedBy::Hostname, "hostname", |h| name_of(&h.hostname)),
    (MatchedBy::Netbios, "NetBIOS name", |h| name_of(&h.netbios)),
];

fn index(hosts: &[ReportHost], of: Identify) -> HashMap<String, Vec<usize>> {
    let mut found: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, h) in hosts.iter().enumerate() {
        let mut ids = of(h);
        ids.sort();
        ids.dedup();
        for id in ids {
            found.entry(id).or_default().push(i);
        }
    }
    found
}

fn mismatch(a: &ReportHost, b: &ReportHost, up_to: usize) -> Option<String> {
    for (_, label, of) in &IDENTIFIERS[..up_to] {
        let ids_a = of(a);
        let ids_b: HashSet<String> = of(b).into_iter().collect();
        if !ids_a.is_empty() && !ids_b.is_empty() && !ids_a.iter().any(|id| ids_b.contains(id)) {
            return Some(format!("{label} differs"));
        }
    }
    None
}

// a machine is followed by its MAC, hostname or NetBIOS name, and by its IP when nothing tells them apart
pub fn pair_hosts<'a>(a: &'a NessusFile, b: &'a NessusFile) -> Vec<HostPair<'a>> {
    let mut pairs: Vec<HostPair> = Vec::new();
    let mut paired_a = vec![false; a.hosts.len()];
    let mut paired_b = vec![false; b.hosts.len()];
    let pair = |pairs: &mut Vec<HostPair<'a>>, ia: Option<usize>, ib: Option<usize>, by: Option<MatchedBy>, conflict: Option<String>, pa: &mut [bool], pb: &mut [bool]| {
        let ha = ia.map(|i| &a.hosts[i]);
        let hb = ib.map(|i| &b.hosts[i]);
        let key = format!("{}|{}|{}", ha.map_or("", |h| h.ip.as_str()), hb.map_or("", |h| h.ip.as_str()), pairs.len());
        pairs.push(HostPair { key, a: ha, b: hb, by, conflict });
        if let Some(i) = ia {
            pa[i] = true;
        }
        if let Some(i) = ib {
            pb[i] = true;
        }
    };

    for (level, (by, _, of)) in IDENTIFIERS.iter().enumerate() {
        let in_a = index(&a.hosts, *of);
        let in_b = index(&b.hosts, *of);
        for (ia, ha) in a.hosts.iter().enumerate() {
            if paired_a[ia] {
                continue;
            }
            for id in of(ha) {
                let candidates = in_b.get(&id);
                let ib = match (candidates, in_a.get(&id)) {
                    (Some(c), Some(own)) if c.len() == 1 && own.len() == 1 => c[0],
                    _ => continue,
                };
                if !paired_b[ib] && mismatch(ha, &b.hosts[ib], level).is_none() {
                    pair(&mut pairs, Some(ia), Some(ib), Some(*by), None, &mut paired_a, &mut paired_b);
                    break;
                }
            }
        }
    }

    let by_ip_b: HashMap<&str, usize> = b.hosts.iter().enumerate().map(|(i, h)| (h.ip.as_str(), i)).collect();
    let mut conflicts_a: HashMap<usize, String> = HashMap::new();
    let mut conflicts_b: HashMap<usize, String> = HashMap::new();
    for ia in 0..a.hosts.len() {
        if paired_a[ia] {
            continue;
        }
        let Some(&ib) = by_ip_b.get(a.hosts[ia].ip.as_str()) else { continue };
        if paired_b[ib] {
            continue;
        }
        match mismatch(&a.hosts[ia], &b.hosts[ib], IDENTIFIERS.len()) {
            Some(conflict) => {
                conflicts_a.insert(ia, conflict.clone());
                conflicts_b.insert(ib, conflict);
            }
            None => pair(&mut pairs, Some(ia), Some(ib), Some(MatchedBy::Ip), None, &mut paired_a, &mut paired_b),
        }
    }

    for ia in 0..a.hosts.len() {
        if !paired_a[ia] {
            pair(&mut pairs, Some(ia), None, None, conflicts_a.remove(&ia), &mut paired_a, &mut paired_b);
        }
    }
    for ib in 0..b.hosts.len() {
        if !paired_b[ib] {
            pair(&mut pairs, None, Some(ib), None, conflicts_b.remove(&ib), &mut paired_a, &mut paired_b);
        }
    }
    pairs
}// pair_hosts

// the first finding of each plugin + port + protocol
fn items_of(host: Option<&ReportHost>) -> Vec<&ReportItem> {
    let mut seen: HashSet<(u32, u16, &str)> = HashSet::new();
    host.map(|h| h.items.iter().filter(|i| seen.insert((i.plugin_id, i.port, &*i.protocol))).collect()).unwrap_or_default()
}

// why a finding seen in one scan only might come from weaker coverage in the other, not a real change
fn coverage_gap(pair: &HostPair, seen_in_a: bool) -> Option<String> {
    let other = if seen_in_a { "B" } else { "A" };
    let (here, there) = if seen_in_a { (pair.a, pair.b) } else { (pair.b, pair.a) };
    let Some(there) = there else {
        return Some(match &pair.conflict {
            Some(c) => format!("A different machine has this IP in scan {other} ({c})"),
            None => format!("Host was not in scan {other}"),
        });
    };
    if here.is_some_and(|h| h.credentialed_scan) && !there.credentialed_scan {
        return Some(format!("Scan {other} was not credentialed on this host"));
    }
    None
}

pub fn scan_delta<'a>(a: &'a NessusFile, b: &'a NessusFile) -> ScanDelta<'a> {
    let pairs = pair_hosts(a, b);
    let mut delta = ScanDelta { pairs: Vec::new(), new: Vec::new(), resolved: Vec::new(), persisted: Vec::new(), unverified: Vec::new() };
    for (p, pair) in pairs.iter().enumerate() {
        let in_a = items_of(pair.a);
        let in_b = items_of(pair.b);
        let keys = |items: &[&'a ReportItem]| items.iter().map(|i| (i.plugin_id, i.port, &*i.protocol)).collect::<HashSet<_>>();
        let (keys_a, keys_b) = (keys(&in_a), keys(&in_b));
        for i in &in_b {
            let d = DeltaItem { plugin_id: i.plugin_id, pair: p };
            if keys_a.contains(&(i.plugin_id, i.port, &*i.protocol)) {
                delta.persisted.push(d);
            } else {
                delta.new.push(d);
            }
        }
        let unverifiable = coverage_gap(pair, true).is_some();
        for i in &in_a {
            if keys_b.contains(&(i.plugin_id, i.port, &*i.protocol)) {
                continue;
            }
            let d = DeltaItem { plugin_id: i.plugin_id, pair: p };
            if unverifiable {
                delta.unverified.push(d);
            } else {
                delta.resolved.push(d);
            }
        }
    }
    delta.pairs = pairs;
    delta
}// scan_delta

// name and worst severity of each plugin in either file
pub fn plugin_info<'a>(files: &[&'a NessusFile]) -> HashMap<u32, (&'a str, u8)> {
    let mut m: HashMap<u32, (&str, u8)> = HashMap::new();
    for f in files {
        for h in &f.hosts {
            for i in &h.items {
                let known = m.entry(i.plugin_id).or_insert((&i.plugin_name, i.severity));
                if i.severity > known.1 {
                    *known = (&i.plugin_name, i.severity);
                }
            }
        }
    }
    m
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum VulnChange {
    New,
    Fixed,
    Unverified,
    Partly,
    Increased,
    Changed,
    Unchanged,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VulnDelta {
    pub plugin_id: u32,
    pub name: String,
    pub severity: u8,
    pub change: VulnChange,
    pub hosts_a: usize,
    pub hosts_b: usize,
    pub added: usize,     // instances only in B
    pub fixed: usize,     // instances gone from a rescanned host
    pub unverified: usize,
}

pub fn delta_by_vuln(delta: &ScanDelta, info: &HashMap<u32, (&str, u8)>) -> Vec<VulnDelta> {
    struct Row { added: usize, fixed: usize, unverified: usize, a: HashSet<usize>, b: HashSet<usize> }
    let mut order: Vec<u32> = Vec::new();
    let mut rows: HashMap<u32, Row> = HashMap::new();
    let lists: [(&[DeltaItem], bool, bool); 4] = [(&delta.persisted, true, true), (&delta.new, false, true), (&delta.resolved, true, false), (&delta.unverified, true, false)];
    for (k, (items, in_a, in_b)) in lists.into_iter().enumerate() {
        for d in items {
            let r = rows.entry(d.plugin_id).or_insert_with(|| {
                order.push(d.plugin_id);
                Row { added: 0, fixed: 0, unverified: 0, a: HashSet::new(), b: HashSet::new() }
            });
            if in_a {
                r.a.insert(d.pair);
            }
            if in_b {
                r.b.insert(d.pair);
            }
            match k {
                1 => r.added += 1,
                2 => r.fixed += 1,
                3 => r.unverified += 1,
                _ => {}
            }
        }
    }
    order.into_iter().map(|id| {
        let r = &rows[&id];
        let gone = r.fixed + r.unverified;
        let change = if r.a.is_empty() {
            VulnChange::New
        } else if r.b.is_empty() {
            if r.unverified > 0 { VulnChange::Unverified } else { VulnChange::Fixed }
        } else if gone > 0 && r.added > 0 {
            VulnChange::Changed
        } else if gone > 0 {
            VulnChange::Partly
        } else if r.added > 0 {
            VulnChange::Increased
        } else {
            VulnChange::Unchanged
        };
        let (name, severity) = info.get(&id).map(|&(n, s)| (n.to_string(), s)).unwrap_or_else(|| (format!("Plugin {id}"), 0));
        VulnDelta { plugin_id: id, name, severity, change, hosts_a: r.a.len(), hosts_b: r.b.len(), added: r.added, fixed: r.fixed, unverified: r.unverified }
    }).collect()
}// delta_by_vuln

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum HostChange {
    Worsened,
    Improved,
    New,
    Missing,
    Replaced,
    Same,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HostDelta {
    pub key: String,
    pub ip: String,       // where it is now, or was when only in A
    pub ip_a: Option<String>,
    pub ip_b: Option<String>,
    pub hostname: Option<String>,
    pub by: Option<MatchedBy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<String>,
    pub change: HostChange,
    pub counts_a: Option<Counts>, // None when the host is not in that scan
    pub counts_b: Option<Counts>,
    pub added: usize,
    pub fixed: usize,
}

// worse or better by the worst severity that changed
fn host_change(a: &Counts, b: &Counts, show_info: bool) -> HostChange {
    for s in (if show_info { 0 } else { 1 }..=4u8).rev() {
        if a.get(s) != b.get(s) {
            return if b.get(s) > a.get(s) { HostChange::Worsened } else { HostChange::Improved };
        }
    }
    HostChange::Same
}

pub fn delta_by_host(delta: &ScanDelta, keep: impl Fn(u32) -> bool, show_info: bool) -> Vec<HostDelta> {
    let counts = |h: &ReportHost| {
        let mut c = Counts::default();
        for i in h.items.iter().filter(|i| show_info || i.severity > 0) {
            c.add(i.severity);
        }
        c
    };
    let tally = |items: &[DeltaItem]| {
        let mut n: HashMap<usize, usize> = HashMap::new();
        for d in items.iter().filter(|d| keep(d.plugin_id)) {
            *n.entry(d.pair).or_default() += 1;
        }
        n
    };
    let added = tally(&delta.new);
    let fixed = tally(&delta.resolved);
    delta.pairs.iter().enumerate().map(|(p, pair)| {
        let counts_a = pair.a.map(counts);
        let counts_b = pair.b.map(counts);
        let change = match (&counts_a, &counts_b) {
            (None, _) => HostChange::New,
            (Some(_), None) => if pair.conflict.is_some() { HostChange::Replaced } else { HostChange::Missing },
            (Some(a), Some(b)) => host_change(a, b, show_info),
        };
        HostDelta {
            key: pair.key.clone(),
            ip: pair.b.or(pair.a).map(|h| h.ip.clone()).unwrap_or_default(),
            ip_a: pair.a.map(|h| h.ip.clone()),
            ip_b: pair.b.map(|h| h.ip.clone()),
            hostname: pair.b.and_then(|h| h.hostname.clone()).or_else(|| pair.a.and_then(|h| h.hostname.clone())),
            by: pair.by,
            conflict: pair.conflict.clone(),
            change,
            counts_a,
            counts_b,
            added: added.get(&p).copied().unwrap_or(0),
            fixed: fixed.get(&p).copied().unwrap_or(0),
        }
    }).collect()
}// delta_by_host

// ── runs of the same scan, for Trends ─────────────────────────────────────────

pub fn split_targets(target: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in target.unwrap_or("").split(['\n', ',']).map(str::trim).filter(|t| !t.is_empty()) {
        if !out.iter().any(|o| o == t) {
            out.push(t.to_string());
        }
    }
    out
}

// two files are runs of the same scan when they list the same targets, or when at least half of all hosts are in both
pub fn same_scan(a: &NessusFile, b: &NessusFile) -> Option<String> {
    let targets = |f: &NessusFile| {
        let mut t: Vec<String> = split_targets(f.target.as_deref()).iter().map(|t| t.to_lowercase()).collect();
        t.sort();
        t
    };
    let ta = targets(a);
    if !ta.is_empty() && ta == targets(b) {
        return Some("same targets".to_string());
    }
    let shared = pair_hosts(a, b).iter().filter(|p| p.a.is_some() && p.b.is_some()).count();
    let all = a.hosts.len() + b.hosts.len() - shared;
    (shared > 0 && shared * 2 >= all).then(|| format!("{shared} of {all} hosts in both"))
}// same_scan

// what came and went since the previous run
pub fn run_changes(previous: &NessusFile, current: &NessusFile, show_info: bool) -> (usize, usize) {
    let info = plugin_info(&[previous, current]);
    let counted = |id: u32| show_info || info.get(&id).is_some_and(|&(_, s)| s > 0);
    let delta = scan_delta(previous, current);
    (delta.new.iter().filter(|d| counted(d.plugin_id)).count(), delta.resolved.iter().filter(|d| counted(d.plugin_id)).count())
}// run_changes

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_str;

    struct H<'a> { ip: &'a str, items: &'a [(u32, u16, u8)], credentialed: bool, mac: Option<&'a str>, hostname: Option<&'a str>, netbios: Option<&'a str> }

    fn h<'a>(ip: &'a str, items: &'a [(u32, u16, u8)]) -> H<'a> {
        H { ip, items, credentialed: false, mac: None, hostname: None, netbios: None }
    }

    fn file(hosts: &[H]) -> NessusFile {
        let xml: String = hosts.iter().map(|h| {
            let mut props = String::new();
            if h.credentialed { props.push_str(r#"<tag name="Credentialed_Scan">true</tag>"#); }
            if let Some(m) = h.mac { props.push_str(&format!(r#"<tag name="mac-address">{m}</tag>"#)); }
            if let Some(n) = h.hostname { props.push_str(&format!(r#"<tag name="host-fqdn">{n}</tag>"#)); }
            if let Some(n) = h.netbios { props.push_str(&format!(r#"<tag name="netbios-name">{n}</tag>"#)); }
            let items: String = h.items.iter().map(|(id, port, sev)| format!(r#"<ReportItem port="{port}" protocol="tcp" severity="{sev}" pluginID="{id}" pluginName="p{id}" pluginFamily="f"/>"#)).collect();
            format!(r#"<ReportHost name="{}"><HostProperties>{props}</HostProperties>{items}</ReportHost>"#, h.ip)
        }).collect();
        parse_str(&format!(r#"<NessusClientData_v2><Report name="r">{xml}</Report></NessusClientData_v2>"#)).unwrap()
    }

    fn ids(items: &[DeltaItem]) -> Vec<u32> {
        items.iter().map(|d| d.plugin_id).collect()
    }

    #[test]
    fn sorts_findings_into_new_resolved_and_persisted() {
        let (a, b) = (file(&[h("10.0.0.1", &[(1, 80, 2), (2, 80, 2)])]), file(&[h("10.0.0.1", &[(2, 80, 2), (3, 80, 2)])]));
        let d = scan_delta(&a, &b);
        assert_eq!((ids(&d.resolved), ids(&d.persisted), ids(&d.new), ids(&d.unverified)), (vec![1], vec![2], vec![3], vec![]));
    }

    #[test]
    fn a_finding_is_not_fixed_when_the_rescan_could_not_see_it() {
        let (a, b) = (file(&[h("10.0.0.1", &[(1, 80, 2)])]), file(&[h("10.0.0.2", &[])]));
        let d = scan_delta(&a, &b);
        assert_eq!((ids(&d.resolved), ids(&d.unverified)), (vec![], vec![1]));
        assert_eq!(coverage_gap(&d.pairs[d.unverified[0].pair], true).as_deref(), Some("Host was not in scan B"));

        let a = file(&[H { credentialed: true, ..h("10.0.0.1", &[(1, 80, 2)]) }]);
        let b = file(&[h("10.0.0.1", &[])]);
        let d = scan_delta(&a, &b);
        assert_eq!(coverage_gap(&d.pairs[d.unverified[0].pair], true).as_deref(), Some("Scan B was not credentialed on this host"));

        let (a, b) = (file(&[h("10.0.0.1", &[(1, 80, 2)])]), file(&[H { credentialed: true, ..h("10.0.0.1", &[]) }]));
        assert_eq!(scan_delta(&a, &b).resolved.len(), 1);
    }

    #[test]
    fn matches_on_port() {
        let (a, b) = (file(&[h("10.0.0.1", &[(1, 80, 2), (1, 443, 2)])]), file(&[h("10.0.0.1", &[(1, 443, 2)])]));
        let d = scan_delta(&a, &b);
        assert_eq!((d.resolved.len(), d.persisted.len()), (1, 1));
    }

    fn pairs(a: &NessusFile, b: &NessusFile) -> Vec<String> {
        let mut p: Vec<String> = pair_hosts(a, b).iter().map(|p| {
            let by = p.by.map(|b| serde_json::to_string(&b).unwrap().trim_matches('"').to_string()).unwrap_or("-".into());
            format!("{} {} {by}{}", p.a.map_or("-", |h| &h.ip), p.b.map_or("-", |h| &h.ip), p.conflict.as_ref().map(|c| format!(" ({c})")).unwrap_or_default())
        }).collect();
        p.sort();
        p
    }

    #[test]
    fn follows_a_machine_by_mac_hostname_or_netbios() {
        let a = file(&[H { mac: Some("00:50:56:AA:00:01"), ..h("10.0.0.1", &[]) }, H { hostname: Some("web.lab"), ..h("10.0.0.2", &[]) }, H { netbios: Some("WS3"), ..h("10.0.0.3", &[]) }]);
        let b = file(&[H { mac: Some("00-50-56-aa-00-01"), ..h("10.0.0.9", &[]) }, H { hostname: Some("WEB.lab"), ..h("10.0.0.8", &[]) }, H { netbios: Some("ws3"), ..h("10.0.0.7", &[]) }]);
        assert_eq!(pairs(&a, &b), ["10.0.0.1 10.0.0.9 mac", "10.0.0.2 10.0.0.8 hostname", "10.0.0.3 10.0.0.7 netbios"]);
        let (a, b) = (file(&[h("10.0.0.1", &[])]), file(&[H { hostname: Some("new.lab"), ..h("10.0.0.1", &[]) }]));
        assert_eq!(pairs(&a, &b), ["10.0.0.1 10.0.0.1 ip"]);
    }

    #[test]
    fn a_different_machine_at_the_same_ip_is_not_the_same_host() {
        let a = file(&[H { mac: Some("00:50:56:aa:00:01"), ..h("10.0.0.1", &[(1, 80, 2)]) }]);
        let b = file(&[H { mac: Some("00:50:56:aa:00:02"), ..h("10.0.0.1", &[(3, 80, 2)]) }]);
        assert_eq!(pairs(&a, &b), ["- 10.0.0.1 - (MAC address differs)", "10.0.0.1 - - (MAC address differs)"]);
        let d = scan_delta(&a, &b);
        assert!(d.resolved.is_empty());
        assert_eq!(coverage_gap(&d.pairs[d.unverified[0].pair], true).as_deref(), Some("A different machine has this IP in scan B (MAC address differs)"));
        let mut changes: Vec<HostChange> = delta_by_host(&d, |_| true, false).iter().map(|r| r.change).collect();
        changes.sort_by_key(|c| format!("{c:?}"));
        assert_eq!(changes, [HostChange::New, HostChange::Replaced]);

        let a = file(&[H { mac: Some("aa:aa:aa:aa:aa:01"), hostname: Some("web"), ..h("10.0.0.1", &[]) }]);
        let b = file(&[H { mac: Some("aa:aa:aa:aa:aa:02"), hostname: Some("web"), ..h("10.0.0.5", &[]) }]);
        assert_eq!(pairs(&a, &b), ["- 10.0.0.5 -", "10.0.0.1 - -"]);
    }

    #[test]
    fn ignores_a_name_more_than_one_host_has() {
        let a = file(&[H { hostname: Some("lb.lab"), ..h("10.0.0.1", &[]) }, H { hostname: Some("lb.lab"), ..h("10.0.0.2", &[]) }]);
        let b = file(&[H { hostname: Some("lb.lab"), ..h("10.0.0.2", &[]) }, H { hostname: Some("lb.lab"), ..h("10.0.0.3", &[]) }]);
        assert_eq!(pairs(&a, &b), ["- 10.0.0.3 -", "10.0.0.1 - -", "10.0.0.2 10.0.0.2 ip"]);
    }

    #[test]
    fn labels_each_vulnerability_by_what_happened() {
        let a = file(&[h("10.0.0.1", &[(1, 80, 2), (2, 80, 2), (3, 80, 2), (4, 80, 2), (6, 80, 2)]), h("10.0.0.2", &[(4, 80, 2), (5, 80, 2)])]);
        let b = file(&[h("10.0.0.1", &[(2, 80, 2), (3, 80, 2), (3, 443, 2), (4, 80, 2), (7, 80, 2)]), h("10.0.0.3", &[(6, 80, 2)])]);
        let d = scan_delta(&a, &b);
        let rows = delta_by_vuln(&d, &plugin_info(&[&a, &b]));
        let change = |id: u32| rows.iter().find(|r| r.plugin_id == id).unwrap().change;
        assert_eq!(change(1), VulnChange::Fixed);
        assert_eq!(change(2), VulnChange::Unchanged);
        assert_eq!(change(3), VulnChange::Increased);
        assert_eq!(change(4), VulnChange::Partly); // 10.0.0.2 wasn't rescanned, so its finding is unverified
        assert_eq!(change(5), VulnChange::Unverified);
        assert_eq!(change(6), VulnChange::Changed);
        assert_eq!(change(7), VulnChange::New);
        let r4 = rows.iter().find(|r| r.plugin_id == 4).unwrap();
        assert_eq!((r4.hosts_a, r4.hosts_b, r4.unverified), (2, 1, 1));
    }

    #[test]
    fn host_changes_count_info_only_when_shown() {
        let a = file(&[h("10.0.0.1", &[(1, 80, 3), (2, 80, 0)]), h("10.0.0.2", &[(3, 80, 2)])]);
        let b = file(&[h("10.0.0.1", &[(1, 80, 3)]), h("10.0.0.2", &[(3, 80, 2), (4, 80, 3)]), h("10.0.0.4", &[])]);
        let d = scan_delta(&a, &b);
        let by = |show_info: bool| delta_by_host(&d, |_| true, show_info).into_iter().map(|r| (r.ip, r.change)).collect::<HashMap<_, _>>();
        assert_eq!(by(false)["10.0.0.1"], HostChange::Same);
        assert_eq!(by(true)["10.0.0.1"], HostChange::Improved);
        assert_eq!(by(false)["10.0.0.2"], HostChange::Worsened);
        assert_eq!(by(false)["10.0.0.4"], HostChange::New);
    }

    #[test]
    fn same_scan_by_targets_or_shared_hosts() {
        let mut a = file(&[h("10.0.0.1", &[])]);
        let mut b = file(&[h("10.0.0.9", &[])]);
        a.target = Some("10.0.0.0/24, Web.lab".into());
        b.target = Some("web.lab\n10.0.0.0/24".into());
        assert_eq!(same_scan(&a, &b).as_deref(), Some("same targets"));
        let (a, b) = (file(&[h("10.0.0.1", &[]), h("10.0.0.2", &[])]), file(&[h("10.0.0.1", &[]), h("10.0.0.3", &[])]));
        assert_eq!(same_scan(&a, &b), None);
        let (a, b) = (file(&[h("10.0.0.1", &[]), h("10.0.0.2", &[])]), file(&[h("10.0.0.1", &[]), h("10.0.0.2", &[]), h("10.0.0.3", &[])]));
        assert_eq!(same_scan(&a, &b).as_deref(), Some("2 of 3 hosts in both"));
    }

    #[test]
    fn run_changes_count_info_only_when_shown() {
        let (a, b) = (file(&[h("10.0.0.1", &[(1, 80, 2), (2, 80, 0)])]), file(&[h("10.0.0.1", &[(3, 80, 3), (4, 80, 0)])]));
        assert_eq!(run_changes(&a, &b, false), (1, 1));
        assert_eq!(run_changes(&a, &b, true), (2, 2));
    }
}
