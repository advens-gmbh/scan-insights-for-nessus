use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;

use serde::Serialize;

use crate::models::{ExportFormat, ExportRequest, NessusFile, ReportHost, ReportItem};
use crate::private_file;
use rust_xlsxwriter::{Format, Workbook, XlsxError};

// why an export failed
#[derive(Debug, Serialize)]
pub struct ExportError {
    pub reason: &'static str,
    pub detail: String,
}// ExportError

impl ExportError {
    fn other(detail: impl Into<String>) -> Self {
        Self { reason: "other", detail: detail.into() }
    }
}

impl From<io::Error> for ExportError {
    fn from(e: io::Error) -> Self {
        Self { reason: io_reason(&e), detail: e.to_string() }
    }
}

impl From<csv::Error> for ExportError {
    fn from(e: csv::Error) -> Self {
        let detail = e.to_string();
        match e.into_kind() {
            csv::ErrorKind::Io(io) => io.into(),
            _ => Self::other(detail),
        }
    }
}

fn io_reason(e: &io::Error) -> &'static str {
    // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION: Excel keeps an open workbook locked
    #[cfg(windows)]
    if matches!(e.raw_os_error(), Some(32 | 33)) {
        return "in_use";
    }
    match e.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => "denied",
        io::ErrorKind::NotFound => "no_folder",
        io::ErrorKind::StorageFull => "disk_full",
        _ => "other",
    }
}// io_reason

pub fn export(all_files: &[Arc<NessusFile>], req: &ExportRequest) -> Result<(), ExportError> {
    let files: Vec<&NessusFile> = all_files
        .iter()
        .filter(|f| req.file_ids.contains(&f.id))
        .map(|f| f.as_ref())
        .collect();

    if files.is_empty() {
        return Err(ExportError::other("No matching files found for export"));
    }

    match req.format {
        ExportFormat::Csv => write_csv(&files, req),
        ExportFormat::Xlsx => write_xlsx(&files, req),
        ExportFormat::Nessus => write_nessus(&files, req),
    }
}// export

const COLUMNS: [&str; 22] = [
    "Source File",
    "Host IP",
    "Hostname",
    "Port",
    "Protocol",
    "Service",
    "Severity",
    "Risk Factor",
    "Plugin ID",
    "Plugin Name",
    "Plugin Family",
    "CVSS v2",
    "CVSS v3",
    "CVSS v4",
    "VPR",
    "EPSS",
    "CVEs",
    "CWEs",
    "Exploit Available",
    "Metasploit Module",
    "Description",
    "Solution",
];

// ── CSV ───────────────────────────────────────────────────────────────────────

fn write_csv(files: &[&NessusFile], req: &ExportRequest) -> Result<(), ExportError> {
    let file = private_file::create(&req.output_path)?;
    write_csv_records(csv::Writer::from_writer(file), files, req)
}// write_csv

fn write_csv_records<W: Write>(mut wtr: csv::Writer<W>, files: &[&NessusFile], req: &ExportRequest,) -> Result<(), ExportError> {
    wtr.write_record(COLUMNS)?;

    for file in files {
        for host in &file.hosts {
            for item in &host.items {
                if !req.severities.contains(&item.severity) {
                    continue;
                }
                let cells: [&str; 22] = [
                    &file.filename,
                    &host.ip,
                    host.hostname.as_deref().unwrap_or(""),
                    &item.port.to_string(),
                    &item.protocol,
                    &item.svc_name,
                    &severity_name(item.severity),
                    &item.risk_factor,
                    &item.plugin_id.to_string(),
                    &item.plugin_name,
                    &item.plugin_family,
                    &opt_f32(item.cvss_base_score),
                    &opt_f32(item.cvss3_base_score),
                    &opt_f32(item.cvss4_base_score),
                    &opt_f32(item.vpr_score),
                    &item.epss_score.map(|v| v.to_string()).unwrap_or_default(),
                    &item.cve.join(", "),
                    &item.cwe.join(", "),
                    if item.exploit_available { "Yes" } else { "No" },
                    item.metasploit_name.as_deref().unwrap_or(""),
                    &item.description,
                    &item.solution,
                ];
                wtr.write_record(cells.map(csv_safe))?;
            }
        }
    }

    Ok(wtr.flush()?)
}// write_csv_records

// Scan data can be influenced by the scanned systems, and spreadsheet apps run a cell
// starting with one of these characters as a formula. A leading ' makes it plain text.
fn csv_safe(value: &str) -> String {
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    }
}// csv_safe

// ── Excel ─────────────────────────────────────────────────────────────────────

// Excel stores every cell with its type, so text from the scan can't run as a formula
// and needs no leading '. Scores and numbers stay numbers, so they sort and filter.
fn write_xlsx(files: &[&NessusFile], req: &ExportRequest) -> Result<(), ExportError> {
    let bytes = build_xlsx(files, req).map_err(|e| ExportError::other(e.to_string()))?;
    Ok(private_file::write(&req.output_path, bytes)?)
}// write_xlsx

fn build_xlsx(files: &[&NessusFile], req: &ExportRequest) -> Result<Vec<u8>, XlsxError> {
    let mut book = Workbook::new();
    let sheet = book.add_worksheet();
    sheet.set_name("Findings")?;
    let bold = Format::new().set_bold();

    for (col, name) in COLUMNS.iter().enumerate() {
        sheet.write_string_with_format(0, col as u16, *name, &bold)?;
    }

    let mut row: u32 = 0;
    for file in files {
        for host in &file.hosts {
            for item in &host.items {
                if !req.severities.contains(&item.severity) {
                    continue;
                }
                row += 1;
                let texts: [(u16, &str); 13] = [
                    (0, &file.filename),
                    (1, &host.ip),
                    (2, host.hostname.as_deref().unwrap_or("")),
                    (4, &item.protocol),
                    (5, &item.svc_name),
                    (6, &severity_name(item.severity)),
                    (7, &item.risk_factor),
                    (9, &item.plugin_name),
                    (10, &item.plugin_family),
                    (16, &item.cve.join(", ")),
                    (17, &item.cwe.join(", ")),
                    (18, if item.exploit_available { "Yes" } else { "No" }),
                    (19, item.metasploit_name.as_deref().unwrap_or("")),
                ];
                for (col, value) in texts {
                    if !value.is_empty() {
                        sheet.write_string(row, col, excel_text(value))?;
                    }
                }
                sheet.write_string(row, 20, excel_text(&item.description))?;
                sheet.write_string(row, 21, excel_text(&item.solution))?;

                let numbers: [(u16, Option<f64>); 7] = [
                    (3, Some(item.port as f64)),
                    (8, Some(item.plugin_id as f64)),
                    (11, item.cvss_base_score.map(round1)),
                    (12, item.cvss3_base_score.map(round1)),
                    (13, item.cvss4_base_score.map(round1)),
                    (14, item.vpr_score.map(round1)),
                    (15, item.epss_score.map(|v| v as f64)),
                ];
                for (col, value) in numbers {
                    if let Some(v) = value {
                        sheet.write_number(row, col, v)?;
                    }
                }
            }
        }
    }

    sheet.set_freeze_panes(1, 0)?;
    sheet.autofilter(0, 0, row, COLUMNS.len() as u16 - 1)?;
    for (col, width) in [(0, 24), (1, 15), (2, 26), (3, 7), (4, 9), (5, 14), (6, 10), (7, 11), (8, 10), (9, 50), (10, 24), (11, 8), (12, 8), (13, 8), (14, 7), (15, 7), (16, 22), (17, 12), (18, 10), (19, 26), (20, 80), (21, 60)] {
        sheet.set_column_width(col, width)?;
    }

    book.save_to_buffer()
}// build_xlsx

// An Excel cell holds at most 32767 characters
fn excel_text(value: &str) -> &str {
    const MAX: usize = 32_767;
    if value.chars().count() <= MAX {
        return value;
    }
    let end = value.char_indices().nth(MAX).map(|(i, _)| i).unwrap_or(value.len());
    &value[..end]
}// excel_text

fn round1(v: f32) -> f64 {
    (v as f64 * 10.0).round() / 10.0
}// round1

// ── Nessus XML ────────────────────────────────────────────────────────────────

fn write_nessus(files: &[&NessusFile], req: &ExportRequest) -> Result<(), ExportError> {
    let xml = build_nessus_xml(files, req);
    Ok(private_file::write(&req.output_path, xml)?)
}// write_nessus

fn build_nessus_xml(files: &[&NessusFile], req: &ExportRequest) -> String {
    let mut out = String::from("<?xml version=\"1.0\" ?>\n<NessusClientData_v2>\n");
    write_policy(&mut out, files);
    out.push_str("<Report name=\"Merged Export\">\n");

    for merged in merge_hosts(files, req) {
        out.push_str(&format!(
            "<ReportHost name=\"{}\">\n<HostProperties>\n",
            xml_escape(&merged.props.name)
        ));
        write_host_props(&mut out, &merged.props);
        out.push_str("</HostProperties>\n");

        for (item, source_file) in &merged.items {
            write_report_item(&mut out, item, source_file);
        }

        out.push_str("</ReportHost>\n");
    }

    out.push_str("</Report>\n</NessusClientData_v2>\n");
    out
}// build_nessus_xml

struct MergedHost<'a> {
    props: ReportHost, // first file's properties, with gaps filled from later files
    items: Vec<(&'a ReportItem, &'a str)>, // finding and the file it came from
    seen: HashMap<(u32, u16, &'a str), usize>, // where each finding first went in `items`
}// MergedHost

impl MergedHost<'_> {
    fn new(host: &ReportHost) -> Self {
        Self {
            props: ReportHost {
                alt_hostnames: Vec::new(),
                items: Vec::new(),
                name: host.name.clone(),
                ip: host.ip.clone(),
                hostname: host.hostname.clone(),
                domain: host.domain.clone(),
                os: host.os.clone(),
                mac: host.mac.clone(),
                netbios: host.netbios.clone(),
                system_type: host.system_type.clone(),
                credentialed_scan: host.credentialed_scan,
                os_unsupported: host.os_unsupported,
                host_start: host.host_start.clone(),
                host_end: host.host_end.clone(),
            },
            items: Vec::new(),
            seen: HashMap::new(),
        }
    }

    fn fill_gaps_from(&mut self, host: &ReportHost) {
        let p = &mut self.props;
        for (field, value) in [
            (&mut p.hostname, &host.hostname),
            (&mut p.domain, &host.domain),
            (&mut p.os, &host.os),
            (&mut p.mac, &host.mac),
            (&mut p.netbios, &host.netbios),
            (&mut p.system_type, &host.system_type),
            (&mut p.host_start, &host.host_start),
            (&mut p.host_end, &host.host_end),
        ] {
            if field.is_none() {
                field.clone_from(value);
            }
        }
        p.credentialed_scan |= host.credentialed_scan;
        p.os_unsupported |= host.os_unsupported;
    }
}

// One entry per IP, as on the Hosts page. A finding also seen in an earlier file isn't
// added again, but keeps the worst rating. Repeats within one file are all kept.
fn merge_hosts<'a>(files: &[&'a NessusFile], req: &ExportRequest) -> Vec<MergedHost<'a>> {
    let mut merged: Vec<MergedHost<'a>> = Vec::new();
    let mut by_ip: HashMap<&'a str, usize> = HashMap::new();

    for file in files {
        for host in &file.hosts {
            let items: Vec<&ReportItem> = host
                .items
                .iter()
                .filter(|i| req.severities.contains(&i.severity))
                .collect();
            if items.is_empty() {
                continue;
            }

            let slot = *by_ip.entry(&host.ip).or_insert_with(|| {
                merged.push(MergedHost::new(host));
                merged.len() - 1
            });
            let target = &mut merged[slot];
            target.fill_gaps_from(host);

            let key = |i: &&'a ReportItem| (i.plugin_id, i.port, &*i.protocol);
            let mut fresh: Vec<&'a ReportItem> = Vec::new();
            for item in items {
                match target.seen.get(&key(&item)) {
                    Some(&slot) if item.severity > target.items[slot].0.severity => {
                        target.items[slot] = (item, &file.filename);
                    }
                    Some(_) => {}
                    None => fresh.push(item),
                }
            }
            for item in fresh {
                let slot = target.items.len();
                target.seen.entry(key(&item)).or_insert(slot);
                target.items.push((item, &file.filename));
            }
        }
    }
    merged
}// merge_hosts

// Only the scan targets are kept from the source policies.
fn write_policy(out: &mut String, files: &[&NessusFile]) {
    let mut targets: Vec<&str> = Vec::new();
    for target in files.iter().filter_map(|f| f.target.as_deref()) {
        for t in target.split([',', '\n']).map(str::trim).filter(|t| !t.is_empty()) {
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
    }
    if targets.is_empty() {
        return;
    }
    out.push_str(&format!(
        "<Policy>\n<policyName>Merged Export</policyName>\n<Preferences>\n<ServerPreferences>\n\
         <preference>\n<name>TARGET</name>\n<value>{}</value>\n</preference>\n\
         </ServerPreferences>\n</Preferences>\n</Policy>\n",
        xml_escape(&targets.join(","))
    ));
}// write_policy

fn write_host_props(out: &mut String, host: &ReportHost) {
    write_tag(out, "host-ip", &host.ip);
    if let Some(h) = &host.hostname {
        write_tag(out, "host-fqdn", h);
    }
    if let Some(os) = &host.os {
        write_tag(out, "operating-system", os);
    }
    if let Some(mac) = &host.mac {
        write_tag(out, "mac-address", mac);
    }
    if let Some(nb) = &host.netbios {
        write_tag(out, "netbios-name", nb);
    }
    if let Some(system_type) = &host.system_type {
        write_tag(out, "system-type", system_type);
    }
    write_tag(
        out,
        "Credentialed_Scan",
        if host.credentialed_scan { "true" } else { "false" },
    );
    if host.os_unsupported {
        write_tag(out, "operating-system-unsupported", "true");
    }
    if let Some(st) = &host.host_start {
        write_tag(out, "HOST_START", st);
    }
    if let Some(en) = &host.host_end {
        write_tag(out, "HOST_END", en);
    }
}// write_host_props

fn write_tag(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!(
        "<tag name=\"{}\">{}</tag>\n",
        xml_escape(name),
        xml_escape(value)
    ));
}// write_tag

fn write_report_item(out: &mut String, item: &ReportItem, source_file: &str) {
    out.push_str(&format!(
        "<ReportItem port=\"{}\" svc_name=\"{}\" protocol=\"{}\" severity=\"{}\" \
         pluginID=\"{}\" pluginName=\"{}\" pluginFamily=\"{}\" scan_source=\"{}\">\n",
        item.port,
        xml_escape(&item.svc_name),
        xml_escape(&item.protocol),
        item.severity,
        item.plugin_id,
        xml_escape(&item.plugin_name),
        xml_escape(&item.plugin_family),
        xml_escape(source_file),
    ));

    write_elem(out, "risk_factor", &item.risk_factor);
    // The parser stores a paragraph break as one newline and reads one newline in a
    // file as a hard wrap, so breaks must be written back as blank lines.
    write_elem(out, "description", &item.description.replace('\n', "\n\n"));
    write_elem(out, "solution", &item.solution.replace('\n', "\n\n"));
    if let Some(synopsis) = &item.synopsis {
        write_elem(out, "synopsis", &synopsis.replace('\n', "\n\n"));
    }

    let scores = [
        ("cvss_base_score", item.cvss_base_score),
        ("cvss3_base_score", item.cvss3_base_score),
        ("cvss4_base_score", item.cvss4_base_score),
        ("vpr_score", item.vpr_score),
        ("epss_score", item.epss_score),
    ];
    for (tag, score) in scores {
        if let Some(score) = score {
            write_elem(out, tag, &score.to_string());
        }
    }
    for cve in &item.cve {
        write_elem(out, "cve", cve);
    }
    for cwe in &item.cwe {
        write_elem(out, "cwe", cwe);
    }
    if !item.see_also.is_empty() {
        write_elem(out, "see_also", &item.see_also.join("\n"));
    }
    if item.exploit_available {
        write_elem(out, "exploit_available", "true");
    }
    if item.metasploit_available {
        write_elem(out, "exploit_framework_metasploit", "true");
    }
    for framework in &item.exploit_frameworks {
        let tag = match framework.as_str() {
            "Core Impact" => "exploit_framework_core",
            "CANVAS" => "exploit_framework_canvas",
            "D2 Elliot" => "exploit_framework_d2_elliot",
            "ExploitHub" => "exploit_framework_exploithub",
            _ => continue,
        };
        write_elem(out, tag, "true");
    }
    if item.exploited_by_malware {
        write_elem(out, "exploited_by_malware", "true");
    }
    if item.exploited_by_nessus {
        write_elem(out, "exploited_by_nessus", "true");
    }
    if item.unsupported_by_vendor {
        write_elem(out, "unsupported_by_vendor", "true");
    }
    let optional = [
        ("metasploit_name", item.metasploit_name.as_deref()),
        ("exploitability_ease", item.exploit_ease.as_deref()),
        ("exploit_code_maturity", item.exploit_maturity.as_deref()),
        ("cisa-known-exploited", item.cisa_known_exploited.as_deref()),
        ("patch_publication_date", item.patch_publication_date.as_deref()),
        ("vuln_publication_date", item.vuln_publication_date.as_deref()),
        ("script_version", item.script_version.as_deref()),
        ("plugin_output", item.plugin_output.as_deref()),
    ];
    for (tag, value) in optional {
        if let Some(value) = value {
            write_elem(out, tag, value);
        }
    }

    out.push_str("</ReportItem>\n");
}// write_report_item

fn write_elem(out: &mut String, tag: &str, value: &str) {
    out.push_str(&format!("<{tag}>{}</{tag}>\n", xml_escape(value)));
}// write_elem

// ── helpers ───────────────────────────────────────────────────────────────────

fn severity_name(s: u8) -> String {
    match s {
        4 => "Critical".into(),
        3 => "High".into(),
        2 => "Medium".into(),
        1 => "Low".into(),
        _ => "Info".into(),
    }
}// severity_name

fn opt_f32(v: Option<f32>) -> String {
    v.map(|f| format!("{:.1}", f)).unwrap_or_default()
}// opt_f32

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}// xml_escape

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{local_samples_dir, parse_nessus_file, parse_str};
    use crate::private_file::testing::TempDir;

    #[test]
    fn exports_reach_the_disk_and_are_private() {
        let scan = parse_str(
            r#"<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.1"><ReportItem port="80" protocol="tcp" severity="2" pluginID="1" pluginName="p" pluginFamily="f"/></ReportHost></Report></NessusClientData_v2>"#,
        )
        .unwrap();
        let temp = TempDir::new();

        let csv_path = temp.path().join("out.csv");
        let mut req = request(&[0, 1, 2, 3, 4]);
        req.output_path = csv_path.to_str().unwrap().to_string();
        write_csv(&[&scan], &req).unwrap();
        assert!(std::fs::read_to_string(&csv_path).unwrap().contains("10.0.0.1"));

        let xlsx_path = temp.path().join("out.xlsx");
        req.output_path = xlsx_path.to_str().unwrap().to_string();
        write_xlsx(&[&scan], &req).unwrap();
        assert!(std::fs::read(&xlsx_path).unwrap().starts_with(b"PK"));

        let nessus_path = temp.path().join("out.nessus");
        req.output_path = nessus_path.to_str().unwrap().to_string();
        write_nessus(&[&scan], &req).unwrap();
        assert!(std::fs::read_to_string(&nessus_path).unwrap().contains("10.0.0.1"));

        #[cfg(unix)]
        {
            use crate::private_file::testing::mode;
            assert_eq!(mode(&csv_path), 0o600);
            assert_eq!(mode(&xlsx_path), 0o600);
            assert_eq!(mode(&nessus_path), 0o600);
        }
    }

    #[test]
    fn a_missing_folder_is_named_as_such() {
        let scan = parse_str(
            r#"<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.1"><ReportItem port="80" protocol="tcp" severity="2" pluginID="1" pluginName="p" pluginFamily="f"/></ReportHost></Report></NessusClientData_v2>"#,
        )
        .unwrap();
        let temp = TempDir::new();
        let mut req = request(&[2]);
        req.output_path = temp.path().join("gone").join("out.csv").to_str().unwrap().to_string();

        let err = write_csv(&[&scan], &req).unwrap_err();

        assert_eq!(err.reason, "no_folder");
        assert!(!err.detail.is_empty());
    }

    #[test]
    fn io_errors_get_a_reason() {
        assert_eq!(io_reason(&io::Error::from(io::ErrorKind::PermissionDenied)), "denied");
        assert_eq!(io_reason(&io::Error::from(io::ErrorKind::NotFound)), "no_folder");
        assert_eq!(io_reason(&io::Error::from(io::ErrorKind::StorageFull)), "disk_full");
        assert_eq!(io_reason(&io::Error::from(io::ErrorKind::Interrupted)), "other");
        #[cfg(windows)]
        assert_eq!(io_reason(&io::Error::from_raw_os_error(32)), "in_use");
    }

    fn request(severities: &[u8]) -> ExportRequest {
        ExportRequest {
            file_ids: Vec::new(),
            severities: severities.to_vec(),
            output_path: String::new(),
            format: ExportFormat::Nessus,
        }
    }

    fn normalized_targets(file: &NessusFile) -> Vec<String> {
        let mut seen = Vec::new();
        for t in file.target.iter().flat_map(|t| t.split([',', '\n'])) {
            let t = t.trim().to_string();
            if !t.is_empty() && !seen.contains(&t) {
                seen.push(t);
            }
        }
        seen
    }

    fn assert_nessus_export_round_trips(original: &NessusFile, label: &str) {
        let xml = build_nessus_xml(&[original], &request(&[0, 1, 2, 3, 4]));
        let again = parse_str(&xml).unwrap();

        assert_eq!(normalized_targets(&again), normalized_targets(original), "{label}");
        assert_eq!(again.hosts.len(), original.hosts.len(), "{label}");
        for (a, b) in again.hosts.iter().zip(&original.hosts) {
            let json = |h: &ReportHost| serde_json::to_string(h).unwrap();
            assert_eq!(json(a), json(b), "{label}");
        }
    }

    #[test]
    fn nessus_export_round_trips_a_detailed_scan() {
        let scan = parse_str(concat!(
            r#"<NessusClientData_v2><Policy><Preferences><ServerPreferences><preference><name>TARGET</name><value>10.0.0.1,10.0.0.0/24</value></preference></ServerPreferences></Preferences></Policy>"#,
            r#"<Report name="detailed"><ReportHost name="10.0.0.1"><HostProperties>"#,
            r#"<tag name="host-ip">10.0.0.1</tag><tag name="host-fqdn">server.example.com</tag><tag name="netbios-name">SERVER</tag>"#,
            r#"<tag name="mac-address">00:00:5e:00:53:01</tag><tag name="operating-system">Linux Kernel 5.4</tag>"#,
            r#"<tag name="HOST_START">Mon Jan  1 10:00:00 2024</tag><tag name="HOST_END">Mon Jan  1 11:00:00 2024</tag></HostProperties>"#,
            r#"<ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="1" pluginName="A &amp; B &lt;critical&gt;" pluginFamily="Web">"#,
            r#"<description>line one
line two &amp; more</description><solution>Upgrade</solution><risk_factor>Critical</risk_factor>"#,
            r#"<cvss_base_score>10.0</cvss_base_score><cvss3_base_score>9.8</cvss3_base_score><cve>CVE-2024-0001</cve><cve>CVE-2024-0002</cve><cwe>79</cwe>"#,
            r#"<see_also>https://example.com/advisory</see_also><exploit_available>true</exploit_available><plugin_output>output</plugin_output></ReportItem>"#,
            r#"<ReportItem port="0" svc_name="general" protocol="udp" severity="0" pluginID="2" pluginName="info" pluginFamily="General"><description>d</description></ReportItem>"#,
            r#"</ReportHost><ReportHost name="10.0.0.2"><ReportItem port="22" svc_name="ssh" protocol="tcp" severity="1" pluginID="3" pluginName="low" pluginFamily="Misc."><description>d</description></ReportItem></ReportHost></Report></NessusClientData_v2>"#,
        ))
        .unwrap();
        assert_eq!(scan.hosts[0].items.len(), 2);

        assert_nessus_export_round_trips(&scan, "detailed scan");
    }

    #[test]
    fn nessus_export_round_trips_local_sample_files() {
        let Ok(entries) = std::fs::read_dir(local_samples_dir()) else {
            return;
        };
        let (mut seen, mut checked) = (0, 0);
        for entry in entries {
            let path = entry.unwrap().path();
            let path = path.to_str().unwrap();
            seen += 1;
            let Ok(original) = parse_nessus_file(path) else {
                continue; // deliberately malformed samples
            };
            assert_nessus_export_round_trips(&original, path);
            checked += 1;
        }
        assert!(seen == 0 || checked > 0, "none of the {seen} local samples could be read");
    }

    #[test]
    fn merged_export_combines_targets_and_applies_the_severity_filter() {
        let a = parse_str(concat!(
            r#"<NessusClientData_v2><Policy><Preferences><ServerPreferences><preference><name>TARGET</name><value>10.0.0.1,10.0.0.2</value></preference></ServerPreferences></Preferences></Policy>"#,
            r#"<Report name="a"><ReportHost name="10.0.0.1"><ReportItem port="1" protocol="tcp" severity="4" pluginID="1" pluginName="crit" pluginFamily="f"><description>d</description></ReportItem><ReportItem port="2" protocol="tcp" severity="0" pluginID="2" pluginName="info" pluginFamily="f"><description>d</description></ReportItem></ReportHost></Report></NessusClientData_v2>"#,
        ))
        .unwrap();
        let b = parse_str(r#"<NessusClientData_v2><Policy><Preferences><ServerPreferences><preference><name>TARGET</name><value>10.0.0.2,10.0.0.3</value></preference></ServerPreferences></Preferences></Policy></NessusClientData_v2>"#).unwrap();

        let merged = parse_str(&build_nessus_xml(&[&a, &b], &request(&[4]))).unwrap();

        assert_eq!(merged.target.as_deref(), Some("10.0.0.1,10.0.0.2,10.0.0.3"));
        let ids: Vec<u32> = merged.hosts[0].items.iter().map(|i| i.plugin_id).collect();
        assert_eq!(ids, [1]);
    }

    #[test]
    fn a_host_in_two_files_is_exported_once() {
        let a = parse_str(concat!(
            r#"<NessusClientData_v2><Report name="a"><ReportHost name="10.0.0.1"><HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>"#,
            r#"<ReportItem port="80" protocol="tcp" severity="3" pluginID="1" pluginName="both" pluginFamily="f"><plugin_output>first</plugin_output></ReportItem>"#,
            r#"<ReportItem port="80" protocol="tcp" severity="3" pluginID="2" pluginName="repeat" pluginFamily="f"><plugin_output>one</plugin_output></ReportItem>"#,
            r#"<ReportItem port="80" protocol="tcp" severity="3" pluginID="2" pluginName="repeat" pluginFamily="f"><plugin_output>two</plugin_output></ReportItem>"#,
            r#"</ReportHost></Report></NessusClientData_v2>"#,
        ))
        .unwrap();
        let b = parse_str(concat!(
            r#"<NessusClientData_v2><Report name="b"><ReportHost name="10.0.0.1"><HostProperties><tag name="host-ip">10.0.0.1</tag><tag name="host-fqdn">web.corp.example</tag><tag name="Credentialed_Scan">true</tag></HostProperties>"#,
            r#"<ReportItem port="80" protocol="tcp" severity="3" pluginID="1" pluginName="both" pluginFamily="f"><plugin_output>second</plugin_output></ReportItem>"#,
            r#"<ReportItem port="443" protocol="tcp" severity="3" pluginID="1" pluginName="both" pluginFamily="f"></ReportItem>"#,
            r#"</ReportHost></Report></NessusClientData_v2>"#,
        ))
        .unwrap();

        let merged = parse_str(&build_nessus_xml(&[&a, &b], &request(&[3]))).unwrap();

        assert_eq!(merged.hosts.len(), 1);
        let host = &merged.hosts[0];
        assert_eq!(host.hostname.as_deref(), Some("web.corp.example"));
        assert!(host.credentialed_scan);
        let items: Vec<(u32, u16)> = host.items.iter().map(|i| (i.plugin_id, i.port)).collect();
        assert_eq!(items, [(1, 80), (2, 80), (2, 80), (1, 443)]);
        assert_eq!(host.items[0].plugin_output.as_deref(), Some("first"));
    }

    #[test]
    fn csv_neutralizes_cells_that_spreadsheets_would_run_as_formulas() {
        for (input, expected) in [
            ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
            ("+1+1", "'+1+1"),
            ("-1+1", "'-1+1"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\t=1", "'\t=1"),
            ("Normal text = fine", "Normal text = fine"),
            ("", ""),
        ] {
            assert_eq!(csv_safe(input), expected);
        }
    }

    #[test]
    fn excel_text_stays_within_a_cell_and_on_a_char_boundary() {
        let long = "é".repeat(40_000);
        assert_eq!(excel_text(&long).chars().count(), 32_767);
        assert_eq!(excel_text("short"), "short");
    }

    #[test]
    fn xlsx_takes_text_that_looks_like_a_formula() {
        let f = parse_str(r#"<NessusClientData_v2><Report name="a"><ReportHost name="10.0.0.1"><ReportItem port="1" protocol="tcp" severity="4" pluginID="1" pluginName="=1+1" pluginFamily="f"><solution>- Force SSL</solution><cvss3_base_score>9.8</cvss3_base_score></ReportItem></ReportHost></Report></NessusClientData_v2>"#).unwrap();
        assert!(build_xlsx(&[&f], &request(&[4])).unwrap().starts_with(b"PK"));
    }

    fn csv_bytes(files: &[&NessusFile], req: &ExportRequest) -> Vec<u8> {
        let mut buf = Vec::new();
        write_csv_records(csv::Writer::from_writer(&mut buf), files, req).unwrap();
        buf
    }

    #[test]
    fn a_merged_finding_keeps_its_worst_rating() {
        let scan = |severity: u8, output: &str| {
            parse_str(&format!(
                r#"<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.1"><ReportItem port="80" protocol="tcp" severity="{severity}" pluginID="1" pluginName="p" pluginFamily="f"><plugin_output>{output}</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>"#
            ))
            .unwrap()
        };
        let (low, critical) = (scan(1, "low"), scan(4, "critical"));

        for files in [[&low, &critical], [&critical, &low]] {
            let merged = parse_str(&build_nessus_xml(&files, &request(&[0, 1, 2, 3, 4]))).unwrap();
            let items = &merged.hosts[0].items;
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].severity, 4);
            assert_eq!(items[0].plugin_output.as_deref(), Some("critical"));
        }
    }

    #[test]
    fn exports_keep_synopsis_and_metasploit_name() {
        let f = parse_str(r#"<NessusClientData_v2><Report name="a"><ReportHost name="10.0.0.1"><ReportItem port="1" protocol="tcp" severity="4" pluginID="1" pluginName="p" pluginFamily="f"><synopsis>First.

Second.</synopsis><metasploit_name>Module &amp; Name</metasploit_name></ReportItem></ReportHost></Report></NessusClientData_v2>"#).unwrap();

        let again = parse_str(&build_nessus_xml(&[&f], &request(&[4]))).unwrap();
        let i = &again.hosts[0].items[0];
        assert_eq!(i.synopsis, f.hosts[0].items[0].synopsis);
        assert_eq!(i.metasploit_name.as_deref(), Some("Module & Name"));

        let text = String::from_utf8(csv_bytes(&[&f], &request(&[4]))).unwrap();
        assert!(text.contains("Metasploit Module"), "{text}");
        assert!(text.contains("Module & Name"), "{text}");
    }

    #[test]
    fn csv_has_one_row_per_matching_finding() {
        let f = parse_str(r#"<NessusClientData_v2><Report name="a"><ReportHost name="10.0.0.1"><ReportItem port="1" protocol="tcp" severity="4" pluginID="1" pluginName="crit" pluginFamily="f"><vpr_score>6.7</vpr_score></ReportItem><ReportItem port="2" protocol="tcp" severity="0" pluginID="2" pluginName="info" pluginFamily="f"></ReportItem></ReportHost></Report></NessusClientData_v2>"#).unwrap();
        let bytes = csv_bytes(&[&f], &request(&[4]));
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.contains(",6.7,"), "{text}");
    }
}
