use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

use quick_xml::events::{BytesRef, Event};
use quick_xml::Reader;
use uuid::Uuid;

use crate::intern::Interner;
use crate::models::{NessusFile, PluginDetails, ReportHost, ReportItem};

#[derive(PartialEq, Clone, Copy)]
enum S {
    Root,
    // Policy / target parsing
    Policy,
    PolicyPrefs,
    ServerPrefs,
    PrefEntry,
    PrefField, // its name is in `field`
    // Report parsing (existing)
    Report,
    ReportHost,
    HostProperties,
    HostPropTag,
    ReportItem,
    ItemField, // its name is in `field`
}

#[cfg(test)]
pub fn parse_nessus_file(path: &str) -> Result<NessusFile, String> {
    parse_nessus_file_with(path, &mut |_| {})
}

// `progress` gets how much of the file has been read, from 0 to 100
pub fn parse_nessus_file_with(path: &str, progress: &mut dyn FnMut(u8)) -> Result<NessusFile, String> {
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let file = File::open(path).map_err(|e| format!("Cannot open file: {e}"))?;
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);
    match parse_source(Reader::from_reader(BufReader::with_capacity(1 << 16, file)), total, path, filename.clone(), progress) {
        Err(e) if e == NOT_UTF8 => {
            let file = File::open(path).map_err(|e| format!("Cannot open file: {e}"))?;
            parse_reader(file, path, filename, progress)
        }
        other => other,
    }
}

// a byte that isn't valid UTF-8 stops the streamed read; the file is then read whole and repaired
const NOT_UTF8: &str = "streamed read hit a byte that is not UTF-8";

fn parse_reader<R: Read>(mut source: R, path: &str, filename: String, progress: &mut dyn FnMut(u8)) -> Result<NessusFile, String> {
    let mut bytes = Vec::new();
    source
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    // The XML reader rejects a whole file over one byte that isn't valid UTF-8, and
    // plugin output can contain such bytes. Replacing them keeps the rest of the scan.
    let text = String::from_utf8_lossy(&bytes);
    parse_source(Reader::from_reader(text.as_bytes()), text.len() as u64, path, filename, progress)
}

fn parse_source<R: BufRead>(mut reader: Reader<R>, total: u64, path: &str, filename: String, progress: &mut dyn FnMut(u8)) -> Result<NessusFile, String> {
    reader.config_mut().allow_dangling_amp = true; // keep a bare & as text

    let mut nessus_file = NessusFile {
        id: Uuid::new_v4().to_string(),
        filename,
        path: path.to_string(),
        loaded_at: chrono::Local::now().to_rfc3339(),
        report_name: String::new(),
        target: None,
        compliance_skipped: 0,
        hosts: Vec::new(),
    };

    let mut state = S::Root;
    let mut current_host: Option<ReportHost> = None;
    let mut current_item: Option<ParsedItem> = None;
    let mut interner = Interner::default();
    let mut current_tag_name: Option<String> = None;
    let mut host_props: HashMap<String, String> = HashMap::new();
    let mut item_field_depth: u32 = 0;
    let mut current_pref_name: Option<String> = None;
    let mut buf = Vec::new();
    let mut root_seen = false;
    let mut depth: u32 = 0;
    let mut text_buf = String::new();
    let mut unnamed_hosts = 0;
    // the name of the field being read
    let mut field = String::new();
    // most findings repeat a plugin's description word for word, so each text is tidied once
    let mut tidied: HashMap<String, String> = HashMap::new();

    // Must run before the state changes, since the text belongs to the current state.
    macro_rules! flush_text {
        () => {
            let text = text_buf.trim();
            if !text.is_empty() {
                dispatch_text(
                    state,
                    &field,
                    &mut tidied,
                    &mut nessus_file,
                    &mut current_pref_name,
                    &current_tag_name,
                    &mut current_item,
                    &mut host_props,
                    text,
                );
            }
            text_buf.clear();
        };
    }

    let total = total.max(1);
    let mut events: u32 = 0;
    let mut told: u8 = 0;
    loop {
        events = events.wrapping_add(1);
        if events.is_multiple_of(8192) {
            let done = (reader.buffer_position() * 100 / total).min(100) as u8;
            if done > told {
                told = done;
                progress(done);
            }
        }
        match reader.read_event_into(&mut buf) {
            Err(quick_xml::Error::Encoding(_)) => return Err(NOT_UTF8.to_string()),
            Err(e) => {
                return Err(format!(
                    "XML parse error at byte {}: {e}",
                    reader.buffer_position()
                ))
            }
            Ok(Event::Eof) => break,

            Ok(Event::Start(e)) => {
                flush_text!();
                let name = e.name();
                let tag: &str = name.as_ref();
                check_root(tag, &mut root_seen)?;
                depth += 1;
                match state {
                    S::Root => {
                        if tag == "Policy" {
                            state = S::Policy;
                        } else if tag == "Report" {
                            nessus_file.report_name = attr_val(&e, "name");
                            state = S::Report;
                        }
                    }
                    S::Policy => {
                        if tag == "Preferences" {
                            state = S::PolicyPrefs;
                        }
                    }
                    S::PolicyPrefs => {
                        if tag == "ServerPreferences" {
                            state = S::ServerPrefs;
                        }
                    }
                    S::ServerPrefs => {
                        if tag == "preference" {
                            current_pref_name = None;
                            state = S::PrefEntry;
                        }
                    }
                    S::PrefEntry => {
                        if tag == "name" || tag == "value" {
                            field.clear();
                            field.push_str(tag);
                            state = S::PrefField;
                        }
                    }
                    S::PrefField => {}
                    S::Report => {
                        if tag == "ReportHost" {
                            let name = single_line(&attr_val(&e, "name"));
                            current_host = Some(ReportHost {
                                ip: name.clone(),
                                name,
                                hostname: None,
                                domain: None,
                                os: None,
                                mac: None,
                                netbios: None,
                                system_type: None,
                                credentialed_scan: false,
                                os_unsupported: false,
                                host_start: None,
                                host_end: None,
                                alt_hostnames: Vec::new(),
                                items: Vec::new(),
                            });
                            host_props.clear();
                            state = S::ReportHost;
                        }
                    }
                    S::ReportHost => {
                        if tag == "HostProperties" {
                            state = S::HostProperties;
                        } else if tag == "ReportItem" {
                            current_item = Some(parse_item_attrs(&e));
                            item_field_depth = 0;
                            state = S::ReportItem;
                        }
                    }
                    S::HostProperties => {
                        if tag == "tag" {
                            current_tag_name = Some(attr_val(&e, "name"));
                            state = S::HostPropTag;
                        }
                    }
                    S::ReportItem => {
                        item_field_depth = 0;
                        field.clear();
                        field.push_str(tag);
                        state = S::ItemField;
                    }
                    S::ItemField => {
                        item_field_depth += 1;
                    }
                    S::HostPropTag => {}
                }
            }

            Ok(Event::End(e)) => {
                flush_text!();
                depth = depth.saturating_sub(1);
                let name = e.name();
                let tag: &str = name.as_ref();
                match state {
                    S::PrefField => {
                        state = S::PrefEntry;
                    }
                    S::PrefEntry => {
                        current_pref_name = None;
                        state = S::ServerPrefs;
                    }
                    S::ServerPrefs => {
                        if tag == "ServerPreferences" {
                            state = S::PolicyPrefs;
                        }
                    }
                    S::PolicyPrefs => {
                        if tag == "Preferences" {
                            state = S::Policy;
                        }
                    }
                    S::Policy => {
                        if tag == "Policy" {
                            state = S::Root;
                        }
                    }
                    S::HostPropTag => {
                        current_tag_name = None;
                        state = S::HostProperties;
                    }
                    S::HostProperties => {
                        if tag == "HostProperties" {
                            apply_host_props(&mut current_host, &host_props);
                            state = S::ReportHost;
                        }
                    }
                    S::ItemField => {
                        if item_field_depth > 0 {
                            item_field_depth -= 1;
                        } else {
                            state = S::ReportItem;
                        }
                    }
                    S::ReportItem => {
                        if tag == "ReportItem" {
                            // Every check of an audit shares one plugin ID, so they would all
                            // merge into one finding. Until they get their own view, they are
                            // only counted.
                            if let (Some(host), Some(item)) =
                                (current_host.as_mut(), current_item.take())
                            {
                                if item.compliance {
                                    nessus_file.compliance_skipped += 1;
                                } else {
                                    host.items.push(item.finish(&mut interner));
                                }
                            }
                            state = S::ReportHost;
                        }
                    }
                    S::ReportHost => {
                        if tag == "ReportHost" {
                            if let Some(mut host) = current_host.take() {
                                if host.ip.is_empty() {
                                    unnamed_hosts += 1;
                                    host.ip = format!("unnamed-host-{unnamed_hosts}");
                                    host.name.clone_from(&host.ip);
                                }
                                host.alt_hostnames = extract_alt_hostnames(&host.items);
                                host.credentialed_scan |= scan_info_says_credentialed(&host.items);
                                nessus_file.hosts.push(host);
                            }
                            state = S::Report;
                        }
                    }
                    S::Report => {
                        if tag == "Report" {
                            state = S::Root;
                        }
                    }
                    S::Root => {}
                }
            }

            // Nessus writes self-closed ReportItems with pluginID 0 as empty placeholders;
            // those are skipped. Any other self-closed ReportItem is a real finding.
            Ok(Event::Empty(e)) => {
                flush_text!();
                let tag = e.name().as_ref().to_string();
                check_root(&tag, &mut root_seen)?;
                if state == S::ReportHost && tag == "ReportItem" {
                    let item = parse_item_attrs(&e);
                    if let (Some(host), true) = (current_host.as_mut(), item.d.plugin_id != 0) {
                        host.items.push(item.finish(&mut interner));
                    }
                }
            }

            // One field's text can arrive in several events, split at every entity
            // reference, so it is collected here and used at the next tag.
            Ok(Event::Text(e)) => text_buf.push_str(e.as_ref()),
            Ok(Event::CData(e)) => text_buf.push_str(e.as_ref()),
            Ok(Event::GeneralRef(e)) => push_reference(&mut text_buf, &e),

            _ => {}
        }
        buf.clear();
    }

    if !root_seen {
        return Err("Not a Nessus scan file: the file is empty or is not XML".into());
    }
    if depth > 0 {
        return Err(
            "The file is incomplete: it ends before the scan data is closed, so it may be truncated"
                .into(),
        );
    }

    Ok(nessus_file)
}

fn check_root(tag: &str, root_seen: &mut bool) -> Result<(), String> {
    if *root_seen {
        return Ok(());
    }
    *root_seen = true;
    match tag {
        "NessusClientData_v2" => Ok(()),
        "NessusClientData" => Err(
            "This is the old .nessus v1 format, which is not supported. Export the scan as .nessus v2"
                .into(),
        ),
        other => Err(format!("Not a Nessus scan file: unexpected root element <{other}>")),
    }
}

// A reference XML does not define (such as &nbsp;) stays as written, so that text is
// never lost. Entities declared in the file itself are never expanded.
fn push_reference(out: &mut String, reference: &BytesRef<'_>) {
    let name: &str = reference.as_ref();
    match name {
        "lt" => out.push('<'),
        "gt" => out.push('>'),
        "amp" => out.push('&'),
        "quot" => out.push('"'),
        "apos" => out.push('\''),
        _ => match reference.resolve_char_ref() {
            Ok(Some(c)) => out.push(c),
            _ => {
                out.push('&');
                out.push_str(name);
                out.push(';');
            }
        },
    }
}

// Host identifiers end up in copied lists, so a line break could add or run extra
// lines when pasted, for example into a terminal.
fn single_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

// Nessus only uses 0 to 4. Anything higher is treated as the most severe rather than
// falling outside every severity filter, where the finding would be hidden.
fn parse_severity(value: &str) -> u8 {
    value.trim().parse::<i64>().map_or(0, |s| s.clamp(0, 4) as u8)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_text(
    state: S,
    field: &str,
    tidied: &mut HashMap<String, String>,
    nessus_file: &mut NessusFile,
    current_pref_name: &mut Option<String>,
    current_tag_name: &Option<String>,
    current_item: &mut Option<ParsedItem>,
    host_props: &mut HashMap<String, String>,
    text: &str,
) {
    match state {
        S::PrefField => {
            if field == "name" {
                *current_pref_name = Some(text.to_string());
            } else if field == "value" && current_pref_name.as_deref() == Some("TARGET") {
                nessus_file.target = Some(text.to_string());
            }
        }
        S::HostPropTag => {
            if let Some(name) = current_tag_name {
                host_props.insert(name.clone(), text.to_string());
            }
        }
        S::ItemField => {
            if let Some(item) = current_item.as_mut() {
                apply_item_field(item, field, text, tidied);
            }
        }
        _ => {}
    }
}

fn apply_item_field(item: &mut ParsedItem, field: &str, text: &str, tidied: &mut HashMap<String, String>) {
    match field {
        "risk_factor" => item.d.risk_factor = text.to_string(),
        "description" => item.d.description = tidy_prose(tidied, text),
        "solution" => item.d.solution = tidy_prose(tidied, text),
        "synopsis" => item.d.synopsis = Some(tidy_prose(tidied, text)).filter(|s| !s.is_empty()),
        "plugin_output" => item.plugin_output = Some(normalize_text(text)),
        "cvss_base_score" => item.d.cvss_base_score = text.parse().ok(),
        "cvss3_base_score" => item.d.cvss3_base_score = text.parse().ok(),
        // Only a fallback: the base score must win whichever order the two appear in.
        "cvss3_temporal_score" if item.d.cvss3_base_score.is_none() => {
            item.d.cvss3_base_score = text.parse().ok();
        }
        "cvss4_base_score" => item.d.cvss4_base_score = text.parse().ok(),
        "vpr_score" => item.d.vpr_score = text.parse().ok(),
        "epss_score" => item.d.epss_score = text.parse().ok(),
        "cve" => item.d.cve.push(text.to_string()),
        "cwe" => item.d.cwe.push(text.to_string()),
        "see_also" => {
            for url in text.lines() {
                let u = url.trim();
                if !u.is_empty() {
                    item.d.see_also.push(u.to_string());
                }
            }
        }
        "exploit_available" => item.d.exploit_available = text == "true",
        "exploit_framework_metasploit" if text == "true" => item.d.metasploit_available = true,
        "metasploit_name" if !text.is_empty() => {
            item.d.metasploit_name = Some(single_line(text));
            item.d.metasploit_available = true;
        }
        "exploitability_ease" => item.d.exploit_ease = Some(text.to_string()),
        "exploit_code_maturity" if !text.is_empty() => item.d.exploit_maturity = Some(single_line(text)),
        "exploit_framework_core" if text == "true" => add_framework(item, "Core Impact"),
        "exploit_framework_canvas" if text == "true" => add_framework(item, "CANVAS"),
        "exploit_framework_d2_elliot" if text == "true" => add_framework(item, "D2 Elliot"),
        "exploit_framework_exploithub" if text == "true" => add_framework(item, "ExploitHub"),
        "exploited_by_malware" => item.d.exploited_by_malware = text == "true",
        "exploited_by_nessus" => item.d.exploited_by_nessus = text == "true",
        "unsupported_by_vendor" => item.d.unsupported_by_vendor = text == "true",
        "compliance" if text == "true" => item.compliance = true,
        f if f.starts_with("cm:compliance") => item.compliance = true,
        "cisa-known-exploited" if !text.is_empty() => item.d.cisa_known_exploited = Some(single_line(text)),
        "patch_publication_date" => item.d.patch_publication_date = Some(text.to_string()),
        "vuln_publication_date" => item.d.vuln_publication_date = Some(text.to_string()),
        "script_version" => item.d.script_version = Some(text.to_string()),
        _ => {}
    }
}

// Older Nessus versions leave out the Credentialed_Scan tag even when the login worked,
// but the Nessus Scan Information finding always has a "Credentialed checks : yes" line.
fn scan_info_says_credentialed(items: &[ReportItem]) -> bool {
    items.iter().any(|i| {
        i.plugin_id == 19506
            && i.plugin_output.as_deref().is_some_and(|output| {
                output.lines().any(|line| {
                    line.trim()
                        .strip_prefix("Credentialed checks")
                        .map(|rest| rest.trim_start().trim_start_matches(':').trim_start())
                        .is_some_and(|value| value.to_lowercase().starts_with("yes"))
                })
            })
    })
}

fn add_framework(item: &mut ParsedItem, name: &str) {
    if !item.d.exploit_frameworks.iter().any(|f| f == name) {
        item.d.exploit_frameworks.push(name.to_string());
    }
}

fn apply_host_props(current_host: &mut Option<ReportHost>, props: &HashMap<String, String>) {
    let Some(host) = current_host.as_mut() else {
        return;
    };
    if let Some(ip) = props.get("host-ip") {
        host.ip = single_line(ip);
    }
    let fqdn = props.get("host-fqdn").or_else(|| props.get("hostname")).map(|f| single_line(f));
    host.domain = fqdn.as_deref()
        .filter(|f| f.parse::<std::net::IpAddr>().is_err())
        .and_then(|f| f.find('.').map(|i| f[i + 1..].to_string()))
        .filter(|d| !d.is_empty());
    host.hostname = fqdn;
    host.os = props.get("operating-system").cloned();
    host.mac = props.get("mac-address").cloned();
    host.netbios = props.get("netbios-name").map(|n| single_line(n));
    host.system_type = props.get("system-type").cloned();
    host.os_unsupported = props.get("operating-system-unsupported").is_some_and(|v| v == "true");
    host.host_start = props.get("HOST_START").cloned();
    host.host_end = props.get("HOST_END").cloned();
    host.credentialed_scan = props
        .iter()
        .find(|(k, _)| k.to_lowercase() == "credentialed_scan")
        .map(|(_, v)| v.to_lowercase() == "true")
        .unwrap_or(false);
}

fn parse_item_attrs(e: &quick_xml::events::BytesStart<'_>) -> ParsedItem {
    let mut item = ParsedItem::default();
    for attr in e.attributes().flatten() {
        match attr.key.as_ref() {
            "port" => item.port = attr.value.as_ref().parse().unwrap_or(0),
            "protocol" => item.protocol = unescape_attr(&attr),
            "svc_name" => item.svc_name = unescape_attr(&attr),
            "severity" => item.severity = parse_severity(attr.value.as_ref()),
            "pluginID" => item.d.plugin_id = attr.value.as_ref().parse().unwrap_or(0),
            "pluginName" => item.d.plugin_name = unescape_attr(&attr),
            "pluginFamily" => item.d.plugin_family = unescape_attr(&attr),
            _ => {}
        }
    }
    item
}

// a finding while it is read. Its plugin details go to the interner when it ends
#[derive(Default)]
struct ParsedItem {
    d: PluginDetails,
    severity: u8,
    port: u16,
    protocol: String,
    svc_name: String,
    plugin_output: Option<String>,
    compliance: bool,
}

impl ParsedItem {
    fn finish(self, interner: &mut Interner) -> ReportItem {
        ReportItem {
            details: interner.details(self.d),
            severity: self.severity,
            port: self.port,
            protocol: interner.word(&self.protocol),
            svc_name: interner.word(&self.svc_name),
            plugin_output: self.plugin_output.map(String::into_boxed_str),
        }
    }
}

fn attr_val(e: &quick_xml::events::BytesStart<'_>, key: &str) -> String {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| unescape_attr(&a))
        .unwrap_or_default()
}

fn unescape_attr(attr: &quick_xml::events::attributes::Attribute<'_>) -> String {
    attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
        .map(|v| v.into_owned())
        .unwrap_or_else(|_| attr.value.to_string())
}

fn normalize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, line) in s.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line.trim());
    }
    out
}

// normalize_prose, done once per distinct text of the file
fn tidy_prose(tidied: &mut HashMap<String, String>, text: &str) -> String {
    if let Some(done) = tidied.get(text) {
        return done.clone();
    }
    // a file whose texts all differ shouldn't keep a copy of each
    if tidied.len() >= 20_000 {
        tidied.clear();
    }
    let done = normalize_prose(text.to_string());
    tidied.insert(text.to_string(), done.clone());
    done
}

// For prose fields (description, solution, synopsis): collapse hard-wrapped single newlines into
// spaces so the UI can reflow the text naturally. Blank lines (paragraph breaks) are kept.
// Runs of spaces inside a line collapse too: some exporters replace each line break with spaces.
fn normalize_prose(s: String) -> String {
    let joined: Vec<String> = s.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect();
    let lines: Vec<&str> = joined.iter().map(String::as_str).collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].is_empty() {
            if !out.ends_with('\n') { out.push('\n'); }
            while i + 1 < lines.len() && lines[i + 1].is_empty() { i += 1; }
        } else {
            if !out.is_empty() && !out.ends_with('\n') { out.push(' '); }
            out.push_str(lines[i]);
        }
        i += 1;
    }
    out.trim().to_string()
}

fn extract_alt_hostnames(items: &[ReportItem]) -> Vec<String> {
    let Some(output) = items
        .iter()
        .find(|i| i.plugin_id == 46180)
        .and_then(|i| i.plugin_output.as_deref())
    else {
        return Vec::new();
    };
    output
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if let Some(name) = t.strip_prefix("- ") {
                let name = name.trim();
                if !name.is_empty() { Some(name.to_string()) } else { None }
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn parse_str(xml: &str) -> Result<NessusFile, String> {
    parse_reader(xml.as_bytes(), "test.nessus", "test.nessus".to_string(), &mut |_| {})
}

#[cfg(test)]
pub(crate) fn local_samples_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Nessus TestFiles")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_file::testing::TempDir;

    fn scan(host: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.1">{host}</ReportHost></Report></NessusClientData_v2>"#
        )
    }

    fn item(body: &str) -> String {
        format!(
            r#"<ReportItem port="80" svc_name="www" protocol="tcp" severity="2" pluginID="7" pluginName="p" pluginFamily="f">{body}</ReportItem>"#
        )
    }

    #[test]
    fn rejects_files_that_are_not_nessus_scans() {
        for (xml, expected) in [
            ("", "empty or is not XML"),
            ("this is not xml at all\n", "empty or is not XML"),
            ("<foo><bar>x</bar></foo>", "unexpected root element <foo>"),
            ("<foo/>", "unexpected root element <foo>"),
            ("<NessusClientData><Report/></NessusClientData>", "v1 format"),
        ] {
            let err = parse_str(xml).unwrap_err();
            assert!(err.contains(expected), "{xml:?} gave {err:?}");
        }
    }

    #[test]
    fn rejects_a_file_cut_off_at_a_tag_boundary() {
        let full = scan(&item(""));
        let cut = &full[..full.find("</ReportHost>").unwrap()];
        assert!(parse_str(cut).unwrap_err().contains("truncated"));
    }

    #[test]
    fn accepts_a_scan_without_hosts() {
        let f = parse_str("<NessusClientData_v2><Policy></Policy></NessusClientData_v2>").unwrap();
        assert!(f.hosts.is_empty());
    }

    #[test]
    fn keeps_text_containing_an_unknown_entity() {
        let f = parse_str(&scan(&item(
            "<description>a &nbsp; b &lt; c AT&amp;T</description><solution>R&D &amp; ops</solution>",
        )))
        .unwrap();
        let i = &f.hosts[0].items[0];
        assert_eq!(i.description, "a &nbsp; b < c AT&T");
        assert_eq!(i.solution, "R&D & ops");
    }

    #[test]
    fn prose_loses_runs_of_spaces_but_plugin_output_keeps_them() {
        let xml = scan(&item(concat!(
            "<description>exist in     Microsoft SMB due to     improper handling.\n\n  - An     unauthenticated attacker</description>",
            "<solution>Apply     MS17-010.</solution><synopsis>Remote     code execution.</synopsis>",
            "<plugin_output>Port   State\n22     open</plugin_output>",
        )));
        let i = &parse_str(&xml).unwrap().hosts[0].items[0];
        assert_eq!(i.description, "exist in Microsoft SMB due to improper handling.\n- An unauthenticated attacker");
        assert_eq!(i.solution, "Apply MS17-010.");
        assert_eq!(i.synopsis.as_deref(), Some("Remote code execution."));
        assert_eq!(i.plugin_output.as_deref(), Some("Port   State\n22     open"));
    }

    #[test]
    fn invalid_utf8_in_a_field_does_not_lose_the_scan() {
        let xml = scan(&item("<description>caf_ menu</description>"));
        let at = xml.find("caf_").unwrap() + 3;
        let mut xml = xml.into_bytes();
        xml[at] = 0xE9; // e-acute in Windows-1252, which is invalid UTF-8
        let f = parse_reader(xml.as_slice(), "t", "t".to_string(), &mut |_| {}).unwrap();
        assert!(f.hosts[0].items[0].description.ends_with(" menu"));
    }

    #[test]
    fn joins_text_split_by_references_and_cdata() {
        let f = parse_str(&scan(&item(
            "<description>  a &amp; b &#65;&#x42; <![CDATA[<raw> & text]]> end  </description>",
        )))
        .unwrap();
        assert_eq!(f.hosts[0].items[0].description, "a & b AB <raw> & text end");
    }

    #[test]
    fn invalid_character_references_stay_as_written() {
        let f = parse_str(&scan(&item("<description>x &#xFFFFFFFF; y &#0; z</description>"))).unwrap();
        assert_eq!(f.hosts[0].items[0].description, "x &#xFFFFFFFF; y &#0; z");
    }

    #[test]
    fn declared_entities_are_not_expanded() {
        let xml = format!(
            r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"><!ENTITY a "aaaa">]>{}"#,
            scan(&item("<description>&xxe; &a;</description>"))
        );
        assert_eq!(parse_str(&xml).unwrap().hosts[0].items[0].description, "&xxe; &a;");
    }

    #[test]
    fn large_runs_of_ampersands_parse_quickly() {
        for text in ["&".repeat(4_000_000), format!("{};", "&".repeat(4_000_000))] {
            let start = std::time::Instant::now();
            let f = parse_str(&scan(&item(&format!("<description>{text}</description>")))).unwrap();
            assert_eq!(f.hosts[0].items[0].description.len(), text.len());
            assert!(start.elapsed().as_secs() < 10, "took {:?}", start.elapsed());
        }
    }

    #[test]
    fn many_attributes_on_one_tag_parse_quickly() {
        let attrs: String = (0..200_000).map(|i| format!(r#" a{i}="1""#)).collect();
        let start = std::time::Instant::now();
        let host = format!(r#"<ReportItem{attrs} port="1" protocol="tcp" severity="1" pluginID="9" pluginName="p" pluginFamily="f"></ReportItem>"#);
        let f = parse_str(&scan(&host)).unwrap();
        assert_eq!(f.hosts[0].items[0].plugin_id, 9);
        assert!(start.elapsed().as_secs() < 10, "took {:?}", start.elapsed());
    }

    #[test]
    fn out_of_range_severities_stay_visible() {
        for (value, expected) in [("0", 0), ("4", 4), ("5", 4), ("9", 4), ("999", 4), ("-1", 0), ("high", 0), ("", 0)] {
            let host = format!(r#"<ReportItem port="1" protocol="tcp" severity="{value}" pluginID="9" pluginName="p" pluginFamily="f"></ReportItem>"#);
            assert_eq!(parse_str(&scan(&host)).unwrap().hosts[0].items[0].severity, expected, "{value}");
        }
    }

    #[test]
    fn hosts_without_a_name_get_distinct_placeholders() {
        let host = |inner: &str| format!(r#"<ReportHost name="">{inner}</ReportHost>"#);
        let xml = format!(
            r#"<NessusClientData_v2><Report name="r">{}{}{}</Report></NessusClientData_v2>"#,
            host(""),
            host(r#"<HostProperties><tag name="host-ip">10.0.0.5</tag></HostProperties>"#),
            host(""),
        );
        let f = parse_str(&xml).unwrap();
        let ips: Vec<&str> = f.hosts.iter().map(|h| h.ip.as_str()).collect();
        assert_eq!(ips, ["unnamed-host-1", "10.0.0.5", "unnamed-host-2"]);
    }

    #[test]
    fn host_identifiers_are_kept_on_one_line() {
        let props = "<HostProperties><tag name=\"host-ip\">10.0.0.1\nrm -rf x</tag><tag name=\"host-fqdn\">a\n b.example</tag><tag name=\"netbios-name\">NB\tX\n</tag></HostProperties>";
        let host = &parse_str(&scan(props)).unwrap().hosts[0];
        assert_eq!(host.ip, "10.0.0.1 rm -rf x");
        assert_eq!(host.hostname.as_deref(), Some("a b.example"));
        assert_eq!(host.netbios.as_deref(), Some("NB X"));
    }

    #[test]
    fn self_closed_items_keep_real_findings_and_skip_placeholders() {
        let host = r#"<ReportItem port="0" protocol="tcp" severity="0" pluginID="0" pluginName="" pluginFamily=""/>
            <ReportItem port="1" protocol="tcp" severity="3" pluginID="5" pluginName="real" pluginFamily="f"/>"#;
        let f = parse_str(&scan(host)).unwrap();
        let ids: Vec<u32> = f.hosts[0].items.iter().map(|i| i.plugin_id).collect();
        assert_eq!(ids, [5]);
    }

    #[test]
    fn cvss3_base_score_wins_over_temporal_in_either_order() {
        for body in [
            "<cvss3_temporal_score>6.1</cvss3_temporal_score><cvss3_base_score>7.5</cvss3_base_score>",
            "<cvss3_base_score>7.5</cvss3_base_score><cvss3_temporal_score>6.1</cvss3_temporal_score>",
        ] {
            let f = parse_str(&scan(&item(body))).unwrap();
            assert_eq!(f.hosts[0].items[0].cvss3_base_score, Some(7.5), "{body}");
        }
    }

    #[test]
    fn reads_cvss4_vpr_and_epss() {
        let f = parse_str(&scan(&item(
            "<cvss4_base_score>8.7</cvss4_base_score><vpr_score>6.7</vpr_score><epss_score>0.25</epss_score>",
        )))
        .unwrap();
        let i = &f.hosts[0].items[0];
        assert_eq!(
            (i.cvss4_base_score, i.vpr_score, i.epss_score),
            (Some(8.7), Some(6.7), Some(0.25))
        );
    }

    #[test]
    fn reads_synopsis_and_metasploit_name() {
        let f = parse_str(&scan(&item(
            "<synopsis>Short summary.</synopsis><metasploit_name>MS08-067 Service</metasploit_name>",
        )))
        .unwrap();
        let i = &f.hosts[0].items[0];
        assert_eq!(i.synopsis.as_deref(), Some("Short summary."));
        assert_eq!(i.metasploit_name.as_deref(), Some("MS08-067 Service"));
        assert!(i.metasploit_available);
    }

    #[test]
    fn scan_information_marks_a_host_credentialed() {
        let info = |answer: &str| format!(
            r#"<ReportItem port="0" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"><plugin_output>Scan type : Normal
Credentialed checks : {answer}
Patch management checks : None</plugin_output></ReportItem>"#
        );
        for (answer, expected) in [("yes, as 'admin' via ssh", true), ("no", false)] {
            let f = parse_str(&scan(&info(answer))).unwrap();
            assert_eq!(f.hosts[0].credentialed_scan, expected, "{answer}");
        }
    }

    #[test]
    fn leaves_compliance_results_out_and_counts_them() {
        let check = |result: &str| format!(
            r#"<ReportItem port="0" svc_name="general" protocol="tcp" severity="3" pluginID="21157" pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance"><cm:compliance-check-name>1.1 Check {result}</cm:compliance-check-name><cm:compliance-result>{result}</cm:compliance-result></ReportItem>"#
        );
        let f = parse_str(&scan(&format!("{}{}{}", check("FAILED"), check("PASSED"), item("<cvss_base_score>5.0</cvss_base_score>")))).unwrap();
        assert_eq!(f.compliance_skipped, 2);
        assert_eq!(f.hosts[0].items.len(), 1);
        assert_eq!(f.hosts[0].items[0].plugin_id, 7);
    }

    #[test]
    fn reads_unsupported_flags() {
        let f = parse_str(&scan(&format!(
            "{}{}",
            r#"<HostProperties><tag name="operating-system-unsupported">true</tag></HostProperties>"#,
            item("<unsupported_by_vendor>true</unsupported_by_vendor>"),
        )))
        .unwrap();
        assert!(f.hosts[0].os_unsupported);
        assert!(f.hosts[0].items[0].unsupported_by_vendor);
    }

    #[test]
    fn reads_exploit_details() {
        let f = parse_str(&scan(&item(
            concat!(
                "<exploit_available>true</exploit_available><exploit_code_maturity>Functional</exploit_code_maturity>",
                "<exploit_framework_canvas>true</exploit_framework_canvas><exploit_framework_core>true</exploit_framework_core>",
                "<exploit_framework_core>true</exploit_framework_core><exploit_framework_exploithub>false</exploit_framework_exploithub>",
                "<exploited_by_malware>true</exploited_by_malware><exploited_by_nessus>false</exploited_by_nessus>",
                "<cisa-known-exploited>2022/05/03</cisa-known-exploited>",
            ),
        )))
        .unwrap();
        let i = &f.hosts[0].items[0];
        assert_eq!(i.exploit_maturity.as_deref(), Some("Functional"));
        assert_eq!(i.exploit_frameworks, ["CANVAS", "Core Impact"]);
        assert!(i.exploited_by_malware && !i.exploited_by_nessus);
        assert_eq!(i.cisa_known_exploited.as_deref(), Some("2022/05/03"));
    }

    #[test]
    fn leaves_empty_exploit_details_out_of_the_json() {
        let f = parse_str(&scan(&item("<exploit_available>true</exploit_available>"))).unwrap();
        let json = serde_json::to_string(&f.hosts[0].items[0]).unwrap();
        assert!(!json.contains("exploit_maturity") && !json.contains("exploit_frameworks") && !json.contains("exploited_by"));
    }

    #[test]
    fn domain_is_not_derived_from_an_ip_hostname() {
        for (name, domain) in [("10.0.0.9", None), ("web.corp.example", Some("corp.example"))] {
            let props = format!(r#"<HostProperties><tag name="host-fqdn">{name}</tag></HostProperties>"#);
            let f = parse_str(&scan(&props)).unwrap();
            assert_eq!(f.hosts[0].domain.as_deref(), domain, "{name}");
        }
    }

    #[test]
    fn local_sample_files_parse_to_known_counts() {
        for (name, hosts, findings) in [
            ("DEFAULT.nessus", 0, 0),
            ("example-scan2.nessus", 11, 268),
            ("example_v2.nessus", 2, 50),
            ("manyhosts.nessus", 8, 373),
            ("metasploitable_a0p4hb.nessus", 1, 148),
            ("same-day-morning.nessus", 2, 9),
            ("topology-test.nessus", 13, 18),
        ] {
            let path = local_samples_dir().join(name);
            if !path.exists() {
                continue;
            }
            let f = parse_nessus_file(path.to_str().unwrap()).unwrap();
            let total: usize = f.hosts.iter().map(|h| h.items.len()).sum();
            assert_eq!((f.hosts.len(), total), (hosts, findings), "{name}");
        }
    }

    #[test]
    fn a_scan_file_on_disk_is_read_with_its_name_and_path() {
        let temp = TempDir::new();
        let path = temp.path().join("two-hosts.nessus");
        std::fs::write(
            &path,
            format!(
                r#"<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.1">{a}{a}</ReportHost><ReportHost name="10.0.0.2">{a}</ReportHost></Report></NessusClientData_v2>"#,
                a = item("<description>d</description>"),
            ),
        )
        .unwrap();
        let path = path.to_str().unwrap();

        let f = parse_nessus_file(path).unwrap();

        assert_eq!(f.filename, "two-hosts.nessus");
        assert_eq!(f.path, path);
        assert_eq!(f.report_name, "r");
        let findings: Vec<usize> = f.hosts.iter().map(|h| h.items.len()).collect();
        assert_eq!(findings, [2, 1]);
    }

    #[test]
    fn a_missing_file_reports_that_it_cannot_be_opened() {
        let temp = TempDir::new();
        let err = parse_nessus_file(temp.path().join("missing.nessus").to_str().unwrap()).unwrap_err();
        assert!(err.contains("Cannot open file"), "{err}");
    }

    #[test]
    fn a_scan_with_broken_xml_is_rejected() {
        for xml in [
            // an opening tag that lost its "<" leaves its closing tag unmatched
            "<?xml version=\"1.0\" ?>\n<NessusClientData_v2>\nPolicy>\n</Policy>\n</NessusClientData_v2>",
            "<?xml version=\"1.0\" ?>\nNessusClientData_v2>\n<Report name=\"r\"></Report>\n</NessusClientData_v2>",
        ] {
            assert!(parse_str(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn a_file_on_disk_is_streamed_and_repaired_when_it_is_not_utf8() {
        let temp = TempDir::new();
        let good = temp.path().join("good.nessus");
        std::fs::write(&good, scan(&item("<description>caf\u{e9} menu</description>"))).unwrap();
        let mut seen = Vec::new();
        let f = parse_nessus_file_with(good.to_str().unwrap(), &mut |p| seen.push(p)).unwrap();
        assert_eq!(f.hosts[0].items[0].description, "caf\u{e9} menu");

        let bad = temp.path().join("bad.nessus");
        let xml = scan(&item("<description>caf_ menu</description>"));
        let at = xml.find("caf_").unwrap() + 3;
        let mut bytes = xml.into_bytes();
        bytes[at] = 0xE9; // e-acute in Windows-1252, which is invalid UTF-8
        std::fs::write(&bad, bytes).unwrap();
        let f = parse_nessus_file(bad.to_str().unwrap()).unwrap();
        assert_eq!(f.hosts[0].items[0].description, "caf\u{fffd} menu");

        let cut = temp.path().join("cut.nessus");
        let full = scan(&item(""));
        std::fs::write(&cut, &full[..full.find("</ReportHost>").unwrap()]).unwrap();
        assert!(parse_nessus_file(cut.to_str().unwrap()).unwrap_err().contains("truncated"));
    }
}

#[cfg(test)]
mod timing {
    use super::*;

    // cargo test --release --lib parser::timing -- --ignored --nocapture, with SCAN set to a big .nessus file
    #[test]
    #[ignore]
    fn where_parsing_time_goes() {
        let path = std::env::var("SCAN").unwrap();
        let t = std::time::Instant::now();
        let mut reader = Reader::from_reader(BufReader::with_capacity(1 << 16, File::open(&path).unwrap()));
        reader.config_mut().allow_dangling_amp = true;
        let mut buf = Vec::new();
        let mut events = 0u64;
        let mut tags = 0u64;
        // the text of each field inside a ReportItem, by field name
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut field: Option<String> = None;
        let mut in_item = false;
        let mut text = String::new();
        loop {
            match reader.read_event_into(&mut buf).unwrap() {
                Event::Eof => break,
                Event::Start(e) => {
                    tags += 1;
                    let name = e.name();
                    let name = name.as_ref();
                    if name == "ReportItem" {
                        in_item = true;
                    } else if in_item {
                        field = Some(name.to_string());
                        text.clear();
                    }
                }
                Event::End(e) => {
                    tags += 1;
                    let name = e.name();
                    if name.as_ref() == "ReportItem" {
                        in_item = false;
                    } else if let Some(f) = field.take() {
                        fields.push((f, std::mem::take(&mut text)));
                    }
                }
                Event::Text(e) => text.push_str(&e),
                Event::GeneralRef(e) => push_reference(&mut text, &e),
                _ => {}
            }
            events += 1;
            buf.clear();
        }
        println!("reading XML events and keeping item fields: {:?} ({events} events, {tags} tags, {} fields)", t.elapsed(), fields.len());

        let t = std::time::Instant::now();
        let mut n = 0usize;
        for _ in 0..tags {
            let s = String::from("plugin_output");
            n += s.len();
        }
        println!("a new string per tag: {:?} ({n})", t.elapsed());

        let t = std::time::Instant::now();
        let mut n = 0usize;
        for (f, v) in &fields {
            n += v.trim().to_string().len() + f.len();
        }
        println!("copying every field's text: {:?} ({} MB)", t.elapsed(), n / 1_000_000);

        let prose: Vec<&String> = fields.iter().filter(|(f, _)| matches!(f.as_str(), "description" | "solution" | "synopsis")).map(|(_, v)| v).collect();
        let t = std::time::Instant::now();
        let mut n = 0usize;
        for v in &prose {
            n += normalize_prose(v.trim().to_string()).len();
        }
        println!("reformatting descriptions, solutions, synopses: {:?} ({} fields, {} MB)", t.elapsed(), prose.len(), n / 1_000_000);
        let distinct: std::collections::HashSet<&String> = prose.iter().copied().collect();
        println!("  of which distinct: {}", distinct.len());

        let outputs: Vec<&String> = fields.iter().filter(|(f, _)| f == "plugin_output").map(|(_, v)| v).collect();
        let t = std::time::Instant::now();
        let mut n = 0usize;
        for v in &outputs {
            n += normalize_text(v.trim()).len();
        }
        println!("reformatting plugin output: {:?} ({} fields, {} MB)", t.elapsed(), outputs.len(), n / 1_000_000);

        let ignored: usize = fields.iter().filter(|(f, _)| !KNOWN.contains(&f.as_str()) && !f.starts_with("cm:compliance")).map(|(_, v)| v.len()).sum();
        println!("text in fields the app ignores: {} MB", ignored / 1_000_000);

        let t = std::time::Instant::now();
        let f = parse_nessus_file(&path).unwrap();
        println!("full parse: {:?} ({} hosts)", t.elapsed(), f.hosts.len());
    }

    const KNOWN: [&str; 33] = ["risk_factor", "description", "solution", "synopsis", "plugin_output", "cvss_base_score", "cvss3_base_score", "cvss3_temporal_score", "cvss4_base_score",
        "vpr_score", "epss_score", "cve", "cwe", "see_also", "exploit_available", "exploit_framework_metasploit", "metasploit_name", "exploitability_ease", "exploit_code_maturity",
        "exploit_framework_core", "exploit_framework_canvas", "exploit_framework_d2_elliot", "exploit_framework_exploithub", "exploited_by_malware", "exploited_by_nessus",
        "unsupported_by_vendor", "compliance", "cisa-known-exploited", "patch_publication_date", "vuln_publication_date", "script_version", "", ""];
}
