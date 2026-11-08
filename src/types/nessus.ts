// Mirror of Rust models - keep in sync with src-tauri/src/models.rs

import { compareHosts } from "../utils/ip";
import { severity } from "../theme/colors";

export interface ReportItem {
  plugin_id: number;
  plugin_name: string;
  plugin_family: string;
  severity: number; // 0=Info 1=Low 2=Med 3=High 4=Crit
  port: number;
  protocol: string;
  svc_name: string;
  risk_factor: string;
  description: string;
  solution: string;
  synopsis: string | null;
  plugin_output: string | null;
  cvss_base_score: number | null;
  cvss3_base_score: number | null;
  cvss4_base_score: number | null;
  vpr_score: number | null;
  epss_score: number | null;
  cve: string[];
  cwe: string[];
  see_also: string[];
  exploit_available: boolean;
  metasploit_available: boolean;
  metasploit_name: string | null;
  exploit_ease: string | null;
  patch_publication_date: string | null;
  vuln_publication_date: string | null;
  script_version: string | null;
}// ReportItem

export interface ReportHost {
  name: string;
  ip: string;
  hostname: string | null;
  domain: string | null;
  os: string | null;
  mac: string | null;
  netbios: string | null;
  system_type: string | null;
  credentialed_scan: boolean;
  host_start: string | null;
  host_end: string | null;
  alt_hostnames: string[];
  items: ReportItem[];
}// ReportHost

export interface NessusFile {
  id: string;
  filename: string;
  path: string;
  loaded_at: string;
  report_name: string;
  target: string | null;
  hosts: ReportHost[];
}// NessusFile

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}// SeverityCounts

export interface ProjectFilePath {
  path: string;
  filename: string;
}// ProjectFilePath

export interface Project {
  id: string;
  name: string;
  description: string | null;
  file_ids: string[];
  file_paths: ProjectFilePath[];
  created_at: string;
}// Project

export interface AppSettings {
  theme: string;
  sidebar_collapsed: boolean;
}// AppSettings

export interface RecentFile {
  path: string;
  filename: string;
  last_opened: string;
}// RecentFile

export interface ExportRequest {
  file_ids: string[];
  severities: number[];
  output_path: string;
  format: "csv" | "nessus";
}// ExportRequest

// ── Derived / denormalized types used in the UI ───────────────────────────────

export interface VulnEntry {
  plugin_id: number;
  plugin_name: string;
  plugin_family: string;
  severity: number;
  cvss2: number | null;
  cvss3: number | null;
  cvss4: number | null;
  vpr: number | null;
  epss: number | null;
  exploit_available: boolean;
  metasploit_available: boolean;
  metasploit_name: string | null;
  description: string;
  solution: string;
  synopsis: string | null;
  patch_publication_date: string | null;
  vuln_publication_date: string | null;
  cve: string[];
  cwe: string[];
  see_also: string[];
  risk_factor: string;
  exploit_ease: string | null;
  affected_hosts: AffectedHost[]; // one per host + port + file
  file_ratings: { file_id: string; filename: string; severity: number }[]; // worst per file
  host_count: number;             // unique hosts in affected_hosts
}// VulnEntry

export interface ServiceFinding {
  plugin_id: number;
  plugin_name: string;
  severity: number;
  host_count: number; // unique hosts with this finding on this port
}// ServiceFinding

export interface ServiceEntry {
  key: string; // port/protocol
  port: number;
  protocol: string;
  svc_names: string[]; // Nessus can name one port differently per host or plugin
  host_ips: string[];
  severity_counts: SeverityCounts; // counts each finding once
  findings: ServiceFinding[];
  exploit_available: boolean;
}// ServiceEntry

export interface AffectedHost {
  id: number; // unique within its VulnEntry; a plugin can repeat on one host and port
  ip: string;
  port: number;
  protocol: string;
  svc_name: string;
  plugin_output: string | null;
  file_id: string;
  filename: string;
}// AffectedHost

export interface HostEntry {
  ip: string;
  hostname: string | null;
  domain: string | null;
  os: string | null;
  mac: string | null;
  netbios: string | null;
  system_type: string | null;
  credentialed_scan: boolean;
  host_start: string | null;
  host_end: string | null;
  alt_hostnames: string[];
  file_id: string;       // primary (first) file
  filename: string;      // primary (first) filename
  file_ids: string[];    // all files this IP was seen in
  filenames: string[];   // corresponding filenames
  severity_counts: SeverityCounts;
  open_ports: string[];
  items: ReportItem[];
  conflicts: string[];   // field names that differ across files (e.g. "MAC address")
}// HostEntry

// ── Severity helpers ─────────────────────────────────────────────────────────

export const SEVERITY_LABELS: Record<number, string> = {
  4: "Critical",
  3: "High",
  2: "Medium",
  1: "Low",
  0: "Info",
};// SEVERITY_LABELS

export const SEVERITY_ORDER = [4, 3, 2, 1, 0] as const;

export const SEVERITY_COLORS: Record<number, { bg: string; text: string; border: string; hex: string }> = {
  4: { bg: "bg-critical/10 dark:bg-critical/20",  text: "text-critical-fg",  border: "border-critical/30",  hex: severity.critical.fill },
  3: { bg: "bg-high/10 dark:bg-high/20",           text: "text-high-fg",      border: "border-high/30",      hex: severity.high.fill },
  2: { bg: "bg-medium/10 dark:bg-medium/20",        text: "text-medium-fg",    border: "border-medium/30",    hex: severity.medium.fill },
  1: { bg: "bg-low/10 dark:bg-low/20",              text: "text-low-fg",       border: "border-low/30",       hex: severity.low.fill },
  0: { bg: "bg-info/10 dark:bg-info/20",            text: "text-info-fg",      border: "border-info/30",      hex: severity.info.fill },
};// SEVERITY_COLORS

export function severityCounts(hosts: { items: Pick<ReportItem, "severity">[] }[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const host of hosts) {
    for (const item of host.items) {
      if (item.severity === 4) {
        c.critical++;
      } else if (item.severity === 3) {
        c.high++;
      } else if (item.severity === 2) {
        c.medium++;
      } else if (item.severity === 1) {
        c.low++;
      } else c.info++;
    }
  }

  return c;
}// severityCounts

// the scan's name in Nessus, unless it is the same as the filename
export function displayScanName(file: Pick<NessusFile, "report_name" | "filename">): string | null {
  const name = file.report_name.trim();
  const filename = file.filename.replace(/\.nessus$/i, "");

  return name && name.toLowerCase() !== filename.toLowerCase() ? name : null;
}// displayScanName

export function visibleCounts(counts: SeverityCounts, showInfo: boolean): SeverityCounts {
  return showInfo ? counts : { ...counts, info: 0 };
}// visibleCounts

export function totalFindings(hosts: Pick<ReportHost, "items">[]): number {
  return hosts.reduce((s, h) => s + h.items.length, 0);
}// totalFindings

export function isWebPort(port: number, svc: string): boolean {
  const webPorts = [80, 443, 8080, 8443, 8000, 8888, 3000, 4443, 9090, 9443, 8008, 4000];
  const svcLow = svc.toLowerCase();

  return (
    webPorts.includes(port) ||
    svcLow.includes("www") ||
    svcLow.includes("http") ||
    svcLow === "ssl"
  );
}// isWebPort

export function isHttps(port: number, svc: string): boolean {
  const httpsPorts = [443, 8443, 4443, 9443];
  const svcLow = svc.toLowerCase();

  return (
    httpsPorts.includes(port) ||
    svcLow.includes("https") ||
    svcLow.includes("ssl/www") ||
    svcLow.includes("www-https") ||
    svcLow === "ssl"
  );
}// isHttps

export function isPlainHttp(port: number, svc: string): boolean {
  return isWebPort(port, svc) && !isHttps(port, svc);
}// isPlainHttp

// Several components need the same derived lists, and the store replaces `files` on
// every change, so results are cached per array. Callers must not mutate them.
function cachedByFiles<T>(build: (files: NessusFile[]) => T): (files: NessusFile[]) => T {
  const cache = new WeakMap<NessusFile[], T>();
  return (files) => {
    if (cache.has(files)) {
      return cache.get(files)!;
    }

    const result = build(files);
    cache.set(files, result);

    return result;
  };
}// cachedByFiles

// severity ranges differ by version: CVSS v2 only counts 10.0 as critical, so a v2 score of 9.3 is correctly rated High. VPR uses the same ranges as CVSS v3
export function cvssSeverity(score: number, version: 2 | 3 | 4): number {
  if (score >= (version === 2 ? 10 : 9)) {
    return 4;
  }

  return score >= 7 ? 3 : score >= 4 ? 2 : score > 0 ? 1 : 0;
}// cvssSeverity

export interface CvssScore {
  score: number;
  version: 2 | 3 | 4;
}// CvssScore

export function ratedScore(v: Pick<VulnEntry, "cvss4" | "cvss3" | "cvss2" | "severity">): CvssScore | null {
  const scores: { score: number | null; version: CvssScore["version"] }[] = [
    { score: v.cvss4, version: 4 },
    { score: v.cvss3, version: 3 },
    { score: v.cvss2, version: 2 },
  ];
  const known = scores.filter((s): s is CvssScore => s.score !== null);

  return known.find((s) => cvssSeverity(s.score, s.version) === v.severity) ?? known[0] ?? null;
}// ratedScore

export function vulnScore(v: VulnEntry): number | null {
  return ratedScore(v)?.score ?? null;
}// vulnScore

// which files gave which rating, worst first. Empty when they all agree
export function ratingDifferences(v: VulnEntry): { severity: number; filenames: string[] }[] {
  const bySeverity = new Map<number, string[]>();
  for (const { severity, filename } of v.file_ratings) {
    bySeverity.set(severity, [...(bySeverity.get(severity) ?? []), filename]);
  }
  if (bySeverity.size < 2) {
    return [];
  }

  return [...bySeverity]
    .map(([severity, filenames]) => ({ severity, filenames }))
    .sort((a, b) => b.severity - a.severity);
}// ratingDifferences

// A severity and its scores belong together, so they are always taken from one finding
function ratingOf(item: ReportItem) {
  return {
    severity: item.severity,
    risk_factor: item.risk_factor,
    cvss2: item.cvss_base_score,
    cvss3: item.cvss3_base_score,
    cvss4: item.cvss4_base_score,
    vpr: item.vpr_score,
    epss: item.epss_score,
  };
}// ratingOf

export const buildVulnEntries = cachedByFiles((files: NessusFile[]): VulnEntry[] => {
  const map = new Map<number, VulnEntry>();
  const hostsByPlugin = new Map<number, Set<string>>();

  for (const file of files) {
    for (const host of file.hosts) {
      for (const item of host.items) {
        let entry = map.get(item.plugin_id);
        if (!entry) {
          entry = {
            plugin_id: item.plugin_id,
            plugin_name: item.plugin_name,
            plugin_family: item.plugin_family,
            ...ratingOf(item),
            exploit_available: item.exploit_available,
            metasploit_available: item.metasploit_available,
            metasploit_name: item.metasploit_name,
            description: item.description,
            solution: item.solution,
            synopsis: item.synopsis,
            patch_publication_date: item.patch_publication_date,
            vuln_publication_date: item.vuln_publication_date,
            cve: item.cve,
            cwe: item.cwe,
            see_also: item.see_also,
            exploit_ease: item.exploit_ease,
            affected_hosts: [],
            file_ratings: [],
            host_count: 0,
          };
          map.set(item.plugin_id, entry);
          hostsByPlugin.set(item.plugin_id, new Set());
        }
        // Plugin updates can re-rate a finding between scans, so show the worst rating.
        if (item.severity > entry.severity) {
          Object.assign(entry, ratingOf(item));
        }
        const lastRating = entry.file_ratings[entry.file_ratings.length - 1];
        if (lastRating?.file_id === file.id) {
          lastRating.severity = Math.max(lastRating.severity, item.severity);
        } else {
          entry.file_ratings.push({ file_id: file.id, filename: file.filename, severity: item.severity });
        }
        entry.exploit_available ||= item.exploit_available;
        entry.metasploit_available ||= item.metasploit_available;
        // An older plugin version in another file may not have these yet.
        entry.synopsis ??= item.synopsis;
        entry.metasploit_name ??= item.metasploit_name;
        entry.patch_publication_date ??= item.patch_publication_date;
        entry.vuln_publication_date ??= item.vuln_publication_date;
        const hosts = hostsByPlugin.get(item.plugin_id)!;
        hosts.add(host.ip);
        entry.host_count = hosts.size;
        entry.affected_hosts.push({
          id: entry.affected_hosts.length,
          ip: host.ip,
          port: item.port,
          protocol: item.protocol,
          svc_name: item.svc_name,
          plugin_output: item.plugin_output,
          file_id: file.id,
          filename: file.filename,
        });
      }
    }
  }

  return Array.from(map.values()).sort((a, b) => b.severity - a.severity || a.plugin_name.localeCompare(b.plugin_name));
});// buildVulnEntries

export const buildHostEntries = cachedByFiles((files: NessusFile[]): HostEntry[] => {
  const map = new Map<string, HostEntry>();
  // per IP, where each plugin+port+protocol combo was first added to entry.items
  const seen = new Map<string, Map<string, number>>();

  for (const file of files) {
    for (const host of file.hosts) {
      const ip = host.ip;
      const existing = map.get(ip);

      if (!existing) {
        const entry: HostEntry = {
          ip,
          hostname: host.hostname,
          domain: host.domain,
          os: host.os,
          mac: host.mac,
          netbios: host.netbios,
          system_type: host.system_type,
          credentialed_scan: host.credentialed_scan,
          host_start: host.host_start,
          host_end: host.host_end,
          alt_hostnames: [...host.alt_hostnames],
          file_id: file.id,
          filename: file.filename,
          file_ids: [file.id],
          filenames: [file.filename],
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          open_ports: [],
          items: [],
          conflicts: [],
        };
        map.set(ip, entry);
        seen.set(ip, new Map());
        addItems(entry, seen.get(ip)!, host.items);
      } else {
        // Merge: fill in any properties the primary record is missing
        if (!existing.hostname) {
          existing.hostname = host.hostname;
        }
        if (!existing.domain) {
          existing.domain = host.domain;
        }
        if (!existing.os) {
          existing.os = host.os;
        }
        if (!existing.system_type) {
          existing.system_type = host.system_type;
        }
        // Check MAC conflict before filling in
        if (host.mac && existing.mac) {
          const normA = existing.mac.split(/[\n,]+/)[0].trim().toLowerCase();
          const normB = host.mac.split(/[\n,]+/)[0].trim().toLowerCase();
          if (normA !== normB && !existing.conflicts.includes("MAC address")) {
            existing.conflicts.push("MAC address");
          }
        }
        if (!existing.mac) {
          existing.mac = host.mac;
        }
        // Check NetBIOS conflict before filling in
        if (host.netbios && existing.netbios &&
            host.netbios.toLowerCase() !== existing.netbios.toLowerCase() &&
            !existing.conflicts.includes("NetBIOS name")) {
          existing.conflicts.push("NetBIOS name");
        }
        if (!existing.netbios) {
          existing.netbios  = host.netbios;
        }
        if (host.credentialed_scan) {
          existing.credentialed_scan = true;
        }
        for (const n of host.alt_hostnames) {
          if (!existing.alt_hostnames.includes(n)) existing.alt_hostnames.push(n);
        }
        if (!existing.file_ids.includes(file.id)) {
          existing.file_ids.push(file.id);
          existing.filenames.push(file.filename);
        }
        addItems(existing, seen.get(ip)!, host.items);
      }
    }
  }

  return Array.from(map.values()).sort((a, b) => compareHosts(a.ip, b.ip));
});// buildHostEntries

// One entry per port and protocol that has at least one finding. Port 0 is excluded
export const buildServiceEntries = cachedByFiles((files: NessusFile[]): ServiceEntry[] => {
  interface Plugin { name: string; severity: number; ips: Set<string> }
  interface Service { port: number; protocol: string; names: Set<string>; ips: Set<string>; plugins: Map<number, Plugin>; exploit: boolean }
  const services = new Map<string, Service>();

  for (const file of files) {
    for (const host of file.hosts) {
      for (const item of host.items) {
        if (item.port === 0) {
          continue;
        }

        const key = `${item.port}/${item.protocol}`;
        let service = services.get(key);
        if (!service) {
          service = { port: item.port, protocol: item.protocol, names: new Set(), ips: new Set(), plugins: new Map(), exploit: false };
          services.set(key, service);
        }

        if (item.svc_name) {
          service.names.add(item.svc_name);
        }
        service.ips.add(host.ip);
        service.exploit ||= item.exploit_available;

        let plugin = service.plugins.get(item.plugin_id);
        if (!plugin) {
          plugin = { name: item.plugin_name, severity: item.severity, ips: new Set() };
          service.plugins.set(item.plugin_id, plugin);
        }
        plugin.severity = Math.max(plugin.severity, item.severity);
        plugin.ips.add(host.ip);
      }
    }
  }

  return Array.from(services, ([key, s]) => {
    const findings = Array.from(s.plugins, ([plugin_id, p]) => ({
      plugin_id,
      plugin_name: p.name,
      severity: p.severity,
      host_count: p.ips.size,
    })).sort((a, b) => b.severity - a.severity || a.plugin_name.localeCompare(b.plugin_name));

    return {
      key,
      port: s.port,
      protocol: s.protocol,
      svc_names: [...s.names].sort(),
      host_ips: [...s.ips].sort(compareHosts),
      severity_counts: severityCounts([{ items: findings }]),
      findings,
      exploit_available: s.exploit,
    };
  }).sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
});// buildServiceEntries

function countSeverity(counts: SeverityCounts, severity: number, change: number): void {
  const name = (["info", "low", "medium", "high", "critical"] as const)[severity] ?? "info";
  counts[name] += change;
}// countSeverity

// a finding already added from an earlier file isn't added again, but keeps the worst rating
function addItems(entry: HostEntry, seen: Map<string, number>, items: ReportItem[]): void {
  const keyOf = (item: ReportItem) => `${item.plugin_id}:${item.port}:${item.protocol}`;
  const fresh: ReportItem[] = [];
  for (const item of items) {
    const slot = seen.get(keyOf(item));
    if (slot === undefined) {
      fresh.push(item);
    } else if (item.severity > entry.items[slot].severity) {
      countSeverity(entry.severity_counts, entry.items[slot].severity, -1);
      countSeverity(entry.severity_counts, item.severity, 1);
      entry.items[slot] = item;
    }
  }

  for (const item of fresh) {
    if (!seen.has(keyOf(item))) {
      seen.set(keyOf(item), entry.items.length);
    }
    entry.items.push(item);
    countSeverity(entry.severity_counts, item.severity, 1);

    if (item.port > 0) {
      const portStr = `${item.port}/${item.protocol}`;
      if (!entry.open_ports.includes(portStr)) {
        entry.open_ports.push(portStr);
      }
    }
  }
}// addItems
