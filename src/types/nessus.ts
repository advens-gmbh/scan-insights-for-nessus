// What the backend answers - keep in sync with src-tauri/src/views.rs, api.rs and models.rs

import { severity } from "../theme/colors";

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
  last_opened?: string | null;
}// Project

export interface AppSettings {
  theme: string;
  sidebar_collapsed: boolean;
}// AppSettings

export interface RecentFile {
  path: string;
  filename: string;
  last_opened: string;
  report_name?: string | null;
}// RecentFile

export interface ExportRequest {
  file_ids: string[];
  severities: number[];
  output_path: string;
  format: ExportFormat;
}// ExportRequest

export type ExportFormat = "xlsx" | "csv" | "nessus";

// ── Derived / denormalized types used in the UI ───────────────────────────────

export interface VulnRow {
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
  patch_publication_date: string | null;
  vuln_publication_date: string | null;
  cve: string[];
  cwe: string[];
  risk_factor: string;
  exploit_ease: string | null;
  exploit_maturity: string | null;
  exploit_frameworks: string[];
  exploited_by_malware: boolean;
  exploited_by_nessus: boolean;
  cisa_known_exploited: string | null;
  unsupported_by_vendor: boolean;
  file_ratings: { file_id: string; filename: string; severity: number }[]; // worst per file
  host_count: number;             // unique hosts
}// VulnRow

export interface ServiceFinding {
  plugin_id: number;
  plugin_name: string;
  severity: number;
  score: CvssScore | null; // from a finding with this severity
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


export interface HostRow {
  ip: string;
  hostname: string | null;
  domain: string | null;
  os: string | null;
  mac: string | null;
  netbios: string | null;
  system_type: string | null;
  credentialed_scan: boolean;
  os_unsupported: boolean;
  host_start: string | null;
  host_end: string | null;
  alt_hostnames: string[];
  file_id: string;       // primary (first) file
  filename: string;      // primary (first) filename
  file_ids: string[];    // all files this IP was seen in
  filenames: string[];   // corresponding filenames
  severity_counts: SeverityCounts;
  open_ports: string[];
  conflicts: string[];   // field names that differ across files (e.g. "MAC address")
}// HostRow

export interface ScanFile {
  id: string;
  filename: string;
  path: string;
  loaded_at: string;
  report_name: string;
  target: string | null;
  compliance_skipped: number;
  size: number;
  host_count: number;
  finding_count: number;
  counts: SeverityCounts;
  start: number | null;       // ms since 1970
  duration_ms: number | null;
  credentialed: number;       // hosts scanned with credentials
}// ScanFile

export type TopologyHost = HostRow & { items: { plugin_id: number; plugin_output: string | null }[] };

export interface FindingRow {
  plugin_id: number;
  plugin_name: string;
  plugin_family: string;
  severity: number;
  port: number;
  protocol: string;
  svc_name: string;
  cvss_base_score: number | null;
  cvss3_base_score: number | null;
  cvss4_base_score: number | null;
  exploit_available: boolean;
}// FindingRow

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

// the scan's name in Nessus, unless it is the same as the filename
export function displayScanName(file: Pick<ScanFile, "report_name" | "filename">): string | null {
  const name = file.report_name.trim();
  const filename = file.filename.replace(/\.nessus$/i, "");

  return name && name.toLowerCase() !== filename.toLowerCase() ? name : null;
}// displayScanName

export function visibleCounts(counts: SeverityCounts, showInfo: boolean): SeverityCounts {
  return showInfo ? counts : { ...counts, info: 0 };
}// visibleCounts

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

export function ratedScore(v: Pick<VulnRow, "cvss4" | "cvss3" | "cvss2" | "severity">): CvssScore | null {
  const scores: { score: number | null; version: CvssScore["version"] }[] = [
    { score: v.cvss4, version: 4 },
    { score: v.cvss3, version: 3 },
    { score: v.cvss2, version: 2 },
  ];
  const known = scores.filter((s): s is CvssScore => s.score !== null);

  return known.find((s) => cvssSeverity(s.score, s.version) === v.severity) ?? known[0] ?? null;
}// ratedScore

export function vulnScore(v: Pick<VulnRow, "cvss4" | "cvss3" | "cvss2" | "severity">): number | null {
  return ratedScore(v)?.score ?? null;
}// vulnScore

// which files gave which rating, worst first. Empty when they all agree
export function ratingDifferences(v: Pick<VulnRow, "file_ratings">): { severity: number; filenames: string[] }[] {
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

// Nessus writes one line per guess when it can't tell the operating system apart
export function osGuesses(os: string | null): string[] {
  return os ? os.split(/\n+/).map((o) => o.trim()).filter(Boolean) : [];
}// osGuesses
