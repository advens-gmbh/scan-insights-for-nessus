import type { ScanFile, SeverityCounts } from "../types/nessus";
import { fileStart } from "./fileFacts";

// The comparison itself runs in the backend (compare_files); these are its answers

export type MatchedBy = "mac" | "hostname" | "netbios" | "ip";

export type VulnChange = "new" | "fixed" | "unverified" | "partly" | "increased" | "changed" | "unchanged";

export interface VulnDelta {
  pluginId: number;
  name: string;
  severity: number;
  change: VulnChange;
  hostsA: number;
  hostsB: number;
  added: number;   // instances only in B
  fixed: number;   // instances gone from a rescanned host
  unverified: number;
}// VulnDelta

export type HostChange = "worsened" | "improved" | "new" | "missing" | "replaced" | "same";

export interface HostDelta {
  key: string;
  ip: string;           // where it is now, or was when only in A
  ipA: string | null;
  ipB: string | null;
  hostname: string | null;
  by: MatchedBy | null;
  conflict?: string;
  change: HostChange;
  countsA: SeverityCounts | null; // null when the host is not in that scan
  countsB: SeverityCounts | null;
  added: number;
  fixed: number;
}// HostDelta

export interface Comparison {
  vulns: VulnDelta[];
  hosts: HostDelta[];
}// Comparison

export function defaultPair(files: ScanFile[]): [string, string] | null {
  if (files.length < 2) {
    return null;
  }

  const byTime = [...files].sort((x, y) => fileStart(x) - fileStart(y));
  const newest = byTime[byTime.length - 1];
  const earlier = byTime.slice(0, -1);
  const sameScan = earlier.filter((f) => f.report_name && f.report_name === newest.report_name);
  const before = (sameScan.length > 0 ? sameScan : earlier)[(sameScan.length > 0 ? sameScan : earlier).length - 1];

  return [before.id, newest.id];
}// defaultPair
