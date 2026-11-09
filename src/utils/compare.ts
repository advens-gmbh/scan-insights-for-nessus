import { severityCounts } from "../types/nessus";
import type { NessusFile, ReportHost, ReportItem, SeverityCounts } from "../types/nessus";
import { scanWindow } from "./dashboard";

export interface DeltaItem {
  pluginId: number;
  host: string; // the host pair it belongs to
  ip: string;
  port: number;
  protocol: string;
  note?: string; // why this result needs a second look
}// DeltaItem

export type MatchedBy = "mac" | "hostname" | "netbios" | "ip";

export interface HostPair {
  key: string;
  a: ReportHost | null;
  b: ReportHost | null;
  by: MatchedBy | null; // null when the host is only in one scan
  conflict?: string;    // why the host at the same IP in the other scan is a different machine
}// HostPair

export interface ScanDelta {
  pairs: HostPair[];
  newItems: DeltaItem[];
  resolvedItems: DeltaItem[];
  persistedItems: DeltaItem[];
  unverifiedItems: DeltaItem[]; // in A, absent from B, but B can't confirm a fix
}// ScanDelta

type Identify = (h: ReportHost) => string[];

const IDENTIFIERS: { by: Exclude<MatchedBy, "ip">; label: string; of: Identify }[] = [
  {
    by: "mac",
    label: "MAC address",
    of: (h) => (h.mac ?? "").split(/[\s,]+/).map((m) => m.trim().toLowerCase().replace(/-/g, ":"))
      .filter((m) => m && m !== "00:00:00:00:00:00" && m !== "ff:ff:ff:ff:ff:ff"),
  },
  { by: "hostname", label: "hostname", of: (h) => (h.hostname?.trim() ? [h.hostname.trim().toLowerCase()] : []) },
  { by: "netbios",  label: "NetBIOS name", of: (h) => (h.netbios?.trim() ? [h.netbios.trim().toLowerCase()] : []) },
];

function index(hosts: ReportHost[], of: Identify): Map<string, ReportHost[]> {
  const found = new Map<string, ReportHost[]>();
  for (const h of hosts) {
    for (const id of new Set(of(h))) {
      found.set(id, [...(found.get(id) ?? []), h]);
    }
  }

  return found;
}// index

function mismatch(a: ReportHost, b: ReportHost, upTo: number): string | undefined {
  for (const { label, of } of IDENTIFIERS.slice(0, upTo)) {
    const idsA = of(a);
    const idsB = new Set(of(b));
    if (idsA.length > 0 && idsB.size > 0 && !idsA.some((id) => idsB.has(id))) {
      return `${label} differs`;
    }
  }

  return undefined;
}// mismatch

export function pairHosts(a: NessusFile, b: NessusFile): HostPair[] {
  const pairs: HostPair[] = [];
  const pairedA = new Set<ReportHost>();
  const pairedB = new Set<ReportHost>();
  const pair = (ha: ReportHost | null, hb: ReportHost | null, by: MatchedBy | null, conflict?: string) => {
    pairs.push({ key: `${ha?.ip ?? ""}|${hb?.ip ?? ""}|${pairs.length}`, a: ha, b: hb, by, ...(conflict ? { conflict } : {}) });
    if (ha) {
      pairedA.add(ha);
    }
    if (hb) {
      pairedB.add(hb);
    }
  };

  IDENTIFIERS.forEach(({ by, of }, level) => {
    const inA = index(a.hosts, of);
    const inB = index(b.hosts, of);
    for (const ha of a.hosts) {
      if (pairedA.has(ha)) {
        continue;
      }
      for (const id of of(ha)) {
        const candidates = inB.get(id);
        const hb = candidates?.length === 1 && inA.get(id)?.length === 1 ? candidates[0] : undefined;
        if (hb && !pairedB.has(hb) && !mismatch(ha, hb, level)) {
          pair(ha, hb, by);
          break;
        }
      }
    }
  });

  const byIpB = new Map(b.hosts.map((h) => [h.ip, h]));
  const conflicts = new Map<ReportHost, string>();
  for (const ha of a.hosts.filter((h) => !pairedA.has(h))) {
    const hb = byIpB.get(ha.ip);
    if (!hb || pairedB.has(hb)) {
      continue;
    }
    const conflict = mismatch(ha, hb, IDENTIFIERS.length);
    if (conflict) {
      conflicts.set(ha, conflict);
      conflicts.set(hb, conflict);
    } else {
      pair(ha, hb, "ip");
    }
  }

  for (const ha of a.hosts.filter((h) => !pairedA.has(h))) {
    pair(ha, null, null, conflicts.get(ha));
  }
  for (const hb of b.hosts.filter((h) => !pairedB.has(h))) {
    pair(null, hb, null, conflicts.get(hb));
  }

  return pairs;
}// pairHosts

function itemsOf(host: ReportHost | null): Map<string, ReportItem> {
  const found = new Map<string, ReportItem>();
  for (const item of host?.items ?? []) {
    const key = `${item.plugin_id}|${item.port}|${item.protocol}`;
    if (!found.has(key)) {
      found.set(key, item);
    }
  }

  return found;
}// itemsOf

// Why a finding seen in one scan only might reflect weaker coverage in the other, rather than a real change.
function coverageGap(pair: HostPair, seenIn: "A" | "B"): string | undefined {
  const other = seenIn === "A" ? "B" : "A";
  const here = seenIn === "A" ? pair.a : pair.b;
  const there = seenIn === "A" ? pair.b : pair.a;
  if (!there) {
    return pair.conflict
      ? `A different machine has this IP in scan ${other} (${pair.conflict})`
      : `Host was not in scan ${other}`;
  }
  if (here?.credentialed_scan && !there.credentialed_scan) {
    return `Scan ${other} was not credentialed on this host`;
  }

  return undefined;
}// coverageGap

export function compareScans(a: NessusFile, b: NessusFile): ScanDelta {
  const pairs = pairHosts(a, b);
  const delta: ScanDelta = { pairs, newItems: [], resolvedItems: [], persistedItems: [], unverifiedItems: [] };

  for (const pair of pairs) {
    const inA = itemsOf(pair.a);
    const inB = itemsOf(pair.b);
    const toDelta = (item: ReportItem, ip: string, note?: string): DeltaItem => ({
      pluginId: item.plugin_id,
      host: pair.key,
      ip,
      port: item.port,
      protocol: item.protocol,
      ...(note ? { note } : {}),
    });

    for (const [key, item] of inB) {
      if (inA.has(key)) {
        delta.persistedItems.push(toDelta(item, pair.b!.ip));
      } else {
        delta.newItems.push(toDelta(item, pair.b!.ip, coverageGap(pair, "B")));
      }
    }
    for (const [key, item] of inA) {
      if (inB.has(key)) {
        continue;
      }
      const gap = coverageGap(pair, "A");
      if (gap) {
        delta.unverifiedItems.push(toDelta(item, pair.a!.ip, gap));
      } else {
        delta.resolvedItems.push(toDelta(item, pair.a!.ip));
      }
    }
  }

  return delta;
}// compareScans

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

export function deltaByVuln(delta: ScanDelta, info: Map<number, { name: string; severity: number }>): VulnDelta[] {
  const rows = new Map<number, VulnDelta & { a: Set<string>; b: Set<string> }>();
  const row = (pluginId: number) => {
    let r = rows.get(pluginId);
    if (!r) {
      const known = info.get(pluginId);
      r = { pluginId, name: known?.name ?? `Plugin ${pluginId}`, severity: known?.severity ?? 0, change: "unchanged",
        hostsA: 0, hostsB: 0, added: 0, fixed: 0, unverified: 0, a: new Set(), b: new Set() };
      rows.set(pluginId, r);
    }

    return r;
  };

  for (const d of delta.persistedItems) {
    const r = row(d.pluginId);
    r.a.add(d.host);
    r.b.add(d.host);
  }
  for (const d of delta.newItems) {
    const r = row(d.pluginId);
    r.b.add(d.host);
    r.added++;
  }
  for (const d of delta.resolvedItems) {
    const r = row(d.pluginId);
    r.a.add(d.host);
    r.fixed++;
  }
  for (const d of delta.unverifiedItems) {
    const r = row(d.pluginId);
    r.a.add(d.host);
    r.unverified++;
  }

  return [...rows.values()].map(({ a, b, ...r }) => {
    const gone = r.fixed + r.unverified;
    const change: VulnChange =
      a.size === 0 ? "new"
      : b.size === 0 ? (r.unverified > 0 ? "unverified" : "fixed")
      : gone > 0 && r.added > 0 ? "changed"
      : gone > 0 ? "partly"
      : r.added > 0 ? "increased"
      : "unchanged";

    return { ...r, hostsA: a.size, hostsB: b.size, change };
  });
}// deltaByVuln

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

const RANKED: (keyof SeverityCounts)[] = ["critical", "high", "medium", "low", "info"];

// worse or better by the worst severity that changed
function hostChange(a: SeverityCounts, b: SeverityCounts, showInfo: boolean): HostChange {
  for (const key of RANKED) {
    if (key === "info" && !showInfo) {
      break;
    }
    if (a[key] !== b[key]) {
      return b[key] > a[key] ? "worsened" : "improved";
    }
  }

  return "same";
}// hostChange

export function deltaByHost(delta: ScanDelta, keep: (pluginId: number) => boolean, showInfo: boolean): HostDelta[] {
  const counts = (host: ReportHost) => severityCounts([{ items: host.items.filter((i) => showInfo || i.severity > 0) }]);
  const tally = (items: DeltaItem[]) => {
    const n = new Map<string, number>();
    for (const d of items) {
      if (keep(d.pluginId)) {
        n.set(d.host, (n.get(d.host) ?? 0) + 1);
      }
    }

    return n;
  };
  const added = tally(delta.newItems);
  const fixed = tally(delta.resolvedItems);

  return delta.pairs.map((pair) => {
    const countsA = pair.a ? counts(pair.a) : null;
    const countsB = pair.b ? counts(pair.b) : null;
    const change: HostChange =
      !countsA ? "new"
      : !countsB ? (pair.conflict ? "replaced" : "missing")
      : hostChange(countsA, countsB, showInfo);

    return {
      key: pair.key,
      ip: pair.b?.ip ?? pair.a!.ip,
      ipA: pair.a?.ip ?? null,
      ipB: pair.b?.ip ?? null,
      hostname: pair.b?.hostname ?? pair.a?.hostname ?? null,
      by: pair.by,
      ...(pair.conflict ? { conflict: pair.conflict } : {}),
      change,
      countsA,
      countsB,
      added: added.get(pair.key) ?? 0,
      fixed: fixed.get(pair.key) ?? 0,
    };
  });
}// deltaByHost

export function defaultPair(files: NessusFile[]): [string, string] | null {
  if (files.length < 2) {
    return null;
  }

  const started = (f: NessusFile) => scanWindow(f.hosts).start?.getTime() ?? new Date(f.loaded_at).getTime();
  const byTime = [...files].sort((x, y) => started(x) - started(y));
  const newest = byTime[byTime.length - 1];
  const earlier = byTime.slice(0, -1);
  const sameScan = earlier.filter((f) => f.report_name && f.report_name === newest.report_name);
  const before = (sameScan.length > 0 ? sameScan : earlier)[(sameScan.length > 0 ? sameScan : earlier).length - 1];

  return [before.id, newest.id];
}// defaultPair
