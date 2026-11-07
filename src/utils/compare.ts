import type { NessusFile, ReportHost, ReportItem } from "../types/nessus";

export interface DeltaItem {
  pluginId: number;
  ip: string;
  port: number;
  protocol: string;
  note?: string; // why this result needs a second look
}// DeltaItem

export interface ScanDelta {
  newItems: DeltaItem[];
  resolvedItems: DeltaItem[];
  persistedItems: DeltaItem[];
  unverifiedItems: DeltaItem[]; // in A, absent from B, but B can't confirm a fix
}// ScanDelta

interface Finding {
  item: ReportItem;
  ip: string;
}// Finding

function findings(file: NessusFile): Map<string, Finding> {
  const found = new Map<string, Finding>();
  for (const host of file.hosts) {
    for (const item of host.items) {
      const key = `${item.plugin_id}|${host.ip}|${item.port}|${item.protocol}`;
      if (!found.has(key)) {
        found.set(key, { item, ip: host.ip });
      }
    }
  }

  return found;
}// findings

function hostsByIp(file: NessusFile): Map<string, ReportHost> {
  return new Map(file.hosts.map((h) => [h.ip, h]));
}// hostsByIp

// Why a finding seen only in `seenIn` might just reflect weaker coverage in `other`, rather than a real change on the host.
function coverageGap(seenIn: ReportHost | undefined, other: ReportHost | undefined, otherLabel: string): string | undefined {
  if (!other) {
    return `Host was not in scan ${otherLabel}`;
  }
  if (seenIn?.credentialed_scan && !other.credentialed_scan) {
    return `Scan ${otherLabel} was not credentialed on this host`;
  }

  return undefined;
}// coverageGap

export function compareScans(a: NessusFile, b: NessusFile): ScanDelta {
  const findingsA = findings(a);
  const findingsB = findings(b);
  const hostsA = hostsByIp(a);
  const hostsB = hostsByIp(b);

  const delta: ScanDelta = { newItems: [], resolvedItems: [], persistedItems: [], unverifiedItems: [] };
  const toDelta = ({ item, ip }: Finding, note?: string): DeltaItem => ({
    pluginId: item.plugin_id,
    ip,
    port: item.port,
    protocol: item.protocol,
    ...(note ? { note } : {}),
  });

  for (const [key, finding] of findingsB) {
    if (findingsA.has(key)) {
      delta.persistedItems.push(toDelta(finding));
    } else {
      delta.newItems.push(toDelta(finding, coverageGap(hostsB.get(finding.ip), hostsA.get(finding.ip), "A")));
    }
  }
  for (const [key, finding] of findingsA) {
    if (findingsB.has(key)) {
      continue;
    }
    
    const gap = coverageGap(hostsA.get(finding.ip), hostsB.get(finding.ip), "B");
    if (gap) {
      delta.unverifiedItems.push(toDelta(finding, gap));
    }
    else {
      delta.resolvedItems.push(toDelta(finding));
    }
  }

  return delta;
}// compareScans
