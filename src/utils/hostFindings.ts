import type { FindingRow } from "../types/nessus";

export interface PortGroup {
  key: string;
  port: number;
  protocol: string;
  service: string;
  items: FindingRow[];
  counts: [number, number, number, number, number];
  worst: number;
}// PortGroup

const names = new Intl.Collator();
const bySeverityThenName = (a: FindingRow, b: FindingRow) =>
  b.severity - a.severity || names.compare(a.plugin_name, b.plugin_name);

export function sortFindings(items: FindingRow[]): FindingRow[] {
  return [...items].sort(bySeverityThenName);
}// sortFindings

// port 0 holds the host-level findings, it goes last
export function groupByPort(items: FindingRow[]): PortGroup[] {
  const groups = new Map<string, PortGroup>();
  for (const item of items) {
    const key = `${item.port}/${item.protocol}`;
    let g = groups.get(key);
    if (!g) {
      g = { key, port: item.port, protocol: item.protocol, service: "", items: [], counts: [0, 0, 0, 0, 0], worst: 0 };
      groups.set(key, g);
    }
    g.items.push(item);
    g.counts[item.severity]++;
    g.worst = Math.max(g.worst, item.severity);
    if (!g.service && item.svc_name && item.svc_name !== "general") {
      g.service = item.svc_name;
    }
  }

  const list = [...groups.values()];
  for (const g of list) {
    g.items.sort(bySeverityThenName);
  }

  return list.sort((a, b) => {
    if ((a.port === 0) !== (b.port === 0)) {
      return a.port === 0 ? 1 : -1;
    }
    for (let s = 4; s >= 0; s--) {
      if (a.counts[s] !== b.counts[s]) {
        return b.counts[s] - a.counts[s];
      }
    }

    return a.port - b.port || a.protocol.localeCompare(b.protocol);
  });
}// groupByPort
