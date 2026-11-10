import { compareHosts } from "./ip";
import type { ReportItem } from "../types/nessus";

export interface PortGroup {
  key: string;
  port: number;
  protocol: string;
  service: string;
  items: ReportItem[];
  counts: [number, number, number, number, number];
  worst: number;
}// PortGroup

const names = new Intl.Collator();
const bySeverityThenName = (a: ReportItem, b: ReportItem) =>
  b.severity - a.severity || names.compare(a.plugin_name, b.plugin_name);

export function sortFindings(items: ReportItem[]): ReportItem[] {
  return [...items].sort(bySeverityThenName);
}// sortFindings

// port 0 holds the host-level findings, it goes last
export function groupByPort(items: ReportItem[]): PortGroup[] {
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

export function openPorts(items: ReportItem[]): { tcp: number[]; udp: number[] } {
  const ports = (protocol: string) =>
    [...new Set(items.filter((i) => i.port > 0 && i.protocol === protocol).map((i) => i.port))].sort((a, b) => a - b);

  return { tcp: ports("tcp"), udp: ports("udp") };
}// openPorts

export interface HostGroup {
  key: string;
  ip: string;
  hostname: string | null;
  items: ReportItem[];
  counts: [number, number, number, number, number];
  worst: number;
}// HostGroup

export function groupByHost(
  hosts: { ip: string; hostname: string | null; netbios: string | null; items: ReportItem[] }[],
  port: number,
  protocol: string,
  include: (item: ReportItem) => boolean,
): HostGroup[] {
  const groups: HostGroup[] = [];
  for (const host of hosts) {
    const items = host.items.filter((i) => i.port === port && i.protocol === protocol && include(i)).sort(bySeverityThenName);
    if (items.length === 0) {
      continue;
    }
    const counts: HostGroup["counts"] = [0, 0, 0, 0, 0];
    for (const i of items) {
      counts[i.severity]++;
    }
    groups.push({ key: host.ip, ip: host.ip, hostname: host.hostname ?? host.netbios, items, counts, worst: items[0].severity });
  }

  return groups.sort((a, b) => {
    for (let s = 4; s >= 0; s--) {
      if (a.counts[s] !== b.counts[s]) {
        return b.counts[s] - a.counts[s];
      }
    }

    return compareHosts(a.ip, b.ip);
  });
}// groupByHost
