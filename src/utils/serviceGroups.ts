import { compareHosts } from "./ip";
import type { ServiceEntry, ServiceFinding, SeverityCounts } from "../types/nessus";

export interface ServiceGroup {
  name: string;
  ports: ServiceEntry[];
  summary: ServiceEntry; // the ports added up, for sorting and the group row
}// ServiceGroup

// confirmed name wins. the ones with ? (e.g. https?) are not considered
export function primaryName(service: Pick<ServiceEntry, "svc_names">): string {
  return service.svc_names.find((n) => !n.endsWith("?")) ?? service.svc_names[0] ?? "unknown";
}// primaryName

export function groupServices(services: ServiceEntry[]): ServiceGroup[] {
  const byName = new Map<string, ServiceEntry[]>();
  for (const s of services) {
    const name = primaryName(s);
    byName.set(name, [...(byName.get(name) ?? []), s]);
  }

  return Array.from(byName, ([name, ports]) => ({ name, ports, summary: summarize(name, ports) }));
}// groupServices

function summarize(name: string, ports: ServiceEntry[]): ServiceEntry {
  const findings = new Map<number, ServiceFinding>();
  for (const p of ports) {
    for (const f of p.findings) {
      const seen = findings.get(f.plugin_id);
      if (!seen || f.severity > seen.severity) {
        findings.set(f.plugin_id, f);
      }
    }
  }
  const list = [...findings.values()];

  return {
    key: `service:${name}`,
    port: Math.min(...ports.map((p) => p.port)),
    protocol: ports[0].protocol,
    svc_names: [name],
    host_ips: [...new Set(ports.flatMap((p) => p.host_ips))].sort(compareHosts),
    severity_counts: countsOf(list),
    findings: list,
    exploit_available: ports.some((p) => p.exploit_available),
  };
}// summarize

function countsOf(findings: { severity: number }[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const keys = ["info", "low", "medium", "high", "critical"] as const;
  for (const f of findings) {
    c[keys[f.severity] ?? "info"]++;
  }
  return c;
}// countsOf
