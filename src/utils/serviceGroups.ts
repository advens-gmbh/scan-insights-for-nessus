import { compareHosts } from "./ip";
import { severityCounts } from "../types/nessus";
import type { ServiceEntry, ServiceFinding } from "../types/nessus";

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
    severity_counts: severityCounts([{ items: list }]),
    findings: list,
    exploit_available: ports.some((p) => p.exploit_available),
  };
}// summarize
