import { describe, expect, it } from "vitest";
import type { ServiceEntry } from "../types/nessus";
import { groupServices, primaryName } from "./serviceGroups";

function service(port: number, names: string[], ips: string[], findings: [number, number][], exploit = false): ServiceEntry {
  const list = findings.map(([plugin_id, severity]) => ({ plugin_id, plugin_name: `p${plugin_id}`, severity, score: null, host_count: 1 }));
  return {
    key: `${port}/tcp`, port, protocol: "tcp", svc_names: names, host_ips: ips,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: list, exploit_available: exploit,
  };
}// service

describe("primaryName", () => {
  it("prefers a sure name over a guess", () => {
    expect(primaryName({ svc_names: ["https?", "www"] })).toBe("www");
  });

  it("falls back to the guess, then to unknown", () => {
    expect(primaryName({ svc_names: ["https?"] })).toBe("https?");
    expect(primaryName({ svc_names: [] })).toBe("unknown");
  });
});

describe("groupServices", () => {
  const groups = groupServices([
    service(80, ["www"], ["10.0.0.2", "10.0.0.1"], [[1, 3], [2, 2]]),
    service(443, ["https?", "www"], ["10.0.0.1", "10.0.0.3"], [[1, 3], [3, 4]], true),
    service(22, ["ssh"], ["10.0.0.1"], [[4, 1]]),
  ]);

  it("groups ports by service name", () => {
    expect(groups.map((g) => [g.name, g.ports.map((p) => p.port)])).toEqual([["www", [80, 443]], ["ssh", [22]]]);
  });

  it("adds the ports up, counting hosts and findings once", () => {
    const www = groups[0].summary;
    expect(www.host_ips).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    expect(www.severity_counts).toEqual({ critical: 1, high: 1, medium: 1, low: 0, info: 0 });
    expect(www.exploit_available).toBe(true);
    expect(www.port).toBe(80);
    expect(www.key).toBe("service:www");
  });
});
