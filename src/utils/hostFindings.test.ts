import { describe, expect, it } from "vitest";
import type { FindingRow } from "../types/nessus";
import { groupByPort, sortFindings } from "./hostFindings";

function item(plugin_name: string, severity: number, port: number, protocol = "tcp", svc_name = ""): FindingRow {
  return {
    plugin_id: plugin_name.length, plugin_name, plugin_family: "", severity, port, protocol, svc_name,
    cvss_base_score: null, cvss3_base_score: null, cvss4_base_score: null, exploit_available: false,
  };
}// item

describe("sortFindings", () => {
  it("puts the worst first, then by name", () => {
    const sorted = sortFindings([item("b", 2, 80), item("a", 2, 80), item("c", 4, 22)]);
    expect(sorted.map((i) => i.plugin_name)).toEqual(["c", "a", "b"]);
  });
});

describe("groupByPort", () => {
  const items = [
    item("Weak SSH", 1, 22, "tcp", "ssh"),
    item("Tomcat creds", 4, 8080, "tcp", "www"),
    item("OS end of life", 4, 0, "tcp", "general"),
    item("Tomcat old", 3, 8080, "tcp", "www"),
    item("SNMP", 2, 161, "udp", "snmp"),
    item("Apache old", 3, 443, "tcp", "www"),
    item("TLS 1.0", 2, 443, "tcp", "www"),
  ];

  it("groups by port and protocol, worst ports first, host-level findings last", () => {
    expect(groupByPort(items).map((g) => g.key)).toEqual(["8080/tcp", "443/tcp", "161/udp", "22/tcp", "0/tcp"]);
  });

  it("counts severities and keeps findings worst first", () => {
    const g = groupByPort(items)[0];
    expect(g.counts).toEqual([0, 0, 0, 1, 1]);
    expect(g.worst).toBe(4);
    expect(g.service).toBe("www");
    expect(g.items.map((i) => i.plugin_name)).toEqual(["Tomcat creds", "Tomcat old"]);
  });

  it("does not use general as a service name", () => {
    const groups = groupByPort(items);
    expect(groups[groups.length - 1].service).toBe("");
  });

  it("orders ports with equal counts by number", () => {
    expect(groupByPort([item("x", 2, 443), item("y", 2, 80)]).map((g) => g.port)).toEqual([80, 443]);
  });
});
