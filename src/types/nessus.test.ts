import { describe, expect, it } from "vitest";
import { buildHostEntries, buildServiceEntries, buildVulnEntries, cvssSeverity, displayScanName, isHttps, isPlainHttp, ratedScore, ratingDifferences, severityCounts, totalFindings, visibleCounts, vulnScore } from "./nessus";
import type { NessusFile, ReportHost, ReportItem } from "./nessus";

function item(pluginId: number, port: number, severity = 2): ReportItem {
  return {
    plugin_id: pluginId,
    plugin_name: `plugin ${pluginId}`,
    port,
    protocol: "tcp",
    severity,
    cvss_base_score: null,
    cvss3_base_score: null,
    cvss4_base_score: null,
  } as ReportItem;
}

function host(ip: string, items: ReportItem[]): ReportHost {
  return { ip, items, alt_hostnames: [] as string[] } as ReportHost;
}

function file(id: string, ...hosts: ReportHost[]): NessusFile {
  return { id, filename: `${id}.nessus`, hosts } as NessusFile;
}

describe("displayScanName", () => {
  const name = (report_name: string, filename = "a1b2c3d4.nessus") => displayScanName({ report_name, filename });

  it("shows a name that adds something", () => {
    expect(name("Quarterly_DMZ_Scan (scheduled)")).toBe("Quarterly_DMZ_Scan (scheduled)");
    expect(name("  local2  ", "nessus_report_local2.nessus")).toBe("local2");
  });

  it("hides a name that only repeats the filename, or is empty", () => {
    expect(name("manyhosts", "manyhosts.nessus")).toBeNull();
    expect(name("ManyHosts", "manyhosts.NESSUS")).toBeNull();
    expect(name("", "scan.nessus")).toBeNull();
    expect(name("   ", "scan.nessus")).toBeNull();
  });
});

describe("visibleCounts", () => {
  const counts = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

  it("only removes Info", () => {
    expect(visibleCounts(counts, false)).toEqual({ ...counts, info: 0 });
    expect(visibleCounts(counts, true)).toBe(counts);
  });
});

describe("cvssSeverity", () => {
  it.each([
    [10, 2, 4], [9.9, 2, 3], [9.3, 2, 3], [7, 2, 3], [6.9, 2, 2], [4, 2, 2], [3.9, 2, 1], [0.1, 2, 1], [0, 2, 0],
    [10, 3, 4], [9, 3, 4], [8.9, 3, 3], [7, 3, 3], [6.9, 3, 2], [4, 3, 2], [3.9, 3, 1], [0, 3, 0],
    [9, 4, 4], [8.9, 4, 3],
  ] as const)("score %d on CVSS v%d is severity %d", (score, version, severity) => {
    expect(cvssSeverity(score, version)).toBe(severity);
  });
});

describe("buildHostEntries ratings across files", () => {
  const rated = (severity: number) => ({ ...item(1, 80, severity), plugin_output: `severity ${severity}` });

  it.each([[[1, 4]], [[4, 1]], [[1, 4, 2]]])("keeps the worst rating with severities %j", (severities) => {
    const [h] = buildHostEntries(severities.map((s, i) => file(String(i), host("10.0.0.1", [rated(s)]))));
    expect(h.items).toHaveLength(1);
    expect(h.items[0].plugin_output).toBe("severity 4");
    expect(h.severity_counts).toMatchObject({ critical: 1, low: 0, medium: 0 });
  });

  it("still keeps repeats within one file", () => {
    const [h] = buildHostEntries([file("a", host("10.0.0.1", [rated(2), rated(2)]))]);
    expect(h.items).toHaveLength(2);
    expect(h.severity_counts.medium).toBe(2);
  });
});

describe("buildServiceEntries", () => {
  const onPort = (pluginId: number, port: number, extra: Partial<ReportItem> = {}): ReportItem => ({ ...item(pluginId, port), svc_name: "www", ...extra });

  it("groups by port and protocol, keeping every service name", () => {
    const [service, ...rest] = buildServiceEntries([
      file("a", host("10.0.0.2", [onPort(1, 443)]), host("10.0.0.10", [onPort(2, 443, { svc_name: "https?" })])),
    ]);
    expect(rest).toHaveLength(0);
    expect(service.key).toBe("443/tcp");
    expect(service.svc_names).toEqual(["https?", "www"]);
    expect(service.host_ips).toEqual(["10.0.0.2", "10.0.0.10"]);
  });

  it("keeps TCP and UDP on the same port apart", () => {
    const services = buildServiceEntries([
      file("a", host("10.0.0.1", [onPort(1, 53), onPort(2, 53, { protocol: "udp" })])),
    ]);
    expect(services.map((s) => s.key)).toEqual(["53/tcp", "53/udp"]);
    expect(services.map((s) => s.findings.length)).toEqual([1, 1]);
  });

  it("leaves out port 0, which is not a service", () => {
    expect(buildServiceEntries([file("a", host("10.0.0.1", [onPort(1, 0)]))])).toEqual([]);
  });

  it("counts a finding once across hosts and files, at its worst severity", () => {
    const [service] = buildServiceEntries([
      file("a", host("10.0.0.1", [onPort(1, 80, { severity: 1 })]), host("10.0.0.2", [onPort(1, 80, { severity: 1 })])),
      file("b", host("10.0.0.1", [onPort(1, 80, { severity: 3 })])),
    ]);
    expect(service.findings).toEqual([{ plugin_id: 1, plugin_name: "plugin 1", severity: 3, host_count: 2 }]);
    expect(service.severity_counts).toMatchObject({ high: 1, low: 0 });
  });

  it("flags a service when any of its findings has an exploit", () => {
    const [service] = buildServiceEntries([
      file("a", host("10.0.0.1", [onPort(1, 80, { exploit_available: true }), onPort(2, 80)])),
    ]);
    expect(service.exploit_available).toBe(true);
  });
});

describe("buildVulnEntries", () => {
  it("takes the scores from the same finding as the worst severity", () => {
    const rated = (severity: number, cvss2: number, cvss3: number | null): ReportItem =>
      ({ ...item(1, 80, severity), cvss_base_score: cvss2, cvss3_base_score: cvss3 });
    const entry = (...items: ReportItem[]) =>
      buildVulnEntries(items.map((it, i) => file(String(i), host("10.0.0.1", [it]))))[0];

    expect(entry(rated(1, 2.6, null), rated(4, 10, 9.8))).toMatchObject({ severity: 4, cvss2: 10, cvss3: 9.8 });
    expect(entry(rated(4, 10, 9.8), rated(1, 2.6, null))).toMatchObject({ severity: 4, cvss2: 10, cvss3: 9.8 });
  });

  it("reports an exploit if any file does", () => {
    const [entry] = buildVulnEntries([
      file("a", host("10.0.0.1", [{ ...item(1, 80), exploit_available: false, metasploit_available: false }])),
      file("b", host("10.0.0.1", [{ ...item(1, 80), exploit_available: true, metasploit_available: true }])),
    ]);
    expect([entry.exploit_available, entry.metasploit_available]).toEqual([true, true]);
  });

  it("says which file rated a finding how", () => {
    const onFile = (id: string, ...severities: number[]) =>
      file(id, host("10.0.0.1", severities.map((s) => item(1, 80, s))));
    const differences = (...files: NessusFile[]) => ratingDifferences(buildVulnEntries(files)[0]);

    expect(differences(onFile("a", 1), onFile("b", 4), onFile("c", 1))).toEqual([
      { severity: 4, filenames: ["b.nessus"] },
      { severity: 1, filenames: ["a.nessus", "c.nessus"] },
    ]);
    expect(differences(onFile("a", 2), onFile("b", 2))).toEqual([]);
    expect(differences(onFile("a", 2))).toEqual([]);
    // two ratings inside one file count as that file's worst
    expect(differences(onFile("a", 1, 3), onFile("b", 3))).toEqual([]);
  });

  it("fills in details missing from the first file", () => {
    const [entry] = buildVulnEntries([
      file("a", host("10.0.0.1", [{ ...item(1, 80), synopsis: null, metasploit_name: null, patch_publication_date: null }])),
      file("b", host("10.0.0.1", [{ ...item(1, 80), synopsis: "s", metasploit_name: "m", patch_publication_date: "2012/01/31" }])),
    ]);
    expect([entry.synopsis, entry.metasploit_name, entry.patch_publication_date]).toEqual(["s", "m", "2012/01/31"]);
  });

  it("counts unique hosts, not ports or repeat scans", () => {
    const [entry] = buildVulnEntries([
      file("a", host("10.0.0.1", [item(1, 80), item(1, 443)]), host("10.0.0.2", [item(1, 80)])),
      file("b", host("10.0.0.1", [item(1, 80)])),
    ]);
    expect(entry.affected_hosts).toHaveLength(4);
    expect(entry.host_count).toBe(2);
  });

  it("shows the worst severity when files disagree", () => {
    const [entry] = buildVulnEntries([
      file("a", host("10.0.0.1", [item(1, 80, 1)])),
      file("b", host("10.0.0.1", [item(1, 80, 3)])),
      file("c", host("10.0.0.1", [item(1, 80, 2)])),
    ]);
    expect(entry.severity).toBe(3);
  });

  it("names the CVSS version of the score it shows", () => {
    const rated = (severity: number, v2: number | null, v3: number | null, v4: number | null) =>
      ratedScore({ severity, cvss2: v2, cvss3: v3, cvss4: v4 } as Parameters<typeof ratedScore>[0]);
    expect(rated(3, 9.3, null, null)).toEqual({ score: 9.3, version: 2 });
    expect(rated(2, 5, 7.5, null)).toEqual({ score: 5, version: 2 });
    expect(rated(3, 7.5, 8.1, null)).toEqual({ score: 8.1, version: 3 });
    expect(rated(4, 10, 9.8, 9.3)).toEqual({ score: 9.3, version: 4 });
    expect(rated(4, null, 8.1, null)).toEqual({ score: 8.1, version: 3 });
    expect(rated(2, null, null, null)).toBeNull();
  });

  it("shows the score behind the finding's severity", () => {
    const score = (severity: number, v2: number | null, v3: number | null) =>
      vulnScore({ severity, cvss2: v2, cvss3: v3, cvss4: null } as Parameters<typeof vulnScore>[0]);
    expect(score(3, 9.3, null)).toBe(9.3);  // v2 only: High up to 9.9
    expect(score(2, 5, 7.5)).toBe(5);       // rated by v2, the newer v3 score would contradict it
    expect(score(3, 7.5, 10)).toBe(7.5);
    expect(score(4, 10, 9.8)).toBe(9.8);    // both agree, so the newest wins
    expect(score(4, null, 8.1)).toBe(8.1);  // no score fits, so show what the file has
  });

  it("prefers the newest CVSS version", () => {
    const entry = (v2: number | null, v3: number | null, v4: number | null) =>
      vulnScore({ cvss2: v2, cvss3: v3, cvss4: v4 } as Parameters<typeof vulnScore>[0]);
    expect(entry(5, 6, 7)).toBe(7);
    expect(entry(5, 6, null)).toBe(6);
    expect(entry(5, null, null)).toBe(5);
    expect(entry(null, null, null)).toBeNull();
  });
});

describe("web address kind", () => {
  it.each([
    [80, "www", true, false],
    [8080, "www", true, false],
    [443, "www", false, true],
    [8443, "www", false, true],
    [443, "https?", false, true],
    [5000, "ssl", false, true],
    [22, "ssh", false, false],
  ])("port %i, service %s", (port, svc, http, https) => {
    expect(isPlainHttp(port, svc)).toBe(http);
    expect(isHttps(port, svc)).toBe(https);
  });
});

describe("merged totals", () => {
  it("counts a finding seen in two files once", () => {
    const files = [
      file("a", host("10.0.0.1", [item(1, 80, 4), item(2, 80, 2)])),
      file("b", host("10.0.0.1", [item(1, 80, 4)]), host("10.0.0.2", [item(1, 80, 4)])),
    ];
    const hosts = buildHostEntries(files);
    expect(hosts).toHaveLength(2);
    expect(totalFindings(hosts)).toBe(3);
    expect(severityCounts(hosts)).toMatchObject({ critical: 2, medium: 1 });
  });

  it("keeps repeats within one file but merges them across files", () => {
    const repeated = [item(1, 80), item(1, 80)];
    const one = buildHostEntries([file("a", host("10.0.0.1", repeated))]);
    expect(totalFindings(one)).toBe(2);

    const two = buildHostEntries([
      file("a", host("10.0.0.1", repeated)),
      file("b", host("10.0.0.1", repeated)),
    ]);
    expect(totalFindings(two)).toBe(2);
  });

  it("gives each affected host row its own id", () => {
    const [entry] = buildVulnEntries([file("a", host("10.0.0.1", [item(1, 80), item(1, 80)]))]);
    expect(new Set(entry.affected_hosts.map((h) => h.id)).size).toBe(2);
  });

  it("sorts hosts without producing NaN for IPv6 or hostnames", () => {
    const hosts = buildHostEntries([
      file("a", host("fe80::1", []), host("10.0.0.10", []), host("10.0.0.2", []), host("db.example", [])),
    ]);
    expect(hosts.map((h) => h.ip)).toEqual(["10.0.0.2", "10.0.0.10", "db.example", "fe80::1"]);
  });
});
