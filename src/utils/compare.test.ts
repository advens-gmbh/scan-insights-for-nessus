import { describe, expect, it } from "vitest";
import type { NessusFile, ReportHost, ReportItem } from "../types/nessus";
import { compareScans, defaultPair, deltaByHost, deltaByVuln, pairHosts } from "./compare";

function item(pluginId: number, port = 80): ReportItem {
  return { plugin_id: pluginId, port, protocol: "tcp" } as ReportItem;
}

function host(ip: string, items: ReportItem[], credentialed = false): ReportHost {
  return { ip, items, credentialed_scan: credentialed } as ReportHost;
}

function file(...hosts: ReportHost[]): NessusFile {
  return { hosts } as NessusFile;
}

describe("compareScans", () => {
  it("sorts findings into new, resolved and persisted", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1), item(2)])),
      file(host("10.0.0.1", [item(2), item(3)])),
    );
    expect(d.resolvedItems.map((i) => i.pluginId)).toEqual([1]);
    expect(d.persistedItems.map((i) => i.pluginId)).toEqual([2]);
    expect(d.newItems.map((i) => i.pluginId)).toEqual([3]);
    expect(d.unverifiedItems).toEqual([]);
  });

  it("does not call a finding resolved when its host was not rescanned", () => {
    const d = compareScans(file(host("10.0.0.1", [item(1)])), file(host("10.0.0.2", [])));
    expect(d.resolvedItems).toEqual([]);
    expect(d.unverifiedItems).toMatchObject([
      { pluginId: 1, ip: "10.0.0.1", port: 80, protocol: "tcp", note: "Host was not in scan B" },
    ]);
  });

  it("does not call a finding resolved when the rescan lost credentials", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1)], true)),
      file(host("10.0.0.1", [], false)),
    );
    expect(d.resolvedItems).toEqual([]);
    expect(d.unverifiedItems[0].note).toBe("Scan B was not credentialed on this host");
  });

  it("calls a finding resolved when the rescan gained credentials", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1)], false)),
      file(host("10.0.0.1", [], true)),
    );
    expect(d.resolvedItems).toHaveLength(1);
  });

  it("matches on port, so a fix on one port is not hidden by another", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1, 80), item(1, 443)])),
      file(host("10.0.0.1", [item(1, 443)])),
    );
    expect(d.resolvedItems.map((i) => i.port)).toEqual([80]);
    expect(d.persistedItems.map((i) => i.port)).toEqual([443]);
  });

  it("flags new findings that may only reflect better coverage in B", () => {
    const d = compareScans(
      file(host("10.0.0.1", [], false)),
      file(host("10.0.0.1", [item(1)], true), host("10.0.0.2", [item(2)])),
    );
    expect(d.newItems.map((i) => i.note)).toEqual([
      "Scan A was not credentialed on this host",
      "Host was not in scan A",
    ]);
  });
});

const sev = (pluginId: number, severity: number, port = 80): ReportItem => ({ plugin_id: pluginId, port, protocol: "tcp", severity } as ReportItem);
const names = new Map([1, 2, 3, 4, 5, 6].map((id) => [id, { name: `p${id}`, severity: 2 }]));

describe("deltaByVuln", () => {
  const a = file(
    host("10.0.0.1", [sev(1, 2), sev(2, 2), sev(3, 2), sev(4, 2), sev(6, 2)]),
    host("10.0.0.2", [sev(3, 2), sev(4, 2), sev(6, 2)]),
    host("10.0.0.9", [sev(5, 2)]),
  );
  const b = file(
    host("10.0.0.1", [sev(3, 2), sev(4, 2), sev(6, 2), sev(7, 2)]),
    host("10.0.0.3", [sev(4, 2), sev(6, 2)]),
  );
  const rows = new Map(deltaByVuln(compareScans(a, b), names).map((r) => [r.pluginId, r]));

  it("labels each vulnerability by what happened to it", () => {
    expect(rows.get(1)!.change).toBe("fixed");
    expect(rows.get(5)!.change).toBe("unverified");
    expect(rows.get(7)!.change).toBe("new");
    expect(rows.get(3)!.change).toBe("partly");
    expect(rows.get(4)!.change).toBe("changed");
  });

  it("counts hosts on each side and the instances that came and went", () => {
    expect(rows.get(4)).toMatchObject({ hostsA: 2, hostsB: 2, added: 1, fixed: 0, unverified: 1 });
    expect(rows.get(7)).toMatchObject({ name: "Plugin 7", hostsA: 0, hostsB: 1, added: 1 });
  });
});

describe("deltaByHost", () => {
  const a = file(host("10.0.0.1", [sev(1, 4), sev(2, 2)]), host("10.0.0.2", [sev(3, 3)]), host("10.0.0.4", [sev(4, 2)]), host("10.0.0.5", [sev(5, 1)]));
  const b = file(host("10.0.0.1", [sev(2, 2)]), host("10.0.0.2", [sev(3, 3), sev(6, 3)]), host("10.0.0.3", [sev(4, 2)]), host("10.0.0.5", [sev(5, 1), sev(8, 0)]));
  const delta = compareScans(a, b);
  const rows = new Map(deltaByHost(delta, () => true, false).map((r) => [r.ip, r]));

  it("says which hosts improved, worsened, appeared or were not rescanned", () => {
    expect(rows.get("10.0.0.1")!.change).toBe("improved");
    expect(rows.get("10.0.0.2")!.change).toBe("worsened");
    expect(rows.get("10.0.0.3")!.change).toBe("new");
    expect(rows.get("10.0.0.4")!.change).toBe("missing");
    expect(rows.get("10.0.0.5")!.change).toBe("same");
  });

  it("counts Info only when it is shown", () => {
    expect(deltaByHost(delta, () => true, true).find((r) => r.ip === "10.0.0.5")!.change).toBe("worsened");
  });

  it("keeps the counts of both sides", () => {
    expect(rows.get("10.0.0.1")).toMatchObject({ added: 0, fixed: 1, countsA: { critical: 1, medium: 1 }, countsB: { critical: 0, medium: 1 } });
    expect(rows.get("10.0.0.3")!.countsA).toBeNull();
  });
});

describe("defaultPair", () => {
  const scan = (id: string, report_name: string, start: string) =>
    ({ id, report_name, loaded_at: "2026-01-01T00:00:00Z", hosts: [{ host_start: start, host_end: null }] } as unknown as NessusFile);

  it("pairs the newest scan with the run of the same scan before it", () => {
    expect(defaultPair([
      scan("lan-q2", "LAN", "Thu Jul  2 21:10:00 2026"),
      scan("dmz-q3", "DMZ", "Mon Oct 12 20:00:00 2026"),
      scan("lan-q3", "LAN", "Wed Oct 14 21:05:00 2026"),
    ])).toEqual(["lan-q2", "lan-q3"]);
  });

  it("falls back to the scan just before the newest", () => {
    expect(defaultPair([scan("x", "X", "Thu Jul  2 21:10:00 2026"), scan("y", "Y", "Wed Oct 14 21:05:00 2026")])).toEqual(["x", "y"]);
    expect(defaultPair([scan("x", "X", "Thu Jul  2 21:10:00 2026")])).toBeNull();
  });
});

describe("pairHosts", () => {
  const named = (ip: string, ids: Partial<ReportHost>, items: ReportItem[] = []) => ({ ...host(ip, items), mac: null, hostname: null, netbios: null, ...ids } as ReportHost);
  const pairs = (a: ReportHost[], b: ReportHost[]) =>
    pairHosts(file(...a), file(...b)).map((p) => `${p.a?.ip ?? "-"} ${p.b?.ip ?? "-"} ${p.by ?? "-"}${p.conflict ? ` (${p.conflict})` : ""}`).sort();

  it("follows a machine to a new IP by its MAC, hostname or NetBIOS name", () => {
    expect(pairs(
      [named("10.0.0.1", { mac: "00:50:56:AA:00:01" }), named("10.0.0.2", { hostname: "web.lab" }), named("10.0.0.3", { netbios: "WS3" })],
      [named("10.0.0.9", { mac: "00-50-56-aa-00-01" }), named("10.0.0.8", { hostname: "WEB.lab" }), named("10.0.0.7", { netbios: "ws3" })],
    )).toEqual(["10.0.0.1 10.0.0.9 mac", "10.0.0.2 10.0.0.8 hostname", "10.0.0.3 10.0.0.7 netbios"]);
  });

  it("falls back to the IP when there is nothing to tell the machines apart", () => {
    expect(pairs([named("10.0.0.1", {})], [named("10.0.0.1", { hostname: "new.lab" })])).toEqual(["10.0.0.1 10.0.0.1 ip"]);
  });

  it("does not take a different machine at the same IP for the same host", () => {
    expect(pairs([named("10.0.0.1", { mac: "00:50:56:aa:00:01" })], [named("10.0.0.1", { mac: "00:50:56:aa:00:02" })]))
      .toEqual(["- 10.0.0.1 - (MAC address differs)", "10.0.0.1 - - (MAC address differs)"]);
    expect(pairs([named("10.0.0.1", { hostname: "laptop-7" })], [named("10.0.0.1", { hostname: "laptop-12" })]))
      .toEqual(["- 10.0.0.1 - (hostname differs)", "10.0.0.1 - - (hostname differs)"]);
  });

  it("trusts the MAC over a changed hostname, but not a shared name over different MACs", () => {
    expect(pairs([named("10.0.0.1", { mac: "aa:aa:aa:aa:aa:01", hostname: "old" })], [named("10.0.0.5", { mac: "aa:aa:aa:aa:aa:01", hostname: "renamed" })]))
      .toEqual(["10.0.0.1 10.0.0.5 mac"]);
    expect(pairs([named("10.0.0.1", { mac: "aa:aa:aa:aa:aa:01", hostname: "web" })], [named("10.0.0.5", { mac: "aa:aa:aa:aa:aa:02", hostname: "web" })]))
      .toEqual(["- 10.0.0.5 -", "10.0.0.1 - -"]);
  });

  it("ignores a name more than one host has", () => {
    expect(pairs(
      [named("10.0.0.1", { hostname: "lb.lab" }), named("10.0.0.2", { hostname: "lb.lab" })],
      [named("10.0.0.2", { hostname: "lb.lab" }), named("10.0.0.3", { hostname: "lb.lab" })],
    )).toEqual(["- 10.0.0.3 -", "10.0.0.1 - -", "10.0.0.2 10.0.0.2 ip"]);
  });

  it("compares findings of a machine that moved, and does not call a replaced machine's findings fixed", () => {
    const moved = compareScans(file(named("10.0.0.1", { mac: "aa:aa:aa:aa:aa:01" }, [item(1), item(2)])), file(named("10.0.0.9", { mac: "aa:aa:aa:aa:aa:01" }, [item(2)])));
    expect(moved.resolvedItems.map((i) => [i.pluginId, i.ip])).toEqual([[1, "10.0.0.1"]]);
    expect(moved.persistedItems.map((i) => [i.pluginId, i.ip])).toEqual([[2, "10.0.0.9"]]);

    const replaced = compareScans(file(named("10.0.0.1", { mac: "aa:aa:aa:aa:aa:01" }, [item(1)])), file(named("10.0.0.1", { mac: "aa:aa:aa:aa:aa:02" }, [item(3)])));
    expect(replaced.resolvedItems).toEqual([]);
    expect(replaced.unverifiedItems[0].note).toBe("A different machine has this IP in scan B (MAC address differs)");
    expect(replaced.newItems[0].note).toBe("A different machine has this IP in scan A (MAC address differs)");
    expect(deltaByHost(replaced, () => true, false).map((r) => r.change).sort()).toEqual(["new", "replaced"]);
  });
});
