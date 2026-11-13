import { describe, expect, it } from "vitest";
import type { TopologyHost } from "../types/nessus";

type Item = TopologyHost["items"][number];
import {
  buildBlocks, buildTopology, buildWays, CROWD_AT, findWay, FOLD_AT, maskToPrefix, netKey, netOf, parseConnections, parseDhcp, parseRoutes, parseSshInterfaces, parseTraceroute,
  parseWmiInterfaces, PLUGIN,
} from "./topology";
import type { WayCrowd, WayGraph, WayNode } from "./topology";

function item(plugin_id: number, plugin_output: string | null = null): Item {
  return { plugin_id, plugin_output };
}// item

function host(ip: string, items: Item[] = [], extra: Partial<TopologyHost> = {}): TopologyHost {
  return {
    ip, hostname: null, domain: null, os: null, mac: null, netbios: null, system_type: null, credentialed_scan: false, os_unsupported: false,
    host_start: null, host_end: null, alt_hostnames: [], file_id: "f", filename: "f.nessus", file_ids: ["f"], filenames: ["f.nessus"],
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, open_ports: [], items, conflicts: [], ...extra,
  };
}// host

const trace = (target: string, hops: string[]) =>
  `For your information, here is the traceroute from 10.0.0.5 to ${target} : \n10.0.0.5\n${hops.join("\n")}\n${target}\n\nHop Count: ${hops.length + 1}\n`;

describe("parsers", () => {
  it("masks", () => {
    expect(maskToPrefix("255.255.254.0")).toBe(23);
    expect(maskToPrefix("255.255.255.255")).toBe(32);
    expect(maskToPrefix("255.0.255.0")).toBeNull();
    expect(netKey(netOf("10.86.151.7", 23))).toBe("10.86.150.0/23");
  });

  it("traceroute in both header forms, with silent hops", () => {
    expect(parseTraceroute(trace("10.20.1.9", ["10.0.0.1", "?", "10.20.1.1"]), "10.20.1.9"))
      .toEqual({ scanner: "10.0.0.5", hops: ["10.0.0.1", "?", "10.20.1.1"] });
    const other = "For your information, here is the traceroute from the Nessus scanner (192.168.1.5) to the target :\n192.168.1.5\n192.168.1.40\n";
    expect(parseTraceroute(other, "192.168.1.40")).toEqual({ scanner: "192.168.1.5", hops: [] });
  });

  it("interfaces over SSH and WMI", () => {
    const ssh = "\nThe following IPv4 addresses are set on the remote host :\n\n - 127.0.0.1 (on interface lo0)\n - 10.86.150.96 (on interface en0)\n - 192.168.8.1 (on interface vmnet1)\n";
    expect(parseSshInterfaces(ssh)).toEqual([
      { ip: "127.0.0.1", iface: "lo0", prefix: null },
      { ip: "10.86.150.96", iface: "en0", prefix: null },
      { ip: "192.168.8.1", iface: "vmnet1", prefix: null },
    ]);
    const wmi = "\n  + Network Interface Information :\n\n  - Network Interface = Intel(R) PRO/1000 MT\n  - MAC Address = 00:0C:29:00:00:01\n  - IPAddress/IPSubnet = 10.20.0.23/255.255.254.0\n  - IPAddress/IPSubnet = fe80::1/64\n\n  - Network Interface = vmxnet3 #2\n  - IPAddress/IPSubnet = 10.60.0.23/255.255.255.0\n";
    expect(parseWmiInterfaces(wmi)).toEqual([
      { ip: "10.20.0.23", iface: "Intel(R) PRO/1000 MT", prefix: 23 },
      { ip: "10.60.0.23", iface: "vmxnet3 #2", prefix: 24 },
    ]);
  });

  it("routes, DHCP and connections", () => {
    expect(parseRoutes("\n10.86.150.0/255.255.254.0\n10.86.150.4/255.255.255.255\n127.0.0.0/255.0.0.0\n").map(netKey))
      .toEqual(["10.86.150.0/23", "10.86.150.4/32", "127.0.0.0/8"]);
    expect(netKey(parseDhcp("  IP address the DHCP server would attribute us : 10.86.150.96\n  Netmask : 255.255.254.0\n")!)).toBe("10.86.150.0/23");
    const netstat = "Proto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 192.168.1.3:5000        10.70.2.15:1433         ESTABLISHED\n";
    const blocks = "tcp4 (listen)\n  src: [host=0.0.0.0, port=22]\n  dst: [host=0.0.0.0, port=*]\n\ntcp4 (established)\n  src: [host=192.168.1.3, port=49790]\n  dst: [host=216.146.43.70, port=80]\n";
    expect(parseConnections(netstat)).toEqual([{ ip: "10.70.2.15", port: "1433" }]);
    expect(parseConnections(blocks)).toEqual([{ ip: "216.146.43.70", port: "80" }]);
  });
});

describe("buildTopology", () => {
  it("groups hosts by /24 unless a real mask is known", () => {
    const t = buildTopology([
      host("10.20.0.10", [item(PLUGIN.dhcp, "IP address the DHCP server would attribute us : 10.20.1.200\nNetmask : 255.255.254.0\n")]),
      host("10.20.1.11"),
      host("192.168.10.5"),
      host("srv.corp.example"),
    ]);
    expect(t.groups.map((g) => [g.key, g.maskFrom, g.hosts.length])).toEqual([["10.20.0.0/23", "DHCP", 2], ["192.168.10.0/24", null, 1]]);
    expect(t.other.map((h) => h.ip)).toEqual(["srv.corp.example"]);
  });

  it("finds a machine whose network cards are on two networks, and the network nobody scanned", () => {
    const ssh = " - 127.0.0.1 (on interface lo)\n - 10.20.1.5 (on interface eth0)\n - 10.60.0.5 (on interface eth1)\n";
    const t = buildTopology([host("10.20.1.5", [item(PLUGIN.ipv4Ssh, ssh), item(PLUGIN.forwarding)], { hostname: "fw-01.corp.example" }), host("10.20.1.6")]);
    expect(t.bridges).toHaveLength(1);
    const b = t.bridges[0];
    expect(b.name).toBe("fw-01.corp.example");
    expect(b.strength).toBe("confirmed");
    expect(b.nets).toEqual([{ key: "10.20.1.0/24", scanned: true }, { key: "10.60.0.0/24", scanned: false }]);
    expect(b.addresses.map((a) => [a.ip, a.iface])).toEqual([["10.20.1.5", "eth0"], ["10.60.0.5", "eth1"]]);
    expect(b.evidence).toEqual(["Network cards listed over SSH (plugin 25203)", "IP forwarding is on, so it can pass traffic between them (plugin 50686)"]);
    expect(t.unscanned).toEqual([{ key: "10.60.0.0/24", net: netOf("10.60.0.5", 24), reasons: [{ ip: "10.20.1.5", text: "fw-01.corp.example has an address here: 10.60.0.5 on eth1" }] }]);
    expect(b.linkNets).toEqual(["10.20.1.0/24"]);
  });

  it("joins two scanned addresses of one machine", () => {
    const ssh = " - 10.20.1.254 (on interface eth0)\n - 192.168.10.254 (on interface eth1)\n";
    const t = buildTopology([host("10.20.1.254", [item(PLUGIN.ipv4Ssh, ssh)]), host("192.168.10.254")]);
    expect(t.bridges).toHaveLength(1);
    expect(t.bridges[0].hosts.map((h) => h.ip)).toEqual(["10.20.1.254", "192.168.10.254"]);
    expect(t.bridges[0].addresses.every((a) => a.host !== null)).toBe(true);
    expect(t.unscanned).toEqual([]);
  });

  it("a scan of 127.0.0.1 counts the machine's first real address as its own", () => {
    const ssh = " - 127.0.0.1 (on interface lo0)\n - 192.168.1.3 (on interface en1)\n";
    const t = buildTopology([host("127.0.0.1", [item(PLUGIN.ipv4Ssh, ssh)])]);
    expect(t.bridges).toEqual([]);
    expect(t.unscanned).toEqual([]);
    const two = buildTopology([host("127.0.0.1", [item(PLUGIN.ipv4Ssh, `${ssh} - 192.168.33.1 (on interface vboxnet0)\n`)])]);
    expect(two.bridges.map((b) => b.nets.map((n) => n.key))).toEqual([["192.168.1.0/24", "192.168.33.0/24"]]);
    expect(two.unscanned.map((u) => u.key)).toEqual(["192.168.33.0/24"]);
  });

  it("IP forwarding alone is only possible", () => {
    const t = buildTopology([host("192.168.1.1", [item(PLUGIN.forwarding)])]);
    expect(t.bridges.map((b) => [b.strength, b.evidence])).toEqual([["possible", ["IP forwarding is on, so it routes traffic, but its other networks aren't in the scan (plugin 50686)"]]]);
  });

  it("an address list on one network isn't a bridge", () => {
    const ssh = " - 127.0.0.1 (on interface lo)\n - 10.20.1.5 (on interface eth0)\n";
    expect(buildTopology([host("10.20.1.5", [item(PLUGIN.ipv4Ssh, ssh)])]).bridges).toEqual([]);
  });

  it("same MAC is likely, same NetBIOS name only possible, one MAC on many hosts is ignored", () => {
    const t = buildTopology([
      host("10.1.1.1", [], { mac: "00:11:22:33:44:55" }), host("10.2.2.2", [], { mac: "00:11:22:33:44:55" }),
      host("10.3.3.3", [], { netbios: "SRV22" }), host("10.4.4.4", [], { netbios: "srv22" }),
      ...Array.from({ length: 8 }, (_, i) => host(`10.${10 + i}.0.1`, [], { mac: "aa:aa:aa:aa:aa:aa" })),
    ]);
    expect(t.bridges.map((b) => [b.hosts.map((h) => h.ip), b.strength])).toEqual([
      [["10.1.1.1", "10.2.2.2"], "likely"],
      [["10.3.3.3", "10.4.4.4"], "possible"],
    ]);
  });

  it("the same NetBIOS name inside one network isn't a bridge", () => {
    expect(buildTopology([host("10.3.3.3", [], { netbios: "PC1" }), host("10.3.3.4", [], { netbios: "PC1" })]).bridges).toEqual([]);
  });

  it("a router's own network is its most specific route, not a summary around it", () => {
    const routes = "0.0.0.0/0.0.0.0\n10.101.0.0/255.255.0.0\n10.101.1.0/255.255.255.0\n10.101.10.0/255.255.255.0\n";
    const t = buildTopology([host("10.101.1.5", [item(PLUGIN.snmpRoutes, routes)]), host("10.101.10.7"), host("10.101.20.9")]);
    expect(t.groups.map((g) => g.key).sort()).toEqual(["10.101.1.0/24", "10.101.10.0/24", "10.101.20.0/24"]);
    expect(t.groups.find((g) => g.key === "10.101.1.0/24")!.maskFrom).toBe("routing table");
  });

  it("a summary route around scanned networks isn't a never scanned network", () => {
    const routes = "10.10.0.0/255.255.0.0\n10.10.7.0/255.255.255.0\n10.99.4.0/255.255.255.0\n192.168.10.0/255.255.255.0\n";
    const t = buildTopology([host("192.168.10.1", [item(PLUGIN.snmpRoutes, routes)], { hostname: "core" }), host("10.10.7.20")]);
    expect(t.unscanned.map((u) => u.key)).toEqual(["10.99.4.0/24"]);
    expect(t.bridges[0].nets.map((n) => n.key)).toEqual(["10.10.7.0/24", "10.99.4.0/24", "192.168.10.0/24"]);
    expect(t.summaries.map(netKey)).toEqual(["10.10.0.0/16"]);
  });

  it("a routing table with several networks, and connections into networks nobody scanned", () => {
    const routes = "10.0.0.0/255.255.255.0\n192.168.10.0/255.255.255.0\n10.60.0.0/255.255.255.0\n0.0.0.0/0.0.0.0\n";
    const netstat = "tcp        0      0 192.168.10.114:5000     10.70.2.15:1433         ESTABLISHED\ntcp        0      0 192.168.10.114:5001     8.8.8.8:443             ESTABLISHED\n";
    const t = buildTopology([host("10.0.0.1", [item(PLUGIN.snmpRoutes, routes)], { hostname: "core-rtr-01" }), host("192.168.10.114", [item(PLUGIN.netstat, netstat)], { hostname: "ws-114" })]);
    expect(t.bridges.map((b) => [b.name, b.strength, b.nets.length])).toEqual([["core-rtr-01", "likely", 3]]);
    expect(t.unscanned.map((u) => [u.key, u.reasons])).toEqual([
      ["10.60.0.0/24", [{ ip: "10.0.0.1", text: "core-rtr-01 routes to it (routing table)" }]],
      ["10.70.2.0/24", [{ ip: "192.168.10.114", text: "ws-114 has a connection to 10.70.2.15:1433" }]],
    ]);
  });

  it("a scan file without any traceroute gets a scanner of its own, and 127.x is the scanner itself", () => {
    const t = buildTopology([
      host("10.20.1.9", [item(PLUGIN.traceroute, trace("10.20.1.9", ["10.0.0.1"]))]),
      host("10.50.3.1", [], { file_ids: ["lab"] }),
      host("127.0.0.1", [], { file_ids: ["local"] }),
    ]);
    expect(t.roots.map((r) => [r.id, r.scanner, r.fileIds, r.unrouted])).toEqual([
      ["scanner:10.0.0.5", "10.0.0.5", ["f"], []],
      ["file:lab", null, ["lab"], ["10.50.3.0/24"]],
      ["file:local", null, ["local"], ["127.0.0.0/24"]],
    ]);
    expect(t.groups.find((g) => g.key === "127.0.0.0/24")!.local).toBe(true);
  });

  it("builds one route tree per scanner, folding straight runs of hops", () => {
    const t = buildTopology([
      host("10.20.1.9", [item(PLUGIN.traceroute, trace("10.20.1.9", ["10.0.0.1", "172.16.0.1", "172.16.0.2", "10.20.1.1"]))]),
      host("10.20.1.10", [item(PLUGIN.traceroute, trace("10.20.1.10", ["10.0.0.1", "172.16.0.1", "172.16.0.2", "10.20.1.1"]))]),
      host("192.168.10.7", [item(PLUGIN.traceroute, trace("192.168.10.7", ["10.0.0.1"]))]),
      host("10.50.3.1"),
    ]);
    expect(t.roots).toHaveLength(1);
    const root = t.roots[0];
    expect(root.hops).toEqual(["10.0.0.5"]);
    expect(root.scanner).toBe("10.0.0.5");
    expect(root.unrouted).toEqual(["10.50.3.0/24"]);
    expect(root.children).toHaveLength(1);
    const core = root.children[0];
    expect(core.hops).toEqual(["10.0.0.1"]);
    expect(core.nets).toEqual(["192.168.10.0/24"]);
    expect(core.children.map((c) => [c.hops, c.nets])).toEqual([[["172.16.0.1", "172.16.0.2", "10.20.1.1"], ["10.20.1.0/24"]]]);
  });
});

describe("ways in", () => {
  const traced = (ip: string, hops: string[], extra: Item[] = [], more: Partial<TopologyHost> = {}) =>
    host(ip, [item(PLUGIN.traceroute, trace(ip, hops)), ...extra], more);
  const ssh = (pairs: [string, string][]) => item(PLUGIN.ipv4Ssh, pairs.map(([ip, i]) => ` - ${ip} (on interface ${i})\n`).join(""));

  const office = () => buildTopology([
    traced("10.0.0.9", []),
    traced("10.0.0.30", [], [ssh([["10.0.0.30", "eth0"], ["192.168.33.1", "vboxnet0"]])], { hostname: "dev-laptop" }),
    traced("10.0.0.1", [], [], { hostname: "core-01" }),
    traced("10.20.1.9", ["10.0.0.1", "10.20.1.1"]),
  ]);

  it("starts where the scanner is, routers lead on from the network their address is in, machines join networks", () => {
    const g = buildWays(office());
    expect(g.starts).toEqual(["net:10.0.0.0/24"]);
    const router = g.nodes.find((n) => n.kind === "machine" && n.router)!;
    expect(router).toMatchObject({ name: "core-01", ips: ["10.0.0.1", "10.20.1.1"], hops: 2 });
    const linksOf = (id: string) => g.edges.filter((e) => e.a === id || e.b === id).map((e) => [e.a === id ? e.b : e.a, e.link]);
    expect(linksOf(router.id)).toEqual([["net:10.0.0.0/24", "routed"], ["net:10.20.1.0/24", "routed"]]);
    const dev = g.nodes.find((n) => n.kind === "machine" && n.name === "dev-laptop")!;
    expect(linksOf(dev.id)).toEqual([["net:10.0.0.0/24", "confirmed"], ["net:192.168.33.0/24", "confirmed"]]);
  });

  it("finds the way: routed where the scanner got through, a takeover where only a machine reaches", () => {
    const g = buildWays(office());
    const routed = findWay(g, "net:10.20.1.0/24")!;
    expect(routed.edges.map((e) => e.link)).toEqual(["routed", "routed"]);
    const hidden = findWay(g, "net:192.168.33.0/24")!;
    expect(hidden.nodes.map((id) => (id.startsWith("net:") ? id : g.nodes.find((n) => n.id === id)!.kind === "machine" ? "machine" : id)))
      .toEqual(["net:10.0.0.0/24", "machine", "net:192.168.33.0/24"]);
    expect(findWay(g, "net:10.99.0.0/24")).toBeNull();
  });

  it("prefers the routed way over taking a machine over", () => {
    const t = buildTopology([
      traced("10.0.0.9", []),
      traced("10.20.1.9", ["10.0.0.1"]),
      traced("10.20.1.30", ["10.0.0.1"], [ssh([["10.20.1.30", "eth0"], ["10.30.1.30", "eth1"]])]),
      traced("10.30.1.30", ["10.0.0.1"]),
    ]);
    const way = findWay(buildWays(t), "net:10.30.1.0/24")!;
    expect(way.edges.map((e) => e.link)).toEqual(["routed", "routed"]);
  });

  it("a confirmed network card beats a routing table that only knows the network", () => {
    const routes = "10.0.0.0/255.255.255.0\n10.20.1.0/255.255.255.0\n10.60.0.0/255.255.255.0\n";
    const t = buildTopology([
      traced("10.0.0.1", [], [item(PLUGIN.snmpRoutes, routes)], { hostname: "core" }),
      traced("10.20.1.9", ["10.0.0.1", "10.20.1.1"]),
      traced("10.20.1.23", ["10.0.0.1", "10.20.1.1"], [ssh([["10.20.1.23", "eth0"], ["10.60.0.23", "eth1"]])], { hostname: "web-03" }),
    ]);
    const g = buildWays(t);
    const way = findWay(g, "net:10.60.0.0/24")!;
    expect(g.nodes.find((n) => n.id === way.nodes[way.nodes.length - 2])).toMatchObject({ name: "web-03" });
    expect(way.edges.map((e) => e.link).slice(-1)).toEqual(["confirmed"]);
  });

  const wmi = (pairs: [string, string][]) =>
    item(PLUGIN.wmiInterfaces, pairs.map(([ip, nic]) => `\n  - Network Interface = ${nic}\n  - IPAddress/IPSubnet = ${ip}/255.255.255.0\n`).join(""));
  const backupServers = (count: number) => Array.from({ length: count }, (_, i) =>
    traced(`10.${10 + i}.1.5`, ["10.0.0.1"], [wmi([[`10.${10 + i}.1.5`, "nic1"], [`192.168.50.${i + 10}`, "nic2 (Backup)"]])], { hostname: `srv-${i}` }));

  it("machines in different networks that all reach the same network are one group; a rare one stays on its own", () => {
    const jump = traced("10.10.1.9", ["10.0.0.1"], [ssh([["10.10.1.9", "eth0"], ["172.20.10.5", "eth1"]])], { hostname: "jump01" });
    const g = buildWays(buildTopology([traced("10.0.0.9", []), ...backupServers(CROWD_AT + 1), jump]));
    const crowds = g.nodes.filter((n): n is WayCrowd => n.kind === "crowd");
    expect(crowds).toHaveLength(1);
    const c = crowds[0];
    expect(c.machines.map((m) => m.name).sort()).toEqual(Array.from({ length: CROWD_AT + 1 }, (_, i) => `srv-${i}`));
    expect(c.reach).toEqual(["net:192.168.50.0/24"]);
    expect(c.homes).toHaveLength(CROWD_AT + 1);
    expect(c.homeOf.get(c.machines.find((m) => m.name === "srv-2")!.id)).toBe("net:10.12.1.0/24");
    // the group replaces its machines on the map, but each machine can still be found
    expect(g.nodes.some((n) => n.kind === "machine" && n.name === "srv-0")).toBe(false);
    expect(g.nodes.some((n) => n.kind === "machine" && n.name === "jump01")).toBe(true);
    expect(g.nodeOf.get(c.machines[0].id)).toBe(c.id);
    expect(g.crowdOf.get(c.machines[0].id)).toBe(c.id);
    expect(g.machines.get(c.machines[0].id)?.name).toBe(c.machines[0].name);
    expect(g.edges.some((e) => g.crowdOf.has(e.a) || g.crowdOf.has(e.b))).toBe(false);
    // the backup network is reached through the group, with a takeover
    const way = findWay(g, "net:192.168.50.0/24")!;
    expect(way.nodes).toContain(c.id);
    expect(way.edges.slice(-1)[0].link).toBe("confirmed");
  });

  it("a way through a block enters and leaves through one network: the one of the most exposed machine", () => {
    const counts = (critical: number) => ({ critical, high: 0, medium: 0, low: 0, info: 0 });
    const nets = Array.from({ length: FOLD_AT + 1 }, (_, i) => traced(`10.10.${i + 1}.5`, ["10.0.0.1"]));
    const servers = Array.from({ length: CROWD_AT + 1 }, (_, i) =>
      traced(`10.10.${i + 1}.6`, ["10.0.0.1"], [wmi([[`10.10.${i + 1}.6`, "nic1"], [`192.168.50.${i + 10}`, "nic2"]])], { hostname: `srv-${i}`, severity_counts: counts(i === 3 ? 9 : 1) }));
    const t = buildTopology([traced("10.0.0.9", []), ...nets, ...servers]);
    const block = buildWays(t).nodes.find((n) => n.kind === "block")!;
    for (const open of [new Set<string>(), new Set([block.id])]) {
      const g = buildWays(t, open);
      const way = findWay(g, "net:192.168.50.0/24")!;
      const at = way.nodes.indexOf(block.id);
      expect(g.nodes.find((n) => n.id === way.nodes[at + 1])?.kind).toBe("crowd");
      const inside = (e: { a: string; b: string }) => (g.nodeOf.get(e.a) === block.id ? e.a : e.b);
      expect(inside(way.edges[at - 1])).toBe("net:10.10.4.0/24");
      expect(inside(way.edges[at])).toBe("net:10.10.4.0/24");
    }
    // a way ending inside an open block ends at the network asked for
    const g = buildWays(t, new Set([block.id]));
    const way = findWay(g, "net:10.10.7.0/24")!;
    expect([way.edges.slice(-1)[0].a, way.edges.slice(-1)[0].b]).toContain("net:10.10.7.0/24");
  });

  it("too few alike machines stay on their own", () => {
    const g = buildWays(buildTopology([traced("10.0.0.9", []), ...backupServers(CROWD_AT - 1)]));
    expect(g.nodes.filter((n) => n.kind === "crowd")).toHaveLength(0);
    expect(g.nodes.filter((n) => n.kind === "machine" && n.name.startsWith("srv-"))).toHaveLength(CROWD_AT - 1);
  });

  it("a group never joins two of its own networks to each other", () => {
    const net = (key: string): WayNode => ({ id: `net:${key}`, kind: "net", net: { key, net: netOf(key.split("/")[0], 24), group: null, reasons: [], scanners: [] } });
    const crowd: WayCrowd = { id: "crowd:x", kind: "crowd", machines: [], homeOf: new Map(), homes: ["net:10.1.1.0/24", "net:10.2.1.0/24"], reach: ["net:192.168.50.0/24"] };
    const nodes = [net("10.1.1.0/24"), net("10.2.1.0/24"), net("192.168.50.0/24"), crowd];
    const g: WayGraph = {
      nodes, starts: ["net:10.1.1.0/24"], nets: new Map(), machines: new Map(), crowdOf: new Map(),
      nodeOf: new Map(nodes.map((n) => [n.id, n.id])),
      edges: [
        { a: "net:10.1.1.0/24", b: "crowd:x", link: "confirmed" },
        { a: "net:10.2.1.0/24", b: "crowd:x", link: "confirmed" },
        { a: "crowd:x", b: "net:192.168.50.0/24", link: "confirmed" },
      ],
    };
    expect(findWay(g, "net:192.168.50.0/24")!.nodes).toEqual(["net:10.1.1.0/24", "crowd:x", "net:192.168.50.0/24"]);
    expect(findWay(g, "net:10.2.1.0/24")).toBeNull();
  });

  it("folds a long list of networks into address blocks, and opens one on request", () => {
    const hosts = [traced("10.0.0.9", []), ...Array.from({ length: FOLD_AT }, (_, i) => traced(`10.10.${i + 1}.5`, ["10.0.0.1"])),
      traced("10.20.1.5", ["10.0.0.1"]), traced("10.20.2.5", ["10.0.0.1"])];
    const t = buildTopology(hosts);
    const g = buildWays(t);
    const block = g.nodes.find((n) => n.kind === "block")!;
    expect(block).toMatchObject({ open: false, block: { key: "10.10.0.0/16" } });
    expect(block.kind === "block" && block.block.nets).toHaveLength(FOLD_AT);
    expect(g.nodeOf.get("net:10.10.3.0/24")).toBe(block.id);
    expect(g.nodeOf.get("net:10.20.1.0/24")).toBe("net:10.20.1.0/24");
    expect(findWay(g, "net:10.10.3.0/24")!.nodes.slice(-1)[0]).toBe(block.id);
    expect(buildWays(t, new Set([block.id])).nodes.find((n) => n.id === block.id)).toMatchObject({ open: true });
  });

  it("a scan file without a scanner address starts at the file, and the scanner itself is a machine", () => {
    const t = buildTopology([
      host("10.50.3.1", [], { file_ids: ["lab"] }),
      host("127.0.0.1", [ssh([["10.50.3.20", "eth0"], ["192.168.56.1", "vboxnet0"]])], { file_ids: ["lab"], hostname: "scanner" }),
    ]);
    const g = buildWays(t);
    expect(g.starts).toEqual(["scanner:file:lab"]);
    expect(g.edges).toContainEqual({ a: "scanner:file:lab", b: "net:10.50.3.0/24", link: "unknown" });
    expect(g.nets.has("127.0.0.0/24")).toBe(false);
    expect(findWay(g, "net:192.168.56.0/24")!.edges.map((e) => e.link)).toEqual(["unknown", "confirmed", "confirmed"]);
  });

  it("a connection into a network nobody scanned makes its machine a possible way", () => {
    const netstat = "tcp        0      0 10.0.0.114:5000     10.70.2.15:1433         ESTABLISHED\n";
    const g = buildWays(buildTopology([traced("10.0.0.9", []), traced("10.0.0.114", [], [item(PLUGIN.netstat, netstat)], { hostname: "ws-114" })]));
    const way = findWay(g, "net:10.70.2.0/24")!;
    expect(way.edges.map((e) => e.link)).toEqual(["confirmed", "possible"]);
    expect(g.nodes.find((n) => n.id === way.nodes[1])).toMatchObject({ name: "ws-114", talks: [{ text: "ws-114 has a connection to 10.70.2.15:1433" }] });
  });

  it("blocks: a summary route, the /16 otherwise, too small blocks and flat /16 networks left over", () => {
    const n = (ip: string, prefix: number) => ({ key: netKey(netOf(ip, prefix)), net: netOf(ip, prefix) });
    const nets = [n("10.10.1.0", 24), n("10.10.2.0", 24), n("10.10.3.0", 24), n("10.20.1.0", 24), n("10.20.2.0", 24), n("10.20.3.0", 23),
      n("10.20.17.0", 24), n("172.16.0.0", 16)];
    const { blocks, rest } = buildBlocks(nets, [netOf("10.20.0.0", 20), netOf("10.40.0.0", 16)]);
    expect(blocks.map((b) => [b.key, b.from, b.nets.length])).toEqual([["10.10.0.0/16", null, 3], ["10.20.0.0/20", "routing table", 3]]);
    expect(rest.map((x) => x.key)).toEqual(["10.20.17.0/24", "172.16.0.0/16"]);
  });

  it("summary routes come from routing tables, without the networks themselves", () => {
    const routes = "10.20.0.0/255.255.240.0\n10.0.0.0/255.255.255.0\n10.0.0.0/255.0.0.0\n10.50.0.0/255.255.255.0\n";
    const t = buildTopology([host("10.0.0.1", [item(PLUGIN.snmpRoutes, routes)])]);
    expect(t.summaries.map(netKey)).toEqual(["10.20.0.0/20"]);
  });
});
