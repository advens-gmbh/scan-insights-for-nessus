import type { HostEntry } from "../types/nessus";
import { compareHosts, isIpv4 } from "./ip";

export const PLUGIN = {
  traceroute: 10287,
  dhcp: 10663,
  ipv4Ssh: 25203,
  wmiInterfaces: 24272,
  snmpRoutes: 34022,
  forwarding: 50686,
  netstat: 58651,
  connections: 64582,
} as const;

// ── addresses and networks ────────────────────────────────────────────────────

export interface Net {
  base: number;
  prefix: number;
}// Net

export function ipToNumber(ip: string): number {
  return ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}// ipToNumber

export function numberToIp(n: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join(".");
}// numberToIp

function blockSize(prefix: number): number {
  return 2 ** (32 - prefix);
}// blockSize

export function netOf(ip: string, prefix: number): Net {
  const size = blockSize(prefix);
  return { base: Math.floor(ipToNumber(ip) / size) * size, prefix };
}// netOf

export function netKey(net: Net): string {
  return `${numberToIp(net.base)}/${net.prefix}`;
}// netKey

export function netContains(net: Net, ip: string): boolean {
  const n = ipToNumber(ip);
  return n >= net.base && n < net.base + blockSize(net.prefix);
}// netContains

// "255.255.254.0" -> 23, null when the mask isn't a valid one
export function maskToPrefix(mask: string): number | null {
  if (!isIpv4(mask)) {
    return null;
  }
  const bits = ipToNumber(mask).toString(2).padStart(32, "0");
  const prefix = bits.indexOf("0") === -1 ? 32 : bits.indexOf("0");

  return bits.slice(prefix).includes("1") ? null : prefix;
}// maskToPrefix

function validIp(ip: string): boolean {
  return isIpv4(ip) && ip.split(".").every((o) => Number(o) <= 255);
}// validIp

// loopback, link-local, multicast and "this network" addresses say nothing about where a machine is
export function isUsableIp(ip: string): boolean {
  if (!validIp(ip)) {
    return false;
  }
  const [a, b] = ip.split(".").map(Number);

  return a !== 0 && a !== 127 && a < 224 && !(a === 169 && b === 254);
}// isUsableIp

export function isPrivateIp(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}// isPrivateIp

// ── plugin output parsers ─────────────────────────────────────────────────────

export interface Traceroute {
  scanner: string | null;
  hops: string[]; // between the scanner and the target, "?" where a hop didn't answer
}// Traceroute

export function parseTraceroute(text: string, target: string): Traceroute {
  const lines = text.split("\n").map((l) => l.trim());
  const head = lines.find((l) => l.toLowerCase().includes("traceroute")) ?? "";
  const scanner = /traceroute from (\S+) to/i.exec(head)?.[1] ?? /scanner \((\S+)\)/i.exec(head)?.[1] ?? null;

  const hops: string[] = [];
  for (const line of lines.slice(lines.indexOf(head) + 1)) {
    if (validIp(line) || line === "?") {
      hops.push(line);
    } else if (hops.length > 0) {
      break;
    }
  }
  if (hops.length > 0 && hops[0] === scanner) {
    hops.shift();
  }
  if (hops.length > 0 && hops[hops.length - 1] === target) {
    hops.pop();
  }

  return { scanner: scanner && validIp(scanner) ? scanner : null, hops };
}// parseTraceroute

export interface InterfaceAddress {
  ip: string;
  iface: string | null;
  prefix: number | null;
}// InterfaceAddress

// plugin 25203: " - 10.86.150.96 (on interface en0)"
export function parseSshInterfaces(text: string): InterfaceAddress[] {
  return [...text.matchAll(/-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\(on interface ([^)]+)\)/g)]
    .map((m) => ({ ip: m[1], iface: m[2].trim(), prefix: null }));
}// parseSshInterfaces

// plugin 24272: "- Network Interface = Intel(R) ..." followed by "- IPAddress/IPSubnet = 10.0.0.5/255.255.255.0"
export function parseWmiInterfaces(text: string): InterfaceAddress[] {
  const out: InterfaceAddress[] = [];
  let iface: string | null = null;
  for (const line of text.split("\n")) {
    const name = /Network Interface\s*=\s*(.+)$/i.exec(line);
    if (name) {
      iface = name[1].trim();
      continue;
    }
    const addr = /IPAddress\/IPSubnet\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\/\s*(\d{1,3}(?:\.\d{1,3}){3})/i.exec(line);
    if (addr) {
      out.push({ ip: addr[1], iface, prefix: maskToPrefix(addr[2]) });
    }
  }

  return out;
}// parseWmiInterfaces

// plugin 34022: one "10.86.150.0/255.255.254.0" per line
export function parseRoutes(text: string): Net[] {
  const out: Net[] = [];
  for (const m of text.matchAll(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,3}(?:\.\d{1,3}){3})\s*$/gm)) {
    const prefix = maskToPrefix(m[2]);
    if (prefix !== null && validIp(m[1])) {
      out.push(netOf(m[1], prefix));
    }
  }

  return out;
}// parseRoutes

// plugin 10663: the address the DHCP server would hand out, with its netmask
export function parseDhcp(text: string): Net | null {
  const ip = /attribute us\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})/i.exec(text)?.[1];
  const mask = /Netmask\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})/i.exec(text)?.[1];
  const prefix = mask ? maskToPrefix(mask) : null;

  return ip && validIp(ip) && prefix !== null ? netOf(ip, prefix) : null;
}// parseDhcp

export interface Connection {
  ip: string;
  port: string;
}// Connection

// plugin 64582 blocks ("tcp4 (established)" ... "dst: [host=X, port=P]") and plugin 58651 netstat lines
export function parseConnections(text: string): Connection[] {
  const out: Connection[] = [];
  for (const m of text.matchAll(/\(established\)\s*\n\s*src:[^\n]*\n\s*dst:\s*\[host=([^,\]]+),\s*port=([^\]]+)\]/gi)) {
    out.push({ ip: m[1].trim(), port: m[2].trim() });
  }
  for (const m of text.matchAll(/^(?:tcp|udp)\S*\s+\d+\s+\d+\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s/gm)) {
    out.push({ ip: m[1], port: m[2] });
  }

  return out.filter((c) => isUsableIp(c.ip));
}// parseConnections

// ── the topology ──────────────────────────────────────────────────────────────

export type Strength = "confirmed" | "likely" | "possible";
const STRENGTH_RANK: Record<Strength, number> = { confirmed: 3, likely: 2, possible: 1 };

export interface NetGroup {
  key: string;
  net: Net;
  maskFrom: string | null; // where the real mask came from; null when /24 is assumed
  local: boolean;          // 127.x: the scanner scanning itself
  hosts: HostEntry[];
}// NetGroup

export interface BridgeAddress {
  ip: string;
  iface: string | null;
  net: string;
  host: HostEntry | null; // the scanned host with this address
}// BridgeAddress

export interface Bridge {
  key: string;
  name: string;
  hosts: HostEntry[];
  addresses: BridgeAddress[];
  nets: { key: string; scanned: boolean }[];
  linkNets: string[];      // scanned networks it has an address on
  strength: Strength;
  evidence: string[];
}// Bridge

export interface Reason {
  ip: string;   // the scanned host that knows about the network
  text: string;
}// Reason

export interface UnscannedNet {
  key: string;
  net: Net;
  reasons: Reason[];
}// UnscannedNet

export interface RouteNode {
  id: string;
  hops: string[];        // one hop, or a straight run of hops folded into one node
  children: RouteNode[];
  nets: string[];        // networks this route ends in
}// RouteNode

export interface ScannerNode extends RouteNode {
  scanner: string | null; // null when no traceroute names it
  fileIds: string[];
  unrouted: string[];     // networks scanned from here without a traceroute
}// ScannerNode

export interface Topology {
  groups: NetGroup[];
  other: HostEntry[];     // hosts without an IPv4 address
  roots: ScannerNode[];   // one per scanner
  unscanned: UnscannedNet[];
  bridges: Bridge[];
  summaries: Net[];       // routes from /16 to /23 in routing tables, which can group networks into blocks
}// Topology

function outputs(host: HostEntry, pluginId: number): string[] {
  return host.items.filter((i) => i.plugin_id === pluginId && i.plugin_output).map((i) => i.plugin_output!);
}// outputs

function machineName(host: HostEntry): string {
  return host.hostname ?? host.netbios ?? host.ip;
}// machineName

export function buildTopology(hosts: HostEntry[]): Topology {
  const v4 = hosts.filter((h) => validIp(h.ip));
  const other = hosts.filter((h) => !validIp(h.ip));
  const byIp = new Map(v4.map((h) => [h.ip, h]));

  // real masks: from DHCP, from the network a routing table puts the host in, and from Windows interface lists
  const known = new Map<string, { net: Net; from: string }>();
  const addKnown = (net: Net, from: string) => {
    if (net.prefix >= 16 && net.prefix <= 30 && !known.has(netKey(net))) {
      known.set(netKey(net), { net, from });
    }
  };
  for (const h of v4) {
    for (const text of outputs(h, PLUGIN.dhcp)) {
      const net = parseDhcp(text);
      if (net) {
        addKnown(net, "DHCP");
      }
    }

    for (const text of outputs(h, PLUGIN.snmpRoutes)) {
      const own = parseRoutes(text).filter((n) => n.prefix >= 16 && n.prefix <= 30 && netContains(n, h.ip)).sort((a, b) => b.prefix - a.prefix)[0];
      if (own) {
        addKnown(own, "routing table");
      }
    }
    for (const text of outputs(h, PLUGIN.wmiInterfaces)) {
      for (const a of parseWmiInterfaces(text)) {
        if (a.prefix !== null && isUsableIp(a.ip)) {
          addKnown(netOf(a.ip, a.prefix), "network card settings");
        }
      }
    }
  }
  const summaries = new Map<string, Net>();
  for (const h of v4) {
    for (const text of outputs(h, PLUGIN.snmpRoutes)) {
      parseRoutes(text).filter((n) => n.prefix >= 16 && n.prefix <= 23).forEach((n) => summaries.set(netKey(n), n));
    }
  }
  const knownList = [...known.values()].sort((a, b) => b.net.prefix - a.net.prefix);
  const placeOf = (ip: string): { net: Net; from: string | null } =>
    knownList.find((k) => netContains(k.net, ip)) ?? { net: netOf(ip, 24), from: null };

  // hosts by network
  const groupMap = new Map<string, NetGroup>();
  for (const h of v4) {
    const { net, from } = placeOf(h.ip);
    const key = netKey(net);
    if (!groupMap.has(key)) {
      groupMap.set(key, { key, net, maskFrom: from, local: h.ip.startsWith("127."), hosts: [] });
    }
    groupMap.get(key)!.hosts.push(h);
  }
  const groups = [...groupMap.values()].sort((a, b) => a.net.base - b.net.base);
  groups.forEach((g) => g.hosts.sort((a, b) => compareHosts(a.ip, b.ip)));
  const scannedNet = (key: string) => groupMap.has(key);
  // a summary route around scanned networks, or a slice of one, isn't a network of its own
  const overlapsScanned = (net: Net) => !scannedNet(netKey(net)) &&
    groups.some((g) => netContains(net, numberToIp(g.net.base)) || netContains(g.net, numberToIp(net.base)));

  // machines: scanned hosts joined when they are the same machine on different networks
  const parent = new Map<string, string>(v4.map((h) => [h.ip, h.ip]));
  const find = (ip: string): string => {
    let root = ip;
    while (parent.get(root) !== root) {
      root = parent.get(root)!;
    }
    parent.set(ip, root);
    return root;
  };
  const union = (a: string, b: string) => parent.set(find(a), find(b));

  interface Facts { addresses: Map<string, BridgeAddress>; routeNets: Set<string>; evidence: { text: string; strength: Strength }[]; forwarding: boolean }
  const facts = new Map<string, Facts>();
  const factsOf = (ip: string) => {
    if (!facts.has(ip)) {
      facts.set(ip, { addresses: new Map(), routeNets: new Set(), evidence: [], forwarding: false });
    }
    return facts.get(ip)!;
  };
  const unscannedReasons = new Map<string, { net: Net; reasons: Reason[] }>();
  const noteUnscanned = (net: Net, ip: string, text: string) => {
    const key = netKey(net);
    if (scannedNet(key) || overlapsScanned(net)) {
      return;
    }
    if (!unscannedReasons.has(key)) {
      unscannedReasons.set(key, { net, reasons: [] });
    }
    const reasons = unscannedReasons.get(key)!.reasons;
    if (!reasons.some((r) => r.text === text)) {
      reasons.push({ ip, text });
    }
  };

  for (const h of v4) {
    const f = factsOf(h.ip);
    const name = machineName(h);
    // a scan of 127.0.0.1 is the scanner itself, its real address only shows in its address list
    const local = !isUsableIp(h.ip);
    if (!local) {
      f.addresses.set(h.ip, { ip: h.ip, iface: null, net: netKey(placeOf(h.ip).net), host: h });
    }

    // the machine's own list of addresses
    const listed: { source: string; addrs: InterfaceAddress[] }[] = [
      { source: "Network cards listed over SSH (plugin 25203)", addrs: outputs(h, PLUGIN.ipv4Ssh).flatMap(parseSshInterfaces) },
      { source: "Network cards listed over WMI (plugin 24272)", addrs: outputs(h, PLUGIN.wmiInterfaces).flatMap(parseWmiInterfaces) },
    ];
    for (const { source, addrs } of listed) {
      const usable = addrs.filter((a) => isUsableIp(a.ip));
      for (const [index, a] of usable.entries()) {
        const net = a.prefix !== null ? netOf(a.ip, a.prefix) : placeOf(a.ip).net;
        const existing = f.addresses.get(a.ip);
        f.addresses.set(a.ip, { ip: a.ip, iface: a.iface ?? existing?.iface ?? null, net: existing?.net ?? netKey(net), host: byIp.get(a.ip) ?? null });
        if (byIp.has(a.ip) && a.ip !== h.ip) {
          union(h.ip, a.ip);
        }
        if (!(local && index === 0)) {
          noteUnscanned(net, h.ip, `${name} has an address here: ${a.ip}${a.iface ? ` on ${a.iface}` : ""}`);
        }
      }
      const nets = new Set(usable.map((a) => f.addresses.get(a.ip)!.net));
      if (nets.size > 1) {
        f.evidence.push({ text: source, strength: "confirmed" });
      }
    }

    // a routing table that knows several private networks
    for (const text of outputs(h, PLUGIN.snmpRoutes)) {
      const nets = parseRoutes(text).filter((n) => n.prefix >= 8 && n.prefix <= 30 && isPrivateIp(numberToIp(n.base)) && !overlapsScanned(n));
      nets.forEach((n) => f.routeNets.add(netKey(n)));
      if (f.routeNets.size > 1) {
        f.evidence.push({ text: `Its routing table lists ${f.routeNets.size} networks (SNMP, plugin 34022)`, strength: "likely" });
        nets.forEach((n) => noteUnscanned(n, h.ip, `${name} routes to it (routing table)`));
      }
    }

    if (h.items.some((i) => i.plugin_id === PLUGIN.forwarding)) {
      f.forwarding = true;
    }

    // connections into private networks nobody scanned
    for (const pid of [PLUGIN.netstat, PLUGIN.connections]) {
      for (const c of outputs(h, pid).flatMap(parseConnections)) {
        if (isPrivateIp(c.ip)) {
          noteUnscanned(placeOf(c.ip).net, h.ip, `${name} has a connection to ${c.ip}:${c.port}`);
        }
      }
    }
  }

  // the same MAC address or NetBIOS name on different networks
  const sameValue = (valuesOf: (h: HostEntry) => string[], strength: Strength, label: string) => {
    const seen = new Map<string, HostEntry[]>();
    for (const h of v4) {
      for (const v of valuesOf(h)) {
        seen.set(v, [...(seen.get(v) ?? []), h]);
      }
    }
    for (const [value, list] of seen) {
      const nets = new Set(list.map((h) => netKey(placeOf(h.ip).net)));
      // one value on many hosts is a router answering for them, not one machine
      if (nets.size < 2 || list.length > 6) {
        continue;
      }
      list.slice(1).forEach((h) => union(list[0].ip, h.ip));
      factsOf(list[0].ip).evidence.push({ text: `${label} ${value} on ${list.map((h) => h.ip).join(" and ")}`, strength });
    }
  };
  sameValue(
    (h) => (h.mac ?? "").split(/[\n,]+/).map((m) => m.trim().toLowerCase()).filter((m) => m && m !== "00:00:00:00:00:00"),
    "likely",
    "Same MAC address"
  );
  sameValue((h) => (h.netbios ? [h.netbios.trim().toUpperCase()] : []), "possible", "Same NetBIOS name");

  const machines = new Map<string, string[]>();
  for (const h of v4) {
    const root = find(h.ip);
    machines.set(root, [...(machines.get(root) ?? []), h.ip]);
  }

  const bridges: Bridge[] = [];
  for (const [root, ips] of machines) {
    const members = ips.map((ip) => facts.get(ip)!);
    const addresses = new Map<string, BridgeAddress>();
    members.forEach((m) => m.addresses.forEach((a, ip) => addresses.set(ip, a.host || !addresses.has(ip) ? a : addresses.get(ip)!)));
    const netKeys = new Set([...addresses.values()].map((a) => a.net));
    members.forEach((m) => m.routeNets.forEach((n) => netKeys.add(n)));
    const evidence = members.flatMap((m) => m.evidence);
    const forwarding = members.some((m) => m.forwarding);
    if ((netKeys.size < 2 || evidence.length === 0) && !forwarding) {
      continue;
    }

    const texts = evidence.map((e) => e.text);
    const strength = evidence.reduce<Strength>((best, e) => (STRENGTH_RANK[e.strength] > STRENGTH_RANK[best] ? e.strength : best), "possible");
    if (forwarding) {
      texts.push(evidence.length > 0 ? "IP forwarding is on, so it can pass traffic between them (plugin 50686)" : "IP forwarding is on, so it routes traffic, but its other networks aren't in the scan (plugin 50686)");
    }

    const scannedHosts = ips.map((ip) => byIp.get(ip)!).sort((a, b) => compareHosts(a.ip, b.ip));
    bridges.push({
      key: root,
      name: machineName(scannedHosts.find((h) => h.hostname) ?? scannedHosts[0]),
      hosts: scannedHosts,
      addresses: [...addresses.values()].sort((a, b) => compareHosts(a.ip, b.ip)),
      nets: [...netKeys].sort((a, b) => compareHosts(a.split("/")[0], b.split("/")[0])).map((key) => ({ key, scanned: scannedNet(key) })),
      linkNets: [...new Set([...addresses.values()].map((a) => a.net))].filter(scannedNet),
      strength,
      evidence: [...new Set(texts)],
    });
  }
  bridges.sort((a, b) => STRENGTH_RANK[b.strength] - STRENGTH_RANK[a.strength] || compareHosts(a.hosts[0].ip, b.hosts[0].ip));

  const unscanned = [...unscannedReasons.entries()]
    .filter(([key]) => !scannedNet(key))
    .map(([key, v]) => ({ key, net: v.net, reasons: v.reasons }))
    .sort((a, b) => a.net.base - b.net.base);

  return { groups, other, roots: buildRoutes(groups), unscanned, bridges, summaries: [...summaries.values()].filter((n) => !scannedNet(netKey(n))) };
}// buildTopology

// the most common traceroute of each network, merged into one tree per scanner; a network without a traceroute hangs off the scanner its scan file used for the others, or one of its own
function buildRoutes(groups: NetGroup[]): ScannerNode[] {
  const traces = new Map<string, Traceroute>();
  const fileScanners = new Map<string, Map<string, number>>();
  for (const h of groups.flatMap((g) => g.hosts)) {
    const text = h.items.find((i) => i.plugin_id === PLUGIN.traceroute && i.plugin_output)?.plugin_output;
    if (!text) {
      continue;
    }
    const trace = parseTraceroute(text, h.ip);
    traces.set(h.ip, trace);
    if (trace.scanner) {
      for (const f of h.file_ids) {
        const counts = fileScanners.get(f) ?? new Map<string, number>();
        counts.set(trace.scanner, (counts.get(trace.scanner) ?? 0) + 1);
        fileScanners.set(f, counts);
      }
    }
  }

  const roots = new Map<string, ScannerNode>();
  const rootFor = (scanner: string | null, fileId: string) => {
    const id = scanner ? `scanner:${scanner}` : `file:${fileId}`;
    if (!roots.has(id)) {
      roots.set(id, { id, hops: [scanner ?? "?"], children: [], nets: [], scanner, fileIds: [], unrouted: [] });
    }
    const root = roots.get(id)!;
    if (!root.fileIds.includes(fileId)) {
      root.fileIds.push(fileId);
    }
    return root;
  };
  const top = <T,>(counts: Map<T, number>): T | undefined => [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];

  for (const g of groups) {
    const paths = new Map<string, { trace: Traceroute; n: number; files: string[] }>();
    for (const h of g.local ? [] : g.hosts) {
      const trace = traces.get(h.ip);
      if (!trace) {
        continue;
      }
      const id = [trace.scanner ?? "", ...trace.hops].join(">");
      const entry = paths.get(id) ?? { trace, n: 0, files: [] };
      entry.n++;
      entry.files.push(...h.file_ids);
      paths.set(id, entry);
    }
    const best = [...paths.values()].sort((a, b) => b.n - a.n)[0];
    if (!best) {
      const fileCounts = new Map<string, number>();
      g.hosts.flatMap((h) => h.file_ids).forEach((f) => fileCounts.set(f, (fileCounts.get(f) ?? 0) + 1));
      const fileId = top(fileCounts) ?? "";
      const scanners = fileScanners.get(fileId);
      rootFor((scanners && top(scanners)) ?? null, fileId).unrouted.push(g.key);
      continue;
    }

    const files = [...new Set(best.files)];
    files.forEach((f) => rootFor(best.trace.scanner, f));
    let node: RouteNode = rootFor(best.trace.scanner, files[0]);
    for (const hop of best.trace.hops) {
      const id = `${node.id}>${hop}`;
      let child = node.children.find((c) => c.id === id);
      if (!child) {
        child = { id, hops: [hop], children: [], nets: [] };
        node.children.push(child);
      }
      node = child;
    }
    node.nets.push(g.key);
  }

  const fold = (node: RouteNode) => {
    node.children.forEach(fold);
    node.children = node.children.map((c) => {
      let n = c;
      while (n.children.length === 1 && n.nets.length === 0) {
        const only = n.children[0];
        n = { ...only, hops: [...n.hops, ...only.hops] };
      }
      return n;
    });
  };
  roots.forEach(fold);

  return [...roots.values()];
}// buildRoutes

// ── ways in: networks and the machines that connect them ─────────────────────

export interface Block<T extends { key: string; net: Net }> {
  key: string;
  net: Net;
  from: "routing table" | "one network" | null; // null when /16 is assumed
  nets: T[];
}// Block

// networks by address block: a routing table's summary route when one covers them, otherwise their /16;
// blocks with only a few networks are left over
export function buildBlocks<T extends { key: string; net: Net }>(nets: T[], summaries: Net[], fewest = 3): { blocks: Block<T>[]; rest: T[] } {
  const own = new Set(nets.map((n) => n.key));
  const usable = summaries.filter((s) => !own.has(netKey(s))).sort((a, b) => b.prefix - a.prefix);
  const map = new Map<string, Block<T>>();
  for (const n of nets) {
    const summary = usable.find((s) => s.prefix < n.net.prefix && netContains(s, numberToIp(n.net.base)));
    const net = n.net.prefix === 16 ? n.net : summary ?? netOf(numberToIp(n.net.base), 16);
    const key = netKey(net);
    if (!map.has(key)) {
      map.set(key, { key, net, from: n.net.prefix === 16 ? "one network" : summary ? "routing table" : null, nets: [] });
    }
    map.get(key)!.nets.push(n);
  }
  const blocks = [...map.values()].sort((a, b) => a.net.base - b.net.base);
  const big = blocks.filter((b) => b.nets.length >= fewest && b.from !== "one network");

  return { blocks: big, rest: blocks.filter((b) => !big.includes(b)).flatMap((b) => b.nets) };
}// buildBlocks

export interface WayNet {
  key: string;
  net: Net;
  group: NetGroup | null;   // null when nobody scanned it
  reasons: Reason[];        // how a never scanned network is known
  scanners: ScannerNode[];  // scanners sitting in this network
}// WayNet

export interface WayMachine {
  id: string;
  kind: "machine";
  name: string;
  ips: string[];
  hosts: HostEntry[];       // the scanned hosts that are this machine
  router: boolean;          // seen as a hop in a traceroute
  hops: number;             // how many routers a folded run of hops stands for
  hopList: string[];        // those routers in order, "?" for one that didn't answer
  bridge: Bridge | null;
  talks: Reason[];          // connections into networks nobody scanned
}// WayMachine

// machines that each lead from their own network to the same other networks, drawn as one
export interface WayCrowd {
  id: string;
  kind: "crowd";
  machines: WayMachine[];
  homeOf: Map<string, string>; // machine id -> the network it sits in
  homes: string[];             // those networks
  reach: string[];             // the networks every one of them leads to
}// WayCrowd

export type WayNode =
  | { id: string; kind: "net"; net: WayNet }
  | { id: string; kind: "block"; block: Block<WayNet>; open: boolean }
  | WayMachine
  | WayCrowd
  | { id: string; kind: "scanner"; root: ScannerNode };

export type Link = "routed" | "unknown" | Strength;

export interface WayEdge {
  a: string; // "net:<key>", a machine id or a scanner id
  b: string;
  link: Link;
}// WayEdge

export interface WayGraph {
  nodes: WayNode[];
  edges: WayEdge[];
  starts: string[];               // where the scanners are
  nodeOf: Map<string, string>;    // edge end -> the node drawing it (a folded network draws as its block, a grouped machine as its group)
  nets: Map<string, WayNet>;
  machines: Map<string, WayMachine>; // every machine, grouped or not
  crowdOf: Map<string, string>;      // machine id -> its group
}// WayGraph

export const FOLD_AT = 8;
export const CROWD_AT = 4;

export const netEnd = (key: string) => `net:${key}`;

export function buildWays(topo: Topology, open: ReadonlySet<string> = new Set()): WayGraph {
  const groups = new Map(topo.groups.map((g) => [g.key, g]));
  const hostByIp = new Map(topo.groups.flatMap((g) => g.hosts.map((h) => [h.ip, h] as const)));
  const groupOfIp = (ip: string) => topo.groups.find((g) => !g.local && netContains(g.net, ip))?.key ?? null;
  const unscanned = new Map(topo.unscanned.map((u) => [u.key, u]));

  const nets = new Map<string, WayNet>();
  const ensureNet = (key: string, net?: Net) => {
    if (!nets.has(key)) {
      const group = groups.get(key) ?? null;
      nets.set(key, { key, net: group?.net ?? unscanned.get(key)?.net ?? net!, group, reasons: unscanned.get(key)?.reasons ?? [], scanners: [] });
    }
    return netEnd(key);
  };
  const machines = new Map<string, WayMachine>();
  const scanners: WayNode[] = [];
  const edges: WayEdge[] = [];
  const seen = new Map<string, WayEdge>();
  const link = (a: string, b: string, l: Link) => {
    const id = [a, b].sort().join("|");
    if (a !== b && !seen.has(id)) {
      const e = { a, b, link: l };
      seen.set(id, e);
      edges.push(e);
    }
  };
  const hanging = new Map<string, string[]>(); // a router or start -> the scanned networks right behind it
  const transit = new Set<string>();           // networks other routers hang off, never folded
  const starts: string[] = [];
  const machineOfIp = new Map<string, string>();

  for (const root of topo.roots) {
    const own = root.scanner ? groupOfIp(root.scanner) : null;
    let start: string;
    if (root.scanner) {
      const key = own ?? netKey(netOf(root.scanner, 24));
      start = ensureNet(key, netOf(root.scanner, 24));
      nets.get(key)!.scanners.push(root);
    } else {
      start = `scanner:${root.id}`;
      scanners.push({ id: start, kind: "scanner", root });
    }
    if (!starts.includes(start)) {
      starts.push(start);
    }
    const hang = (parent: string, key: string, l: Link) => {
      if (groups.get(key)?.local || key === own) {
        return;
      }
      link(parent, ensureNet(key), l);
      hanging.set(parent, [...(hanging.get(parent) ?? []), key]);
    };
    root.nets.forEach((k) => hang(start, k, "routed"));
    root.unrouted.forEach((k) => hang(start, k, "unknown"));

    const walk = (node: RouteNode, parent: string, parentNets: string[]) => {
      for (const child of node.children) {
        const id = `machine:${child.id}`;
        const known = child.hops.filter((h) => h !== "?");
        const scanned = known.map((ip) => hostByIp.get(ip)).filter((h): h is HostEntry => !!h);
        const named = scanned[scanned.length - 1];
        machines.set(id, {
          id, kind: "machine", name: named?.hostname ?? named?.ip ?? known[known.length - 1] ?? "router that didn't answer",
          ips: known, hosts: scanned, router: true, hops: child.hops.length, hopList: child.hops, bridge: null, talks: [],
        });
        known.forEach((ip) => machineOfIp.set(ip, id));
        const via = known[0] ? parentNets.find((k) => netContains(nets.get(k)?.net ?? groups.get(k)!.net, known[0])) : undefined;
        if (via) {
          transit.add(via);
          link(netEnd(via), id, "routed");
        } else {
          link(parent, id, "routed");
        }
        child.nets.forEach((k) => hang(id, k, "routed"));
        walk(child, id, child.nets);
      }
    };
    walk(root, start, own ? [own, ...root.nets] : root.nets);
  }

  // machines with a foot in more than one network
  for (const b of topo.bridges) {
    const ips = [...b.hosts.map((h) => h.ip), ...b.addresses.map((a) => a.ip)];
    const existing = ips.map((ip) => machineOfIp.get(ip)).find(Boolean);
    const keys = b.nets.map((n) => n.key).filter((k) => !groups.get(k)?.local);
    if (!existing && keys.length < 2) {
      continue;
    }
    const id = existing ?? `machine:${b.key}`;
    if (existing) {
      const m = machines.get(existing)!;
      m.bridge = b;
      m.hosts = [...new Set([...m.hosts, ...b.hosts])];
    } else {
      machines.set(id, { id, kind: "machine", name: b.name, ips: b.hosts.map((h) => h.ip), hosts: b.hosts, router: false, hops: 1, hopList: [], bridge: b, talks: [] });
    }
    b.hosts.forEach((h) => machineOfIp.set(h.ip, id));
    keys.forEach((k) => link(id, ensureNet(k, netOf(k.split("/")[0], Number(k.split("/")[1]))), b.strength));
  }

  // networks nobody scanned that only a connection points at
  for (const u of topo.unscanned) {
    for (const r of u.reasons) {
      let id = machineOfIp.get(r.ip);
      if (!id) {
        const host = hostByIp.get(r.ip);
        const home = groupOfIp(r.ip);
        if (!host || !home) {
          continue;
        }
        id = `machine:${r.ip}`;
        machines.set(id, { id, kind: "machine", name: host.hostname ?? r.ip, ips: [r.ip], hosts: [host], router: false, hops: 1, hopList: [], bridge: null, talks: [] });
        machineOfIp.set(r.ip, id);
        link(ensureNet(home), id, "confirmed");
      }
      const m = machines.get(id)!;
      if (!m.bridge?.nets.some((n) => n.key === u.key)) {
        m.talks.push(r);
      }
      link(id, ensureNet(u.key), m.router && /routing table/.test(r.text) ? "likely" : "possible");
    }
  }

  // machines that each lead from their own network to exactly the same other networks become one group
  // a jump host or a DMZ server with one foot inside, stay on their own
  const alike = new Map<string, { machines: WayMachine[]; homeOf: Map<string, string>; homeLink: Map<string, Link>; reach: { end: string; link: Link }[] }>();
  const linksAt = new Map<string, { end: string; link: Link }[]>();
  for (const e of edges) {
    linksAt.set(e.a, [...(linksAt.get(e.a) ?? []), { end: e.b, link: e.link }]);
    linksAt.set(e.b, [...(linksAt.get(e.b) ?? []), { end: e.a, link: e.link }]);
  }
  for (const m of machines.values()) {
    const homes = new Set(m.hosts.map((h) => groupOfIp(h.ip)).filter((k): k is string => !!k).map(netEnd));
    const links = linksAt.get(m.id) ?? [];
    const reach = links.filter((l) => !homes.has(l.end));
    if (m.router || homes.size !== 1 || reach.length === 0 || links.some((l) => !l.end.startsWith("net:"))) {
      continue;
    }
    const key = reach.map((l) => `${l.end}=${l.link}`).sort().join(",");
    const entry = alike.get(key) ?? { machines: [] as WayMachine[], homeOf: new Map<string, string>(), homeLink: new Map<string, Link>(), reach };
    entry.machines.push(m);
    entry.homeOf.set(m.id, [...homes][0]);
    links.filter((l) => homes.has(l.end)).forEach((l) => entry.homeLink.set(l.end, l.link));
    alike.set(key, entry);
  }
  const crowds: WayCrowd[] = [];
  const crowdOf = new Map<string, string>();
  for (const [key, a] of alike) {
    if (a.machines.length >= CROWD_AT) {
      const id = `crowd:${key}`;
      a.machines.forEach((m) => crowdOf.set(m.id, id));
      crowds.push({ id, kind: "crowd", machines: a.machines, homeOf: a.homeOf, homes: [...a.homeLink.keys()], reach: a.reach.map((r) => r.end) });
    }
  }
  if (crowds.length) {
    const kept = edges.filter((e) => !crowdOf.has(e.a) && !crowdOf.has(e.b));
    edges.length = 0;
    kept.forEach((e) => edges.push(e));
    for (const c of crowds) {
      const a = alike.get(c.id.slice("crowd:".length))!;
      a.homeLink.forEach((l, end) => link(end, c.id, l));
      a.reach.forEach((r) => link(c.id, r.end, r.link));
    }
  }

  // fold long lists of networks into address blocks
  const nodeOf = new Map<string, string>();
  const blocks: WayNode[] = [];
  for (const [parent, keys] of hanging) {
    const loose = keys.filter((k) => !transit.has(k) && !starts.includes(netEnd(k)));
    if (loose.length <= FOLD_AT) {
      continue;
    }
    const { blocks: found } = buildBlocks(loose.map((k) => nets.get(k)!), topo.summaries);
    for (const block of found) {
      const id = `block:${parent}|${block.key}`;
      blocks.push({ id, kind: "block", block, open: open.has(id) });
      block.nets.forEach((n) => nodeOf.set(netEnd(n.key), id));
    }
  }
  const netNodes: WayNode[] = [...nets.values()].filter((n) => !nodeOf.has(netEnd(n.key))).map((n) => ({ id: netEnd(n.key), kind: "net", net: n }));
  const nodes = [...scanners, ...netNodes, ...blocks, ...[...machines.values()].filter((m) => !crowdOf.has(m.id)), ...crowds];
  crowdOf.forEach((crowd, id) => nodeOf.set(id, crowd));
  nodes.forEach((n) => !nodeOf.has(n.id) && nodeOf.set(n.id, n.id));

  return { nodes, edges, starts, nodeOf, nets, machines, crowdOf };
}// buildWays

const topologies = new WeakMap<HostEntry[], Topology>();
const graphs = new WeakMap<Topology, Map<string, WayGraph>>();

export function topologyOf(hosts: HostEntry[]): Topology {
  let topo = topologies.get(hosts);
  if (!topo) {
    topo = buildTopology(hosts);
    topologies.set(hosts, topo);
  }
  return topo;
}// topologyOf

export function waysOf(topo: Topology, open: readonly string[]): WayGraph {
  const key = [...open].sort().join("|");
  let byOpen = graphs.get(topo);
  if (!byOpen) {
    byOpen = new Map();
    graphs.set(topo, byOpen);
  }
  let graph = byOpen.get(key);
  if (!graph) {
    if (byOpen.size > 20) {
      byOpen.clear();
    }
    graph = buildWays(topo, new Set(open));
    byOpen.set(key, graph);
  }
  return graph;
}// waysOf

const COST: Record<Link, number> = { routed: 1, unknown: 1, confirmed: 10, likely: 16, possible: 24 };

// the cheapest way from any scanner to a network: routed steps first, then the surest takeovers;
// a takeover is paid once, when leaving the machine for its other network
export function findWay(graph: WayGraph, target: string): { nodes: string[]; edges: WayEdge[] } | null {
  const goal = graph.nodeOf.get(target);
  if (!goal) {
    return null;
  }
  const around = new Map<string, { to: string; edge: WayEdge }[]>();
  for (const e of graph.edges) {
    const a = graph.nodeOf.get(e.a)!;
    const b = graph.nodeOf.get(e.b)!;
    if (a !== b) {
      around.set(a, [...(around.get(a) ?? []), { to: b, edge: e }]);
      around.set(b, [...(around.get(b) ?? []), { to: a, edge: e }]);
    }
  }
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const cost = new Map<string, number>(graph.starts.map((s) => [graph.nodeOf.get(s)!, 0]));
  const back = new Map<string, { from: string; edge: WayEdge }>();
  const done = new Set<string>();
  while (true) {
    let here: string | null = null;
    for (const [n, c] of cost) {
      if (!done.has(n) && (here === null || c < cost.get(here)!)) {
        here = n;
      }
    }
    if (here === null) {
      return null;
    }
    if (here === goal) {
      break;
    }
    done.add(here);
    const node = byId.get(here);
    const leaving = node?.kind === "machine" || node?.kind === "crowd";
    const homes = node?.kind === "crowd" ? new Set(node.homes.map((h) => graph.nodeOf.get(h))) : null;
    const fromHome = !!homes && homes.has(back.get(here)?.from);
    for (const { to, edge } of around.get(here) ?? []) {
      if (fromHome && homes!.has(to)) {
        continue;
      }
      const c = cost.get(here)! + (leaving ? COST[edge.link] : 1);
      if (c < (cost.get(to) ?? Infinity)) {
        cost.set(to, c);
        back.set(to, { from: here, edge });
      }
    }
  }
  const nodes = [goal];
  const edges: WayEdge[] = [];
  while (back.has(nodes[0])) {
    const step = back.get(nodes[0])!;
    nodes.unshift(step.from);
    edges.unshift(step.edge);
  }
  throughOneNetwork(graph, byId, nodes, edges, target);

  return { nodes, edges };
}// findWay

// critical first, then high, medium and low, over all of a machine's hosts
export function exposure(m: WayMachine): number {
  return m.hosts.reduce((s, h) => s + h.severity_counts.critical * 1e9 + h.severity_counts.high * 1e6 + h.severity_counts.medium * 1e3 + h.severity_counts.low, 0);
}// exposure

// the machines of a group that sit in a node of the map (a network, or a block holding it)
export function crowdMembersIn(graph: WayGraph, crowd: WayCrowd, nodeId: string): WayMachine[] {
  return crowd.machines.filter((m) => graph.nodeOf.get(crowd.homeOf.get(m.id) ?? "") === nodeId);
}// crowdMembersIn

function throughOneNetwork(graph: WayGraph, byId: Map<string, WayNode>, nodes: string[], edges: WayEdge[], target: string) {
  const endIn = (e: WayEdge, node: string) => (graph.nodeOf.get(e.a) === node ? e.a : e.b);
  const edgeBetween = (end: string, node: string) =>
    graph.edges.find((e) => (e.a === end && graph.nodeOf.get(e.b) === node) || (e.b === end && graph.nodeOf.get(e.a) === node));
  for (let i = 1; i < nodes.length; i++) {
    if (byId.get(nodes[i])?.kind !== "block") {
      continue;
    }
    let leave: string | null = null;
    const next = byId.get(nodes[i + 1] ?? "");
    if (i === nodes.length - 1) {
      leave = graph.nodeOf.get(target) === nodes[i] ? target : null;
    } else if (next?.kind === "crowd") {
      const best = [...crowdMembersIn(graph, next, nodes[i])].sort((a, b) => exposure(b) - exposure(a))[0];
      const home = best ? next.homeOf.get(best.id)! : null;
      const e = home ? edgeBetween(home, next.id) : undefined;
      if (e) {
        edges[i] = e;
        leave = home;
      }
    } else {
      leave = endIn(edges[i], nodes[i]);
    }
    if (leave && endIn(edges[i - 1], nodes[i]) !== leave) {
      const e = edgeBetween(leave, nodes[i - 1]);
      if (e) {
        edges[i - 1] = e;
      }
    }
  }
}// throughOneNetwork
