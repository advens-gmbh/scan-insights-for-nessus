import { useEffect, useMemo, useRef } from "react";
import cytoscape, { type Core } from "cytoscape";
import type { HostEntry, NessusFile } from "../../types/nessus";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "../../types/nessus";
import { useUiStore } from "../../stores/uiStore";
import { isIpv4 } from "../../utils/ip";

interface Props {
  hosts: HostEntry[];
  files: NessusFile[];
  severityFilter: Set<number>;
}// Props

// graph ids always carry a prefix because cytoscape can't handle every string as an id(empty, or names like __proto__)
const hostNode = (ip: string) => `host:${ip}`;
const subnetNode = (subnet: string) => `subnet:${subnet}`;

function getSubnet(ip: string): string {
  const parts = ip.split(".");
  if (isIpv4(ip)) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }

  return "0.0.0.0/24";
}// getSubnet

function worstSeverity(host: HostEntry): number {
  return host.items.reduce((worst, item) => Math.max(worst, item.severity), 0);
}// worstSeverity

function hexToRgb(hex: string) {
  return {
    r: parseInt(hex.slice(1, 3), 16),
    g: parseInt(hex.slice(3, 5), 16),
    b: parseInt(hex.slice(5, 7), 16),
  };
}// hexToRgb

// draw centered monitor icon
function drawMonitor(ctx: CanvasRenderingContext2D, cx: number, cy: number, r: number, rgba: string, lwMult = 1,) {
  const sw = r * 1.6;
  const sh = r * 1.05;
  const standH = sh * 0.32;
  const baseW  = sw * 0.55;
  const cr     = r * 0.13;
  const top  = cy - (sh + standH) / 2;
  const left = cx - sw / 2;

  ctx.strokeStyle = rgba;
  ctx.lineWidth   = Math.max(0.8, r * 0.13) * lwMult;
  ctx.lineJoin    = "round";
  ctx.lineCap     = "round";

  // rounded screen rectangle
  ctx.beginPath();
  ctx.moveTo(left + cr, top);
  ctx.lineTo(left + sw - cr, top);
  ctx.arcTo(left + sw, top,          left + sw, top + cr,     cr);
  ctx.lineTo(left + sw, top + sh - cr);
  ctx.arcTo(left + sw, top + sh,     left + sw - cr, top + sh, cr);
  ctx.lineTo(left + cr, top + sh);
  ctx.arcTo(left,       top + sh,    left, top + sh - cr,      cr);
  ctx.lineTo(left,      top + cr);
  ctx.arcTo(left,       top,         left + cr, top,           cr);
  ctx.closePath();
  ctx.stroke();

  // stand
  ctx.beginPath();
  ctx.moveTo(cx, top + sh);
  ctx.lineTo(cx, top + sh + standH);
  ctx.stroke();

  // base
  ctx.beginPath();
  ctx.moveTo(cx - baseW / 2, top + sh + standH);
  ctx.lineTo(cx + baseW / 2, top + sh + standH);
  ctx.stroke();
}// drawMonitor

// draw router/gateway icon(circle with 4 outward directional arrows (standard network diagram symbol))
function drawRouter(ctx: CanvasRenderingContext2D, cx: number, cy: number, r: number, rgba: string, lwMult = 1,) {
  const lw      = Math.max(0.8, r * 0.13) * lwMult;
  const circleR = r * 0.42;
  const shaftL  = r * 0.35;
  const ah      = r * 0.20;
  const aw      = r * 0.13;

  ctx.strokeStyle = rgba;
  ctx.lineWidth   = lw;
  ctx.lineCap     = "round";
  ctx.lineJoin    = "round";

  ctx.beginPath();
  ctx.arc(cx, cy, circleR, 0, Math.PI * 2);
  ctx.stroke();

  // N, E, S, W arrows radiating from circle edge
  const dirs: [number, number][] = [[0, -1], [1, 0], [0, 1], [-1, 0]];
  for (const [dx, dy] of dirs) {
    const sx = cx + dx * circleR;
    const sy = cy + dy * circleR;
    const ex = cx + dx * (circleR + shaftL);
    const ey = cy + dy * (circleR + shaftL);
    const px = -dy;
    const py =  dx;

    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.lineTo(ex, ey);
    ctx.stroke();

    ctx.beginPath();
    ctx.moveTo(ex - dx * ah + px * aw, ey - dy * ah + py * aw);
    ctx.lineTo(ex, ey);
    ctx.lineTo(ex - dx * ah - px * aw, ey - dy * ah - py * aw);
    ctx.stroke();
  }
}// drawRouter

interface GatewayResult {
  ips: Set<string>;
  connections: Map<string, Set<string>>; // gatewayIp --> subnets it connects (only cross-subnet gateways)
}// GatewayResult

// Hosts that appear as intermediate hops in traceroute paths (plugin 10287) connecting two different /24s.
// Only IPs whose traceroute hops span more than one subnet are treated as gateways.
function parseTracerouteGateways(hosts: HostEntry[], filteredIps: Set<string>): GatewayResult {
  const connections = new Map<string, Set<string>>();
  const ipRe        = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

  for (const host of hosts) {
    const tr = host.items.find((i) => i.plugin_id === 10287);
    if (!tr?.plugin_output) {
      continue;
    }

    for (const line of tr.plugin_output.split("\n")) {
      for (const m of line.matchAll(ipRe)) {
        const hop = m[1];
        if (hop !== host.ip && filteredIps.has(hop)) {
          if (!connections.has(hop)) {
            connections.set(hop, new Set());
          }
          connections.get(hop)!.add(getSubnet(hop));
          connections.get(hop)!.add(getSubnet(host.ip));
        }
      }
    }
  }

  // only count as a gateway if the hop connects two different subnets
  const ips = new Set<string>();
  for (const [ip, subnets] of connections) {
    if (subnets.size > 1) ips.add(ip);
  }

  return { ips, connections };
}// parseTracerouteGateways

interface MultiHomedResult {
  ips: Set<string>;
  crossEdges: Array<{ sourceIp: string; targetSubnet: string }>;
}// MultiHomedResult

// Hosts whose MAC address or NetBIOS name appears on IPs in more than one /24 subnet.
// Also returns cross-subnet edges so each multi-homed IP visually connects to its peer subnet hubs.
function detectMultiHomedHosts(hosts: HostEntry[]): MultiHomedResult {
  const macMap = new Map<string, Map<string, string>>();
  const nbMap  = new Map<string, Map<string, string>>();

  for (const host of hosts) {
    const subnet = getSubnet(host.ip);
    if (host.mac) {
      for (const mac of host.mac.split(/[\n,]+/).map((m) => m.trim().toLowerCase()).filter(Boolean)) {
        if (!macMap.has(mac)) {
          macMap.set(mac, new Map());
        }
        macMap.get(mac)!.set(subnet, host.ip);
      }
    }
    if (host.netbios) {
      const nb = host.netbios.toLowerCase().trim();
      if (nb) {
        if (!nbMap.has(nb)) {
          nbMap.set(nb, new Map());
        }
        nbMap.get(nb)!.set(subnet, host.ip);
      }
    }
  }

  const ips = new Set<string>();
  const crossEdgeSet = new Set<string>();
  const crossEdges: Array<{ sourceIp: string; targetSubnet: string }> = [];
  const collect = (m: Map<string, Map<string, string>>) => {
    for (const subnetIpMap of m.values()) {
      if (subnetIpMap.size < 2) {
        continue;
      }

      const entries = [...subnetIpMap.entries()];
      for (const [, ip] of entries) {
        ips.add(ip);
        for (const [otherSubnet, otherIp] of entries) {
          if (otherIp === ip) {
            continue;
          }

          const key = `${ip}|||${otherSubnet}`;
          if (!crossEdgeSet.has(key)) {
            crossEdgeSet.add(key);
            crossEdges.push({ sourceIp: ip, targetSubnet: otherSubnet });
          }
        }
      }
    }
  };

  collect(macMap);
  collect(nbMap);

  return { ips, crossEdges };
}// detectMultiHomedHosts

const NODE_D = 24;
const NODE_R = NODE_D / 2;

export default function NetworkGraph({ hosts, files, severityFilter }: Props) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const cyContainerRef = useRef<HTMLDivElement>(null);
  const overlayRef = useRef<HTMLCanvasElement>(null);
  const cyRef = useRef<Core | null>(null);
  const openHostPanel = useUiStore((s) => s.openHostPanel);

  const filtered = useMemo(
    () => hosts.filter((h) => h.items.some((i) => severityFilter.has(i.severity))),
    [hosts, severityFilter]
  );

  useEffect(() => {
    if (!cyContainerRef.current) {
      return;
    }

    const isDark = document.documentElement.classList.contains("dark");
    const filteredIps = new Set(filtered.map((h) => h.ip));
    const gatewayResult = parseTracerouteGateways(hosts, filteredIps);
    const gatewayIps = gatewayResult.ips;
    const multiHomedResult = detectMultiHomedHosts(hosts);
    const multiHomedIps = multiHomedResult.ips;
    const subnetSet = new Set(filtered.map((h) => getSubnet(h.ip)));

    // no dashed line needed for subnet pairs which already have a confirmed gateway
    const gatewaySubnetPairs = new Set<string>();
    for (const subnets of gatewayResult.connections.values()) {
      const arr = [...subnets];
      for (let i = 0; i < arr.length; i++)
        for (let j = i + 1; j < arr.length; j++)
          gatewaySubnetPairs.add([arr[i], arr[j]].sort().join("|||"));
    }

    const elements: cytoscape.ElementDefinition[] = [];

    for (const subnet of subnetSet) {
      elements.push({ data: { id: subnetNode(subnet), label: subnet, type: "subnet" } });
    }

    // Track (ip|||subnet) pairs that have a teal gateway edge, to avoid duplicate multi-homed edges
    const gatewayEdgeKeys = new Set<string>();

    for (const host of filtered) {
      const severity = worstSeverity(host);
      const subnet   = getSubnet(host.ip);
      const isGw     = gatewayIps.has(host.ip);
      elements.push({
        data: {
          id: hostNode(host.ip),
          label: host.ip,
          type: "host",
          severity,
          ip: host.ip,
          isGateway: isGw,
          isMultiHomed: multiHomedIps.has(host.ip),
        },
      });

      if (isGw) {
        // Own-subnet edge is teal for gateways
        elements.push({ data: { id: `e-${subnet}-${host.ip}`, source: subnetNode(subnet), target: hostNode(host.ip), type: "gateway-edge" } });
        gatewayEdgeKeys.add(`${host.ip}|||${subnet}`);
        // Add teal edges to every other subnet this gateway connects
        for (const peerSubnet of gatewayResult.connections.get(host.ip) ?? []) {
          if (peerSubnet !== subnet && subnetSet.has(peerSubnet)) {
            elements.push({ data: { id: `gw-${host.ip}-${peerSubnet}`, source: hostNode(host.ip), target: subnetNode(peerSubnet), type: "gateway-edge" } });
            gatewayEdgeKeys.add(`${host.ip}|||${peerSubnet}`);
          }
        }
      } else {
        elements.push({ data: { id: `e-${subnet}-${host.ip}`, source: subnetNode(subnet), target: hostNode(host.ip) } });
      }
    }

    // Inter-subnet edges: connect subnet hubs that co-appear in the same scan file.
    // A dashed edge means "these two subnets were reachable from the same scanner run."
    const interSubnetPairs = new Set<string>();
    for (const file of files) {
      const fileSubnets = [
        ...new Set(
          file.hosts
            .filter((h) => filteredIps.has(h.ip))
            .map((h) => getSubnet(h.ip))
        ),
      ];

      for (let i = 0; i < fileSubnets.length; i++) {
        for (let j = i + 1; j < fileSubnets.length; j++) {
          interSubnetPairs.add([fileSubnets[i], fileSubnets[j]].sort().join("|||"));
        }
      }
    }

    for (const pair of interSubnetPairs) {
      if (gatewaySubnetPairs.has(pair)) {
        continue; // gateway already handles this pair with teal lines
      }

      const [a, b] = pair.split("|||");
      elements.push({ data: { id: `inter-${pair}`, source: subnetNode(a), target: subnetNode(b), type: "inter-subnet" } });
    }

    // Multi-homed cross-subnet edges: normal solid lines to peer subnet hubs.
    // Skip if a teal gateway edge already covers that (host, subnet) pair.
    for (const { sourceIp, targetSubnet } of multiHomedResult.crossEdges) {
      if (filteredIps.has(sourceIp) && subnetSet.has(targetSubnet) && !gatewayEdgeKeys.has(`${sourceIp}|||${targetSubnet}`)) {
        elements.push({ data: { id: `mh-${sourceIp}-${targetSubnet}`, source: hostNode(sourceIp), target: subnetNode(targetSubnet) } });
      }
    }

    const severityBorders: any[] = SEVERITY_ORDER.map((sev) => ({
      selector: `node[type='host'][severity=${sev}]`,
      style: { "border-color": SEVERITY_COLORS[sev].hex },
    }));

    // A separate element per graph, because cytoscape destroys any earlier instance that
    // used the same element, which would happen while its layout is still running.
    const container = document.createElement("div");
    container.className = "absolute inset-0";
    cyContainerRef.current.appendChild(container);

    const cy = cytoscape({
      container,
      elements,
      maxZoom: 3,
      minZoom: 0.2,
      layout: { name: "preset" }, // the real layout runs below, once listeners are attached
      style: [
        {
          selector: "node[type='subnet']",
          style: {
            shape: "round-rectangle",
            "background-color": isDark ? "#1e293b" : "#e2e8f0",
            "border-color": isDark ? "#475569" : "#94a3b8",
            "border-width": 1,
            label: "data(label)",
            color: isDark ? "#94a3b8" : "#475569",
            "font-size": 10,
            "text-valign": "center",
            "text-halign": "center",
            width: 110,
            height: 30,
          },
        },
        {
          selector: "node[type='host']",
          style: {
            shape: "ellipse",
            "background-color": isDark ? "#1a2235" : "#e2e8f0",
            "border-width": 1.5,
            "border-color": "#64748b",
            label: "data(label)",
            color: isDark ? "#94a3b8" : "#475569",
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 6,
            "text-background-color": isDark ? "#0f172a" : "#f8fafc",
            "text-background-opacity": 0.9,
            "text-background-padding": "2px",
            "text-background-shape": "roundrectangle",
            width: NODE_D,
            height: NODE_D,
          },
        },
        ...severityBorders,
        {
          selector: "edge",
          style: {
            "line-color": "#334155",
            width: 1,
            "curve-style": "bezier",
          },
        },
        {
          selector: "edge[type='inter-subnet']",
          style: {
            "line-color": "#64748b",
            width: 1.5,
            "line-style": "dashed",
            "line-dash-pattern": [8, 4],
            "curve-style": "bezier",
            opacity: 0.55,
          },
        },
        {
          selector: "edge[type='gateway-edge']",
          style: {
            "line-color": "rgb(20,184,166)",
            width: 2,
            "curve-style": "bezier",
            opacity: 0.85,
          },
        },
        {
          selector: "node[type='host']:selected",
          style: { "border-color": "#a78bfa", "border-width": 2.5 } as any,
        },
      ],
    });

    // Overlay canvas sits above Cytoscape and draws:
    //   1. Opaque node fill  - blocks the glow ring from bleeding inward
    //   2. Neon ring bloom   - layered strokes around the border
    //   3. Monitor icon      - always centered, any zoom/window size
    const drawOverlay = () => {
      const canvas  = overlayRef.current;
      const wrapper = wrapperRef.current;
      if (!canvas || !wrapper) {
        return;
      }

      const rect = wrapper.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width  * dpr;
      canvas.height = rect.height * dpr;
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;

      const ctx = canvas.getContext("2d")!;
      const darkMode = document.documentElement.classList.contains("dark");
      const nodeFill = darkMode ? "#1a2235" : "#e2e8f0";
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, rect.width, rect.height);

      const zoom = cy.zoom();

      cy.nodes("[type='host']").forEach((node) => {
        const pos = node.renderedPosition();
        const sev = node.data("severity") as number;
        const hex = SEVERITY_COLORS[sev]?.hex ?? "#6b7280";
        const { r, g, b } = hexToRgb(hex);
        const isGateway = node.data("isGateway")   as boolean;
        const isMultiHomed = node.data("isMultiHomed") as boolean;
        const sr = NODE_R * zoom;

        // 1. Fill node interior
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, sr, 0, Math.PI * 2);
        ctx.fillStyle = nodeFill;
        ctx.fill();

        // 2. Neon ring bloom
        const passes: [number, number][] = [
          [13 * zoom, 0.05],
          [8  * zoom, 0.13],
          [5  * zoom, 0.28],
          [3  * zoom, 0.52],
          [1.5 * zoom, 0.85],
        ];
        for (const [lw, op] of passes) {
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, sr, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(${r},${g},${b},${op})`;
          ctx.lineWidth   = lw;
          ctx.stroke();
        }

        // 3. Extra dashed teal ring for multi-homed hosts (bridges multiple subnets)
        if (isMultiHomed) {
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, sr + 5 * zoom, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(20,184,166,0.85)`;
          ctx.lineWidth   = Math.max(1, 1.5 * zoom);
          ctx.setLineDash([4 * zoom, 3 * zoom]);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // 4. Icon bloom: thick→thin passes at decreasing opacity (same technique as the ring)
        const iconR    = sr * 0.62;
        const drawIcon = (c: string, lw: number) => isGateway ? drawRouter(ctx, pos.x, pos.y, iconR, c, lw) : drawMonitor(ctx, pos.x, pos.y, iconR, c, lw);

        drawIcon(`rgba(${r},${g},${b},0.12)`, 4);
        drawIcon(`rgba(${r},${g},${b},0.30)`, 2.2);
        drawIcon(`rgba(${r},${g},${b},1.0)`,  1);
      });
    };

    cy.on("render viewport", drawOverlay);

    cy.on("tap", "node[type='host']", (evt) => {
      const ip: string = evt.target.data("ip");
      if (ip) {
        openHostPanel(ip);
      }
    });

    // When the user toggles dark/light mode, update Cytoscape node styles so labels
    // and fills reflect the new theme. The resulting Cytoscape re-render triggers
    // drawOverlay, which reads darkMode live.
    const onThemeChange = () => {
      const dark = document.documentElement.classList.contains("dark");
      cy.nodes("[type='host']").style({
        "background-color": dark ? "#1a2235" : "#e2e8f0",
        color: dark ? "#94a3b8" : "#475569",
        "text-background-color": dark ? "#0f172a" : "#f8fafc",
      });
      cy.nodes("[type='subnet']").style({
        "background-color": dark ? "#1e293b" : "#e2e8f0",
        "border-color": dark ? "#475569" : "#94a3b8",
        color: dark ? "#94a3b8" : "#475569",
      });
    };
    const themeObserver = new MutationObserver(onThemeChange);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    cyRef.current = cy;

    // After stop() the layout still updates nodes on its next animation frame, and only
    // then calls its `stop` option. Destroying the graph any earlier throws an error.
    let layoutFinished = false;
    let destroyWhenFinished = false;
    const destroyGraph = () => {
      cy.destroy();
      container.remove();
    };
    const layout = cy.layout({
      name: "cose",
      animate: true,
      animationDuration: 400,
      nodeRepulsion: () => 12000,
      idealEdgeLength: () => 100,
      fit: true,
      padding: 60,
      stop: () => {
        layoutFinished = true;
        if (destroyWhenFinished) {
          destroyGraph();
        }
      },
    });
    layout.run();

    return () => {
      themeObserver.disconnect();
      cy.off("render viewport", drawOverlay);
      cyRef.current = null;
      if (layoutFinished) {
        destroyGraph();
      } else {
        container.style.visibility = "hidden";
        destroyWhenFinished = true;
        layout.stop();
      }
    };
  }, [filtered, hosts, files, openHostPanel]);

  return (
    <div ref={wrapperRef} className="w-full h-full relative">
      {/* Transparent container so the card background shows through in both light and dark mode */}
      <div
        ref={cyContainerRef}
        className="absolute inset-0"
        style={{ zIndex: 1, background: "transparent" }}
      />
      {/* Overlay canvas above Cytoscape: glow rings + monitor icons */}
      <canvas
        ref={overlayRef}
        className="absolute inset-0 pointer-events-none"
        style={{ zIndex: 2 }}
      />
    </div>
  );
}// NetworkGraph
