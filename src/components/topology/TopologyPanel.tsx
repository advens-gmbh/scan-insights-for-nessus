import { useState } from "react";
import type { ReactNode } from "react";
import { ChevronRight, X } from "lucide-react";
import type { HostEntry, SeverityCounts } from "../../types/nessus";
import type { Bridge, Link, Strength, WayCrowd, WayEdge, WayGraph, WayMachine, WayNode } from "../../utils/topology";
import { crowdMembersIn, exposure } from "../../utils/topology";
import { useUiStore } from "../../stores/uiStore";
import { useScanStore } from "../../stores/scanStore";
import { compareHosts } from "../../utils/ip";
import IpLink from "../common/IpLink";
import CopyButton from "../common/CopyButton";
import { SEVERITY_BG, crowdReach } from "./WaysMap";

export interface Level { sev: number; key: keyof SeverityCounts; label: string; fg: string }

const STRENGTH: Record<Strength, { label: string; rank: number; className: string }> = {
  confirmed: { label: "Confirmed", rank: 3, className: "bg-accent-600 text-white" },
  likely:    { label: "Likely",    rank: 2, className: "bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300" },
  possible:  { label: "Possible",  rank: 1, className: "border border-ink-300 dark:border-ink-600 text-ink-600 dark:text-ink-300" },
};

export const strengthRank = (s: Strength) => STRENGTH[s].rank;

const HEAD = "flex items-center gap-2 px-4 py-3 border-b border-ink-100 dark:border-ink-700/50";
const SECTION = "text-caption font-semibold text-ink-500 dark:text-ink-400 mb-1.5";

function countsOf(hosts: HostEntry[], levels: Level[]) {
  return levels.map((l) => ({ ...l, n: hosts.reduce((sum, h) => sum + h.severity_counts[l.key], 0) }));
}// countsOf

export function machineScore(b: Bridge, levels: Level[]): number {
  return countsOf(b.hosts, levels).reduce((s, c) => s * 1000 + c.n, 0);
}// machineScore

function Counts({ hosts, levels, bar = false }: { hosts: HostEntry[]; levels: Level[]; bar?: boolean }) {
  const counts = countsOf(hosts, levels).filter((c) => c.n > 0);
  if (counts.length === 0) {
    return null;
  }
  return (
    <>
      <span className="flex flex-wrap gap-x-2.5 text-caption font-semibold">
        {counts.map((c) => <span key={c.key} className={c.fg}>{c.n} {c.label}</span>)}
      </span>
      {bar && (
        <div className="flex gap-0.5 h-2 mt-1.5 rounded-full overflow-hidden">
          {counts.map((c) => <span key={c.key} className={SEVERITY_BG[c.sev]} style={{ flex: c.n }} />)}
        </div>
      )}
    </>
  );
}// Counts

function Machine({ b, levels, lit, onHover, bare = false }: { b: Bridge; levels: Level[]; lit: boolean; onHover: (b: Bridge | null) => void; bare?: boolean }) {
  const openHostPanel = useUiStore((s) => s.openHostPanel);
  return (
    <div
      onMouseEnter={() => onHover(b)}
      onMouseLeave={() => onHover(null)}
      className={`flex flex-col gap-1.5 transition-colors ${bare ? "rounded-md border border-ink-200 dark:border-ink-700 px-3 py-2.5" : "px-4 py-3 border-b border-ink-100 dark:border-ink-700/50"} ${
        lit ? "bg-accent-50/60 dark:bg-accent-900/20" : ""
      }`}
    >
      <div className="flex items-center gap-2">
        <button onClick={() => openHostPanel(b.hosts[0].ip)} className="flex-1 min-w-0 truncate text-left text-body font-semibold text-ink-800 dark:text-ink-100 hover:underline" title={b.name}>
          {b.name}
        </button>
        <span className={`inline-flex items-center h-5 px-2 rounded-full text-tiny font-semibold shrink-0 ${STRENGTH[b.strength].className}`}>{STRENGTH[b.strength].label}</span>
      </div>
      <div className="flex flex-col text-caption text-ink-500 dark:text-ink-400">
        {b.addresses.map((a) => (
          <span key={a.ip} className="truncate" title={a.iface ? `${a.ip} on ${a.iface}` : a.ip}>
            {a.host ? (
              <button onClick={() => openHostPanel(a.ip)} className="tabular-nums text-accent-700 dark:text-accent-400 hover:underline">{a.ip}</button>
            ) : <span className="tabular-nums text-ink-700 dark:text-ink-200" title="Nessus didn't scan this address, so there are no findings for it">{a.ip}</span>}
            {a.iface && <span> on {a.iface}</span>}
            {!a.host && <span className="ml-1.5 px-1 rounded bg-ink-100 dark:bg-ink-700 text-tiny font-semibold text-ink-500 dark:text-ink-400">not scanned</span>}
          </span>
        ))}
      </div>
      <div className="flex flex-wrap gap-1">
        {b.nets.map((n) => (
          <span
            key={n.key}
            className={`inline-flex items-center gap-1 h-5 px-1.5 rounded border text-tiny tabular-nums whitespace-nowrap ${
              n.scanned ? "border-ink-200 dark:border-ink-600 text-ink-700 dark:text-ink-200" : "border-dashed border-ink-300 dark:border-ink-500 text-ink-500 dark:text-ink-400"
            }`}
          >
            {n.key}{!n.scanned && <span className="text-ink-400 dark:text-ink-500">never scanned</span>}
          </span>
        ))}
      </div>
      <ul className="text-caption text-ink-600 dark:text-ink-300 leading-[17px]">
        {b.evidence.map((e) => <li key={e}>{e}</li>)}
      </ul>
      <Counts hosts={b.hosts} levels={levels} />
    </div>
  );
}// Machine

export function MachineList({ bridges, crowds, graph, levels, highlighted, hidden, onPick, onCrowd, onHover, onHide }: {
  bridges: Bridge[];
  crowds: WayCrowd[];
  graph: WayGraph;
  levels: Level[];
  highlighted: string | null;
  hidden: HiddenNet[];
  onPick: (target: string) => void;
  onCrowd: (id: string) => void;
  onHover: (b: Bridge | null) => void;
  onHide: () => void;
}) {
  const grouped = new Set(crowds.flatMap((c) => c.machines.map((m) => m.bridge?.key)));
  const single = bridges.filter((b) => !grouped.has(b.key));
  return (
    <>
      <div className={HEAD}>
        <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100">Machines on multiple networks</h2>
        <span className="px-2 rounded-full bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300 text-caption font-bold leading-5">{bridges.length}</span>
        <button onClick={onHide} className="ml-auto btn-ghost h-7 w-7 p-0 justify-center" title="Hide" aria-label="Hide the list"><ChevronRight size={16} /></button>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto">
        {hidden.length > 0 && (
          <div className="px-4 py-3 border-b border-ink-100 dark:border-ink-700/50 bg-ink-50/60 dark:bg-ink-900/30">
            <h3 className={SECTION}>Never scanned, but a machine reaches it</h3>
            <HiddenList hidden={hidden} onPick={onPick} />
          </div>
        )}
        {bridges.length === 0 && (
          <p className="px-4 py-4 text-small text-ink-500 dark:text-ink-400">None found. Credentialed scans find these best, because they list each machine's network cards.</p>
        )}
        {single.map((b) => <Machine key={b.key} b={b} levels={levels} lit={highlighted === b.key} onHover={onHover} />)}
        {crowds.length > 0 && (
          <>
            <h3 className={`${SECTION} px-4 pt-3 mb-0`}>Groups: machines in different networks that all reach the same ones</h3>
            {crowds.map((c) => <CrowdCard key={c.id} c={c} graph={graph} levels={levels} onOpen={() => onCrowd(c.id)} onPick={onPick} />)}
          </>
        )}
      </div>
      <p className="px-4 py-2.5 text-tiny leading-4 text-ink-500 dark:text-ink-400 border-t border-ink-100 dark:border-ink-700/50">
        Confirmed: the machine lists these addresses itself. Likely: its routing table knows them, or the same MAC address is on both. Possible: only the same NetBIOS name, or IP forwarding with its other networks unknown.
      </p>
    </>
  );
}// MachineList

function ReachChips({ c, graph, onPick }: { c: WayCrowd; graph: WayGraph; onPick: (target: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1">
      {c.reach.map((end) => {
        const key = end.replace(/^net:/, "");
        const scanned = !!graph.nets.get(key)?.group;
        return (
          <button
            key={end}
            onClick={() => onPick(end)}
            title="Show the attack path"
            className={`inline-flex items-center gap-1 h-5 px-1.5 rounded border text-tiny tabular-nums whitespace-nowrap hover:border-accent-500 ${
              scanned ? "border-ink-200 dark:border-ink-600 text-ink-700 dark:text-ink-200" : "border-dashed border-ink-300 dark:border-ink-500 text-ink-500 dark:text-ink-400"
            }`}
          >
            {key}{!scanned && <span className="text-ink-400 dark:text-ink-500">never scanned</span>}
          </button>
        );
      })}
    </div>
  );
}// ReachChips

const evidenceOf = (c: WayCrowd) => [...new Set(c.machines.flatMap((m) => m.bridge?.evidence ?? []))];
const talkersOf = (c: WayCrowd) => c.machines.filter((m) => m.talks.length > 0).length;

function CrowdCard({ c, graph, levels, onOpen, onPick }: { c: WayCrowd; graph: WayGraph; levels: Level[]; onOpen: () => void; onPick: (target: string) => void }) {
  const talkers = talkersOf(c);
  return (
    <div className="flex flex-col gap-1.5 px-4 py-3 border-b border-ink-100 dark:border-ink-700/50">
      <button onClick={onOpen} className="text-left text-body font-semibold text-ink-800 dark:text-ink-100 hover:underline">
        {c.machines.length} machines <span className="font-normal text-ink-500 dark:text-ink-400">in {c.homes.length} {c.homes.length === 1 ? "network" : "networks"}</span>
      </button>
      <span className="text-caption text-ink-500 dark:text-ink-400">Each one also reaches:</span>
      <ReachChips c={c} graph={graph} onPick={onPick} />
      <ul className="text-caption text-ink-600 dark:text-ink-300 leading-[17px]">
        {evidenceOf(c).map((e) => <li key={e}>{e}</li>)}
        {talkers > 0 && <li>{talkers} of them have connections there</li>}
      </ul>
      <Counts hosts={c.machines.flatMap((m) => m.hosts)} levels={levels} />
    </div>
  );
}// CrowdCard

export function CrowdPanel({ crowd, graph, levels, worstShown, onMachine, onPick, onClose, onHide }: {
  crowd: WayCrowd;
  graph: WayGraph;
  levels: Level[];
  worstShown: (h: HostEntry) => number | null;
  onMachine: (id: string) => void;
  onPick: (target: string) => void;
  onClose: () => void;
  onHide: () => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const worst = (m: WayMachine) => m.hosts.reduce<number>((w, h) => Math.max(w, worstShown(h) ?? -1), -1);
  const rows = [...crowd.machines].sort((a, b) => worst(b) - worst(a) || exposure(b) - exposure(a) || compareHosts(a.ips[0] ?? "", b.ips[0] ?? ""));
  const shown = showAll ? rows : rows.slice(0, HOSTS_COLLAPSED);
  const homes = [...crowd.homes].map((h) => h.replace(/^net:/, "")).sort((a, b) => compareHosts(a.split("/")[0], b.split("/")[0]));
  const talkers = talkersOf(crowd);
  const evidence = evidenceOf(crowd);
  return (
    <>
      <div className={HEAD}>
        <div className="min-w-0">
          <div className="text-caption font-semibold text-ink-500 dark:text-ink-400">Group of machines</div>
          <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100 truncate">{crowd.machines.length} machines</h2>
        </div>
        <button onClick={onClose} className="ml-auto btn-ghost h-7 w-7 p-0 justify-center" title="Back" aria-label="Back"><X size={16} /></button>
        <button onClick={onHide} className="btn-ghost h-7 w-7 p-0 justify-center" title="Hide" aria-label="Hide the list"><ChevronRight size={16} /></button>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto px-4 py-3.5 flex flex-col gap-4">
        <p className="text-small leading-[19px] text-ink-600 dark:text-ink-300">
          Each of these machines sits in its own network and also reaches the networks below. Taking over any one of them is enough, so the map draws them as one.
        </p>
        <div>
          <h3 className={SECTION}>They all reach</h3>
          <ReachChips c={crowd} graph={graph} onPick={onPick} />
        </div>
        <div>
          <h3 className={SECTION}>They sit in {homes.length} {homes.length === 1 ? "network" : "networks"}</h3>
          <p className="text-caption leading-[18px] tabular-nums text-ink-600 dark:text-ink-300">{homes.join(", ")}</p>
        </div>
        {(evidence.length > 0 || talkers > 0) && (
          <div>
            <h3 className={SECTION}>How we know</h3>
            <ul className="text-caption leading-[18px] text-ink-600 dark:text-ink-300">
              {evidence.map((e) => <li key={e}>{e}</li>)}
              {talkers > 0 && <li>{talkers} of them have connections there</li>}
            </ul>
          </div>
        )}
        <div>
          <h3 className={SECTION}>Their findings</h3>
          <Counts hosts={crowd.machines.flatMap((m) => m.hosts)} levels={levels} bar />
        </div>
        <div>
          <h3 className={SECTION}>The machines, most exposed first</h3>
          <div className="flex flex-wrap items-center gap-1 mb-1.5">
            <CopyButton text={rows.map((m) => m.ips[0]).filter(Boolean).join("\n")} label="Copy IPs" />
            <CopyButton text={rows.map((m) => `${m.ips[0] ?? ""} (${m.name})`).join("\n")} label="Copy IPs with names" />
          </div>
          <ul className="flex flex-col gap-1">
            {shown.map((m) => {
              const w = worst(m);
              return (
                <li key={m.id} className="flex items-center gap-2 min-w-0 text-small">
                  <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${w < 0 ? "bg-ink-200 dark:bg-ink-600" : SEVERITY_BG[w]}`} title={w < 0 ? "Nothing at the selected severities" : LEVEL_NAME[w]} />
                  <button onClick={() => onMachine(m.id)} className="min-w-0 truncate text-left text-accent-700 dark:text-accent-400 hover:underline" title={m.name}>{m.name}</button>
                  <span className="ml-auto shrink-0 text-caption tabular-nums text-ink-500 dark:text-ink-400 select-text">{m.ips[0]}</span>
                </li>
              );
            })}
          </ul>
          {rows.length > HOSTS_COLLAPSED && (
            <button onClick={() => setShowAll((v) => !v)} className="btn-ghost w-full justify-center text-caption mt-2">
              {showAll ? "Show less" : `Show all ${rows.length}`}
            </button>
          )}
        </div>
      </div>
    </>
  );
}// CrowdPanel

// a network only a machine can reach, and the machine needs to be taken over
export interface HiddenNet {
  target: string;
  key: string;
  via: string;
}// HiddenNet

function HiddenList({ hidden, onPick }: { hidden: HiddenNet[]; onPick: (target: string) => void }) {
  return (
    <div className="flex flex-col gap-1">
      {hidden.map((h) => (
        <button key={h.key} onClick={() => onPick(h.target)} className="text-left text-small text-accent-700 dark:text-accent-400 hover:underline">
          <span className="tabular-nums font-semibold">{h.key}</span> <span className="text-ink-500 dark:text-ink-400">through {h.via}</span>
        </button>
      ))}
    </div>
  );
}// HiddenList

interface Step {
  title: ReactNode;
  text: string;
  hosts?: HostEntry[];
  files?: string[];          // the scan files Nessus ran from
  machines?: WayMachine[];   // a group's machines to choose from, most exposed first
}// Step

const label = (n: WayNode): string =>
  n.kind === "net" ? n.net.key : n.kind === "block" ? `${n.block.key} (${n.block.nets.length} networks)` : n.kind === "machine" ? n.name : n.kind === "crowd" ? `${n.machines.length} machines` : "Nessus";
const smooth = (l: Link) => l === "routed" || l === "unknown";

// the attack path steps explained simple
function stepsOf(graph: WayGraph, way: { nodes: string[]; edges: WayEdge[] }, target: string): { steps: Step[]; why: string[] } {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const nodes = way.nodes.map((id) => byId.get(id)!);
  const end = graph.nets.get(target.replace(/^net:/, ""));
  const steps: Step[] = [];
  const why: string[] = [];
  let skip = false;

  nodes.forEach((n, i) => {
    const into = way.edges[i - 1];
    const out = way.edges[i];
    const name = i === nodes.length - 1 && end && n.kind === "block" ? end.key : label(n);
    if (i === 0) {
      steps.push(n.kind === "net"
        ? { title: <>Start in <b>{n.net.key}</b></>, text: `Nessus is here (${n.net.scanners.map((s) => s.scanner).join(", ")}).`, files: n.net.scanners.flatMap((s) => s.fileIds) }
        : n.kind === "scanner"
          ? { title: "Start at Nessus", text: "Its address isn't in the scan, so where it sits is unknown.", files: n.root.fileIds }
          : { title: "Start at Nessus", text: "" });
      return;
    }
    if (n.kind === "crowd") {
      const prev = nodes[i - 1];
      const near = crowdMembersIn(graph, n, prev.id);
      const pool = [...(near.length ? near : n.machines)].sort((a, b) => exposure(b) - exposure(a));
      const next = nodes[i + 1];
      const goes = next ? (i + 1 === nodes.length - 1 && end ? end.key : label(next)) : crowdReach(n);
      const cards = pool.some((m) => m.bridge?.evidence[0]?.startsWith("Network cards"));
      steps.push({
        title: <>Take over one of <b>{pool.length} machines</b>{prev.kind === "net" || prev.kind === "block" ? <> in <b>{label(prev)}</b></> : null}</>,
        text: `Each ${cards ? "has a network card in" : "reaches"} ${goes}, so any one will do.`,
        machines: pool,
      });
      why.push(...(pool[0].bridge?.evidence ?? []), ...pool[0].talks.map((t) => t.text));
      return;
    }
    if (n.kind === "machine") {
      const next = nodes[i + 1];

      if (!out || smooth(out.link)) {
        steps.push({
          title: <>Go through <b>{n.name}</b>{next && next.kind !== "machine" ? <> to <b>{i + 1 === nodes.length - 1 && end ? end.key : label(next)}</b></> : null}</>,
          text: n.router ? "It routes traffic there, so no takeover is needed." : "No takeover needed.",
        });
        skip = !!next && next.kind !== "machine";
        return;
      }
      const prev = nodes[i - 1];
      steps.push({
        title: <>Take over <b>{n.name}</b></>,
        text: `${n.ips.join(", ")}${prev.kind !== "machine" ? `, in ${label(prev)}` : ""}.${n.hosts.length ? "" : " It wasn't scanned, so its weak spots are unknown."}`,
        hosts: n.hosts,
      });
      why.push(...(n.bridge?.evidence ?? []), ...n.talks.map((t) => t.text));
      return;
    }
    if (skip) {
      skip = false;
      return;
    }
    const net = n.kind === "net" ? n.net : null;
    const never = !!net && !net.group;
    const prev = nodes[i - 1];
    if (into.link === "unknown") {
      steps.push({ title: <>Reach <b>{name}</b></>, text: "Nessus scanned it, but without a traceroute, so the route there is unknown." });
    } else if (prev.kind === "crowd") {
      steps.push({ title: <>You are in <b>{name}</b></>, text: never ? "It wasn't scanned." : "" });
    } else if (prev.kind !== "machine") {
      steps.push({ title: <>Reach <b>{name}</b></>, text: "It's right next to Nessus." });
    } else {
      const m = prev;
      const how = m.kind === "machine" ? (never ? net!.reasons.filter((r) => m.ips.includes(r.ip)).map((r) => r.text)[0] : null) : null;
      steps.push({
        title: <>You are in <b>{name}</b></>,
        text: `${how ? `${how}. ` : m.kind === "machine" ? `${m.name} is on this network too. ` : ""}${never ? "It wasn't scanned." : ""}`.trim(),
      });
    }
  });

  return { steps, why: [...new Set(why)] };
}// stepsOf

export function WayPanel({ graph, way, target, levels, worstShown, hidden, onPick, onMachine, onClose, onHide }: {
  graph: WayGraph;
  way: { nodes: string[]; edges: WayEdge[] } | null;
  target: string;
  levels: Level[];
  worstShown: (h: HostEntry) => number | null;
  hidden: HiddenNet[];
  onPick: (target: string) => void;
  onMachine: (id: string) => void;
  onClose: () => void;
  onHide: () => void;
}) {
  const node = graph.nodes.find((n) => n.id === target);
  const net = graph.nets.get(target.replace(/^net:/, ""));
  const title = net?.key ?? (node?.kind === "block" ? node.block.key : node ? label(node) : target);
  const sub = !net && node?.kind === "block" ? `${node.block.nets.length} networks` : null;
  const hosts = net ? net.group?.hosts ?? [] : node?.kind === "block" ? node.block.nets.flatMap((n) => n.group?.hosts ?? []) : [];
  const { steps, why } = way ? stepsOf(graph, way, target) : { steps: [], why: [] };

  return (
    <>
      <div className={HEAD}>
        <div className="min-w-0">
          <div className="text-caption font-semibold text-ink-500 dark:text-ink-400">Possible attack path to</div>
          <h2 className="text-heading font-semibold tabular-nums text-ink-800 dark:text-ink-100 truncate">
            {title}{sub && <span className="ml-2 text-caption font-normal text-ink-500 dark:text-ink-400">{sub}</span>}
          </h2>
        </div>
        <button onClick={onClose} className="ml-auto btn-ghost h-7 w-7 p-0 justify-center" title="Back to the machines" aria-label="Back to the machines"><X size={16} /></button>
        <button onClick={onHide} className="btn-ghost h-7 w-7 p-0 justify-center" title="Hide" aria-label="Hide the list"><ChevronRight size={16} /></button>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto px-4 py-3.5 flex flex-col gap-4">
        {way ? (
          <ol className="flex flex-col">
            {steps.map((s, i) => (
              <li key={i} className="relative grid grid-cols-[26px_1fr] gap-2.5 pb-3.5">
                {i < steps.length - 1 && <span className="absolute left-3 top-7 bottom-0.5 border-l-2 border-accent-500" aria-hidden="true" />}
                <span className="w-[26px] h-[26px] rounded-full bg-accent-50 dark:bg-accent-900/40 text-accent-700 dark:text-accent-300 text-caption font-bold flex items-center justify-center">{i + 1}</span>
                <div className="min-w-0">
                  <div className="text-small text-ink-800 dark:text-ink-100 [&_b]:font-semibold">{s.title}</div>
                  {s.text && <p className="mt-0.5 text-caption leading-[18px] text-ink-500 dark:text-ink-400">{s.text}</p>}
                  {s.files && s.files.length > 0 && <FileLinks ids={s.files} />}
                  {s.machines && <StepMachines machines={s.machines} worstShown={worstShown} onMachine={onMachine} />}
                  {s.hosts && s.hosts.length > 0 && (
                    countsOf(s.hosts, levels).some((c) => c.n > 0)
                      ? <div className="mt-1 flex flex-wrap items-baseline gap-x-2 text-caption text-ink-500 dark:text-ink-400">Its findings: <Counts hosts={s.hosts} levels={levels} /></div>
                      : <p className="mt-0.5 text-caption text-ink-500 dark:text-ink-400">No findings at the selected severities.</p>
                  )}
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-small text-ink-500 dark:text-ink-400">No attack path found from Nessus to this network.</p>
        )}
        {why.length > 0 && (
          <div className="border-t border-ink-100 dark:border-ink-700/50 pt-3">
            <h3 className={SECTION}>How we know</h3>
            <ul className="text-caption leading-[18px] text-ink-600 dark:text-ink-300">{why.map((w) => <li key={w}>{w}</li>)}</ul>
          </div>
        )}
        {hosts.length > 0 && (
          <div className="border-t border-ink-100 dark:border-ink-700/50 pt-3">
            <h3 className={SECTION}>In this network: {hosts.length} {hosts.length === 1 ? "host" : "hosts"}</h3>
            <div className="flex flex-wrap items-baseline gap-x-2 text-caption text-ink-500 dark:text-ink-400">Findings: <Counts hosts={hosts} levels={levels} /></div>
            <HostList hosts={hosts} worstShown={worstShown} />
          </div>
        )}
        {hidden.filter((h) => h.target !== target).length > 0 && (
          <div className="border-t border-ink-100 dark:border-ink-700/50 pt-3">
            <h3 className={SECTION}>Other networks only a machine reaches</h3>
            <HiddenList hidden={hidden.filter((h) => h.target !== target)} onPick={onPick} />
          </div>
        )}
      </div>
    </>
  );
}// WayPanel

const MACHINES_COLLAPSED = 5;

function StepMachines({ machines, worstShown, onMachine }: { machines: WayMachine[]; worstShown: (h: HostEntry) => number | null; onMachine: (id: string) => void }) {
  const [all, setAll] = useState(false);
  const shown = all ? machines : machines.slice(0, MACHINES_COLLAPSED);
  return (
    <div className="mt-1.5">
      <ul className="flex flex-col gap-0.5">
        {shown.map((m) => {
          const worst = m.hosts.reduce<number>((w, h) => Math.max(w, worstShown(h) ?? -1), -1);
          return (
            <li key={m.id} className="flex items-center gap-2 min-w-0 text-caption">
              <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${worst < 0 ? "bg-ink-200 dark:bg-ink-600" : SEVERITY_BG[worst]}`} title={worst < 0 ? "Nothing at the selected severities" : LEVEL_NAME[worst]} />
              <button onClick={() => onMachine(m.id)} className="min-w-0 truncate text-left font-semibold text-accent-700 dark:text-accent-400 hover:underline" title={m.name}>{m.name}</button>
              <span className="ml-auto shrink-0 tabular-nums text-ink-500 dark:text-ink-400 select-text">{m.ips[0]}</span>
            </li>
          );
        })}
      </ul>
      {machines.length > MACHINES_COLLAPSED && (
        <button onClick={() => setAll((a) => !a)} className="mt-1 text-caption font-semibold text-accent-700 dark:text-accent-400 hover:underline">
          {all ? "Show fewer" : `Show all ${machines.length}`}
        </button>
      )}
    </div>
  );
}// StepMachines

function FileLinks({ ids }: { ids: string[] }) {
  const openFilePanel = useUiStore((s) => s.openFilePanel);
  const files = useScanStore((s) => s.files);
  return (
    <div className="mt-1 flex flex-wrap gap-x-3 text-caption">
      {[...new Set(ids)].map((id) => (
        <button key={id} onClick={() => openFilePanel(id)} className="text-accent-700 dark:text-accent-400 hover:underline" title="Open the scan file">
          {files.find((f) => f.id === id)?.filename ?? "scan file"}
        </button>
      ))}
    </div>
  );
}// FileLinks

const HOSTS_COLLAPSED = 20;

function HostList({ hosts, worstShown }: { hosts: HostEntry[]; worstShown: (h: HostEntry) => number | null }) {
  const [showAll, setShowAll] = useState(false);
  const ordered = [...hosts].sort((a, b) => (worstShown(b) ?? -1) - (worstShown(a) ?? -1) || compareHosts(a.ip, b.ip));
  const shown = showAll ? ordered : ordered.slice(0, HOSTS_COLLAPSED);
  return (
    <>
      <div className="flex flex-wrap items-center gap-1 mt-2 mb-1.5">
        <CopyButton text={ordered.map((h) => h.ip).join("\n")} label="Copy IPs" />
        <CopyButton text={ordered.map((h) => (h.hostname ? `${h.ip} (${h.hostname})` : h.ip)).join("\n")} label="Copy IPs with names" />
      </div>
      <ul className="flex flex-col gap-1">
        {shown.map((h) => {
          const worst = worstShown(h);
          return (
            <li key={h.ip} className="flex items-center gap-2 min-w-0 text-small">
              <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${worst === null ? "bg-ink-200 dark:bg-ink-600" : SEVERITY_BG[worst]}`} title={worst === null ? "Nothing at the selected severities" : LEVEL_NAME[worst]} />
              <IpLink ip={h.ip} className="shrink-0 select-text" />
              {h.hostname && <span className="min-w-0 truncate select-text text-ink-500 dark:text-ink-400" title={h.hostname}>{h.hostname}</span>}
            </li>
          );
        })}
      </ul>
      {hosts.length > HOSTS_COLLAPSED && (
        <button onClick={() => setShowAll((v) => !v)} className="btn-ghost w-full justify-center text-caption mt-2">
          {showAll ? "Show less" : `Show all ${hosts.length}`}
        </button>
      )}
    </>
  );
}// HostList

const LEVEL_NAME = ["Info", "Low", "Medium", "High", "Critical"];

// one machine or a run of routers
export function MachinePanel({ machine, levels, worstShown, onClose, onHide }: {
  machine: WayMachine;
  levels: Level[];
  worstShown: (h: HostEntry) => number | null;
  onClose: () => void;
  onHide: () => void;
}) {
  const byIp = new Map(machine.hosts.map((h) => [h.ip, h]));
  const rows = machine.router ? machine.hopList : machine.ips;
  return (
    <>
      <div className={HEAD}>
        <div className="min-w-0">
          <div className="text-caption font-semibold text-ink-500 dark:text-ink-400">{machine.router ? (machine.hops > 1 ? "Routers in a row" : "Router") : "Machine"}</div>
          <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100 truncate" title={machine.name}>{machine.name}</h2>
        </div>
        <button onClick={onClose} className="ml-auto btn-ghost h-7 w-7 p-0 justify-center" title="Back" aria-label="Back"><X size={16} /></button>
        <button onClick={onHide} className="btn-ghost h-7 w-7 p-0 justify-center" title="Hide" aria-label="Hide the list"><ChevronRight size={16} /></button>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto px-4 py-3.5 flex flex-col gap-4">
        {machine.router && machine.hops > 1 && (
          <p className="text-small leading-[19px] text-ink-600 dark:text-ink-300">
            Nessus's traceroute passed these {machine.hops} routers one after the other, with nothing else branching off between them, so the map draws them as one.
          </p>
        )}
        {machine.router && machine.hops === 1 && machine.hosts.length === 0 && (
          <p className="text-small leading-[19px] text-ink-600 dark:text-ink-300">Nessus's traffic passed this router, but the router itself wasn't scanned, so nothing more is known about it.</p>
        )}
        <div>
          <h3 className={SECTION}>{machine.router ? "In the order Nessus passed them" : "Its addresses"}</h3>
          <ol className="flex flex-col gap-2">
            {rows.map((ip, i) => {
              const h = byIp.get(ip);
              const worst = h ? worstShown(h) : null;
              return (
                <li key={`${ip}-${i}`} className="flex items-start gap-2.5">
                  <span className={`mt-1 w-2.5 h-2.5 shrink-0 ${machine.router ? "rounded-[3px]" : "rounded-full"} ${worst === null ? "bg-ink-200 dark:bg-ink-600" : SEVERITY_BG[worst]}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-2 min-w-0">
                      {ip === "?" ? <span className="text-small text-ink-500 dark:text-ink-400">a router that didn't answer</span>
                        : h ? <IpLink ip={ip} className="select-text" />
                          : <span className="text-small tabular-nums select-text text-ink-800 dark:text-ink-100">{ip}</span>}
                      {h?.hostname && <span className="min-w-0 truncate text-caption text-ink-500 dark:text-ink-400 select-text">{h.hostname}</span>}
                    </div>
                    {ip !== "?" && (h ? (
                      <div className="flex flex-wrap items-center gap-x-2 text-caption">
                        <Counts hosts={[h]} levels={levels} />
                      </div>
                    ) : <div className="text-caption text-ink-500 dark:text-ink-400">not scanned</div>)}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
        {machine.bridge && (
          <div>
            <h3 className={SECTION}>On more than one network</h3>
            <Machine b={machine.bridge} levels={levels} lit={false} onHover={() => {}} bare />
          </div>
        )}
        {machine.talks.length > 0 && (
          <div>
            <h3 className={SECTION}>Talks to networks nobody scanned</h3>
            <ul className="text-caption leading-[18px] text-ink-600 dark:text-ink-300">{machine.talks.map((t) => <li key={t.text}>{t.text}</li>)}</ul>
          </div>
        )}
      </div>
    </>
  );
}// MachinePanel
