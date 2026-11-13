import { useCallback, useMemo, useRef, useState } from "react";
import { Maximize2, Minus, Plus, RotateCcw } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { useQuery } from "../data/query";
import type { TopologyHost } from "../types/nessus";
import SeverityPills from "../components/common/SeverityPills";
import Select from "../components/common/Select";
import WaysMap from "../components/topology/WaysMap";
import type { WaysControls } from "../components/topology/WaysMap";
import { CrowdPanel, MachineList, MachinePanel, WayPanel, machineScore, strengthRank } from "../components/topology/TopologyPanel";
import type { HiddenNet, Level } from "../components/topology/TopologyPanel";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useSeverityStore } from "../stores/severityStore";
import { countBySeverity, severitiesOf } from "../utils/severityFilter";
import { findWay, netEnd, PLUGIN, topologyOf, waysOf } from "../utils/topology";
import type { Bridge, WayCrowd } from "../utils/topology";
import EmptyFilesNotice from "./EmptyFilesNotice";
import { usePageState } from "../stores/pageStore";

// every criticality selected expect info
const START_SELECTED = [4, 3, 2, 1];

const LEVELS: Level[] = [
  { sev: 4, key: "critical", label: "Critical", fg: "text-critical-fg" },
  { sev: 3, key: "high",     label: "High",     fg: "text-high-fg" },
  { sev: 2, key: "medium",   label: "Medium",   fg: "text-medium-fg" },
  { sev: 1, key: "low",      label: "Low",      fg: "text-low-fg" },
  { sev: 0, key: "info",     label: "Info",     fg: "text-info-fg" },
];

const TOPOLOGY_PLUGINS = Object.values(PLUGIN);
const NO_HOSTS: TopologyHost[] = [];

const ICON_BUTTON = "h-8 w-8 flex items-center justify-center text-ink-500 hover:bg-ink-100 dark:hover:bg-ink-700";

export default function Topology() {
  const files = useScanStore((s) => s.files);
  const panel = useUiStore((s) => s.topologyPanel);
  const togglePanel = useUiStore((s) => s.toggleTopologyPanel);
  const resetLayout = useUiStore((s) => s.resetTopologyLayout);
  const open = useUiStore((s) => s.topologyOpen);
  const toggleBlock = useUiStore((s) => s.toggleTopologyBlock);
  const target = useUiStore((s) => s.topologyTarget);
  const setTarget = useUiStore((s) => s.setTopologyTarget);
  const { selected: chosenLevels } = useSeverityFilter("topology", START_SELECTED);
  const setSelection = useSeverityStore((s) => s.setSelection);
  const showInfo = useUiStore((s) => s.showInfo);
  const toggleShowInfo = useUiStore((s) => s.toggleShowInfo);
  // the pills as shown: the picked levels from Critical to Low, and Info when it is shown
  const severities = useMemo(() => [...chosenLevels.filter((sev) => sev !== 0), ...(showInfo ? [0] : [])], [chosenLevels, showInfo]);
  const toggle = (sev: number) => {
    if (sev === 0) {
      toggleShowInfo();
      return;
    }
    const others = chosenLevels.filter((x) => x !== 0);
    setSelection("topology", others.includes(sev) ? others.filter((x) => x !== sev) : [...others, sev]);
  };
  const [hovered, setHovered] = useState<Bridge | null>(null);
  const [machineId, setMachineId] = usePageState<string | null>("topology:machine", null);
  const [zoom, setZoom] = useState(1);
  const map = useRef<WaysControls>(null);

  const hosts = useQuery<TopologyHost[]>("topology_hosts", files.length > 0 ? { plugins: TOPOLOGY_PLUGINS } : null) ?? NO_HOSTS;
  const topo = useMemo(() => topologyOf(hosts), [hosts]);
  const graph = useMemo(() => waysOf(topo, open), [topo, open]);
  const severityCounts = useMemo(() => countBySeverity(hosts.map((h) => severitiesOf(h.severity_counts))), [hosts]);
  const levels = useMemo(() => LEVELS.filter((l) => severities.includes(l.sev)), [severities]);
  const worstShown = useCallback((h: TopologyHost) => levels.find((l) => h.severity_counts[l.key] > 0)?.sev ?? null, [levels]);

  const goal = target && graph.nodeOf.has(target) ? target : null;
  const way = useMemo(() => (goal ? findWay(graph, goal) : null), [graph, goal]);
  const machines = useMemo(() => [...graph.machines.values()], [graph]);
  const crowds = useMemo(() => graph.nodes.filter((n): n is WayCrowd => n.kind === "crowd"), [graph]);
  const litId = hovered ? machines.find((m) => m.bridge?.key === hovered.key)?.id ?? null : null;
  const lit = litId ? graph.nodeOf.get(litId) ?? litId : null;
  const machine = machineId ? graph.machines.get(machineId) ?? null : null;
  const crowd = crowds.find((c) => c.id === machineId) ?? null;
  const picked = machineId ? graph.nodeOf.get(machineId) ?? null : null;

  const hidden = useMemo<HiddenNet[]>(() => [...graph.nets.values()]
    .filter((n) => !n.group && n.scanners.length === 0)
    .map((n) => {
      const end = netEnd(n.key);
      const nameOf = (id: string) => {
        const node = graph.nodes.find((x) => x.id === id);
        return node?.kind === "machine" ? node.name : node?.kind === "crowd" ? `any of ${node.machines.length} machines` : undefined;
      };
      const via = graph.edges.filter((e) => e.a === end || e.b === end).map((e) => nameOf(e.a === end ? e.b : e.a)).find(Boolean);
      return { target: end, key: n.key, via: via ?? "a machine" };
    }), [graph]);

  const choices = useMemo(() => {
    const all = [...graph.nets.values()].filter((n) => n.scanners.length === 0).sort((a, b) => a.net.base - b.net.base || a.net.prefix - b.net.prefix);
    return { never: all.filter((n) => !n.group), scanned: all.filter((n) => n.group) };
  }, [graph]);

  if (files.length === 0) {
    return <EmptyFilesNotice page="topology" />;
  }

  const pick = (end: string | null) => {
    setMachineId(null);
    setTarget(end === target ? null : end);
    // a network folded into a block opens it, so the way ends at the network itself
    const home = end ? graph.nodeOf.get(end) : undefined;
    if (end && home && home !== end && !open.includes(home)) {
      toggleBlock(home);
    }
    if (end && !panel) {
      togglePanel();
    }
  };
  const showMachine = (id: string) => {
    setMachineId(id === machineId ? null : id);
    if (!panel) {
      togglePanel();
    }
  };
  const bridges = [...topo.bridges].sort((a, b) => strengthRank(b.strength) - strengthRank(a.strength) || machineScore(b, levels) - machineScore(a, levels));

  return (
    <div className="h-full min-h-[480px] flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityPills counts={severityCounts} selected={severities} onToggle={toggle} />
        <span className="flex-1" />
        <span className="inline-flex items-center gap-2 text-small text-ink-500 dark:text-ink-400">
          Attack path to
          <Select
            value={goal ?? ""}
            onChange={(v) => pick(v || null)}
            placeholder="a network…"
            ariaLabel="Attack path to"
            className="w-48"
            options={[
              ...choices.never.map((n) => ({ value: netEnd(n.key), label: n.key, group: "Never scanned" })),
              ...choices.scanned.map((n) => ({ value: netEnd(n.key), label: n.key, group: "Scanned" })),
            ]}
          />
        </span>
        {/* the view controls wrap as one group */}
        <span className="inline-flex items-center gap-2">
          <span className="inline-flex items-center h-8 rounded-lg border border-ink-200 dark:border-ink-700 bg-white dark:bg-ink-800 overflow-hidden">
            <button onClick={() => map.current?.zoomBy(1 / 1.25)} className={ICON_BUTTON} aria-label="Zoom out"><Minus size={14} /></button>
            <span className="w-12 text-center text-caption tabular-nums text-ink-600 dark:text-ink-300 border-x border-ink-200 dark:border-ink-700 leading-8">{Math.round(zoom * 100)}%</span>
            <button onClick={() => map.current?.zoomBy(1.25)} className={ICON_BUTTON} aria-label="Zoom in"><Plus size={14} /></button>
          </span>
          <button onClick={() => map.current?.fit()} className="btn-ghost h-8 w-8 p-0 justify-center" title="Show everything" aria-label="Fit"><Maximize2 size={15} /></button>
          <button
            onClick={() => {
              resetLayout();
              requestAnimationFrame(() => map.current?.fit());
            }}
            className="btn-ghost h-8 w-8 p-0 justify-center"
            title="Put every moved box back"
            aria-label="Reset layout"
          >
            <RotateCcw size={15} />
          </button>
        </span>
        <button
          onClick={togglePanel}
          aria-pressed={panel}
          className={`h-8 px-2.5 rounded-lg text-small font-medium inline-flex items-center gap-1.5 transition-colors ${
            panel ? "bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300" : "text-ink-600 dark:text-ink-300 hover:bg-ink-100 dark:hover:bg-ink-700"
          }`}
        >
          Machines on multiple networks <strong>{topo.bridges.length}</strong>
        </button>
      </div>

      <div className="flex-1 min-h-0 flex gap-3">
        <section className="card flex-1 min-w-0 flex flex-col overflow-hidden">
          <WaysMap ref={map} graph={graph} way={way} target={goal} lit={lit} picked={picked} worstShown={worstShown} onPick={pick} onMachine={showMachine} onZoom={setZoom} />
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 border-t border-ink-100 dark:border-ink-700/50 text-caption text-ink-500 dark:text-ink-400">
            <span className="flex items-center gap-1.5"><span className="w-4 h-3 rounded border border-ink-300 dark:border-ink-600 bg-white dark:bg-ink-800" />Network</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-high" />Machine that connects networks, coloured by its worst finding</span>
            <span className="flex items-center gap-1.5"><span className="relative w-4 h-3"><span className="absolute left-1 -top-0.5 w-3 h-3 rounded-full bg-high/50" /><span className="absolute left-0 top-0 w-3 h-3 rounded-full bg-high" /></span>Group of machines that all reach the same networks</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-medium" />Router</span>
            <span className="flex items-center gap-1.5"><span className="w-5 border-t-2 border-ink-300 dark:border-ink-600" />Confirmed</span>
            <span className="flex items-center gap-1.5"><span className="w-5 border-t-2 border-dashed border-ink-300 dark:border-ink-600" />Likely or possible</span>
            <span className="flex items-center gap-1.5"><span className="w-5 border-t-4 rounded border-accent-500" />Attack path</span>
            <span className="flex items-center gap-1.5"><span className="w-4 h-3 rounded border border-dashed border-ink-400" />Never scanned</span>
            <span className="ml-auto text-ink-500 dark:text-ink-400">Click a network for its attack path · drag to move · scroll to zoom</span>
          </div>
        </section>

        {panel && (
          <aside className="card w-[340px] shrink-0 flex flex-col overflow-hidden" aria-label={crowd ? "Group of machines" : machine ? "Machine" : goal ? "Attack path" : "Machines on more than one network"}>
            {crowd ? (
              <CrowdPanel crowd={crowd} graph={graph} levels={levels} worstShown={worstShown} onMachine={showMachine} onPick={pick} onClose={() => setMachineId(null)} onHide={togglePanel} />
            ) : machine ? (
              <MachinePanel machine={machine} levels={levels} worstShown={worstShown} onClose={() => setMachineId(graph.crowdOf.get(machine.id) ?? null)} onHide={togglePanel} />
            ) : goal ? (
              <WayPanel
                graph={graph}
                way={way}
                target={goal}
                levels={levels}
                worstShown={worstShown}
                hidden={hidden}
                onPick={pick}
                onMachine={showMachine}
                onClose={() => setTarget(null)}
                onHide={togglePanel}
              />
            ) : (
              <MachineList bridges={bridges} crowds={crowds} graph={graph} levels={levels} highlighted={hovered?.key ?? null} hidden={hidden} onPick={pick} onCrowd={showMachine} onHover={setHovered} onHide={togglePanel} />
            )}
          </aside>
        )}
      </div>

      <p className="text-caption text-ink-500 dark:text-ink-400">
        Hosts are placed by IP address, with a /24 network unless a real mask is known. Scans of unrelated networks that reuse the same addresses would share a network here.
      </p>
    </div>
  );
}// Topology
