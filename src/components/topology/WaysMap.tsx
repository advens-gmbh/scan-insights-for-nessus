import { forwardRef, useCallback, useEffect, useImperativeHandle, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent as ReactPointerEvent, ReactNode } from "react";
import { ChevronDown, ChevronUp, Monitor, Router } from "lucide-react";
import type { HostEntry } from "../../types/nessus";
import type { Link, ScannerNode, WayCrowd, WayEdge, WayGraph, WayMachine, WayNet, WayNode } from "../../utils/topology";
import { useUiStore } from "../../stores/uiStore";
import { useScanStore } from "../../stores/scanStore";
import { usePageState } from "../../stores/pageStore";

export const SEVERITY_BG = ["bg-info", "bg-low", "bg-medium", "bg-high", "bg-critical"];

const NET_W = 184;
const NET_H = 62;
const START_H = 22;      // the "Nessus" badge
const NEVER_H = 52;
const BLOCK_W = 224;
const HEAT = 9;          // one network in a folded block's strip
const HEAT_ROW = 20;
const CELL_W = 172;
const CELL_H = 66;
const CELL_GAP = 8;
const FRAME_HEAD = 40;
const MACHINE_W = 128;
const MACHINE_H = 78;
const RING = 36;
const COL_GAP = 64;
const ROW_GAP = 16;
const HEAD = 28;         // room for the column titles
const MIN_ZOOM = 0.15;
const MAX_ZOOM = 2.5;
const FIRST_ZOOM = 0.5;  // a big map opens readable at the top left instead of tiny

type Box = { x: number; y: number; w: number; h: number };

interface Placed {
  node: WayNode;
  box: Box;
  cells: Map<string, Box>; // an open block's networks, relative to its box
}// Placed

export interface WaysControls {
  fit: () => void;
  zoomBy: (factor: number) => void;
}// WaysControls

interface Props {
  graph: WayGraph;
  way: { nodes: string[]; edges: WayEdge[] } | null;
  target: string | null;
  lit: string | null;                           // a hovered machine
  picked: string | null;                        // the machine shown in the side panel
  worstShown: (h: HostEntry) => number | null;
  onPick: (target: string) => void;
  onMachine: (id: string) => void;
  onZoom: (k: number) => void;
}// Props

const isNever = (n: WayNet) => !n.group && n.scanners.length === 0;
const isMachine = (n: WayNode) => n.kind === "machine" || n.kind === "crowd";

function cellsOf(count: number) {
  const cols = count <= 3 ? count : Math.min(4, Math.ceil(Math.sqrt(count)));
  return { cols, rows: Math.ceil(count / cols) };
}// cellsOf

function sizeOf(n: WayNode): { w: number; h: number } {
  switch (n.kind) {
    case "net":
      return { w: NET_W, h: (isNever(n.net) ? NEVER_H : NET_H) + (n.net.scanners.length ? START_H : 0) };
    case "scanner":
      return { w: NET_W, h: NET_H };
    case "machine":
    case "crowd":
      return { w: MACHINE_W, h: MACHINE_H };
    case "block": {
      if (!n.open) {
        return { w: BLOCK_W, h: 96 + Math.ceil(n.block.nets.length / HEAT_ROW) * HEAT };
      }
      const { cols, rows } = cellsOf(n.block.nets.length);
      return { w: cols * (CELL_W + CELL_GAP) + CELL_GAP + 4, h: FRAME_HEAD + rows * (CELL_H + CELL_GAP) + 6 };
    }
  }
}// sizeOf

const rank = (n: WayNode) => (n.kind === "net" && isNever(n.net) ? 2 : isMachine(n) ? 1 : 0);

function layout(graph: WayGraph) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const near = new Map<string, Set<string>>();
  for (const e of graph.edges) {
    const a = graph.nodeOf.get(e.a)!;
    const b = graph.nodeOf.get(e.b)!;
    if (a !== b) {
      near.set(a, (near.get(a) ?? new Set()).add(b));
      near.set(b, (near.get(b) ?? new Set()).add(a));
    }
  }
  const depth = new Map<string, number>();
  const kids = new Map<string, string[]>();
  const queue = graph.starts.map((s) => graph.nodeOf.get(s)!);
  queue.forEach((s) => depth.set(s, 0));
  while (queue.length) {
    const id = queue.shift()!;
    const next = [...(near.get(id) ?? [])].filter((n) => !depth.has(n)).sort((a, b) => rank(byId.get(a)!) - rank(byId.get(b)!));
    for (const n of next) {
      depth.set(n, depth.get(id)! + 1);
      kids.set(id, [...(kids.get(id) ?? []), n]);
      queue.push(n);
    }
  }
  graph.nodes.filter((n) => !depth.has(n.id)).forEach((n) => depth.set(n.id, 0));

  const sizes = new Map(graph.nodes.map((n) => [n.id, sizeOf(n)]));
  const ys = new Map<string, number>();
  let cursor = 0;
  const place = (id: string): number => {
    const { h } = sizes.get(id)!;
    const children = kids.get(id) ?? [];
    if (children.length === 0) {
      ys.set(id, cursor);
      cursor += h + ROW_GAP;
      return cursor - ROW_GAP - h / 2;
    }
    const centres = children.map(place);
    const mid = (Math.min(...centres) + Math.max(...centres)) / 2;
    ys.set(id, mid - h / 2);
    cursor = Math.max(cursor, mid + h / 2 + ROW_GAP);
    return mid;
  };
  const roots = [...new Set([...graph.starts.map((s) => graph.nodeOf.get(s)!), ...graph.nodes.filter((n) => depth.get(n.id) === 0).map((n) => n.id)])];
  roots.forEach((r) => {
    place(r);
    cursor += ROW_GAP;
  });

  const columns: string[][] = [];
  graph.nodes.forEach((n) => (columns[depth.get(n.id)!] ??= []).push(n.id));
  const xs: number[] = [];
  columns.forEach((ids, c) => {
    xs[c] = c === 0 ? 0 : xs[c - 1] + Math.max(...(columns[c - 1] ?? []).map((id) => sizes.get(id)!.w), 0) + COL_GAP;
    ids.sort((a, b) => ys.get(a)! - ys.get(b)!);
    ids.forEach((id, i) => {
      if (i > 0) {
        const prev = ids[i - 1];
        ys.set(id, Math.max(ys.get(id)!, ys.get(prev)! + sizes.get(prev)!.h + ROW_GAP));
      }
    });
  });
  const top = Math.min(0, ...ys.values());

  const placed = new Map<string, Placed>();
  for (const n of graph.nodes) {
    const c = depth.get(n.id)!;
    const { w, h } = sizes.get(n.id)!;
    const cells = new Map<string, Box>();
    if (n.kind === "block" && n.open) {
      const { cols } = cellsOf(n.block.nets.length);
      n.block.nets.forEach((net, i) => cells.set(`net:${net.key}`, {
        x: CELL_GAP + 2 + (i % cols) * (CELL_W + CELL_GAP), y: FRAME_HEAD + Math.floor(i / cols) * (CELL_H + CELL_GAP), w: CELL_W, h: CELL_H,
      }));
    }
    const x = isMachine(n) ? xs[c] + (Math.max(...columns[c].map((id) => sizes.get(id)!.w)) - w) / 2 : xs[c];
    placed.set(n.id, { node: n, box: { x, y: HEAD + ys.get(n.id)! - top, w, h }, cells });
  }

  let steps = 0;
  const titles = columns.map((ids, c) => {
    const nets = ids.some((id) => !isMachine(byId.get(id)!));
    const machines = ids.some((id) => isMachine(byId.get(id)!));
    const title = !nets ? null : c === 0 ? "Where Nessus is" : steps === 0 ? "Next to the scanner" : `${steps} ${steps === 1 ? "step" : "steps"} away`;
    if (machines) {
      steps++;
    }
    return { x: xs[c], title };
  });

  return { placed, titles };
}// layout

function linkStyle(link: Link) {
  return link === "likely" || link === "possible" ? "6 5" : link === "unknown" ? "3 5" : undefined;
}// linkStyle

const WaysMap = forwardRef<WaysControls, Props>(function WaysMap({ graph, way, target, lit, picked, worstShown, onPick, onMachine, onZoom }, ref) {
  const openFilePanel = useUiStore((s) => s.openFilePanel);
  const toggleBlock = useUiStore((s) => s.toggleTopologyBlock);
  const moved = useUiStore((s) => s.topologyMoved);
  const move = useUiStore((s) => s.moveTopologyNode);
  const files = useScanStore((s) => s.files);
  const fileName = useCallback((id: string) => files.find((f) => f.id === id)?.filename.replace(/\.nessus$/i, "") ?? "", [files]);

  const { placed, titles } = useMemo(() => layout(graph), [graph]);
  const boxOf = useCallback((id: string): Box => {
    const p = placed.get(id)!;
    const d = moved[id];
    return d ? { ...p.box, x: p.box.x + d.x, y: p.box.y + d.y } : p.box;
  }, [placed, moved]);

  // pan and zoom
  const frame = useRef<HTMLDivElement>(null);
  // where the map was left, kept while the same files are loaded
  const loaded = graph.starts.join("|") + graph.nets.size;
  const [saved, save] = usePageState<{ loaded: string; x: number; y: number; k: number } | null>("topology:view", null);
  const restored = useRef(saved?.loaded === loaded);
  const [view, setView] = useState(() => (saved?.loaded === loaded ? { x: saved.x, y: saved.y, k: saved.k } : { x: 20, y: 10, k: 1 }));
  useEffect(() => save({ loaded, ...view }), [loaded, view, save]);
  const viewRef = useRef(view);
  useLayoutEffect(() => {
    viewRef.current = view;
  }, [view]);
  useEffect(() => onZoom(view.k), [view.k, onZoom]);

  const fit = useCallback((floor = MIN_ZOOM) => {
    const el = frame.current;
    if (!el || placed.size === 0) {
      return;
    }
    const boxes = [...placed.keys()].map(boxOf);
    const maxX = Math.max(...boxes.map((b) => b.x + b.w)) + 70;
    const maxY = Math.max(...boxes.map((b) => b.y + b.h)) + 20;
    const k = Math.max(floor, Math.min(1, (el.clientWidth - 30) / maxX, (el.clientHeight - 20) / maxY));
    setView({ x: Math.max(15, (el.clientWidth - maxX * k) / 2), y: 10, k });
  }, [placed, boxOf]);

  const zoomAt = useCallback((factor: number, cx: number, cy: number) => {
    const v = viewRef.current;
    const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.k * factor));
    setView({ k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k });
  }, []);

  useImperativeHandle(ref, () => ({
    fit: () => fit(),
    zoomBy: (factor) => {
      const el = frame.current;
      zoomAt(factor, el ? el.clientWidth / 2 : 0, el ? el.clientHeight / 2 : 0);
    },
  }), [fit, zoomAt]);

  // fit when other files are loaded, not when a block opens or a box is dragged
  const fitRef = useRef(fit);
  useLayoutEffect(() => {
    fitRef.current = fit;
  }, [fit]);
  useLayoutEffect(() => {
    if (restored.current) {
      restored.current = false;
      return;
    }
    fitRef.current(FIRST_ZOOM);
  }, [loaded]);

  useEffect(() => {
    const el = frame.current;
    if (!el) {
      return;
    }
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  const drag = useRef<{ id: string | null; startX: number; startY: number; base: { x: number; y: number }; moved: boolean } | null>(null);
  const suppressClick = useRef(false);
  const startDrag = (e: ReactPointerEvent, id: string | null) => {
    if (e.button !== 0) {
      return;
    }
    e.stopPropagation();
    suppressClick.current = false;
    window.getSelection()?.removeAllRanges();
    if (!id) {
      e.currentTarget.setPointerCapture(e.pointerId);
    }
    const base = id ? moved[id] ?? { x: 0, y: 0 } : { x: viewRef.current.x, y: viewRef.current.y };
    drag.current = { id, startX: e.clientX, startY: e.clientY, base, moved: false };
  };
  const onMove = (e: ReactPointerEvent) => {
    const d = drag.current;
    if (!d) {
      return;
    }
    const dx = e.clientX - d.startX;
    const dy = e.clientY - d.startY;
    if (!d.moved && Math.hypot(dx, dy) < 4) {
      return;
    }
    if (!d.moved && d.id) {
      e.currentTarget.setPointerCapture(e.pointerId);
    }
    d.moved = true;
    if (d.id) {
      move(d.id, { x: d.base.x + dx / viewRef.current.k, y: d.base.y + dy / viewRef.current.k });
    } else {
      setView((v) => ({ ...v, x: d.base.x + dx, y: d.base.y + dy }));
    }
  };
  const endDrag = () => {
    suppressClick.current = !!drag.current?.moved && !!drag.current.id;
    drag.current = null;
  };
  const draggable = (id: string) => ({
    onPointerDown: (e: ReactPointerEvent) => startDrag(e, id),
    onClickCapture: (e: React.MouseEvent) => {
      if (suppressClick.current) {
        e.stopPropagation();
        e.preventDefault();
        suppressClick.current = false;
      }
    },
  });

  const anchor = (end: string) => {
    const id = graph.nodeOf.get(end)!;
    const p = placed.get(id)!;
    const b = boxOf(id);
    const cell = p.cells.get(end);
    if (cell) {
      return { id: `${id}|${end}`, x: b.x + cell.x, y: b.y + cell.y, w: cell.w, h: cell.h, mid: b.y + cell.y + 20 };
    }
    if (isMachine(p.node)) {
      return { id, x: b.x + (b.w - RING) / 2, y: b.y, w: RING, h: RING, mid: b.y + RING / 2 };
    }
    return { id, ...b, mid: b.y + (p.node.kind === "net" && p.node.net.scanners.length ? START_H : 0) + 22 };
  };
  const pairKey = (e: WayEdge) => [anchor(e.a).id, anchor(e.b).id].sort().join("~");
  const onWay = new Set((way?.edges ?? []).map(pairKey));
  const litEdges = new Set(lit ? graph.edges.filter((e) => e.a === lit || e.b === lit).map(pairKey) : []);

  const lines = new Map<string, ReactNode>();
  for (const e of graph.edges) {
    const key = pairKey(e);
    if (lines.has(key)) {
      continue;
    }
    let p = anchor(e.a);
    let q = anchor(e.b);
    if (p.x > q.x) {
      [p, q] = [q, p];
    }
    let d: string;
    if (q.x - (p.x + p.w) < 20) {
      const out = Math.max(p.x + p.w, q.x + q.w) + 30;
      d = `M${p.x + p.w},${p.mid} C${out},${p.mid} ${out},${q.mid} ${q.x + q.w},${q.mid}`;
    } else {
      const sx = p.x + p.w;
      const mx = (sx + q.x) / 2;
      d = `M${sx},${p.mid} C${mx},${p.mid} ${mx},${q.mid} ${q.x},${q.mid}`;
    }
    const strong = onWay.has(key);
    lines.set(key, (
      <path
        key={key}
        d={d}
        fill="none"
        strokeWidth={strong ? 4 : litEdges.has(key) ? 3 : 1.6}
        strokeLinecap="round"
        strokeDasharray={strong ? undefined : linkStyle(e.link)}
        className={strong || litEdges.has(key) ? "stroke-accent-500" : "stroke-ink-300 dark:stroke-ink-600"}
      />
    ));
  }

  const below = [...lines.entries()].filter(([k]) => !onWay.has(k)).map(([, l]) => l);
  const above = [...lines.entries()].filter(([k]) => onWay.has(k)).map(([, l]) => l);

  const onWayNode = new Set(way?.nodes ?? []);
  const worstOf = (hosts: HostEntry[]) => hosts.reduce<number | null>((w, h) => {
    const s = worstShown(h);
    return s !== null && (w === null || s > w) ? s : w;
  }, null);
  const bar = (hosts: HostEntry[]) => {
    const counts = [0, 0, 0, 0, 0];
    hosts.forEach((h) => {
      const s = worstShown(h);
      if (s !== null) {
        counts[s]++;
      }
    });
    return (
      <span className="flex gap-0.5 h-1.5 mt-1.5 rounded-full overflow-hidden bg-ink-100 dark:bg-ink-700">
        {[4, 3, 2, 1, 0].map((s) => counts[s] > 0 && <span key={s} className={SEVERITY_BG[s]} style={{ flex: counts[s] }} />)}
      </span>
    );
  };
  const ring = (id: string) =>
    target && graph.nodeOf.get(target) === id && !placed.get(id)!.cells.has(target)
      ? "ring-4 ring-accent-500/70"
      : onWayNode.has(id) ? "ring-2 ring-accent-500" : "";

  const fileLink = (roots: ScannerNode[]) => {
    const ids = [...new Set(roots.flatMap((r) => r.fileIds))];
    return (
      <button
        onClick={(e) => {
          e.stopPropagation();
          if (ids[0]) {
            openFilePanel(ids[0]);
          }
        }}
        title="Open the scan file"
        className="min-w-0 truncate text-caption text-accent-700 dark:text-accent-400 hover:underline"
      >
        {ids.length === 1 ? fileName(ids[0]) : `${ids.length} scan files`}
      </button>
    );
  };

  const netCard = (n: WayNet, id: string, box: Box, extra: string) => {
    const hosts = n.group?.hosts ?? [];
    const shown = hosts.filter((h) => worstShown(h) !== null).length;
    const nessus = n.scanners.map((s) => s.scanner).join(", ");
    return (
      <div
        key={id}
        role="button"
        tabIndex={0}
        data-net={n.key}
        onClick={() => onPick(`net:${n.key}`)}
        onKeyDown={(e) => e.key === "Enter" && onPick(`net:${n.key}`)}
        title={n.reasons.map((r) => r.text).join("\n") || undefined}
        className={`absolute flex flex-col items-stretch text-left rounded-[10px] px-2.5 py-2 cursor-pointer select-none ${
          isNever(n) ? "border-[1.5px] border-dashed border-ink-400 dark:border-ink-500 bg-ink-50/70 dark:bg-ink-900/50" : "border border-ink-200 dark:border-ink-600 bg-white dark:bg-ink-800 shadow-sm"
        } ${extra}`}
        style={{ left: box.x, top: box.y, width: box.w, height: box.h }}
      >
        {n.scanners.length > 0 && (
          <span className="flex items-center gap-1.5 mb-1 min-w-0">
            <span className="shrink-0 px-2 rounded-full bg-accent-600 text-white text-tiny font-bold leading-[18px]">Nessus</span>
            {fileLink(n.scanners)}
          </span>
        )}
        <span className={`text-body font-semibold tabular-nums ${isNever(n) ? "text-ink-500 dark:text-ink-400" : "text-ink-800 dark:text-ink-100"}`}>{n.key}</span>
        <span className="text-caption text-ink-500 dark:text-ink-400 truncate">
          {n.group
            ? `${shown === hosts.length ? hosts.length : `${shown} of ${hosts.length}`} ${hosts.length === 1 ? "host" : "hosts"}${nessus ? ` · Nessus ${nessus}` : ""}`
            : nessus ? `Nessus ${nessus} · not scanned` : "never scanned"}
        </span>
        {n.group && bar(hosts)}
      </div>
    );
  };

  const render = (p: Placed): ReactNode => {
    const n = p.node;
    const b = boxOf(n.id);
    const drag = draggable(n.id);
    switch (n.kind) {
      case "net":
        return <div key={n.id} {...drag} className="contents">{netCard(n.net, n.id, b, ring(n.id))}</div>;
      case "scanner": {
        return (
          <div
            key={n.id}
            {...drag}
            className="absolute flex flex-col text-left rounded-[10px] border border-dashed border-ink-300 dark:border-ink-500 bg-white dark:bg-ink-800 px-2.5 py-2 select-none"
            style={{ left: b.x, top: b.y, width: b.w, height: b.h }}
          >
            <span className="flex items-center gap-1.5 min-w-0">
              <span className="shrink-0 px-2 rounded-full bg-accent-600 text-white text-tiny font-bold leading-[18px]">Nessus</span>
              {fileLink([n.root])}
            </span>
            <span className="mt-1 text-caption text-ink-500 dark:text-ink-400">address unknown</span>
          </div>
        );
      }
      case "machine":
        return <Machine key={n.id} m={n} box={b} worst={worstOf(n.hosts)} ring={picked === n.id ? "ring-4 ring-accent-500/70" : ring(n.id) || (lit === n.id ? "ring-2 ring-accent-500" : "")} drag={drag} onOpen={() => onMachine(n.id)} />;
      case "crowd":
        return <Crowd key={n.id} c={n} box={b} worst={worstOf(n.machines.flatMap((m) => m.hosts))} ring={picked === n.id ? "ring-4 ring-accent-500/70" : ring(n.id) || (lit === n.id ? "ring-2 ring-accent-500" : "")} drag={drag} onOpen={() => onMachine(n.id)} />;
      case "block": {
        const nets = n.block.nets;
        const hosts = nets.flatMap((x) => x.group?.hosts ?? []);
        const head = (
          <>
            <span className="flex items-center gap-2 whitespace-nowrap">
              <span className="text-body font-semibold tabular-nums text-ink-800 dark:text-ink-100">{n.block.key}</span>
              {n.block.from === "routing table" && <span className="px-1.5 rounded bg-ink-100 dark:bg-ink-700 text-tiny font-semibold text-ink-600 dark:text-ink-300">routing table</span>}
            </span>
            <span className="text-caption text-ink-500 dark:text-ink-400">{nets.length} networks · {hosts.length} hosts</span>
          </>
        );
        const toggle = (
          <button
            onClick={(e) => {
              e.stopPropagation();
              toggleBlock(n.id);
            }}
            className="inline-flex items-center gap-1 h-6 px-2 rounded-md bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300 text-caption font-semibold hover:bg-accent-100 dark:hover:bg-accent-900/50"
          >
            {n.open ? <><ChevronUp size={13} /> Fold</> : <><ChevronDown size={13} /> Show {nets.length} networks</>}
          </button>
        );
        if (!n.open) {
          return (
            <div
              key={n.id}
              {...drag}
              role="button"
              tabIndex={0}
              data-block={n.block.key}
              onClick={() => onPick(n.id)}
              onKeyDown={(e) => e.key === "Enter" && onPick(n.id)}
              className={`absolute flex flex-col rounded-[10px] border border-ink-200 dark:border-ink-600 bg-white dark:bg-ink-800 shadow-sm px-2.5 py-2 text-left cursor-pointer select-none ${ring(n.id)}`}
              style={{ left: b.x, top: b.y, width: b.w, height: b.h }}
            >
              {head}
              {bar(hosts)}
              <span className="flex flex-wrap gap-0.5 mt-1.5" aria-hidden="true">
                {nets.map((x) => {
                  const w = worstOf(x.group?.hosts ?? []);
                  return <i key={x.key} className={`w-[7px] h-[7px] rounded-[2px] ${w === null ? "bg-ink-100 dark:bg-ink-700" : SEVERITY_BG[w]}`} />;
                })}
              </span>
              <span className="mt-auto pt-1.5">{toggle}</span>
            </div>
          );
        }
        return (
          <div
            key={n.id}
            {...drag}
            data-block={n.block.key}
            className={`absolute rounded-xl border border-dashed border-accent-500/60 bg-accent-50/30 dark:bg-accent-900/10 select-none ${ring(n.id)}`}
            style={{ left: b.x, top: b.y, width: b.w, height: b.h }}
          >
            <div className="flex items-center gap-2 h-[40px] px-3">
              {head}
              <span className="ml-auto">{toggle}</span>
            </div>
            {nets.map((x) => {
              const c = p.cells.get(`net:${x.key}`)!;
              return netCard(x, x.key, c, target === `net:${x.key}` ? "ring-4 ring-accent-500/70" : onWay.size && way?.edges.some((e) => e.a === `net:${x.key}` || e.b === `net:${x.key}`) ? "ring-2 ring-accent-500" : "");
            })}
          </div>
        );
      }
    }
  };

  return (
    <div
      ref={frame}
      className="relative flex-1 min-h-0 overflow-hidden select-none cursor-grab active:cursor-grabbing touch-none bg-[radial-gradient(theme(colors.ink.200)_1px,transparent_1px)] dark:bg-[radial-gradient(theme(colors.ink.700)_1px,transparent_1px)] [background-size:20px_20px]"
      onPointerDown={(e) => startDrag(e, null)}
      onPointerMove={onMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onLostPointerCapture={endDrag}
      onDragStart={(e) => e.preventDefault()}
    >
      <div className="absolute left-0 top-0 origin-top-left" style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})` }}>
        {titles.map((t, i) => t.title && (
          <span key={i} className="absolute top-0 text-caption font-semibold text-ink-500 dark:text-ink-400 whitespace-nowrap" style={{ left: t.x }}>{t.title}</span>
        ))}
        <svg width={1} height={1} className="absolute left-0 top-0 overflow-visible" aria-hidden="true">{below}</svg>
        {[...placed.values()].map(render)}
        {above.length > 0 && <svg width={1} height={1} className="absolute left-0 top-0 overflow-visible pointer-events-none" aria-hidden="true">{above}</svg>}
      </div>
    </div>
  );
});

export default WaysMap;

export function crowdReach(c: WayCrowd): string {
  return c.reach.length === 1 ? c.reach[0].replace(/^net:/, "") : `${c.reach.length} networks`;
}// crowdReach

export function machineNote(m: WayMachine): string {
  if (m.router) {
    const more = m.hops - 1;
    return more > 0 ? `+ ${more} more ${more === 1 ? "router" : "routers"} in a row` : m.name === m.ips[0] ? "router" : `router · ${m.ips[0] ?? "no answer"}`;
  }
  const ev = m.bridge?.evidence[0] ?? "";
  const count = m.bridge?.nets.length ?? 0;
  if (ev.startsWith("Network cards")) {
    return `${m.bridge!.addresses.length} network cards`;
  }
  if (ev.startsWith("Its routing table")) {
    return `knows ${count} networks`;
  }
  if (ev.startsWith("Same MAC")) {
    return `same MAC on ${count} networks`;
  }
  if (ev.startsWith("Same NetBIOS")) {
    return `same name on ${count} networks`;
  }
  return m.talks.length ? "talks to a network nobody scanned" : m.ips[0] ?? "";
}// machineNote

function Machine({ m, box, worst, ring, drag, onOpen }: {
  m: WayMachine;
  box: Box;
  worst: number | null;
  ring: string;
  drag: { onPointerDown: (e: ReactPointerEvent) => void; onClickCapture: (e: React.MouseEvent) => void };
  onOpen: () => void;
}) {
  const Icon = m.router ? Router : Monitor;
  return (
    <div {...drag} className="absolute flex flex-col items-center text-center select-none" style={{ left: box.x, top: box.y, width: box.w }}>
      <button
        onClick={onOpen}
        title={m.hopList.length > 1 ? m.hopList.map((h) => (h === "?" ? "no answer" : h)).join(" → ") : m.ips.join(", ")}
        aria-label={m.name}
        className={`flex items-center justify-center w-9 h-9 text-white ring-offset-2 ring-offset-white dark:ring-offset-ink-900 ${m.router ? "rounded-[10px]" : "rounded-full"} ${
          worst === null ? "bg-ink-300 dark:bg-ink-600" : SEVERITY_BG[worst]
        } ${ring}`}
      >
        <Icon size={18} strokeWidth={2.2} />
      </button>
      <span className="mt-1 text-caption font-semibold leading-4 text-ink-800 dark:text-ink-100 max-w-full truncate">{m.name}</span>
      <span className="text-tiny leading-[14px] text-ink-500 dark:text-ink-400 max-w-full truncate">{machineNote(m)}</span>
    </div>
  );
}// Machine

// several machines drawn as one. a stack of circles with their number
function Crowd({ c, box, worst, ring, drag, onOpen }: {
  c: WayCrowd;
  box: Box;
  worst: number | null;
  ring: string;
  drag: { onPointerDown: (e: ReactPointerEvent) => void; onClickCapture: (e: React.MouseEvent) => void };
  onOpen: () => void;
}) {
  const fill = worst === null ? "bg-ink-300 dark:bg-ink-600" : SEVERITY_BG[worst];
  return (
    <div {...drag} className="absolute flex flex-col items-center text-center select-none" style={{ left: box.x, top: box.y, width: box.w }}>
      <span className="relative w-9 h-9">
        <span className={`absolute inset-0 translate-x-[7px] -translate-y-[5px] rounded-full opacity-35 ${fill}`} aria-hidden="true" />
        <span className={`absolute inset-0 translate-x-[3.5px] -translate-y-[2.5px] rounded-full opacity-60 ${fill}`} aria-hidden="true" />
        <button
          onClick={onOpen}
          title={`${c.machines.length} machines, each in its own network, that all reach ${crowdReach(c)}`}
          aria-label={`${c.machines.length} machines`}
          className={`absolute inset-0 flex items-center justify-center rounded-full text-white text-caption font-bold tabular-nums ring-offset-2 ring-offset-white dark:ring-offset-ink-900 ${fill} ${ring}`}
        >
          {c.machines.length > 999 ? "999+" : c.machines.length}
        </button>
      </span>
      <span className="mt-1 text-caption font-semibold leading-4 text-ink-800 dark:text-ink-100 max-w-full truncate">{c.machines.length} machines</span>
      <span className="text-tiny leading-[14px] text-ink-500 dark:text-ink-400 max-w-full truncate">all reach {crowdReach(c)}</span>
    </div>
  );
}// Crowd
