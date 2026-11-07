import { useMemo, useState, useRef, useCallback, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { ChevronUp, ChevronDown, SlidersHorizontal, Check, Copy, AlertTriangle } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { buildHostEntries, SEVERITY_ORDER, SEVERITY_LABELS } from "../types/nessus";
import type { HostEntry } from "../types/nessus";
import { compareHosts } from "../utils/ip";
import { spreadsheetCell } from "../utils/spreadsheet";
import IpLink from "../components/common/IpLink";
import SearchBar from "../components/common/SearchBar";
import SpacerRow from "../components/common/SpacerRow";
import { useVirtualRows } from "../hooks/useVirtualRows";
import EmptyFilesNotice from "./EmptyFilesNotice";

// ── Column definitions ────────────────────────────────────────────────────────

type ColKey = "ip" | "hostname" | "os" | "system_type" | "netbios" | "mac" | "credentialed" |
              "critical" | "high" | "medium" | "low" | "info" | "ports";
type SortDir = "asc" | "desc";

interface ColDef {
  key: ColKey;
  label: string;
  required: boolean;
  defaultVisible: boolean;
  defaultWidth: number;
  align: "left" | "center";
}// ColDef

const COLUMNS: ColDef[] = [
  { key: "ip",           label: "IP Address",  required: true,  defaultVisible: true,  defaultWidth: 130, align: "left"   },
  { key: "hostname",     label: "Hostname",     required: true,  defaultVisible: true,  defaultWidth: 220, align: "left"   },
  { key: "os",           label: "OS",           required: false, defaultVisible: true,  defaultWidth: 200, align: "left"   },
  { key: "system_type",  label: "System Type",  required: false, defaultVisible: false, defaultWidth: 140, align: "left"   },
  { key: "netbios",      label: "NetBIOS",      required: false, defaultVisible: false, defaultWidth: 140, align: "left"   },
  { key: "mac",          label: "MAC Address",  required: false, defaultVisible: false, defaultWidth: 155, align: "left"   },
  { key: "credentialed", label: "Credentialed", required: false, defaultVisible: false, defaultWidth: 110, align: "center" },
  { key: "critical",     label: "Critical",     required: false, defaultVisible: true,  defaultWidth: 80,  align: "center" },
  { key: "high",         label: "High",         required: false, defaultVisible: true,  defaultWidth: 70,  align: "center" },
  { key: "medium",       label: "Medium",       required: false, defaultVisible: true,  defaultWidth: 80,  align: "center" },
  { key: "low",          label: "Low",          required: false, defaultVisible: true,  defaultWidth: 70,  align: "center" },
  { key: "info",         label: "Info",         required: false, defaultVisible: true,  defaultWidth: 70,  align: "center" },
  { key: "ports",        label: "Open Ports",   required: false, defaultVisible: true,  defaultWidth: 200, align: "left"   },
];// COLUMNS

const TEXT_SORT_KEYS: ColKey[] = ["ip", "hostname", "os", "system_type", "netbios", "mac"];

// ── Component ─────────────────────────────────────────────────────────────────

export default function Hosts() {
  const files = useScanStore((s) => s.files);
  const { openHostPanel, showInfo, toggleShowInfo } = useUiStore();
  const location = useLocation();

  const [search, setSearch] = useState("");
  const [fileFilter, setFileFilter] = useState<string>(
    (location.state as { fileFilter?: string } | null)?.fileFilter ?? "all"
  );
  const [severityFilter, setSeverityFilter] = useState<Set<number>>(new Set([4, 3, 2, 1]));
  const [sortKey, setSortKey] = useState<ColKey>("critical");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const [hiddenCols, setHiddenCols] = useState<Set<ColKey>>(
    () => new Set(COLUMNS.filter((c) => !c.defaultVisible).map((c) => c.key))
  );
  const [showColPicker, setShowColPicker] = useState(false);
  const [colWidths, setColWidths] = useState<Record<ColKey, number>>(
    () => Object.fromEntries(COLUMNS.map((c) => [c.key, c.defaultWidth])) as Record<ColKey, number>
  );

  const availableCols = useMemo(() => COLUMNS.filter((c) => c.key !== "info" || showInfo), [showInfo]);
  const visibleCols = useMemo(() => availableCols.filter((c) => !hiddenCols.has(c.key)), [availableCols, hiddenCols]);
  // Info column can be hidden while it is the sort column
  const activeSort = sortKey === "info" && !showInfo ? "critical" : sortKey;
  const resizeRef = useRef<{ col: ColKey; startX: number; startW: number } | null>(null);
  const colWidthsRef = useRef(colWidths);
  useEffect(() => { colWidthsRef.current = colWidths; }, [colWidths]);
  const wasResizingRef = useRef(false);
  const colPickerRef = useRef<HTMLDivElement>(null);

  // Resize mouse handlers
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      wasResizingRef.current = true;
      const { col, startX, startW } = resizeRef.current;
      setColWidths((prev) => ({ ...prev, [col]: Math.max(50, startW + e.clientX - startX) }));
    };
    const onUp = () => {
      resizeRef.current = null;
      // Reset after the click event fires
      if (wasResizingRef.current) setTimeout(() => { wasResizingRef.current = false; }, 0);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    return () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
  }, []);

  const startResize = useCallback((col: ColKey, e: React.MouseEvent) => {
    resizeRef.current = { col, startX: e.clientX, startW: colWidthsRef.current[col] };
  }, []);

  // Close column picker on outside click
  useEffect(() => {
    if (!showColPicker) {
      return;
    }

    const handler = (e: MouseEvent) => {
      if (colPickerRef.current && !colPickerRef.current.contains(e.target as Node)) {
        setShowColPicker(false);
      }
    };
    document.addEventListener("mousedown", handler);

    return () => document.removeEventListener("mousedown", handler);
  }, [showColPicker]);

  const toggleCol = (key: ColKey) => {
    if (COLUMNS.find((c) => c.key === key)?.required) {
      return;
    }
    setHiddenCols((prev) => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };

  // ── Data pipeline ───────────────────────────────────────────────────────────

  const filteredFiles = useMemo(
    () => (fileFilter === "all" ? files : files.filter((f) => f.id === fileFilter)),
    [files, fileFilter]
  );

  const allHosts = useMemo(() => buildHostEntries(filteredFiles), [filteredFiles]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return allHosts.filter((h) => {
      // hiding Info findings must not hide hosts. Most of the hosts have nothing else only info findings. Customer expects to find here
      const allRatingsOn = severityFilter.size === 4;
      if (!allRatingsOn && !h.items.some((i) => (i.severity === 0 ? showInfo : severityFilter.has(i.severity)))) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        h.ip.includes(q) ||
        (h.hostname?.toLowerCase().includes(q) ?? false) ||
        (h.domain?.toLowerCase().includes(q) ?? false) ||
        (h.os?.toLowerCase().includes(q) ?? false) ||
        (h.system_type?.toLowerCase().includes(q) ?? false) ||
        (h.netbios?.toLowerCase().includes(q) ?? false) ||
        h.alt_hostnames.some((n) => n.toLowerCase().includes(q)) ||
        h.open_ports.some((p) => p.includes(q))
      );
    });
  }, [allHosts, search, severityFilter, showInfo]);

  const sorted = useMemo(() => [...filtered].sort((a, b) => {
    let cmp = 0;
    switch (activeSort) {
      case "ip":           cmp = compareHosts(a.ip, b.ip); break;
      case "hostname":     cmp = (a.hostname ?? a.netbios ?? "").localeCompare(b.hostname ?? b.netbios ?? ""); break;
      case "os":           cmp = (a.os ?? "").localeCompare(b.os ?? ""); break;
      case "system_type":  cmp = (a.system_type ?? "").localeCompare(b.system_type ?? ""); break;
      case "netbios":      cmp = (a.netbios ?? "").localeCompare(b.netbios ?? ""); break;
      case "mac":          cmp = (a.mac ?? "").localeCompare(b.mac ?? ""); break;
      case "credentialed": cmp = Number(a.credentialed_scan) - Number(b.credentialed_scan); break;
      case "critical":     cmp = a.severity_counts.critical - b.severity_counts.critical; break;
      case "high":         cmp = a.severity_counts.high     - b.severity_counts.high;     break;
      case "medium":       cmp = a.severity_counts.medium   - b.severity_counts.medium;   break;
      case "low":          cmp = a.severity_counts.low      - b.severity_counts.low;      break;
      case "info":         cmp = a.severity_counts.info     - b.severity_counts.info;     break;
      case "ports":        cmp = a.open_ports.length        - b.open_ports.length;        break;
    }

    return sortDir === "desc" ? -cmp : cmp;
  }), [filtered, activeSort, sortDir]);

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow } = useVirtualRows(sorted.length);

  const toggleSort = (key: ColKey) => {
    if (wasResizingRef.current) {
      return;
    }
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    }
    else { 
      setSortKey(key); 
      setSortDir(TEXT_SORT_KEYS.includes(key) ? "asc" : "desc"); 
    }
  };

  const [copied, setCopied] = useState(false);
  const [showCopyMenu, setShowCopyMenu] = useState(false);
  const copyMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!showCopyMenu) {
      return;
    }
    const handler = (e: MouseEvent) => {
      if (copyMenuRef.current && !copyMenuRef.current.contains(e.target as Node)) {
        setShowCopyMenu(false);
      }
    };
    document.addEventListener("mousedown", handler);

    return () => document.removeEventListener("mousedown", handler);
  }, [showCopyMenu]);

  const copy = useCallback((mode: "ips" | "hostnames" | "visible") => {
    let text: string;
    if (mode === "ips") {
      text = sorted.map((h) => h.ip).join("\n");
    } else if (mode === "hostnames") {
      text = sorted.map((h) => h.hostname ?? h.netbios ?? h.ip).join("\n");
    } else {
      const headers = visibleCols.map((c) => c.label);
      const rows = sorted.map((h) =>
        visibleCols.map((col) => {
          switch (col.key) {
            case "ip":           return h.ip;
            case "hostname":     return h.hostname ?? h.netbios ?? "";
            case "os":           return h.os ?? "";
            case "system_type":  return h.system_type ?? "";
            case "netbios":      return h.netbios ?? "";
            case "mac":          return h.mac?.split(/[\n,]+/)[0].trim() ?? "";
            case "credentialed": return h.credentialed_scan ? "Yes" : "No";
            case "critical":     return h.severity_counts.critical.toString();
            case "high":         return h.severity_counts.high.toString();
            case "medium":       return h.severity_counts.medium.toString();
            case "low":          return h.severity_counts.low.toString();
            case "info":         return h.severity_counts.info.toString();
            case "ports":        return h.open_ports.map((p) => p.split("/")[0]).join(", ");
            default:             return "";
          }
        })
      );
      text = [headers, ...rows.map((r) => r.map(spreadsheetCell))].map((r) => r.join("\t")).join("\n");
    }
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setShowCopyMenu(false);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [sorted, visibleCols]);

  const toggleSeverity = (sev: number) => {
    if (sev === 0) {
      toggleShowInfo();
      return;
    }

    setSeverityFilter((prev) => { const n = new Set(prev); n.has(sev) ? n.delete(sev) : n.add(sev); return n; });
  };

  const countBySev = useMemo(() => {
    const c: Record<number, number> = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 };
    for (const h of allHosts) {
      if (h.severity_counts.critical > 0) c[4]++;
      if (h.severity_counts.high     > 0) c[3]++;
      if (h.severity_counts.medium   > 0) c[2]++;
      if (h.severity_counts.low      > 0) c[1]++;
      if (h.severity_counts.info     > 0) c[0]++;
    }

    return c;
  }, [allHosts]);

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters bar */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <div className="flex items-center gap-1.5 flex-wrap">
          {SEVERITY_ORDER.map((sev) => {
            const count = countBySev[sev] ?? 0;
            if (count === 0) return null;
            const active = sev === 0 ? showInfo : severityFilter.has(sev);
            const colors = {
              4: active ? "bg-critical text-white" : "bg-critical/10 text-critical",
              3: active ? "bg-high text-white"     : "bg-high/10 text-high",
              2: active ? "bg-medium text-white"   : "bg-medium/10 text-medium",
              1: active ? "bg-low text-white"      : "bg-low/10 text-low",
              0: active ? "bg-info text-white"     : "bg-info/10 text-info",
            }[sev];
            return (
              <button key={sev} onClick={() => toggleSeverity(sev)}
                className={`pill px-3 py-1 text-sm font-semibold cursor-pointer transition-colors ${colors}`}>
                {SEVERITY_LABELS[sev]} {count}
              </button>
            );
          })}
        </div>

        {files.length > 1 && (
          <select value={fileFilter} onChange={(e) => setFileFilter(e.target.value)}
            className="input h-8 py-0 text-xs w-auto">
            <option value="all">All files</option>
            {files.map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
        )}

        <SearchBar value={search} onChange={setSearch} placeholder="Search IP, hostname, OS, port…" className="flex-1 min-w-48" />

        {/* Column picker */}
        <div className="relative" ref={colPickerRef}>
          <button
            onClick={() => setShowColPicker((v) => !v)}
            title="Choose columns"
            className={`btn-ghost h-8 px-2.5 flex items-center gap-1.5 text-xs font-medium transition-colors ${
              showColPicker ? "bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200" : ""
            }`}
          >
            <SlidersHorizontal size={13} />
            Columns
          </button>
          {showColPicker && (
            <div className="absolute right-0 top-full mt-1 z-50 card p-1.5 w-44 shadow-xl">
              {availableCols.map((col) => {
                const visible = !hiddenCols.has(col.key);
                return (
                  <button
                    key={col.key}
                    onClick={() => toggleCol(col.key)}
                    disabled={col.required}
                    className={`w-full flex items-center gap-2.5 px-2 py-1.5 rounded text-sm text-left transition-colors ${
                      col.required
                        ? "opacity-40 cursor-not-allowed"
                        : "hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer"
                    }`}
                  >
                    <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                      visible ? "bg-violet-500 border-violet-500" : "border-slate-300 dark:border-slate-600"
                    }`}>
                      {visible && <Check size={10} className="text-white" strokeWidth={3} />}
                    </div>
                    <span className="text-slate-700 dark:text-slate-300">{col.label}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-slate-400">{sorted.length} hosts</span>
          {sorted.length > 0 && (
            <div className="relative" ref={copyMenuRef}>
              <button
                onClick={() => setShowCopyMenu((v) => !v)}
                className={`btn-ghost h-8 px-2.5 flex items-center gap-1.5 text-xs font-medium transition-colors ${
                  copied ? "text-low" : showCopyMenu ? "bg-slate-100 dark:bg-slate-700" : ""
                }`}
              >
                {copied ? <Check size={13} strokeWidth={2.5} /> : <Copy size={13} />}
                {copied ? "Copied!" : "Copy"}
                {!copied && <ChevronDown size={11} className="opacity-60" />}
              </button>
              {showCopyMenu && (
                <div className="absolute right-0 top-full mt-1 z-50 card p-1 w-52 shadow-xl">
                  <CopyMenuItem label="IP addresses" sub="one per line" onClick={() => copy("ips")} />
                  <CopyMenuItem label="Hostnames" sub="one per line" onClick={() => copy("hostnames")} />
                  <div className="my-1 border-t border-slate-100 dark:border-slate-700" />
                  <CopyMenuItem label="Visible columns" sub="TSV - pastes into Excel / Sheets" onClick={() => copy("visible")} />
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="card flex-1 overflow-hidden">
        <div ref={scrollRef} className="overflow-auto h-full">
          <table style={{ tableLayout: "fixed", width: "100%" }}>
            <colgroup>
              {visibleCols.map((col) => (
                <col key={col.key} style={{ width: colWidths[col.key] }} />
              ))}
            </colgroup>
            <thead className="sticky top-0 z-10">
              <tr>
                {visibleCols.map((col) => (
                  <Th
                    key={col.key}
                    col={col}
                    current={activeSort}
                    dir={sortDir}
                    onSort={toggleSort}
                    onResizeStart={startResize}
                  />
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              <SpacerRow height={paddingTop} colSpan={visibleCols.length} />
              {rows.map((row) => {
                const h = sorted[row.index];
                const fileId = fileFilter !== "all" ? fileFilter : undefined;
                return (
                  <HostRow
                    key={h.ip}
                    host={h}
                    visibleCols={visibleCols}
                    fileId={fileId}
                    index={row.index}
                    measureRow={measureRow}
                    onClick={() => openHostPanel(h.ip, fileId)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={visibleCols.length} />
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={visibleCols.length} className="table-cell text-center text-slate-400 py-10">
                    No hosts match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}// Hosts

// ── Table sub-components ──────────────────────────────────────────────────────

function HostRow({ host, visibleCols, fileId, index, measureRow, onClick }: {
  host: HostEntry;
  visibleCols: ColDef[];
  fileId?: string;
  index: number;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const sc = host.severity_counts;
  const portSample = host.open_ports.map((p) => p.split("/")[0]).slice(0, 8).join(", ");
  const extra = host.open_ports.length > 8 ? ` +${host.open_ports.length - 8}` : "";

  return (
    <tr ref={measureRow} data-index={index} className="table-row" onClick={onClick}>
      {visibleCols.map((col) => {
        switch (col.key) {
          case "ip":
            return <td key="ip" className="table-cell"><IpLink ip={host.ip} fileId={fileId} /></td>;

          case "hostname":
            return (
              <td key="hostname" className="table-cell text-slate-500">
                <span className="flex items-center gap-1.5">
                  <span className="truncate">{host.hostname ?? host.netbios ?? "-"}</span>
                  {host.conflicts.length > 0 && (
                    <span
                      className="shrink-0"
                      title={`Identity conflict: ${host.conflicts.join(", ")} differ across files`}
                    >
                      <AlertTriangle size={11} className="text-amber-500" />
                    </span>
                  )}
                  {host.file_ids.length > 1 && (
                    <span
                      className="shrink-0 text-[9px] font-bold uppercase tracking-wide px-1 py-px rounded bg-violet-100 dark:bg-violet-900/40 text-violet-600 dark:text-violet-400"
                      title={host.filenames.join("\n")}
                    >
                      {host.file_ids.length} files
                    </span>
                  )}
                </span>
                {host.domain && (
                  <span className="truncate block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                    {host.domain}
                  </span>
                )}
                {host.alt_hostnames.length > 0 && (
                  <span className="truncate block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                    {host.alt_hostnames.slice(0, 2).join(", ")}
                    {host.alt_hostnames.length > 2 ? ` +${host.alt_hostnames.length - 2}` : ""}
                  </span>
                )}
              </td>
            );

          case "os":
            return (
              <td key="os" className="table-cell text-slate-500">
                <span className="truncate block">{host.os ?? "-"}</span>
              </td>
            );

          case "system_type":
            return (
              <td key="system_type" className="table-cell text-slate-500">
                <span className="truncate block">{host.system_type ?? "-"}</span>
              </td>
            );

          case "netbios":
            return (
              <td key="netbios" className="table-cell text-slate-500">
                <span className="truncate block">{host.netbios ?? "-"}</span>
              </td>
            );

          case "mac":
            return (
              <td key="mac" className="table-cell font-mono text-xs text-slate-500">
                <span className="truncate block">{host.mac?.split(/[\n,]+/)[0].trim() ?? "-"}</span>
              </td>
            );

          case "credentialed":
            return (
              <td key="credentialed" className="table-cell text-center">
                <span className={`text-xs font-semibold ${host.credentialed_scan ? "text-low" : "text-slate-400 dark:text-slate-600"}`}>
                  {host.credentialed_scan ? "Yes" : "No"}
                </span>
              </td>
            );

          case "critical": return <td key="critical" className="table-cell text-center">{sc.critical > 0 ? <SevCount value={sc.critical} sev={4} /> : <Dash />}</td>;
          case "high":     return <td key="high"     className="table-cell text-center">{sc.high     > 0 ? <SevCount value={sc.high}     sev={3} /> : <Dash />}</td>;
          case "medium":   return <td key="medium"   className="table-cell text-center">{sc.medium   > 0 ? <SevCount value={sc.medium}   sev={2} /> : <Dash />}</td>;
          case "low":      return <td key="low"      className="table-cell text-center">{sc.low      > 0 ? <SevCount value={sc.low}      sev={1} /> : <Dash />}</td>;
          case "info":     return <td key="info"     className="table-cell text-center">{sc.info     > 0 ? <SevCount value={sc.info}     sev={0} /> : <Dash />}</td>;

          case "ports":
            return (
              <td key="ports" className="table-cell font-mono text-xs text-slate-500">
                <span className="truncate block">{portSample}{extra}</span>
              </td>
            );

          default: return null;
        }
      })}
    </tr>
  );
}// HostRow

function SevCount({ value, sev }: { value: number; sev: number }) {
  const color = { 4: "text-critical", 3: "text-high", 2: "text-medium", 1: "text-low", 0: "text-info" }[sev] ?? "text-info";
  return <span className={`font-semibold text-sm ${color}`}>{value}</span>;
}// SevCount

function Dash() {
  return <span className="text-slate-300 dark:text-slate-600">-</span>;
}// Dash

function Th({ col, current, dir, onSort, onResizeStart }: {
  col: ColDef;
  current: ColKey;
  dir: SortDir;
  onSort: (k: ColKey) => void;
  onResizeStart: (col: ColKey, e: React.MouseEvent) => void;
}) {
  const active = current === col.key;
  return (
    <th
      className={`relative px-4 py-3 text-xs uppercase tracking-wider select-none cursor-pointer transition-colors overflow-hidden ${
        col.align === "center" ? "text-center" : "text-left"
      } ${
        active
          ? "bg-violet-50 dark:bg-violet-900/20 text-violet-700 dark:text-violet-300 font-bold"
          : "bg-slate-50 dark:bg-slate-900/50 text-slate-500 dark:text-slate-400 font-semibold hover:text-slate-700 dark:hover:text-slate-200"
      }`}
      onClick={() => onSort(col.key)}
    >
      <span className={`flex items-center gap-1 ${col.align === "center" ? "justify-center" : ""}`}>
        {col.label}
        {active
          ? (dir === "desc" ? <ChevronDown size={12} /> : <ChevronUp size={12} />)
          : <ChevronDown size={12} className="opacity-30" />}
      </span>
      {/* Resize handle - always shows a subtle line, highlights on hover */}
      <div
        className="absolute right-0 top-0 bottom-0 w-3 flex items-center justify-center cursor-col-resize group z-10"
        onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); onResizeStart(col.key, e); }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="w-px h-4 rounded-full bg-slate-300 dark:bg-slate-600 group-hover:bg-violet-500 group-hover:w-0.5 transition-all" />
      </div>
    </th>
  );
}// Th

function CopyMenuItem({ label, sub, onClick }: { label: string; sub: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full flex flex-col items-start px-3 py-2 rounded text-left hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
    >
      <span className="text-sm text-slate-700 dark:text-slate-200 font-medium">{label}</span>
      <span className="text-[11px] text-slate-400 dark:text-slate-500">{sub}</span>
    </button>
  );
}// CopyMenuItem
