import { useMemo, useState, useRef, useCallback, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { ChevronDown, Check, Copy, AlertTriangle } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { buildHostEntries, osGuesses } from "../types/nessus";
import type { HostEntry } from "../types/nessus";
import { compareHosts } from "../utils/ip";
import { countBySeverity, severitiesOf } from "../utils/severityFilter";
import { spreadsheetCell } from "../utils/spreadsheet";
import IpLink from "../components/common/IpLink";
import SearchBar from "../components/common/SearchBar";
import SpacerRow from "../components/common/SpacerRow";
import ColumnPicker from "../components/common/ColumnPicker";
import SeverityPills from "../components/common/SeverityPills";
import TableHead from "../components/common/TableHead";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { useTableSort } from "../hooks/useTableSort";
import { usePageState } from "../stores/pageStore";
import { useVirtualRows } from "../hooks/useVirtualRows";
import type { TableColumn } from "../utils/tableColumns";
import EmptyFilesNotice from "./EmptyFilesNotice";
import { Tag } from "../panels/PanelParts";

// ── Column definitions ────────────────────────────────────────────────────────

type ColKey = "ip" | "hostname" | "os" | "system_type" | "netbios" | "mac" | "credentialed" |
              "critical" | "high" | "medium" | "low" | "info" | "ports";

type ColDef = TableColumn<ColKey>;

const COLUMNS: ColDef[] = [
  { key: "ip",           label: "IP Address",   width: 130, required: true },
  { key: "hostname",     label: "Hostname",     width: 220, required: true },
  { key: "os",           label: "OS",           width: 200 },
  { key: "system_type",  label: "System Type",  width: 140, defaultHidden: true },
  { key: "netbios",      label: "NetBIOS",      width: 140, defaultHidden: true },
  { key: "mac",          label: "MAC Address",  width: 155, defaultHidden: true },
  { key: "credentialed", label: "Credentialed", width: 110, defaultHidden: true, align: "center" },
  { key: "critical",     label: "Critical",     width: 96,  align: "center", dot: "bg-critical" },
  { key: "high",         label: "High",         width: 80,  align: "center", dot: "bg-high" },
  { key: "medium",       label: "Medium",       width: 96,  align: "center", dot: "bg-medium" },
  { key: "low",          label: "Low",          width: 76,  align: "center", dot: "bg-low" },
  { key: "info",         label: "Info",         width: 76,  align: "center", dot: "bg-info", defaultHidden: true },
  { key: "ports",        label: "Open Ports",   width: 200 },
];// COLUMNS

const TEXT_SORT_KEYS: ColKey[] = ["ip", "hostname", "os", "system_type", "netbios", "mac"];

// ── Component ─────────────────────────────────────────────────────────────────

const COPY_MENU_W = 208; // w-52

export default function Hosts() {
  const files = useScanStore((s) => s.files);
  const openHostPanel = useUiStore((s) => s.openHostPanel);
  const openIp = useUiStore((s) => s.hostPanelIp);
  const location = useLocation();

  const [search, setSearch] = usePageState("hosts:search", "");
  const [chosenFile, setFileFilter] = usePageState("hosts:file", "all");
  const fileFilter = chosenFile === "all" || files.some((f) => f.id === chosenFile) ? chosenFile : "all";

  useEffect(() => {
    const handed = (location.state as { fileFilter?: string } | null)?.fileFilter;
    if (handed) {
      setFileFilter(handed);
    }
  }, [location.key, location.state, setFileFilter]);
  const { selected: selectedSeverities, toggle: toggleSeverity, matches: matchesSeverity } = useSeverityFilter("hosts");

  const table = useTableColumns("hosts", COLUMNS);
  const visibleCols = table.visible;
  const { sortKey: activeSort, sortDir, toggleSort } = useTableSort("hosts", visibleCols, "critical", "desc", TEXT_SORT_KEYS);

  // ── Data pipeline ───────────────────────────────────────────────────────────

  const filteredFiles = useMemo(
    () => (fileFilter === "all" ? files : files.filter((f) => f.id === fileFilter)),
    [files, fileFilter]
  );

  const allHosts = useMemo(() => buildHostEntries(filteredFiles), [filteredFiles]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return allHosts.filter((h) => {
      if (!matchesSeverity(severitiesOf(h.severity_counts))) {
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
  }, [allHosts, search, matchesSeverity]);

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

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow, scrollToIndex } = useVirtualRows(sorted.length);

  useEffect(() => {
    if (openIp === null) {
      return;
    }

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") {
        return;
      }
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) {
        return;
      }

      const index = sorted.findIndex((h) => h.ip === openIp);
      const next = index === -1 ? 0 : index + (e.key === "ArrowDown" ? 1 : -1);
      if (next < 0 || next >= sorted.length) {
        return;
      }

      e.preventDefault();
      openHostPanel(sorted[next].ip, fileFilter !== "all" ? fileFilter : undefined);
      scrollToIndex(next, { align: "auto" });
    };
    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, [openIp, sorted, fileFilter, openHostPanel, scrollToIndex]);

  const [copied, setCopied] = useState(false);
  const [showCopyMenu, setShowCopyMenu] = useState(false);
  const [menuLeftward, setMenuLeftward] = useState(false);
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
            case "os":           return osGuesses(h.os).join(" / ");
            case "system_type":  return h.system_type ?? "";
            case "netbios":      return h.netbios ?? "";
            case "mac":          return macAddresses(h.mac).join(", ");
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

  const severityCounts = useMemo(
    () => countBySeverity(allHosts.map((h) => severitiesOf(h.severity_counts))),
    [allHosts]
  );

  if (files.length === 0) {
    return <EmptyFilesNotice page="hosts" columns={COLUMNS} search="Search IP, hostname, OS, port…" />;
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters bar */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <SeverityPills counts={severityCounts} selected={selectedSeverities} onToggle={toggleSeverity} />

        {files.length > 1 && (
          <select value={fileFilter} onChange={(e) => setFileFilter(e.target.value)}
            className="input h-8 py-0 text-xs w-auto max-w-[16rem]">
            <option value="all">All files</option>
            {files.map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
        )}

        <SearchBar value={search} onChange={setSearch} placeholder="Search IP, hostname, OS, port…" className="flex-1 min-w-48" />

        <div className="flex items-center gap-3 shrink-0">
          <ColumnPicker table={table} />
          <span className="text-xs text-ink-400">{sorted.length.toLocaleString()} {sorted.length === 1 ? "host" : "hosts"}</span>
          {sorted.length > 0 && (
            <div className="relative" ref={copyMenuRef}>
              <button
                onClick={(e) => {
                  // open towards whichever side has room for the menu
                  const r = e.currentTarget.getBoundingClientRect();
                  setMenuLeftward(r.left + COPY_MENU_W > window.innerWidth - 8);
                  setShowCopyMenu((v) => !v);
                }}
                className={`btn-ghost h-8 px-2.5 flex items-center gap-1.5 text-xs font-medium transition-colors ${
                  copied ? "text-emerald-600 dark:text-emerald-400" : showCopyMenu ? "bg-ink-100 dark:bg-ink-700" : ""
                }`}
              >
                {copied ? <Check size={13} strokeWidth={2.5} /> : <Copy size={13} />}
                {copied ? "Copied!" : "Copy"}
                {!copied && <ChevronDown size={11} className="opacity-60" />}
              </button>
              {showCopyMenu && (
                <div className={`absolute ${menuLeftward ? "right-0" : "left-0"} top-full mt-1 z-50 card p-1 w-52 shadow-xl`}>
                  <CopyMenuItem label="IP addresses" sub="one per line" onClick={() => copy("ips")} />
                  <CopyMenuItem label="Hostnames" sub="one per line" onClick={() => copy("hostnames")} />
                  <div className="my-1 border-t border-ink-100 dark:border-ink-700" />
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
          <table style={table.style}>
            <TableHead table={table} sortKey={activeSort} sortDir={sortDir} onSort={toggleSort} />
            <tbody className="divide-y divide-ink-100 dark:divide-ink-700/50">
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
                    selected={h.ip === openIp}
                    measureRow={measureRow}
                    onClick={() => openHostPanel(h.ip, fileId)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={visibleCols.length} />
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={visibleCols.length} className="table-cell text-center text-ink-400 py-10">
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

function HostRow({ host, visibleCols, fileId, index, selected, measureRow, onClick }: {
  host: HostEntry;
  visibleCols: ColDef[];
  fileId?: string;
  index: number;
  selected: boolean;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const sc = host.severity_counts;
  const portSample = host.open_ports.map((p) => p.split("/")[0]).slice(0, 8).join(", ");
  const extra = host.open_ports.length > 8 ? ` +${host.open_ports.length - 8}` : "";
  const macs = macAddresses(host.mac);

  return (
    <tr
      ref={measureRow}
      data-index={index}
      className={`table-row ${selected ? "!bg-accent-50 dark:!bg-accent-900/30" : ""}`}
      aria-selected={selected}
      onClick={onClick}
    >
      {visibleCols.map((col) => {
        switch (col.key) {
          case "ip":
            return <td key="ip" className="table-cell"><IpLink ip={host.ip} fileId={fileId} /></td>;

          case "hostname":
            return (
              <td key="hostname" className="table-cell text-ink-500">
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
                    <span className="shrink-0" title={host.filenames.join("\n")}>
                      <Tag>{host.file_ids.length} files</Tag>
                    </span>
                  )}
                </span>
                {host.domain && (
                  <span className="truncate block text-[10px] text-ink-400 dark:text-ink-500 mt-0.5">
                    {host.domain}
                  </span>
                )}
                {host.alt_hostnames.length > 0 && (
                  <span className="truncate block text-[10px] text-ink-400 dark:text-ink-500 mt-0.5">
                    {host.alt_hostnames.slice(0, 2).join(", ")}
                    {host.alt_hostnames.length > 2 ? ` +${host.alt_hostnames.length - 2}` : ""}
                  </span>
                )}
              </td>
            );

          case "os": {
            const guesses = osGuesses(host.os);
            const title = guesses.length > 1 ? `Nessus could not tell which of these it is:\n${guesses.join("\n")}` : guesses[0];
            return (
              <td key="os" className="table-cell text-ink-500">
                <span className="flex items-center gap-1.5 min-w-0" title={title}>
                  <span className="truncate">{guesses[0] ?? "-"}</span>
                  {guesses.length > 1 && <span className="shrink-0 text-ink-400">+{guesses.length - 1}</span>}
                </span>
                {host.os_unsupported && (
                  <span className="block mt-1 leading-none"><Tag title="The vendor no longer supports this operating system">Unsupported</Tag></span>
                )}
              </td>
            );
          }

          case "system_type":
            return (
              <td key="system_type" className="table-cell text-ink-500">
                <span className="truncate block">{host.system_type ?? "-"}</span>
              </td>
            );

          case "netbios":
            return (
              <td key="netbios" className="table-cell text-ink-500">
                <span className="truncate block">{host.netbios ?? "-"}</span>
              </td>
            );

          case "mac":
            return (
              <td key="mac" className="table-cell text-ink-500" title={macs.length > 1 ? macs.join("\n") : undefined}>
                <span className="truncate block">
                  {macs[0] ?? "-"}
                  {macs.length > 1 && ` +${macs.length - 1}`}
                </span>
              </td>
            );

          case "credentialed":
            return (
              <td key="credentialed" className="table-cell text-center">
                <span className={`text-xs font-semibold ${host.credentialed_scan ? "text-emerald-600 dark:text-emerald-400" : "text-ink-400 dark:text-ink-600"}`}>
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
              <td key="ports" className="table-cell text-ink-500">
                <span className="truncate block">{portSample}{extra}</span>
              </td>
            );

          default: return null;
        }
      })}
    </tr>
  );
}// HostRow

function macAddresses(mac: string | null): string[] {
  return mac ? mac.split(/[\n,]+/).map((m) => m.trim()).filter(Boolean) : [];
}// macAddresses

function SevCount({ value, sev }: { value: number; sev: number }) {
  const color = { 4: "text-critical-fg", 3: "text-high-fg", 2: "text-medium-fg", 1: "text-low-fg", 0: "text-info-fg" }[sev] ?? "text-info-fg";
  return <span className={`font-semibold text-sm ${color}`}>{value.toLocaleString()}</span>;
}// SevCount

function Dash() {
  return <span className="text-ink-300 dark:text-ink-600">-</span>;
}// Dash

function CopyMenuItem({ label, sub, onClick }: { label: string; sub: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full flex flex-col items-start px-3 py-2 rounded text-left hover:bg-ink-50 dark:hover:bg-ink-700/50 transition-colors"
    >
      <span className="text-sm text-ink-700 dark:text-ink-200 font-medium">{label}</span>
      <span className="text-[11px] text-ink-400 dark:text-ink-500">{sub}</span>
    </button>
  );
}// CopyMenuItem
