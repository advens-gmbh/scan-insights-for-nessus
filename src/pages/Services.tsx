import { useMemo, useState } from "react";
import { useScanStore } from "../stores/scanStore";
import { buildServiceEntries } from "../types/nessus";
import type { ServiceEntry } from "../types/nessus";
import ServiceDetail from "../panels/ServiceDetail";
import SearchBar from "../components/common/SearchBar";
import SpacerRow from "../components/common/SpacerRow";
import ColumnPicker from "../components/common/ColumnPicker";
import SeverityPills from "../components/common/SeverityPills";
import TableHead from "../components/common/TableHead";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { countBySeverity, severitiesOf } from "../utils/severityFilter";
import { useTableSort } from "../hooks/useTableSort";
import { useVirtualRows } from "../hooks/useVirtualRows";
import type { TableColumn } from "../utils/tableColumns";
import EmptyFilesNotice from "./EmptyFilesNotice";

type SortKey = "port" | "protocol" | "service" | "hosts" | "findings" | "critical" | "high" | "medium" | "low" | "info" | "exploit";
type ColDef = TableColumn<SortKey>;
type Protocol = "all" | "tcp" | "udp";

const ASCENDING_FIRST: SortKey[] = ["port", "protocol", "service"];

const COLUMNS: ColDef[] = [
  { key: "port",     label: "Port",     width: 96, required: true },
  { key: "protocol", label: "Protocol", width: 112 },
  { key: "service",  label: "Service",  width: 240, stretch: true },
  { key: "hosts",    label: "Hosts",    width: 96 },
  { key: "findings", label: "Findings", width: 112, defaultHidden: true },
  { key: "critical", label: "Critical", width: 112 },
  { key: "high",     label: "High",     width: 80 },
  { key: "medium",   label: "Medium",   width: 112 },
  { key: "low",      label: "Low",      width: 80 },
  { key: "info",     label: "Info",     width: 80, defaultHidden: true },
  { key: "exploit",  label: "Exploit",  width: 112 },
];// COLUMNS


export default function Services() {
  const files = useScanStore((s) => s.files);

  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState<Protocol>("all");
  const [fileFilter, setFileFilter] = useState("all");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const { selected: selectedSeverities, toggle: toggleSeverity, matches: matchesSeverity } = useSeverityFilter("services");

  const table = useTableColumns("services", COLUMNS);
  const { sortKey: activeSort, sortDir, toggleSort } = useTableSort(table.visible, "port", "asc", ASCENDING_FIRST);

  const activeFile = files.some((f) => f.id === fileFilter) ? fileFilter : "all";
  const filteredFiles = useMemo(
    () => (activeFile === "all" ? files : files.filter((f) => f.id === activeFile)),
    [files, activeFile]
  );
  const services = useMemo(() => buildServiceEntries(filteredFiles), [filteredFiles]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return services.filter((s) => {
      if (protocol !== "all" && s.protocol !== protocol) {
        return false;
      }
      if (!matchesSeverity(severitiesOf(s.severity_counts))) {
        return false;
      }

      return !q || s.key.includes(q) || s.svc_names.some((n) => n.toLowerCase().includes(q)) || s.host_ips.some((ip) => ip.includes(q));
    });
  }, [services, search, protocol, matchesSeverity]);

  const severityCounts = useMemo(
    () => countBySeverity(services.map((s) => severitiesOf(s.severity_counts))),
    [services]
  );

  const sorted = useMemo(() => [...filtered].sort((a, b) => {
    let cmp = 0;
    switch (activeSort) {
      case "port":     cmp = a.port - b.port; break;
      case "protocol": cmp = a.protocol.localeCompare(b.protocol); break;
      case "service":  cmp = a.svc_names.join().localeCompare(b.svc_names.join()); break;
      case "hosts":    cmp = a.host_ips.length - b.host_ips.length; break;
      case "findings": cmp = a.findings.length - b.findings.length; break;
      case "critical": cmp = a.severity_counts.critical - b.severity_counts.critical; break;
      case "high":     cmp = a.severity_counts.high - b.severity_counts.high; break;
      case "medium":   cmp = a.severity_counts.medium - b.severity_counts.medium; break;
      case "low":      cmp = a.severity_counts.low - b.severity_counts.low; break;
      case "info":     cmp = a.severity_counts.info - b.severity_counts.info; break;
      case "exploit":  cmp = Number(a.exploit_available) - Number(b.exploit_available); break;
    }

    return sortDir === "desc" ? -cmp : cmp;
  }), [filtered, activeSort, sortDir]);

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow } = useVirtualRows(sorted.length);

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  const selected = services.find((s) => s.key === selectedKey);
  const columnCount = table.visible.length;

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <SeverityPills counts={severityCounts} selected={selectedSeverities} onToggle={toggleSeverity} />

        <div className="flex items-center gap-1.5">
          {(["all", "tcp", "udp"] as const).map((p) => (
            <button
              key={p}
              onClick={() => setProtocol(p)}
              className={`pill px-3 py-1 text-sm font-semibold cursor-pointer transition-colors ${
                protocol === p
                  ? "bg-violet-600 text-white"
                  : "bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
              }`}
            >
              {p === "all" ? "All" : p.toUpperCase()}
            </button>
          ))}
        </div>

        {files.length > 1 && (
          <select
            value={activeFile}
            onChange={(e) => setFileFilter(e.target.value)}
            className="input h-8 py-0 text-xs w-auto"
          >
            <option value="all">All files</option>
            {files.map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
        )}

        <SearchBar value={search} onChange={setSearch} placeholder="Search port, service, IP…" className="flex-1 min-w-48" />

        <ColumnPicker table={table} />

        <span className="text-xs text-slate-400 shrink-0">
          {sorted.length.toLocaleString()} services
        </span>
      </div>

      {/* Table - fills remaining height, scrolls internally so thead stays sticky */}
      <div className="card flex-1 overflow-hidden">
        <div ref={scrollRef} className="overflow-auto h-full">
          <table style={table.style}>
            <TableHead table={table} sortKey={activeSort} sortDir={sortDir} onSort={toggleSort} />
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              <SpacerRow height={paddingTop} colSpan={columnCount} />
              {rows.map((row) => {
                const s = sorted[row.index];
                return (
                  <ServiceRow
                    key={s.key}
                    service={s}
                    visibleCols={table.visible}
                    index={row.index}
                    measureRow={measureRow}
                    onClick={() => setSelectedKey(s.key)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={columnCount} />
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={columnCount} className="table-cell text-center text-slate-400 py-10">
                    No services match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <ServiceDetail
          key={selected.key}
          service={selected}
          files={filteredFiles}
          fileId={activeFile !== "all" ? activeFile : undefined}
          onClose={() => setSelectedKey(null)}
        />
      )}
    </div>
  );
}// Services

function ServiceRow({ service, visibleCols, index, measureRow, onClick }: {
  service: ServiceEntry;
  visibleCols: ColDef[];
  index: number;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const sc = service.severity_counts;
  const names = service.svc_names.join(", ");

  return (
    <tr ref={measureRow} data-index={index} className="table-row" onClick={onClick}>
      {visibleCols.map((col) => {
        switch (col.key) {
          case "port":
            return <td key={col.key} className="table-cell font-semibold text-slate-800 dark:text-slate-200">{service.port}</td>;
          case "protocol":
            return <td key={col.key} className="table-cell uppercase text-slate-500 dark:text-slate-400 truncate" title={service.protocol}>{service.protocol}</td>;
          case "service":
            return <td key={col.key} className="table-cell text-slate-700 dark:text-slate-300 truncate" title={names}>{names || "-"}</td>;
          case "hosts":
            return <td key={col.key} className="table-cell font-semibold text-slate-700 dark:text-slate-200">{service.host_ips.length}</td>;
          case "findings":
            return <td key={col.key} className="table-cell font-semibold text-slate-700 dark:text-slate-200">{service.findings.length}</td>;
          case "critical":
            return <Count key={col.key} value={sc.critical} color="text-critical" />;
          case "high":
            return <Count key={col.key} value={sc.high} color="text-high" />;
          case "medium":
            return <Count key={col.key} value={sc.medium} color="text-medium" />;
          case "low":
            return <Count key={col.key} value={sc.low} color="text-low" />;
          case "info":
            return <Count key={col.key} value={sc.info} color="text-info" />;
          case "exploit":
            return (
              <td key={col.key} className="table-cell">
                {service.exploit_available && (
                  <span className="pill bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 text-xs">EXPLOIT</span>
                )}
              </td>
            );
        }
      })}
    </tr>
  );
}// ServiceRow

function Count({ value, color }: { value: number; color: string }) {
  return (
    <td className="table-cell">
      {value > 0
        ? <span className={`font-semibold text-sm ${color}`}>{value}</span>
        : <span className="text-slate-300 dark:text-slate-600">-</span>}
    </td>
  );
}// Count
