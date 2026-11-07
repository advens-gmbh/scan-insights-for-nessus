import { useMemo, useState } from "react";
import { ChevronUp, ChevronDown } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import { buildServiceEntries } from "../types/nessus";
import type { ServiceEntry } from "../types/nessus";
import ServiceDetail from "../panels/ServiceDetail";
import SearchBar from "../components/common/SearchBar";
import SpacerRow from "../components/common/SpacerRow";
import { useVirtualRows } from "../hooks/useVirtualRows";
import EmptyFilesNotice from "./EmptyFilesNotice";

type SortKey = "port" | "protocol" | "service" | "hosts" | "critical" | "high" | "medium" | "low" | "info" | "exploit";
type SortDir = "asc" | "desc";
type Protocol = "all" | "tcp" | "udp";

const ASCENDING_FIRST: SortKey[] = ["port", "protocol", "service"];

export default function Services() {
  const files = useScanStore((s) => s.files);
  const showInfo = useUiStore((s) => s.showInfo);

  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState<Protocol>("all");
  const [fileFilter, setFileFilter] = useState("all");
  const [sortKey, setSortKey] = useState<SortKey>("port");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

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

      return !q || s.key.includes(q) || s.svc_names.some((n) => n.toLowerCase().includes(q)) || s.host_ips.some((ip) => ip.includes(q));
    });
  }, [services, search, protocol]);

  // the Info column can be hidden while it is the sort column
  const activeSort = sortKey === "info" && !showInfo ? "port" : sortKey;
  const sorted = useMemo(() => [...filtered].sort((a, b) => {
    let cmp = 0;
    switch (activeSort) {
      case "port":     cmp = a.port - b.port; break;
      case "protocol": cmp = a.protocol.localeCompare(b.protocol); break;
      case "service":  cmp = a.svc_names.join().localeCompare(b.svc_names.join()); break;
      case "hosts":    cmp = a.host_ips.length - b.host_ips.length; break;
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

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(ASCENDING_FIRST.includes(key) ? "asc" : "desc");
    }
  };

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  const selected = services.find((s) => s.key === selectedKey);
  const th = { current: activeSort, dir: sortDir, onSort: toggleSort };
  const columnCount = showInfo ? 10 : 9;

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
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

        <ShowInfoCheckbox />

        <span className="text-xs text-slate-400 shrink-0">
          {sorted.length.toLocaleString()} services
        </span>
      </div>

      {/* Table - fills remaining height, scrolls internally so thead stays sticky */}
      <div className="card flex-1 overflow-hidden">
        <div ref={scrollRef} className="overflow-auto h-full">
          <table className="w-full min-w-[65rem] table-fixed">
            <thead className="sticky top-0 z-10">
              <tr>
                <Th label="Port"     sortKey="port"     width="w-24" {...th} />
                <Th label="Protocol" sortKey="protocol" width="w-28" {...th} />
                <Th label="Service"  sortKey="service"  {...th} />
                <Th label="Hosts"    sortKey="hosts"    width="w-24" {...th} />
                <Th label="Critical" sortKey="critical" width="w-28" {...th} />
                <Th label="High"     sortKey="high"     width="w-20" {...th} />
                <Th label="Medium"   sortKey="medium"   width="w-28" {...th} />
                <Th label="Low"      sortKey="low"      width="w-20" {...th} />
                {showInfo && <Th label="Info" sortKey="info" width="w-20" {...th} />}
                <Th label="Exploit"  sortKey="exploit"  width="w-28" {...th} />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              <SpacerRow height={paddingTop} colSpan={columnCount} />
              {rows.map((row) => {
                const s = sorted[row.index];
                return (
                  <ServiceRow
                    key={s.key}
                    service={s}
                    showInfo={showInfo}
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

function ServiceRow({ service, showInfo, index, measureRow, onClick }: {
  service: ServiceEntry;
  showInfo: boolean;
  index: number;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const sc = service.severity_counts;
  const names = service.svc_names.join(", ");

  return (
    <tr ref={measureRow} data-index={index} className="table-row" onClick={onClick}>
      <td className="table-cell font-mono text-sm font-semibold text-slate-800 dark:text-slate-200">{service.port}</td>
      <td className="table-cell font-mono text-xs uppercase text-slate-500 dark:text-slate-400 truncate" title={service.protocol}>{service.protocol}</td>
      <td className="table-cell text-slate-700 dark:text-slate-300 truncate" title={names}>{names || "-"}</td>
      <td className="table-cell font-semibold text-slate-700 dark:text-slate-200">{service.host_ips.length}</td>
      <Count value={sc.critical} color="text-critical" />
      <Count value={sc.high} color="text-high" />
      <Count value={sc.medium} color="text-medium" />
      <Count value={sc.low} color="text-low" />
      {showInfo && <Count value={sc.info} color="text-info" />}
      <td className="table-cell">
        {service.exploit_available && (
          <span className="pill bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 text-xs">EXPLOIT</span>
        )}
      </td>
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

function Th({ label, sortKey, current, dir, onSort, width = "" }: {
  label: string;
  sortKey: SortKey;
  current: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
  width?: string;
}) {
  const active = current === sortKey;
  return (
    <th
      className={`px-4 py-3 text-xs uppercase tracking-wider text-left select-none cursor-pointer transition-colors ${width} ${
        active
          ? "bg-violet-50 dark:bg-violet-900/20 text-violet-700 dark:text-violet-300 font-bold"
          : "bg-slate-50 dark:bg-slate-900/50 text-slate-500 dark:text-slate-400 font-semibold hover:text-slate-700 dark:hover:text-slate-200"
      }`}
      onClick={() => onSort(sortKey)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active ? (
          dir === "desc" ? <ChevronDown size={12} /> : <ChevronUp size={12} />
        ) : (
          <ChevronDown size={12} className="opacity-30" />
        )}
      </span>
    </th>
  );
}// Th
