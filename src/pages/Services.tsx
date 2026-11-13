import { useEffect, useMemo } from "react";
import { useLocation } from "react-router-dom";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import type { ServiceEntry } from "../types/nessus";
import { useQuery } from "../data/query";
import SearchBar from "../components/common/SearchBar";
import Select, { fileOption } from "../components/common/Select";
import SpacerRow from "../components/common/SpacerRow";
import ColumnPicker from "../components/common/ColumnPicker";
import SeverityPills from "../components/common/SeverityPills";
import TableHead from "../components/common/TableHead";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { countBySeverity, severitiesOf } from "../utils/severityFilter";
import { groupServices } from "../utils/serviceGroups";
import { useTableSort } from "../hooks/useTableSort";
import { usePageState } from "../stores/pageStore";

const NO_GROUPS = new Set<string>();
import { useVirtualRows } from "../hooks/useVirtualRows";
import type { TableColumn } from "../utils/tableColumns";
import EmptyFilesNotice from "./EmptyFilesNotice";
import { ExploitTag } from "../panels/PanelParts";

type SortKey = "port" | "service" | "hosts" | "findings" | "critical" | "high" | "medium" | "low" | "info" | "exploit";
type ColDef = TableColumn<SortKey>;
type Protocol = "all" | "tcp" | "udp";

type Row =
  | { kind: "service"; service: ServiceEntry; nested: boolean }
  | { kind: "group"; name: string; summary: ServiceEntry; ports: ServiceEntry[]; open: boolean };

const ASCENDING_FIRST: SortKey[] = ["port", "service"];

const COLUMNS: ColDef[] = [
  { key: "port",     label: "Port",     width: 120, required: true },
  { key: "service",  label: "Service",  width: 240 },
  { key: "hosts",    label: "Hosts",    width: 96,  align: "center" },
  { key: "findings", label: "Findings", width: 112, align: "center", defaultHidden: true },
  { key: "critical", label: "Critical", width: 96,  align: "center", dot: "bg-critical" },
  { key: "high",     label: "High",     width: 80,  align: "center", dot: "bg-high" },
  { key: "medium",   label: "Medium",   width: 96,  align: "center", dot: "bg-medium" },
  { key: "low",      label: "Low",      width: 76,  align: "center", dot: "bg-low" },
  { key: "info",     label: "Info",     width: 76,  align: "center", dot: "bg-info", defaultHidden: true },
  { key: "exploit",  label: "Exploit",  width: 100 },
];// COLUMNS


const NO_ROWS: ServiceEntry[] = [];

export default function Services() {
  const files = useScanStore((s) => s.files);
  const openKey = useUiStore((s) => s.servicePanelKey);
  const openServicePanel = useUiStore((s) => s.openServicePanel);
  const grouped = useUiStore((s) => s.groupServices);
  const toggleGrouped = useUiStore((s) => s.toggleGroupServices);

  const [search, setSearch] = usePageState("services:search", "");
  const [protocol, setProtocol] = usePageState<Protocol>("services:protocol", "all");
  const location = useLocation();
  const [chosenFile, setFileFilter] = usePageState("services:file", "all");
  const fileFilter = chosenFile === "all" || files.some((f) => f.id === chosenFile) ? chosenFile : "all";
  const [openGroups, setOpenGroups] = usePageState<Set<string>>("services:open", NO_GROUPS);

  useEffect(() => {
    const handed = (location.state as { fileFilter?: string } | null)?.fileFilter;
    if (handed) {
      setFileFilter(handed);
    }
  }, [location.key, location.state, setFileFilter]);
  const { selected: selectedSeverities, toggle: toggleSeverity, clear: clearSeverities, matches: matchesSeverity } = useSeverityFilter("services");

  const table = useTableColumns("services", COLUMNS);
  const { sortKey: activeSort, sortDir, toggleSort } = useTableSort("services", table.visible, "port", "asc", ASCENDING_FIRST);

  const activeFile = files.some((f) => f.id === fileFilter) ? fileFilter : "all";
  const fileId = activeFile !== "all" ? activeFile : undefined;
  const answer = useQuery<ServiceEntry[]>("service_rows", files.length > 0 ? { file: fileId ?? null } : null);
  const services = answer ?? NO_ROWS;

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

  const rows = useMemo<Row[]>(() => {
    const compare = (a: ServiceEntry, b: ServiceEntry) => {
      let cmp = 0;
      switch (activeSort) {
        case "port":     cmp = a.port - b.port || a.protocol.localeCompare(b.protocol); break;
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
    };

    if (!grouped) {
      return [...filtered].sort(compare).map((service) => ({ kind: "service", service, nested: false }));
    }

    const out: Row[] = [];
    for (const g of groupServices(filtered).sort((a, b) => compare(a.summary, b.summary))) {
      if (g.ports.length === 1) {
        out.push({ kind: "service", service: g.ports[0], nested: false });
        continue;
      }
      const open = openGroups.has(g.name);
      out.push({ kind: "group", name: g.name, summary: g.summary, ports: g.ports, open });
      if (open) {
        for (const service of [...g.ports].sort(compare)) {
          out.push({ kind: "service", service, nested: true });
        }
      }
    }

    return out;
  }, [filtered, grouped, openGroups, activeSort, sortDir]);

  const { scrollRef, rows: virtualRows, paddingTop, paddingBottom, measureRow, scrollToIndex } = useVirtualRows(rows.length);

  const toggleGroup = (name: string) => {
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }

      return next;
    });
  };

  useEffect(() => {
    if (openKey === null) {
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

      const step = e.key === "ArrowDown" ? 1 : -1;
      const current = rows.findIndex((r) => r.kind === "service" && r.service.key === openKey);
      let next = current === -1 ? 0 : current + step;
      while (next >= 0 && next < rows.length && rows[next].kind !== "service") {
        next += current === -1 ? 1 : step;
      }
      const row = rows[next];
      if (!row || row.kind !== "service") {
        return;
      }

      e.preventDefault();
      openServicePanel(row.service.key, fileId);
      scrollToIndex(next, { align: "auto" });
    };
    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, [openKey, rows, fileId, openServicePanel, scrollToIndex]);

  if (files.length === 0) {
    return <EmptyFilesNotice page="services" columns={COLUMNS} search="Search port, service, IP…" />;
  }

  const columnCount = table.visible.length;
  const groupCount = grouped ? new Set(rows.filter((r) => !(r.kind === "service" && r.nested)).map((r) => r.kind === "group" ? r.name : r.service.key)).size : 0;

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters */}
      {/* line 1 holds the filter pills; line 2 search and file, with the table's tools on the right. */}
      <div className="flex flex-col gap-3 shrink-0">
        <div className="flex flex-wrap items-center gap-3">
        <SeverityPills counts={severityCounts} selected={selectedSeverities} onToggle={toggleSeverity} onClear={clearSeverities} />

        <div className="flex items-center gap-1.5">
          {(["all", "tcp", "udp"] as const).map((p) => (
            <button
              key={p}
              onClick={() => setProtocol(p)}
              aria-pressed={protocol === p}
              className={`pill px-3 py-1 text-body font-semibold cursor-pointer transition-colors ${
                protocol === p
                  ? "bg-accent-600 text-white"
                  : "bg-ink-100 dark:bg-ink-700 text-ink-600 dark:text-ink-300"
              }`}
            >
              {p === "all" ? "All" : p.toUpperCase()}
            </button>
          ))}
        </div>

        </div>

        <div className="flex items-center gap-3">
          <SearchBar value={search} onChange={setSearch} placeholder="Search port, service, IP…" className="flex-[1_1_15rem] min-w-40" />
          {files.length > 1 && (
            <Select value={activeFile} onChange={setFileFilter} options={[{ value: "all", label: "All files" }, ...files.map(fileOption)]} ariaLabel="Show the services from" className="flex-[0_1_15rem] min-w-[9.5rem]" />
          )}
          <div className="ml-auto flex items-center gap-3 shrink-0">
            <ColumnPicker table={table} />
            <label className="flex items-center gap-1.5 text-caption text-ink-500 dark:text-ink-400 cursor-pointer select-none">
              <input type="checkbox" checked={grouped} onChange={toggleGrouped} className="rounded accent-accent-600" />
              Group by service
            </label>
            <span className="text-caption text-ink-500">
              {grouped
                ? `${groupCount.toLocaleString()} services, ${filtered.length.toLocaleString()} ports`
                : `${filtered.length.toLocaleString()} services`}
            </span>
          </div>
        </div>
      </div>

      {/* Table - fills remaining height, scrolls internally so thead stays sticky */}
      <div className="card min-h-0 flex flex-col overflow-hidden">
        <div ref={scrollRef} className="overflow-auto flex-1 min-h-0">
          <table style={table.style}>
            <TableHead table={table} sortKey={activeSort} sortDir={sortDir} onSort={toggleSort} />
            <tbody className="divide-y divide-ink-100 dark:divide-ink-700/50">
              <SpacerRow height={paddingTop} colSpan={columnCount} />
              {virtualRows.map((vr) => {
                const row = rows[vr.index];
                return row.kind === "group" ? (
                  <ServiceRow
                    key={`group:${row.name}`}
                    service={row.summary}
                    visibleCols={table.visible}
                    index={vr.index}
                    measureRow={measureRow}
                    group={{ name: row.name, ports: row.ports, open: row.open }}
                    onClick={() => toggleGroup(row.name)}
                  />
                ) : (
                  <ServiceRow
                    key={row.service.key}
                    service={row.service}
                    visibleCols={table.visible}
                    index={vr.index}
                    nested={row.nested}
                    selected={row.service.key === openKey}
                    measureRow={measureRow}
                    onClick={() => openServicePanel(row.service.key, fileId)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={columnCount} />
              {rows.length === 0 && answer !== undefined && (
                <tr>
                  <td colSpan={columnCount} className="table-cell text-center text-ink-500 py-10">
                    No services match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}// Services

function ServiceRow({ service, visibleCols, index, nested = false, selected = false, group, measureRow, onClick }: {
  service: ServiceEntry;
  visibleCols: ColDef[];
  index: number;
  nested?: boolean;
  selected?: boolean;
  group?: { name: string; ports: ServiceEntry[]; open: boolean };
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const sc = service.severity_counts;
  const names = service.svc_names.join(", ");
  const tone = group ? "bg-ink-50 dark:bg-ink-800/60" : selected ? "!bg-accent-50 dark:!bg-accent-900/30" : "";

  return (
    <tr
      ref={measureRow}
      data-index={index}
      className={`table-row ${tone}`}
      aria-selected={group ? undefined : selected}
      aria-expanded={group ? group.open : undefined}
      onClick={onClick}
    >
      {visibleCols.map((col) => {
        switch (col.key) {
          case "port":
            return group ? (
              <td key={col.key} className="table-cell">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onClick();
                  }}
                  className="flex items-center gap-1.5 font-semibold text-ink-900 dark:text-ink-50"
                  aria-label={`${group.open ? "Collapse" : "Expand"} ${group.name}`}
                >
                  {group.open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  {group.ports.length} ports
                </button>
              </td>
            ) : (
              <td key={col.key} className={`table-cell font-semibold text-ink-800 dark:text-ink-200 ${nested ? "pl-10" : ""}`}>{service.key}</td>
            );
          case "service":
            return group ? (
              <td key={col.key} className="table-cell truncate" title={group.ports.map((p) => p.key).join(", ")}>
                <span className="font-semibold text-ink-900 dark:text-ink-50">{group.name}</span>
                <span className="ml-2 text-caption text-ink-500 dark:text-ink-400">{group.ports.map((p) => p.port).join(", ")}</span>
              </td>
            ) : (
              <td key={col.key} className="table-cell text-ink-700 dark:text-ink-300 truncate" title={names}>{names || "-"}</td>
            );
          case "hosts":
            return <td key={col.key} className="table-cell text-center text-ink-700 dark:text-ink-200">{service.host_ips.length.toLocaleString()}</td>;
          case "findings":
            return <td key={col.key} className="table-cell text-center text-ink-700 dark:text-ink-200">{service.findings.length.toLocaleString()}</td>;
          case "critical":
            return <Count key={col.key} value={sc.critical} color="text-critical-fg" />;
          case "high":
            return <Count key={col.key} value={sc.high} color="text-high-fg" />;
          case "medium":
            return <Count key={col.key} value={sc.medium} color="text-medium-fg" />;
          case "low":
            return <Count key={col.key} value={sc.low} color="text-low-fg" />;
          case "info":
            return <Count key={col.key} value={sc.info} color="text-info-fg" />;
          case "exploit":
            return (
              <td key={col.key} className="table-cell">
                {service.exploit_available && (
                  <ExploitTag />
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
    <td className="table-cell text-center">
      {value > 0
        ? <span className={`font-semibold text-body ${color}`}>{value.toLocaleString()}</span>
        : <span className="text-ink-300 dark:text-ink-600">-</span>}
    </td>
  );
}// Count
