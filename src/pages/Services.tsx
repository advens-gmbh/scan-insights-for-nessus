import { useMemo } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import type { ServiceEntry } from "../types/nessus";
import { useQuery } from "../data/query";
import SeverityPills from "../components/common/SeverityPills";
import DataTable from "../components/common/DataTable";
import TableToolbar from "../components/common/TableToolbar";
import { CountCell, SELECTED_ROW } from "../components/common/TableCells";
import { useFileFilter } from "../hooks/useFileFilter";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { countBySeverity, severitiesOf } from "../utils/severityFilter";
import { groupServices } from "../utils/serviceGroups";
import { useTableSort } from "../hooks/useTableSort";
import { usePageState } from "../stores/pageStore";
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
const NO_GROUPS = new Set<string>();
const SEARCH = "Search port, service, IP…";

export default function Services() {
  const files = useScanStore((s) => s.files);
  const openKey = useUiStore((s) => s.servicePanelKey);
  const openServicePanel = useUiStore((s) => s.openServicePanel);
  const grouped = useUiStore((s) => s.groupServices);
  const toggleGrouped = useUiStore((s) => s.toggleGroupServices);

  const [search, setSearch] = usePageState("services:search", "");
  const [protocol, setProtocol] = usePageState<Protocol>("services:protocol", "all");
  const [fileFilter, setFileFilter] = useFileFilter("services");
  const [openGroups, setOpenGroups] = usePageState<Set<string>>("services:open", NO_GROUPS);

  const { selected: selectedSeverities, toggle: toggleSeverity, clear: clearSeverities, matches: matchesSeverity } = useSeverityFilter("services");

  const table = useTableColumns("services", COLUMNS);
  const sort = useTableSort("services", table.visible, "port", "asc", ASCENDING_FIRST);
  const { sortKey: activeSort, sortDir } = sort;

  const fileId = fileFilter !== "all" ? fileFilter : undefined;
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

  if (files.length === 0) {
    return <EmptyFilesNotice page="services" columns={COLUMNS} search={SEARCH} />;
  }

  const groupCount = grouped ? new Set(rows.filter((r) => !(r.kind === "service" && r.nested)).map((r) => r.kind === "group" ? r.name : r.service.key)).size : 0;

  return (
    <div className="h-full flex flex-col gap-4">
      <TableToolbar
        pills={
          <>
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
          </>
        }
        search={{ value: search, onChange: setSearch, placeholder: SEARCH }}
        file={{ value: fileFilter, onChange: setFileFilter, ariaLabel: "Show the services from" }}
        table={table}
        tools={
          <label className="flex items-center gap-1.5 text-caption text-ink-500 dark:text-ink-400 cursor-pointer select-none">
            <input type="checkbox" checked={grouped} onChange={toggleGrouped} className="rounded accent-accent-600" />
            Group by service
          </label>
        }
        count={grouped
          ? `${groupCount.toLocaleString()} services, ${filtered.length.toLocaleString()} ports`
          : `${filtered.length.toLocaleString()} services`}
      />

      <DataTable
        table={table}
        sort={sort}
        count={rows.length}
        empty={answer !== undefined ? "No services match the current filter." : null}
        keys={{
          open: openKey !== null,
          current: () => rows.findIndex((r) => r.kind === "service" && r.service.key === openKey),
          selectable: (i) => rows[i].kind === "service",
          go: (i) => {
            const row = rows[i];
            if (row.kind === "service") openServicePanel(row.service.key, fileId);
          },
        }}
        row={(index, measure) => {
          const row = rows[index];
          return row.kind === "group" ? (
            <ServiceRow
              key={`group:${row.name}`}
              service={row.summary}
              visibleCols={table.visible}
              index={index}
              measureRow={measure}
              group={{ name: row.name, ports: row.ports, open: row.open }}
              onClick={() => toggleGroup(row.name)}
            />
          ) : (
            <ServiceRow
              key={row.service.key}
              service={row.service}
              visibleCols={table.visible}
              index={index}
              nested={row.nested}
              selected={row.service.key === openKey}
              measureRow={measure}
              onClick={() => openServicePanel(row.service.key, fileId)}
            />
          );
        }}
      />
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
  const tone = group ? "bg-ink-50 dark:bg-ink-800/60" : selected ? SELECTED_ROW : "";

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
            return <CountCell key={col.key} value={sc.critical} severity={4} />;
          case "high":
            return <CountCell key={col.key} value={sc.high} severity={3} />;
          case "medium":
            return <CountCell key={col.key} value={sc.medium} severity={2} />;
          case "low":
            return <CountCell key={col.key} value={sc.low} severity={1} />;
          case "info":
            return <CountCell key={col.key} value={sc.info} severity={0} />;
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
