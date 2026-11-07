import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { buildVulnEntries, ratedScore, SEVERITY_COLORS, vulnScore } from "../types/nessus";
import { formatNessusDate } from "../utils/format";
import type { VulnEntry } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import SearchBar from "../components/common/SearchBar";
import SpacerRow from "../components/common/SpacerRow";
import ColumnPicker from "../components/common/ColumnPicker";
import SeverityPills from "../components/common/SeverityPills";
import TableHead from "../components/common/TableHead";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { countBySeverity } from "../utils/severityFilter";
import { useTableSort } from "../hooks/useTableSort";
import { useVirtualRows } from "../hooks/useVirtualRows";
import type { TableColumn } from "../utils/tableColumns";
import EmptyFilesNotice from "./EmptyFilesNotice";

type SortKey = "severity" | "plugin_id" | "name" | "family" | "cve" | "cvss" | "vpr" | "epss" | "hosts" | "patch" | "exploit" | "metasploit" | "ease";
type ColDef = TableColumn<SortKey>;

const ASCENDING_FIRST: SortKey[] = ["plugin_id", "name", "family", "cve", "patch", "ease"];

const COLUMNS: ColDef[] = [
  { key: "severity",   label: "Severity",       width: 112 },
  { key: "plugin_id",  label: "Plugin ID",      width: 130, defaultHidden: true },
  { key: "name",       label: "Name",           width: 272, stretch: true, required: true },
  { key: "family",     label: "Family",         width: 160 },
  { key: "cve",        label: "CVE",            width: 190, defaultHidden: true },
  { key: "cvss",       label: "CVSS",           width: 96 },
  { key: "vpr",        label: "VPR",            width: 90,  defaultHidden: true },
  { key: "epss",       label: "EPSS",           width: 90,  defaultHidden: true },
  { key: "hosts",      label: "Hosts",          width: 96 },
  { key: "patch",      label: "Patch Released", width: 176 },
  { key: "exploit",    label: "Exploit",        width: 112 },
  { key: "metasploit", label: "Metasploit",     width: 130, defaultHidden: true },
  { key: "ease",       label: "Exploit Ease",   width: 170, defaultHidden: true },
];// COLUMNS

export default function Vulnerabilities() {
  const files = useScanStore((s) => s.files);
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);
  const location = useLocation();

  const [search, setSearch] = useState("");
  const [fileFilter, setFileFilter] = useState<string>(
    (location.state as { fileFilter?: string } | null)?.fileFilter ?? "all"
  );
  const { selected: selectedSeverities, toggle: toggleSeverity, matches: matchesSeverity } = useSeverityFilter("vulnerabilities");
  const table = useTableColumns("vulnerabilities", COLUMNS);
  const { sortKey, sortDir, toggleSort } = useTableSort(table.visible, "severity", "desc", ASCENDING_FIRST);

  const filteredFiles = useMemo(() => {
    if (fileFilter === "all") {
      return files;
    }

    return files.filter((f) => f.id === fileFilter);
  }, [files, fileFilter]);

  const vulnsForFilter = useMemo(() => buildVulnEntries(filteredFiles), [filteredFiles]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return vulnsForFilter.filter((v) => {
      if (!matchesSeverity([v.severity])) {
        return false;
      }

      if (q) {
        return (
          v.plugin_name.toLowerCase().includes(q) ||
          v.plugin_family.toLowerCase().includes(q) ||
          v.cve.some((c) => c.toLowerCase().includes(q)) ||
          v.cwe.some((c) => c.toLowerCase().includes(q)) ||
          v.affected_hosts.some((h) => h.ip.includes(q))
        );
      }

      return true;
    });
  }, [vulnsForFilter, search, matchesSeverity]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      // findings without a date stay at the bottom in both directions
      if (sortKey === "patch" && (!a.patch_publication_date || !b.patch_publication_date)) {
        return Number(!a.patch_publication_date) - Number(!b.patch_publication_date);
      }

      let cmp = 0;
      switch (sortKey) {
        case "severity":   cmp = a.severity - b.severity; break;
        case "plugin_id":  cmp = a.plugin_id - b.plugin_id; break;
        case "name":       cmp = a.plugin_name.localeCompare(b.plugin_name); break;
        case "family":     cmp = a.plugin_family.localeCompare(b.plugin_family); break;
        case "cve":        cmp = (a.cve[0] ?? "").localeCompare(b.cve[0] ?? ""); break;
        case "cvss":       cmp = (vulnScore(a) ?? -1) - (vulnScore(b) ?? -1); break;
        case "vpr":        cmp = (a.vpr ?? -1) - (b.vpr ?? -1); break;
        case "epss":       cmp = (a.epss ?? -1) - (b.epss ?? -1); break;
        case "hosts":      cmp = a.host_count - b.host_count; break;
        case "patch":      cmp = a.patch_publication_date!.localeCompare(b.patch_publication_date!); break;
        case "exploit":    cmp = Number(a.exploit_available) - Number(b.exploit_available); break;
        case "metasploit": cmp = Number(a.metasploit_available) - Number(b.metasploit_available); break;
        case "ease":       cmp = (a.exploit_ease ?? "").localeCompare(b.exploit_ease ?? ""); break;
      }
      return sortDir === "desc" ? -cmp : cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow } = useVirtualRows(sorted.length);

  const severityCounts = useMemo(
    () => countBySeverity(vulnsForFilter.map((v) => [v.severity])),
    [vulnsForFilter]
  );

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <SeverityPills counts={severityCounts} selected={selectedSeverities} onToggle={toggleSeverity} />

        {/* File filter */}
        {files.length > 1 && (
          <select
            value={fileFilter}
            onChange={(e) => setFileFilter(e.target.value)}
            className="input h-8 py-0 text-xs w-auto"
          >
            <option value="all">All files</option>
            {files.map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
        )}

        <div className="flex-1 min-w-48">
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder="Search vulnerabilities, CVEs, IPs…"
          />
        </div>

        <ColumnPicker table={table} />

        <span className="text-xs text-slate-400 shrink-0">
          {sorted.length.toLocaleString()} results
        </span>
      </div>

      {/* Table - fills remaining height, scrolls internally so thead stays sticky */}
      <div className="card flex-1 overflow-hidden">
        <div ref={scrollRef} className="overflow-auto h-full">
          <table style={table.style}>
            <TableHead table={table} sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              <SpacerRow height={paddingTop} colSpan={table.visible.length} />
              {rows.map((row) => {
                const v = sorted[row.index];
                return (
                  <VulnRow
                    key={v.plugin_id}
                    vuln={v}
                    visibleCols={table.visible}
                    index={row.index}
                    measureRow={measureRow}
                    onClick={() => openVulnPanel(v.plugin_id, fileFilter !== "all" ? fileFilter : undefined)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={table.visible.length} />
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={table.visible.length} className="table-cell text-center text-slate-400 py-10">
                    No vulnerabilities match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}// Vulnerabilities

function VulnRow({ vuln, visibleCols, index, measureRow, onClick }: {
  vuln: VulnEntry;
  visibleCols: ColDef[];
  index: number;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const cvss = ratedScore(vuln);
  return (
    <tr ref={measureRow} data-index={index} className="table-row" onClick={onClick}>
      {visibleCols.map((col) => {
        switch (col.key) {
          case "severity":
            return (
              <td key={col.key} className="table-cell">
                <SeverityBadge severity={vuln.severity} />
              </td>
            );
          case "plugin_id":
            return <td key={col.key} className="table-cell text-slate-500 dark:text-slate-400">{vuln.plugin_id}</td>;
          case "name":
            return (
              <td key={col.key} className="table-cell font-medium text-slate-800 dark:text-slate-200">
                <span className="line-clamp-2">{vuln.plugin_name}</span>
              </td>
            );
          case "family":
            return <td key={col.key} className="table-cell text-slate-500 dark:text-slate-400 truncate" title={vuln.plugin_family}>{vuln.plugin_family}</td>;
          case "cve":
            return (
              <td key={col.key} className="table-cell text-slate-500 dark:text-slate-400 truncate" title={vuln.cve.join("\n")}>
                {vuln.cve[0] ?? <Dash />}
                {vuln.cve.length > 1 && ` +${vuln.cve.length - 1}`}
              </td>
            );
          case "cvss":
            return (
              <td key={col.key} className="table-cell">
                {cvss !== null ? (
                  <span className={`${SEVERITY_COLORS[vuln.severity].text} ${vuln.severity >= 3 ? "font-semibold" : ""}`}>
                    {cvss.score.toFixed(1)}
                  </span>
                ) : (
                  <Dash />
                )}
                {cvss !== null && (
                  <span className="ml-1 text-[10px] text-slate-400" title={`CVSS v${cvss.version}`}>v{cvss.version}</span>
                )}
              </td>
            );
          case "vpr":
            return <td key={col.key} className="table-cell">{vuln.vpr !== null ? vuln.vpr.toFixed(1) : <Dash />}</td>;
          case "epss":
            return <td key={col.key} className="table-cell">{vuln.epss ?? <Dash />}</td>;
          case "hosts":
            return (
              <td key={col.key} className="table-cell text-center font-semibold text-slate-700 dark:text-slate-200">
                {vuln.host_count}
              </td>
            );
          case "patch":
            return (
              <td key={col.key} className="table-cell text-slate-500 dark:text-slate-400">
                {vuln.patch_publication_date ? formatNessusDate(vuln.patch_publication_date) : <Dash />}
              </td>
            );
          case "exploit":
            return (
              <td key={col.key} className="table-cell">
                {vuln.exploit_available && (
                  <span className="pill bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 text-xs">
                    EXPLOIT
                  </span>
                )}
              </td>
            );
          case "metasploit":
            return (
              <td key={col.key} className="table-cell" title={vuln.metasploit_name ?? undefined}>
                {vuln.metasploit_available && (
                  <span className="pill bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 text-xs">
                    METASPLOIT
                  </span>
                )}
              </td>
            );
          case "ease":
            return (
              <td key={col.key} className="table-cell text-slate-500 dark:text-slate-400 truncate" title={vuln.exploit_ease ?? undefined}>
                {vuln.exploit_ease ?? <Dash />}
              </td>
            );
        }
      })}
    </tr>
  );
}// VulnRow

function Dash() {
  return <span className="text-slate-300 dark:text-slate-600">-</span>;
}// Dash
