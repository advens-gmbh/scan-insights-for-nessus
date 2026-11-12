import { X } from "lucide-react";
import { ExploitTag, Tag } from "../panels/PanelParts";
import { useEffect, useMemo } from "react";
import { useLocation } from "react-router-dom";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { buildVulnEntries, ratedScore, SEVERITY_COLORS, vulnScore } from "../types/nessus";
import { formatNessusDate } from "../utils/format";
import type { VulnEntry } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import SearchBar from "../components/common/SearchBar";
import Select, { fileOption } from "../components/common/Select";
import SpacerRow from "../components/common/SpacerRow";
import ColumnPicker from "../components/common/ColumnPicker";
import SeverityPills from "../components/common/SeverityPills";
import TableHead from "../components/common/TableHead";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { countBySeverity } from "../utils/severityFilter";
import { useTableSort } from "../hooks/useTableSort";
import { usePageState } from "../stores/pageStore";
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
  const openPluginId = useUiStore((s) => s.vulnPanelId);
  const location = useLocation();

  const [search, setSearch] = usePageState("vulns:search", "");
  const [chosenFile, setFileFilter] = usePageState("vulns:file", "all");
  const fileFilter = chosenFile === "all" || files.some((f) => f.id === chosenFile) ? chosenFile : "all";

  useEffect(() => {
    const handed = (location.state as { fileFilter?: string } | null)?.fileFilter;
    if (handed) {
      setFileFilter(handed);
    }
  }, [location.key, location.state, setFileFilter]);
  const [exploitOnly, setExploitOnly] = usePageState("vulns:exploit", false);
  const [familyFilter, setFamilyFilter] = usePageState("vulns:family", "");
  const { selected: selectedSeverities, toggle: toggleSeverity, clear: clearSeverities, matches: matchesSeverity } = useSeverityFilter("vulnerabilities");
  const table = useTableColumns("vulnerabilities", COLUMNS);
  const { sortKey, sortDir, toggleSort } = useTableSort("vulnerabilities", table.visible, "severity", "desc", ASCENDING_FIRST);

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
      if (!matchesSeverity([v.severity]) || (exploitOnly && !v.exploit_available)) {
        return false;
      }

      if (familyFilter && (v.plugin_family || "Other") !== familyFilter) {
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
  }, [vulnsForFilter, search, matchesSeverity, exploitOnly, familyFilter]);

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
      return (sortDir === "desc" ? -cmp : cmp) || b.severity - a.severity || b.host_count - a.host_count;
    });
  }, [filtered, sortKey, sortDir]);

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow, scrollToIndex } = useVirtualRows(sorted.length);

  // while a finding is open, up and down move to the previous and next one in the table's order
  useEffect(() => {
    if (openPluginId === null) {
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

      const index = sorted.findIndex((v) => v.plugin_id === openPluginId);
      const next = index === -1 ? 0 : index + (e.key === "ArrowDown" ? 1 : -1);
      if (next < 0 || next >= sorted.length) {
        return;
      }

      e.preventDefault();
      openVulnPanel(sorted[next].plugin_id, fileFilter !== "all" ? fileFilter : undefined);
      scrollToIndex(next, { align: "auto" });
    };
    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, [openPluginId, sorted, fileFilter, openVulnPanel, scrollToIndex]);

  const severityCounts = useMemo(
    () => countBySeverity(vulnsForFilter.filter((v) => !exploitOnly || v.exploit_available).map((v) => [v.severity])),
    [vulnsForFilter, exploitOnly]
  );
  const exploitCount = useMemo(
    () => vulnsForFilter.filter((v) => v.exploit_available && matchesSeverity([v.severity])).length,
    [vulnsForFilter, matchesSeverity]
  );

  if (files.length === 0) {
    return <EmptyFilesNotice page="vulnerabilities" columns={COLUMNS} search="Search vulnerabilities, CVEs, IPs…" />;
  }

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <SeverityPills counts={severityCounts} selected={selectedSeverities} onToggle={toggleSeverity} onClear={clearSeverities} />
        {(exploitCount > 0 || exploitOnly) && (
          <button
            onClick={() => setExploitOnly(!exploitOnly)}
            aria-pressed={exploitOnly}
            title={exploitOnly ? "Show all vulnerabilities" : "Show only vulnerabilities with a public exploit"}
            className={`pill px-3 py-1 text-body font-semibold cursor-pointer transition-colors ${
              exploitOnly ? "bg-ink-800 text-white dark:bg-ink-100 dark:text-ink-900" : "bg-ink-100 text-ink-700 hover:bg-ink-200 dark:bg-ink-700 dark:text-ink-200 dark:hover:bg-ink-600"
            }`}
          >
            Exploit available {exploitCount.toLocaleString()}
          </button>
        )}
        {familyFilter && (
          <button
            onClick={() => setFamilyFilter("")}
            title="Show every family"
            className="pill px-3 py-1 text-body font-semibold gap-1.5 bg-ink-800 text-white dark:bg-ink-100 dark:text-ink-900"
          >
            {familyFilter} <X size={14} aria-hidden="true" />
          </button>
        )}

        {/* File filter */}
        {files.length > 1 && (
          <Select value={fileFilter} onChange={setFileFilter} options={[{ value: "all", label: "All files" }, ...files.map(fileOption)]} ariaLabel="Show the findings from" className="w-60 shrink-0" />
        )}

        <div className="flex-1 min-w-60">
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder="Search vulnerabilities, CVEs, IPs…"
          />
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <ColumnPicker table={table} />
          <span className="text-caption text-ink-500">
            {sorted.length.toLocaleString()} {sorted.length === 1 ? "vulnerability" : "vulnerabilities"}
          </span>
        </div>
      </div>

      {/* Table - fills remaining height, scrolls internally so thead stays sticky */}
      <div className="card min-h-0 flex flex-col overflow-hidden">
        <div ref={scrollRef} className="overflow-auto flex-1 min-h-0">
          <table style={table.style}>
            <TableHead table={table} sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
            <tbody className="divide-y divide-ink-100 dark:divide-ink-700/50">
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
                    selected={v.plugin_id === openPluginId}
                    onClick={() => openVulnPanel(v.plugin_id, fileFilter !== "all" ? fileFilter : undefined)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={table.visible.length} />
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={table.visible.length} className="table-cell text-center text-ink-500 py-10">
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

function VulnRow({ vuln, visibleCols, index, selected, measureRow, onClick }: {
  vuln: VulnEntry;
  visibleCols: ColDef[];
  index: number;
  selected: boolean;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const cvss = ratedScore(vuln);
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
          case "severity":
            return (
              <td key={col.key} className="table-cell">
                <SeverityBadge severity={vuln.severity} />
              </td>
            );
          case "plugin_id":
            return <td key={col.key} className="table-cell text-ink-500 dark:text-ink-400">{vuln.plugin_id}</td>;
          case "name":
            return (
              <td key={col.key} className="table-cell font-medium text-ink-800 dark:text-ink-200">
                <span className="line-clamp-2">{vuln.plugin_name}</span>
              </td>
            );
          case "family":
            return <td key={col.key} className="table-cell text-ink-500 dark:text-ink-400 truncate" title={vuln.plugin_family}>{vuln.plugin_family}</td>;
          case "cve":
            return (
              <td key={col.key} className="table-cell text-ink-500 dark:text-ink-400 truncate" title={vuln.cve.join("\n")}>
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
                  <span className="ml-1 text-tiny text-ink-500" title={`CVSS v${cvss.version}`}>v{cvss.version}</span>
                )}
              </td>
            );
          case "vpr":
            return <td key={col.key} className="table-cell">{vuln.vpr !== null ? vuln.vpr.toFixed(1) : <Dash />}</td>;
          case "epss":
            return <td key={col.key} className="table-cell">{vuln.epss ?? <Dash />}</td>;
          case "hosts":
            return (
              <td key={col.key} className="table-cell text-center font-semibold text-ink-700 dark:text-ink-200">
                {vuln.host_count.toLocaleString()}
              </td>
            );
          case "patch":
            return (
              <td key={col.key} className="table-cell text-ink-500 dark:text-ink-400">
                {vuln.patch_publication_date ? formatNessusDate(vuln.patch_publication_date) : <Dash />}
              </td>
            );
          case "exploit":
            return (
              <td key={col.key} className="table-cell">
                {vuln.exploit_available && <ExploitTag />}
              </td>
            );
          case "metasploit":
            return (
              <td key={col.key} className="table-cell" title={vuln.metasploit_name ?? undefined}>
                {vuln.metasploit_available && <Tag>Metasploit</Tag>}
              </td>
            );
          case "ease":
            return (
              <td key={col.key} className="table-cell text-ink-500 dark:text-ink-400 truncate" title={vuln.exploit_ease ?? undefined}>
                {vuln.exploit_ease ?? <Dash />}
              </td>
            );
        }
      })}
    </tr>
  );
}// VulnRow

function Dash() {
  return <span className="text-ink-300 dark:text-ink-600">-</span>;
}// Dash
