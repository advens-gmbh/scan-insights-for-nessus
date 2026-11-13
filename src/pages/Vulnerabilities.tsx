import { X } from "lucide-react";
import { ExploitTag, Tag } from "../panels/PanelParts";
import { useMemo } from "react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { ratedScore, SEVERITY_COLORS, vulnScore } from "../types/nessus";
import { formatNessusDate } from "../utils/format";
import type { VulnRow } from "../types/nessus";
import { useQuery } from "../data/query";
import SeverityBadge from "../components/common/SeverityBadge";
import SeverityPills from "../components/common/SeverityPills";
import DataTable from "../components/common/DataTable";
import TableToolbar from "../components/common/TableToolbar";
import { Dash, SELECTED_ROW } from "../components/common/TableCells";
import { useFileFilter } from "../hooks/useFileFilter";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { useTableColumns } from "../hooks/useTableColumns";
import { countBySeverity } from "../utils/severityFilter";
import { useTableSort } from "../hooks/useTableSort";
import { usePageState } from "../stores/pageStore";
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

const NO_ROWS: VulnRow[] = [];
const SEARCH = "Search vulnerabilities, CVEs, IPs…";

export default function Vulnerabilities() {
  const files = useScanStore((s) => s.files);
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);
  const openPluginId = useUiStore((s) => s.vulnPanelId);

  const [search, setSearch] = usePageState("vulns:search", "");
  const [fileFilter, setFileFilter] = useFileFilter("vulns");
  const [exploitOnly, setExploitOnly] = usePageState("vulns:exploit", false);
  const [familyFilter, setFamilyFilter] = usePageState("vulns:family", "");
  const { selected: selectedSeverities, toggle: toggleSeverity, clear: clearSeverities, matches: matchesSeverity } = useSeverityFilter("vulnerabilities");
  const table = useTableColumns("vulnerabilities", COLUMNS);
  const sort = useTableSort("vulnerabilities", table.visible, "severity", "desc", ASCENDING_FIRST);
  const { sortKey, sortDir } = sort;

  const scope = fileFilter === "all" ? null : fileFilter;
  const answer = useQuery<VulnRow[]>("vuln_rows", files.length > 0 ? { file: scope } : null);
  const vulnsForFilter = answer ?? NO_ROWS;
  // a search for part of an address also finds the vulnerabilities on those hosts
  const ipText = /^[0-9a-f.:]+$/i.test(search.trim()) ? search.trim().toLowerCase() : "";
  const onIp = useQuery<number[]>("vulns_on_ip", ipText ? { file: scope, text: ipText } : null);
  const onIpSet = useMemo(() => new Set(onIp ?? []), [onIp]);

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
          onIpSet.has(v.plugin_id)
        );
      }

      return true;
    });
  }, [vulnsForFilter, search, matchesSeverity, exploitOnly, familyFilter, onIpSet]);

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

  const fileId = fileFilter !== "all" ? fileFilter : undefined;

  const severityCounts = useMemo(
    () => countBySeverity(vulnsForFilter.filter((v) => !exploitOnly || v.exploit_available).map((v) => [v.severity])),
    [vulnsForFilter, exploitOnly]
  );
  const exploitCount = useMemo(
    () => vulnsForFilter.filter((v) => v.exploit_available && matchesSeverity([v.severity])).length,
    [vulnsForFilter, matchesSeverity]
  );

  if (files.length === 0) {
    return <EmptyFilesNotice page="vulnerabilities" columns={COLUMNS} search={SEARCH} />;
  }

  return (
    <div className="h-full flex flex-col gap-4">
      <TableToolbar
        pills={
          <>
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
          </>
        }
        search={{ value: search, onChange: setSearch, placeholder: SEARCH }}
        file={{ value: fileFilter, onChange: setFileFilter, ariaLabel: "Show the findings from" }}
        table={table}
        count={`${sorted.length.toLocaleString()} ${sorted.length === 1 ? "vulnerability" : "vulnerabilities"}`}
      />

      <DataTable
        table={table}
        sort={sort}
        count={sorted.length}
        empty={answer !== undefined ? "No vulnerabilities match the current filter." : null}
        keys={{
          open: openPluginId !== null,
          current: () => sorted.findIndex((v) => v.plugin_id === openPluginId),
          go: (i) => openVulnPanel(sorted[i].plugin_id, fileId),
        }}
        row={(index, measure) => {
          const v = sorted[index];
          return (
            <VulnRow
              key={v.plugin_id}
              vuln={v}
              visibleCols={table.visible}
              index={index}
              measureRow={measure}
              selected={v.plugin_id === openPluginId}
              onClick={() => openVulnPanel(v.plugin_id, fileId)}
            />
          );
        }}
      />
    </div>
  );
}// Vulnerabilities

function VulnRow({ vuln, visibleCols, index, selected, measureRow, onClick }: {
  vuln: VulnRow;
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
      className={`table-row ${selected ? SELECTED_ROW : ""}`}
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
