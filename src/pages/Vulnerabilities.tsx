import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { ChevronUp, ChevronDown } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { buildVulnEntries, ratedScore, SEVERITY_COLORS, SEVERITY_ORDER, SEVERITY_LABELS, vulnScore } from "../types/nessus";
import { formatNessusDate } from "../utils/format";
import type { VulnEntry } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import SearchBar from "../components/common/SearchBar";
import SpacerRow from "../components/common/SpacerRow";
import { useVirtualRows } from "../hooks/useVirtualRows";
import EmptyFilesNotice from "./EmptyFilesNotice";

type SortKey = "severity" | "name" | "family" | "cvss" | "hosts" | "patch" | "exploit";
type SortDir = "asc" | "desc";

const ASCENDING_FIRST: SortKey[] = ["name", "family", "patch"];

export default function Vulnerabilities() {
  const files = useScanStore((s) => s.files);
  const { openVulnPanel, showInfo, toggleShowInfo } = useUiStore();
  const location = useLocation();

  const [search, setSearch] = useState("");
  const [fileFilter, setFileFilter] = useState<string>(
    (location.state as { fileFilter?: string } | null)?.fileFilter ?? "all"
  );
  const [severityFilter, setSeverityFilter] = useState<Set<number>>(new Set([4, 3, 2, 1]));
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

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
      if (v.severity === 0 ? !showInfo : !severityFilter.has(v.severity)) {
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
  }, [vulnsForFilter, search, severityFilter, showInfo]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      // findings without a date stay at the bottom in both directions
      if (sortKey === "patch" && (!a.patch_publication_date || !b.patch_publication_date)) {
        return Number(!a.patch_publication_date) - Number(!b.patch_publication_date);
      }

      let cmp = 0;
      switch (sortKey) {
        case "severity": cmp = a.severity - b.severity; break;
        case "name":     cmp = a.plugin_name.localeCompare(b.plugin_name); break;
        case "family":   cmp = a.plugin_family.localeCompare(b.plugin_family); break;
        case "cvss":     cmp = (vulnScore(a) ?? -1) - (vulnScore(b) ?? -1); break;
        case "hosts":    cmp = a.host_count - b.host_count; break;
        case "patch":    cmp = a.patch_publication_date!.localeCompare(b.patch_publication_date!); break;
        case "exploit":  cmp = Number(a.exploit_available) - Number(b.exploit_available); break;
      }
      return sortDir === "desc" ? -cmp : cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow } = useVirtualRows(sorted.length);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    }
    else { 
      setSortKey(key); 
      setSortDir(ASCENDING_FIRST.includes(key) ? "asc" : "desc"); 
    }
  };

  const toggleSeverity = (sev: number) => {
    if (sev === 0) {
      toggleShowInfo();
      return;
    }

    setSeverityFilter((prev) => {
      const n = new Set(prev);
      n.has(sev) ? n.delete(sev) : n.add(sev);
      return n;
    });
  };

  const countsAll = useMemo(() => {
    const c: Record<number, number> = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 };
    for (const v of vulnsForFilter) {
      c[v.severity] = (c[v.severity] ?? 0) + 1;
    }

    return c;
  }, [vulnsForFilter]);

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        {/* Severity pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {SEVERITY_ORDER.map((sev) => {
            const count = countsAll[sev] ?? 0;
            if (count === 0) return null;
            const active = sev === 0 ? showInfo : severityFilter.has(sev);
            const colors = {
              4: active ? "bg-critical text-white" : "bg-critical/10 text-critical",
              3: active ? "bg-high text-white" : "bg-high/10 text-high",
              2: active ? "bg-medium text-white" : "bg-medium/10 text-medium",
              1: active ? "bg-low text-white" : "bg-low/10 text-low",
              0: active ? "bg-info text-white" : "bg-info/10 text-info",
            }[sev];
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={`pill px-3 py-1 text-sm font-semibold cursor-pointer transition-colors ${colors}`}
              >
                {SEVERITY_LABELS[sev]} {count}
              </button>
            );
          })}
        </div>

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

        <span className="text-xs text-slate-400 shrink-0">
          {sorted.length.toLocaleString()} results
        </span>
      </div>

      {/* Table - fills remaining height, scrolls internally so thead stays sticky */}
      <div className="card flex-1 overflow-hidden">
        <div ref={scrollRef} className="overflow-auto h-full">
          <table className="w-full min-w-[64rem] table-fixed">
            <thead className="sticky top-0 z-10">
              <tr>
                <Th label="Severity" sortKey="severity" current={sortKey} dir={sortDir} onSort={toggleSort} width="w-28" />
                <Th label="Name"     sortKey="name"     current={sortKey} dir={sortDir} onSort={toggleSort} />
                <Th label="Family"   sortKey="family"   current={sortKey} dir={sortDir} onSort={toggleSort} width="w-40" />
                <Th label="CVSS"     sortKey="cvss"     current={sortKey} dir={sortDir} onSort={toggleSort} width="w-24" />
                <Th label="Hosts"    sortKey="hosts"    current={sortKey} dir={sortDir} onSort={toggleSort} width="w-24" />
                <Th label="Patch Released" sortKey="patch" current={sortKey} dir={sortDir} onSort={toggleSort} width="w-44" />
                <Th label="Exploit"  sortKey="exploit"  current={sortKey} dir={sortDir} onSort={toggleSort} width="w-28" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              <SpacerRow height={paddingTop} colSpan={7} />
              {rows.map((row) => {
                const v = sorted[row.index];
                return (
                  <VulnRow
                    key={v.plugin_id}
                    vuln={v}
                    index={row.index}
                    measureRow={measureRow}
                    onClick={() => openVulnPanel(v.plugin_id, fileFilter !== "all" ? fileFilter : undefined)}
                  />
                );
              })}
              <SpacerRow height={paddingBottom} colSpan={7} />
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={7} className="table-cell text-center text-slate-400 py-10">
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

function VulnRow({ vuln, index, measureRow, onClick }: {
  vuln: VulnEntry;
  index: number;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const cvss = ratedScore(vuln);
  return (
    <tr ref={measureRow} data-index={index} className="table-row" onClick={onClick}>
      <td className="table-cell">
        <SeverityBadge severity={vuln.severity} />
      </td>
      <td className="table-cell font-medium text-slate-800 dark:text-slate-200">
        <span className="line-clamp-2">{vuln.plugin_name}</span>
      </td>
      <td className="table-cell text-slate-500 dark:text-slate-400 truncate" title={vuln.plugin_family}>{vuln.plugin_family}</td>
      <td className="table-cell font-mono text-sm">
        {cvss !== null ? (
          <span className={`${SEVERITY_COLORS[vuln.severity].text} ${vuln.severity >= 3 ? "font-semibold" : ""}`}>
            {cvss.score.toFixed(1)}
          </span>
        ) : (
          <span className="text-slate-300 dark:text-slate-600">-</span>
        )}
        {cvss !== null && (
          <span className="ml-1 font-sans text-[10px] text-slate-400" title={`CVSS v${cvss.version}`}>v{cvss.version}</span>
        )}
      </td>
      <td className="table-cell text-center font-semibold text-slate-700 dark:text-slate-200">
        {vuln.host_count}
      </td>
      <td className="table-cell tabular-nums text-slate-500 dark:text-slate-400">
        {vuln.patch_publication_date ? formatNessusDate(vuln.patch_publication_date) : <span className="text-slate-300 dark:text-slate-600">-</span>}
      </td>
      <td className="table-cell">
        {vuln.exploit_available && (
          <span className="pill bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 text-xs">
            EXPLOIT
          </span>
        )}
      </td>
    </tr>
  );
}// VulnRow

function Th({label, sortKey, current, dir, onSort, width = "",}: {
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
