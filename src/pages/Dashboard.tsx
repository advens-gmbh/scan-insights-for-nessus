import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Trash2, ShieldAlert, Server, Layers } from "lucide-react";
import type { ReactNode } from "react";
import { useScanStore } from "../stores/scanStore";
import { useSeverityStore } from "../stores/severityStore";
import { usePageStore } from "../stores/pageStore";
import { severityCounts, buildHostEntries, buildVulnEntries, visibleCounts, ratedScore, SEVERITY_LABELS } from "../types/nessus";
import { useUiStore } from "../stores/uiStore";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import ScanName from "../components/common/ScanName";
import IpLink from "../components/common/IpLink";
import SeverityBadge from "../components/common/SeverityBadge";
import type { SeverityCounts } from "../types/nessus";
import { formatDuration, formatScanStart, rankHosts, scanWindow, topVulnerabilities } from "../utils/dashboard";
import SeverityDonut from "../components/charts/SeverityDonut";
import SeverityBar from "../components/charts/SeverityBar";
import TableHead from "../components/common/TableHead";
import { useTableColumns } from "../hooks/useTableColumns";
import { useTableSort } from "../hooks/useTableSort";
import type { TableColumn } from "../utils/tableColumns";
import Welcome from "./Welcome";

const TOP_HOSTS = 10;
const TOP_VULNS = 8;

const LEVELS = [
  { key: "critical", sev: 4, fg: "text-critical-fg", bg: "bg-critical" },
  { key: "high",     sev: 3, fg: "text-high-fg",     bg: "bg-high" },
  { key: "medium",   sev: 2, fg: "text-medium-fg",   bg: "bg-medium" },
  { key: "low",      sev: 1, fg: "text-low-fg",      bg: "bg-low" },
  { key: "info",     sev: 0, fg: "text-info-fg",     bg: "bg-info" },
] as const;

type FileCol = "file" | "scanned" | "hosts" | "critical" | "high" | "medium" | "low" | "info" | "distribution" | "actions";

const FILE_COLUMNS: TableColumn<FileCol>[] = [
  { key: "file",         label: "File",         width: 144, required: true },
  { key: "scanned",      label: "Scanned",      width: 156 },
  { key: "hosts",        label: "Hosts",        width: 76,  align: "center" },
  { key: "critical",     label: "Critical",     width: 88, align: "center" },
  { key: "high",         label: "High",         width: 74,  align: "center" },
  { key: "medium",       label: "Medium",       width: 88, align: "center" },
  { key: "low",          label: "Low",          width: 72,  align: "center" },
  { key: "info",         label: "Info",         width: 76,  align: "center" },
  { key: "distribution", label: "Distribution", width: 88, sortable: false },
  { key: "actions",      label: "",             width: 136, sortable: false },
];// FILE_COLUMNS

const total = (c: SeverityCounts) => c.critical + c.high + c.medium + c.low + c.info;

export default function Dashboard() {
  const files = useScanStore((s) => s.files);
  const unloadFile = useScanStore((s) => s.unloadFile);
  const navigate = useNavigate();
  const { showInfo, openVulnPanel } = useUiStore();
  const openFilePanel = useUiStore((s) => s.openFilePanel);

  const allHosts = useMemo(() => buildHostEntries(files), [files]);
  const allVulns = useMemo(() => buildVulnEntries(files), [files]);
  const combined = useMemo(() => severityCounts(allHosts), [allHosts]);
  const shown = visibleCounts(combined, showInfo);

  const affectedHosts = useMemo(() => {
    const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const h of allHosts) {
      for (const l of LEVELS) {
        if (h.severity_counts[l.key] > 0) c[l.key]++;
      }
    }

    return c;
  }, [allHosts]);

  // counted like the severity tiles: each finding on each host
  const exploits = useMemo(() => {
    let findings = 0, metasploit = 0;
    const hosts = new Set<string>();
    for (const h of allHosts) {
      for (const item of h.items) {
        if (item.exploit_available) {
          findings++;
          hosts.add(h.ip);
        }
        if (item.metasploit_available) metasploit++;
      }
    }

    return { findings, metasploit, hosts: hosts.size };
  }, [allHosts]);
  const seriousCount = allVulns.filter((v) => v.severity >= 3).length;
  const topVulns = useMemo(() => topVulnerabilities(allVulns, TOP_VULNS), [allVulns]);

  const topHosts = useMemo(() => rankHosts(allHosts, showInfo, TOP_HOSTS), [allHosts, showInfo]);
  const hostMax = Math.max(0, ...topHosts.map((h) => total(visibleCounts(h.severity_counts, showInfo))));

  const fileRows = useMemo(() => files.map((file) => {
    const counts = severityCounts(file.hosts);
    return { file, counts, window: scanWindow(file.hosts) };
  }), [files]);

  const fileTable = useTableColumns("dashboard-files", FILE_COLUMNS);
  const fileSort = useTableSort("dashboard-files", fileTable.visible, "scanned", "desc", ["file"]);
  const sortedFiles = useMemo(() => [...fileRows].sort((a, b) => {
    let cmp = 0;
    switch (fileSort.sortKey) {
      case "file":    cmp = a.file.filename.localeCompare(b.file.filename); break;
      case "scanned": cmp = (a.window.start?.getTime() ?? 0) - (b.window.start?.getTime() ?? 0); break;
      case "hosts":   cmp = a.file.hosts.length - b.file.hosts.length; break;
      case "critical": case "high": case "medium": case "low": case "info":
        cmp = a.counts[fileSort.sortKey] - b.counts[fileSort.sortKey]; break;
    }

    return fileSort.sortDir === "desc" ? -cmp : cmp;
  }), [fileRows, fileSort.sortKey, fileSort.sortDir]);

  // opens Vulnerabilities with these severity pills selected
  const showSeverities = (sevs: number[]) => {
    useSeverityStore.getState().setSelection("vulnerabilities", sevs);
    navigate("/vulnerabilities");
  };

  const showExploitable = () => {
    usePageStore.getState().set("sort:vulnerabilities", { key: "exploit", dir: "desc" });
    showSeverities([]);
  };

  if (files.length === 0) {
    return <Welcome />;
  }

  const shownTotal = total(shown);

  return (
    <div className="flex flex-col gap-6">
      {/* Totals */}
      <section aria-label="Totals" className="grid grid-cols-3 xl:grid-cols-6 gap-3">
        {LEVELS.map((l) => (
          <button
            key={l.key}
            onClick={() => showSeverities([l.sev])}
            className="card relative overflow-hidden px-4 py-3.5 flex flex-col gap-1.5 text-left hover:border-ink-300 dark:hover:border-ink-600 transition-colors"
            title={`Show ${SEVERITY_LABELS[l.sev]} findings`}
          >
            <span className="flex items-center gap-2 text-[13px] font-semibold text-ink-500 dark:text-ink-400">
              <span className={`w-2.5 h-2.5 rounded-full ${l.bg}`} />{SEVERITY_LABELS[l.sev]}
            </span>
            <span className={`text-3xl font-bold leading-none tabular-nums ${l.fg}`}>{combined[l.key].toLocaleString()}</span>
            <span className="text-xs text-ink-500 dark:text-ink-400">on {affectedHosts[l.key].toLocaleString()} hosts</span>
            <span className={`absolute inset-x-0 bottom-0 h-1 ${l.bg}`} />
          </button>
        ))}
        <button
          onClick={showExploitable}
          className="card relative overflow-hidden px-4 py-3.5 flex flex-col gap-1.5 text-left hover:border-ink-300 dark:hover:border-ink-600 transition-colors"
          title={`Findings with a public exploit, counted on each host they are on. ${exploits.metasploit.toLocaleString()} of them have a Metasploit module.\nShow them first in Vulnerabilities`}
        >
          <span className="text-[13px] font-semibold text-ink-500 dark:text-ink-400">Exploitable</span>
          <span className="text-3xl font-bold leading-none tabular-nums text-ink-900 dark:text-ink-50">{exploits.findings.toLocaleString()}</span>
          <span className="text-xs text-ink-500 dark:text-ink-400">on {exploits.hosts.toLocaleString()} hosts</span>
          <span className="absolute inset-x-0 bottom-0 h-1 bg-critical" />
        </button>
      </section>

      {/* Top vulnerabilities */}
      <section>
        <div className="flex items-baseline justify-between gap-3 mb-2.5">
          <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Top vulnerabilities</h2>
          {seriousCount > 0 && (
            <button onClick={() => showSeverities([4, 3])} className="text-sm font-medium text-accent-700 dark:text-accent-400 hover:underline">
              Show all {seriousCount.toLocaleString()} in Vulnerabilities
            </button>
          )}
        </div>
        <div className="card divide-y divide-ink-100 dark:divide-ink-700">
          {topVulns.length === 0 && <p className="px-4 py-5 text-sm text-ink-500 dark:text-ink-400">No critical or high findings.</p>}
          {topVulns.map((v) => {
            const cvss = ratedScore(v);
            return (
              <button
                key={v.plugin_id}
                onClick={() => openVulnPanel(v.plugin_id)}
                className="w-full grid grid-cols-[5.5rem_minmax(0,1fr)_auto_5.75rem_5.5rem] gap-3.5 items-center px-4 py-2.5 text-left hover:bg-ink-50 dark:hover:bg-ink-700/40 transition-colors"
              >
                <span><SeverityBadge severity={v.severity} size="sm" /></span>
                <span className="truncate text-sm font-medium text-ink-800 dark:text-ink-100" title={v.plugin_name}>{v.plugin_name}</span>
                <span className="flex gap-1">
                  {v.exploit_available && <span className="px-1.5 py-px rounded text-[11px] font-semibold bg-ink-100 dark:bg-ink-700 text-critical-fg">Exploit</span>}
                  {v.metasploit_available && <span className="px-1.5 py-px rounded text-[11px] font-semibold bg-ink-100 dark:bg-ink-700 text-ink-700 dark:text-ink-200">Metasploit</span>}
                </span>
                <span className="text-right text-[13px] text-ink-500 dark:text-ink-400 tabular-nums">
                  {cvss ? <>CVSS <b className="text-ink-800 dark:text-ink-100">{cvss.score.toFixed(1)}</b> <span className="text-[10px]">v{cvss.version}</span></> : "-"}
                </span>
                <span className="text-right text-[13px] text-ink-500 dark:text-ink-400 tabular-nums">
                  <b className="text-sm text-ink-800 dark:text-ink-100">{v.host_count}</b> {v.host_count === 1 ? "host" : "hosts"}
                </span>
              </button>
            );
          })}
        </div>
      </section>

      {/* Hosts + distribution */}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <section className="flex flex-col min-w-0">
          <div className="flex items-baseline justify-between gap-3 mb-2.5">
            <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Most vulnerable hosts</h2>
            <button onClick={() => navigate("/hosts")} className="text-sm font-medium text-accent-700 dark:text-accent-400 hover:underline">
              All {allHosts.length.toLocaleString()} hosts
            </button>
          </div>
          <div className="card flex-1 divide-y divide-ink-100 dark:divide-ink-700">
            {topHosts.length === 0 && <p className="px-4 py-5 text-sm text-ink-500 dark:text-ink-400">No findings above Info.</p>}
            {topHosts.map((h) => {
              const counts = visibleCounts(h.severity_counts, showInfo);
              const name = h.hostname ?? h.netbios;
              return (
                <div key={h.ip} className="grid grid-cols-[8.5rem_minmax(0,10rem)_minmax(0,1fr)_2.5rem] gap-3.5 items-center px-4 py-2">
                  <IpLink ip={h.ip} className="text-left" />
                  <span className="truncate text-sm text-ink-500 dark:text-ink-400" title={name ?? undefined}>{name ?? "-"}</span>
                  <SeverityBar counts={counts} max={hostMax} />
                  <span className="text-right text-sm font-semibold tabular-nums text-ink-800 dark:text-ink-100">{total(counts)}</span>
                </div>
              );
            })}
          </div>
        </section>

        <section className="flex flex-col min-w-0">
          <div className="flex items-baseline justify-between gap-3 mb-2.5">
            <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Severity distribution</h2>
            <ShowInfoCheckbox />
          </div>
          <div className="card flex-1 flex flex-col items-center justify-center gap-3 p-5">
            <SeverityDonut counts={shown} size={190} emptyText={combined.info > 0 ? "Only Info findings" : undefined} />
            <div className="w-full flex flex-col gap-1.5">
              {LEVELS.map((l) => {
                const present = shownTotal > 0 && shown[l.key] > 0;
                return { l, present };
              }).sort((a, b) => Number(b.present) - Number(a.present)).map(({ l, present }) => (
                <div key={l.key} className={`grid grid-cols-[0.875rem_1fr_auto_3rem] gap-2 items-center text-sm h-5 ${present ? "" : "invisible"}`} aria-hidden={!present}>
                  <span className={`w-2.5 h-2.5 rounded-full ${l.bg}`} />
                  <span className="text-ink-700 dark:text-ink-200">{SEVERITY_LABELS[l.sev]}</span>
                  <span className={`text-right font-bold tabular-nums ${l.fg}`}>{shown[l.key].toLocaleString()}</span>
                  <span className="text-right text-xs tabular-nums text-ink-500 dark:text-ink-400">{shownTotal > 0 ? Math.round((shown[l.key] / shownTotal) * 100) : 0}%</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>

      {/* Scan files */}
      <section>
        <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100 mb-2.5">Scan files</h2>
        <div className="card overflow-x-auto">
          <table style={fileTable.style} className="text-sm tabular-nums">
            <TableHead table={fileTable} sortKey={fileSort.sortKey} sortDir={fileSort.sortDir} onSort={fileSort.toggleSort} />
            <tbody className="divide-y divide-ink-100 dark:divide-ink-700">
              {sortedFiles.map(({ file, counts, window }) => (
                <tr key={file.id} className="whitespace-nowrap">
                  {fileTable.visible.map((col) => {
                    switch (col.key) {
                      case "file":
                        return (
                          <td key={col.key} className="px-4 py-2.5 overflow-hidden">
                            <button
                              onClick={() => openFilePanel(file.id)}
                              className="block max-w-full truncate font-semibold text-ink-800 dark:text-ink-100 hover:text-accent-700 dark:hover:text-accent-400 text-left"
                              title={`${file.path}\nClick for file details`}
                            >
                              {file.filename.replace(/\.nessus$/i, "")}
                            </button>
                            <ScanName file={file} />
                          </td>
                        );
                      case "scanned":
                        return (
                          <td key={col.key} className="px-4 py-2.5 overflow-hidden">
                            {window.start ? (
                              <>
                                <div className="text-ink-700 dark:text-ink-200">{formatScanStart(window.start)}</div>
                                {window.durationMs !== null && <div className="text-xs text-ink-500 dark:text-ink-400">ran for {formatDuration(window.durationMs)}</div>}
                              </>
                            ) : <span className="text-ink-400 dark:text-ink-500">-</span>}
                          </td>
                        );
                      case "hosts":
                        return <td key={col.key} className="px-4 py-2.5 text-center text-ink-700 dark:text-ink-200">{file.hosts.length.toLocaleString()}</td>;
                      case "distribution":
                        return (
                          <td key={col.key} className="px-4 py-2.5">
                            <SeverityBar counts={visibleCounts(counts, showInfo)} max={total(visibleCounts(counts, showInfo))} numbers={false} className="h-2.5" />
                          </td>
                        );
                      case "actions":
                        return (
                          <td key={col.key} className="px-1 py-2.5 text-right whitespace-nowrap">
                            <FileAction label="Vulnerabilities" onClick={() => navigate("/vulnerabilities", { state: { fileFilter: file.id } })}><ShieldAlert size={15} /></FileAction>
                            <FileAction label="Hosts" onClick={() => navigate("/hosts", { state: { fileFilter: file.id } })}><Server size={15} /></FileAction>
                            <FileAction label="Services" onClick={() => navigate("/services", { state: { fileFilter: file.id } })}><Layers size={15} /></FileAction>
                            <FileAction label="Unload" danger onClick={() => unloadFile(file.id)}><Trash2 size={14} /></FileAction>
                          </td>
                        );
                      default: {
                        const level = LEVELS.find((l) => l.key === col.key)!;
                        return (
                          <td key={col.key} className={`px-4 py-2.5 text-center ${counts[level.key] > 0 ? `font-bold ${level.fg}` : "text-ink-400 dark:text-ink-500"}`}>
                            {counts[level.key].toLocaleString()}
                          </td>
                        );
                      }
                    }
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

    </div>
  );
}// Dashboard

// icon button with the same icon as the page in the sidebar
function FileAction({ label, danger = false, onClick, children }: { label: string; danger?: boolean; onClick: () => void; children: ReactNode }) {
  const text = danger ? "Unload this file" : `Open in ${label}`;
  return (
    <button
      onClick={onClick}
      title={text}
      aria-label={text}
      className={`inline-flex items-center justify-center w-8 h-8 rounded-md text-ink-500 dark:text-ink-400 hover:bg-ink-100 dark:hover:bg-ink-700 transition-colors ${
        danger ? "hover:text-red-600 dark:hover:text-red-400" : "hover:text-accent-700 dark:hover:text-accent-400"
      }`}
    >
      {children}
    </button>
  );
}// FileAction
