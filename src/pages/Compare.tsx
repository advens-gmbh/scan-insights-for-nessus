import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { ArrowLeftRight } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { severityCounts, SEVERITY_COLORS } from "../types/nessus";
import type { NessusFile, SeverityCounts } from "../types/nessus";
import { compareScans, defaultPair, deltaByHost, deltaByVuln } from "../utils/compare";
import type { HostChange, HostDelta, MatchedBy, VulnChange, VulnDelta } from "../utils/compare";
import { formatScanStart, scanWindow } from "../utils/dashboard";
import { compareHosts } from "../utils/ip";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import Segmented from "../components/common/Segmented";
import SeverityBadge from "../components/common/SeverityBadge";
import SpacerRow from "../components/common/SpacerRow";
import TableHead from "../components/common/TableHead";
import { useTableColumns } from "../hooks/useTableColumns";
import { useTableSort } from "../hooks/useTableSort";
import { useVirtualRows } from "../hooks/useVirtualRows";
import type { TableColumn } from "../utils/tableColumns";
import EmptyFilesNotice from "./EmptyFilesNotice";

type View = "vulns" | "hosts";
type VulnFilter = "changes" | "new" | "fixed" | "partly" | "increased" | "unverified" | "unchanged";
type HostFilter = "all" | HostChange;

const VULN_CHANGE: Record<VulnChange, { label: string; tone: string; title: string }> = {
  new:        { label: "New",          tone: "bad",  title: "Only in B" },
  increased:  { label: "Increased",    tone: "bad",  title: "On more hosts or ports in B, none fixed" },
  changed:    { label: "Changed",      tone: "warn", title: "Fixed on some hosts, new on others" },
  partly:     { label: "Partly fixed", tone: "good", title: "Gone from some rescanned hosts, still on others" },
  fixed:      { label: "Fixed",        tone: "good", title: "Gone from every host, all of them rescanned" },
  unverified: { label: "Not verified", tone: "warn", title: "Gone from B, but B can't confirm it: the host was not rescanned or lost its credentials" },
  unchanged:  { label: "Unchanged",    tone: "same", title: "On the same hosts in both scans" },
};

const HOST_CHANGE: Record<HostChange, { label: string; tone: string; title: string }> = {
  worsened: { label: "Worsened",          tone: "bad",  title: "More findings at the worst severity that changed" },
  improved: { label: "Improved",          tone: "good", title: "Fewer findings at the worst severity that changed" },
  new:      { label: "New host",          tone: "bad",  title: "Only in B" },
  missing:  { label: "Not rescanned",     tone: "warn", title: "Only in A, so nothing on it can be confirmed fixed" },
  replaced: { label: "Different machine", tone: "warn", title: "Another machine has this IP in B, so nothing on this one can be confirmed fixed" },
  same:     { label: "No change",         tone: "same", title: "The same counts in both scans" },
};

const MATCHED_BY: Record<MatchedBy, { label: string; title: string }> = {
  mac:      { label: "MAC",      title: "The same MAC address in both scans" },
  hostname: { label: "Hostname", title: "The same hostname in both scans" },
  netbios:  { label: "NetBIOS",  title: "The same NetBIOS name in both scans" },
  ip:       { label: "IP only",  title: "Only the IP matches: neither scan has a MAC address or name to confirm it is the same machine" },
};

const TONE: Record<string, string> = {
  bad:  "bg-critical/10 text-critical-fg dark:bg-critical/20",
  good: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300",
  warn: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300",
  same: "bg-ink-100 text-ink-600 dark:bg-ink-700 dark:text-ink-300",
};

type VulnKey = "severity" | "name" | "change" | "hostsA" | "hostsB" | "added" | "fixed";
const VULN_COLUMNS: TableColumn<VulnKey>[] = [
  { key: "severity", label: "Severity",   width: 112, required: true },
  { key: "name",     label: "Name",       width: 260, stretch: true, required: true },
  { key: "change",   label: "Change",     width: 140 },
  { key: "hostsA",   label: "Hosts in A", width: 112, align: "center" },
  { key: "hostsB",   label: "Hosts in B", width: 112, align: "center" },
  { key: "added",    label: "New",        width: 88,  align: "center" },
  { key: "fixed",    label: "Fixed",      width: 104, align: "center" },
];// VULN_COLUMNS

type HostKey = "host" | "change" | "by" | "critical" | "high" | "medium" | "low" | "info" | "added" | "fixed";
const HOST_COLUMNS: TableColumn<HostKey>[] = [
  { key: "host",     label: "Host",     width: 220, stretch: true, required: true },
  { key: "change",   label: "Change",   width: 150 },
  { key: "by",       label: "Matched by", width: 120 },
  { key: "critical", label: "Critical", width: 112, align: "center", dot: "bg-critical" },
  { key: "high",     label: "High",     width: 112, align: "center", dot: "bg-high" },
  { key: "medium",   label: "Medium",   width: 112, align: "center", dot: "bg-medium" },
  { key: "low",      label: "Low",      width: 112, align: "center", dot: "bg-low" },
  { key: "info",     label: "Info",     width: 112, align: "center", dot: "bg-info", defaultHidden: true },
  { key: "added",    label: "New",      width: 88,  align: "center" },
  { key: "fixed",    label: "Fixed",    width: 88,  align: "center" },
];// HOST_COLUMNS

const CHANGE_ORDER: Record<string, number> = { new: 0, increased: 1, worsened: 1, changed: 2, missing: 2, replaced: 2, unverified: 3, partly: 4, improved: 4, fixed: 5, unchanged: 6, same: 6 };
const MATCH_ORDER: Record<string, number> = { mac: 0, hostname: 1, netbios: 2, ip: 3 };

export default function Compare() {
  const files = useScanStore((s) => s.files);
  const showInfo = useUiStore((s) => s.showInfo);
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);
  const openHostPanel = useUiStore((s) => s.openHostPanel);
  const openFilePanel = useUiStore((s) => s.openFilePanel);
  const openPluginId = useUiStore((s) => s.vulnPanelId);
  const openIp = useUiStore((s) => s.hostPanelIp);

  const location = useLocation();
  const [picked, setPicked] = useState<[string, string] | null>((location.state as { pair?: [string, string] } | null)?.pair ?? null);
  const [view, setView] = useState<View>("vulns");
  const [vulnFilter, setVulnFilter] = useState<VulnFilter>("changes");
  const [hostFilter, setHostFilter] = useState<HostFilter>("all");

  // what was picked while both files are still loaded, else the newest pair
  const pair = picked && picked.every((id) => files.some((f) => f.id === id)) ? picked : defaultPair(files);
  const fileA = files.find((f) => f.id === pair?.[0]);
  const fileB = files.find((f) => f.id === pair?.[1]);

  const delta = useMemo(() => (fileA && fileB ? compareScans(fileA, fileB) : null), [fileA, fileB]);

  const info = useMemo(() => {
    const m = new Map<number, { name: string; severity: number }>();
    for (const f of [fileA, fileB]) {
      for (const host of f?.hosts ?? []) {
        for (const item of host.items) {
          const known = m.get(item.plugin_id);
          if (!known || item.severity > known.severity) {
            m.set(item.plugin_id, { name: item.plugin_name, severity: item.severity });
          }
        }
      }
    }

    return m;
  }, [fileA, fileB]);

  const vulnRows = useMemo(
    () => (delta ? deltaByVuln(delta, info).filter((r) => showInfo || r.severity > 0) : []),
    [delta, info, showInfo]
  );
  const hostRows = useMemo(
    () => (delta ? deltaByHost(delta, (id) => showInfo || (info.get(id)?.severity ?? 0) > 0, showInfo) : []),
    [delta, info, showInfo]
  );

  const vulnTable = useTableColumns("compare-vulns", VULN_COLUMNS);
  const vulnSort = useTableSort(vulnTable.visible, "severity", "desc", ["name", "change"]);
  const hostTable = useTableColumns("compare-hosts", HOST_COLUMNS);
  const hostSort = useTableSort(hostTable.visible, "change", "asc", ["host", "change"]);

  const vulnCounts = countBy(vulnRows.map((r) => r.change));
  const shownVulns = useMemo(() => {
    const matches = (c: VulnChange) =>
      vulnFilter === "changes" ? c !== "unchanged" : vulnFilter === "partly" ? c === "partly" || c === "changed" : c === vulnFilter;
    const cmp = (a: VulnDelta, b: VulnDelta) => {
      switch (vulnSort.sortKey) {
        case "severity": return a.severity - b.severity || b.name.localeCompare(a.name);
        case "name":     return a.name.localeCompare(b.name);
        case "change":   return CHANGE_ORDER[a.change] - CHANGE_ORDER[b.change];
        case "hostsA":   return a.hostsA - b.hostsA;
        case "hostsB":   return a.hostsB - b.hostsB;
        case "added":    return a.added - b.added;
        case "fixed":    return a.fixed + a.unverified - b.fixed - b.unverified;
      }
    };

    return vulnRows.filter((r) => matches(r.change)).sort((a, b) => (vulnSort.sortDir === "desc" ? -cmp(a, b) : cmp(a, b)));
  }, [vulnRows, vulnFilter, vulnSort.sortKey, vulnSort.sortDir]);

  const hostCounts = countBy(hostRows.map((r) => r.change));
  const shownHosts = useMemo(() => {
    const value = (r: HostDelta, k: keyof SeverityCounts) => (r.countsB ?? r.countsA)?.[k] ?? 0;
    const cmp = (a: HostDelta, b: HostDelta) => {
      switch (hostSort.sortKey) {
        case "host":   return compareHosts(a.ip, b.ip);
        case "change": return CHANGE_ORDER[a.change] - CHANGE_ORDER[b.change] || compareHosts(a.ip, b.ip);
        case "by":     return (MATCH_ORDER[a.by ?? ""] ?? 9) - (MATCH_ORDER[b.by ?? ""] ?? 9);
        case "added":  return a.added - b.added;
        case "fixed":  return a.fixed - b.fixed;
        default:       return value(a, hostSort.sortKey) - value(b, hostSort.sortKey);
      }
    };

    return hostRows.filter((r) => hostFilter === "all" || r.change === hostFilter).sort((a, b) => (hostSort.sortDir === "desc" ? -cmp(a, b) : cmp(a, b)));
  }, [hostRows, hostFilter, hostSort.sortKey, hostSort.sortDir]);

  const rowCount = view === "vulns" ? shownVulns.length : shownHosts.length;
  const { scrollRef, rows, paddingTop, paddingBottom, measureRow } = useVirtualRows(rowCount);

  if (files.length < 2) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <div className="text-center text-ink-500 dark:text-ink-400">
          <p className="text-lg font-medium mb-2">Load at least 2 scan files to compare.</p>
          <EmptyFilesNotice />
        </div>
      </div>
    );
  }

  if (!fileA || !fileB || !pair) {
    return null;
  }

  const countsA = severityCounts(fileA.hosts);
  const countsB = severityCounts(fileB.hosts);
  const table = view === "vulns" ? vulnTable : hostTable;
  const columnCount = table.visible.length;

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Scans */}
      <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-end gap-3 shrink-0">
        <ScanPicker label="Before (A)" file={fileA} files={files.filter((f) => f.id !== fileB.id)} onPick={(id) => setPicked([id, fileB.id])} onOpen={() => openFilePanel(fileA.id)} />
        <button
          onClick={() => setPicked([fileB.id, fileA.id])}
          className="btn-ghost h-10 w-10 p-0 justify-center border border-ink-200 dark:border-ink-700 mb-6"
          title="Swap A and B"
          aria-label="Swap A and B"
        >
          <ArrowLeftRight size={16} />
        </button>
        <ScanPicker label="After (B)" file={fileB} files={files.filter((f) => f.id !== fileA.id)} onPick={(id) => setPicked([fileA.id, id])} onOpen={() => openFilePanel(fileB.id)} />
      </div>

      {/* Before and after */}
      <p className="-mb-2 text-xs text-ink-500 dark:text-ink-400 shrink-0">
        Findings in A → in B, each one counted once per host, like on the Dashboard. The table below lists each vulnerability once.
      </p>
      <div className={`grid gap-3 shrink-0 ${showInfo ? "grid-cols-6" : "grid-cols-5"}`}>
        <Change label="Critical" dot="bg-critical" a={countsA.critical} b={countsB.critical} color={SEVERITY_COLORS[4].text} />
        <Change label="High"     dot="bg-high"     a={countsA.high}     b={countsB.high}     color={SEVERITY_COLORS[3].text} />
        <Change label="Medium"   dot="bg-medium"   a={countsA.medium}   b={countsB.medium}   color={SEVERITY_COLORS[2].text} />
        <Change label="Low"      dot="bg-low"      a={countsA.low}      b={countsB.low}      color={SEVERITY_COLORS[1].text} />
        {showInfo && <Change label="Info" dot="bg-info" a={countsA.info} b={countsB.info} color={SEVERITY_COLORS[0].text} />}
        <Change label="Hosts" a={fileA.hosts.length} b={fileB.hosts.length} neutral />
      </div>

      {/* View and filter */}
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <Segmented
          label="View"
          value={view}
          onChange={setView}
          options={[{ value: "vulns", label: "By vulnerability" }, { value: "hosts", label: "By host" }]}
        />
        {view === "vulns" ? (
          <Segmented
            label="Show"
            value={vulnFilter}
            onChange={setVulnFilter}
            options={[
              { value: "changes",    label: "All changes",  count: vulnRows.length - (vulnCounts.unchanged ?? 0) },
              { value: "new",        label: "New",          count: vulnCounts.new ?? 0 },
              { value: "fixed",      label: "Fixed",        count: vulnCounts.fixed ?? 0 },
              { value: "partly",     label: "Partly fixed", count: (vulnCounts.partly ?? 0) + (vulnCounts.changed ?? 0) },
              { value: "increased",  label: "Increased",    count: vulnCounts.increased ?? 0 },
              { value: "unverified", label: "Not verified", count: vulnCounts.unverified ?? 0 },
              { value: "unchanged",  label: "Unchanged",    count: vulnCounts.unchanged ?? 0 },
            ]}
          />
        ) : (
          <Segmented
            label="Show"
            value={hostFilter}
            onChange={setHostFilter}
            options={[
              { value: "all",     label: "All hosts",     count: hostRows.length },
              { value: "worsened", label: "Worsened",          count: hostCounts.worsened ?? 0 },
              { value: "improved", label: "Improved",          count: hostCounts.improved ?? 0 },
              { value: "new",      label: "New hosts",         count: hostCounts.new ?? 0 },
              { value: "missing",  label: "Not rescanned",     count: hostCounts.missing ?? 0 },
              ...((hostCounts.replaced ?? 0) > 0 ? [{ value: "replaced" as const, label: "Different machine", count: hostCounts.replaced ?? 0 }] : []),
              { value: "same",     label: "No change",         count: hostCounts.same ?? 0 },
            ]}
          />
        )}
        <span className="ml-auto"><ShowInfoCheckbox /></span>
      </div>

      {/* Table */}
      <div className="card flex-1 min-h-[320px] overflow-hidden">
        <div ref={scrollRef} className="overflow-auto h-full">
          <table style={table.style}>
            {view === "vulns"
              ? <TableHead table={vulnTable} sortKey={vulnSort.sortKey} sortDir={vulnSort.sortDir} onSort={vulnSort.toggleSort} />
              : <TableHead table={hostTable} sortKey={hostSort.sortKey} sortDir={hostSort.sortDir} onSort={hostSort.toggleSort} />}
            <tbody className="divide-y divide-ink-100 dark:divide-ink-700/50">
              <SpacerRow height={paddingTop} colSpan={columnCount} />
              {rows.map((row) => view === "vulns" ? (
                <VulnRow
                  key={shownVulns[row.index].pluginId}
                  row={shownVulns[row.index]}
                  cols={vulnTable.visible}
                  index={row.index}
                  selected={shownVulns[row.index].pluginId === openPluginId}
                  measureRow={measureRow}
                  onClick={() => openVulnPanel(shownVulns[row.index].pluginId, shownVulns[row.index].hostsB > 0 ? fileB.id : fileA.id)}
                />
              ) : (
                <HostRow
                  key={shownHosts[row.index].key}
                  row={shownHosts[row.index]}
                  cols={hostTable.visible}
                  index={row.index}
                  selected={shownHosts[row.index].ip === openIp && shownHosts[row.index].countsB !== null}
                  measureRow={measureRow}
                  onClick={() => openHostPanel(shownHosts[row.index].ip, shownHosts[row.index].countsB ? fileB.id : fileA.id)}
                />
              ))}
              <SpacerRow height={paddingBottom} colSpan={columnCount} />
              {rowCount === 0 && (
                <tr>
                  <td colSpan={columnCount} className="table-cell text-center text-ink-400 py-10">Nothing in this group.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-xs text-ink-500 dark:text-ink-400 shrink-0">
        Hosts are matched by MAC address, then hostname, then NetBIOS name, and by IP only when neither scan has one of these.
        Findings are then compared within each matched pair of hosts, by plugin, port and protocol, so they follow a host that changed IP. A different scan policy between the two scans can still hide a finding, so check that both used the same one.
      </p>
    </div>
  );
}// Compare

function countBy<T extends string>(values: T[]): Partial<Record<T, number>> {
  const counts: Partial<Record<T, number>> = {};
  for (const v of values) {
    counts[v] = (counts[v] ?? 0) + 1;
  }

  return counts;
}// countBy

function ScanPicker({ label, file, files, onPick, onOpen }: {
  label: string;
  file: NessusFile;
  files: NessusFile[];
  onPick: (id: string) => void;
  onOpen: () => void;
}) {
  const id = `scan-${label.slice(0, label.indexOf(" ")).toLowerCase()}`;
  const start = scanWindow(file.hosts).start;
  const details = [file.report_name, start && formatScanStart(start), `${file.hosts.length} hosts`].filter(Boolean).join(" · ");

  return (
    <div className="flex flex-col gap-1 min-w-0">
      <label className="text-[13px] font-semibold text-ink-500 dark:text-ink-400" htmlFor={id}>{label}</label>
      <select id={id} value={file.id} onChange={(e) => onPick(e.target.value)} className="input">
        {[file, ...files.filter((f) => f.id !== file.id)].map((f) => (
          <option key={f.id} value={f.id}>{f.filename.replace(/\.nessus$/i, "")}</option>
        ))}
      </select>
      <button onClick={onOpen} className="h-5 text-left text-xs text-ink-500 dark:text-ink-400 hover:text-accent-700 dark:hover:text-accent-400 truncate" title="Scan file details">
        {details}
      </button>
    </div>
  );
}// ScanPicker

function Change({ label, dot, a, b, color, neutral = false }: { label: string; dot?: string; a: number; b: number; color?: string; neutral?: boolean }) {
  const d = b - a;
  const tone = d === 0 || neutral ? "text-ink-500 dark:text-ink-400" : d > 0 ? "text-critical-fg" : "text-emerald-700 dark:text-emerald-400";
  const text = d === 0 ? "no change" : d > 0 ? `▲ ${d.toLocaleString()} more` : `▼ ${(-d).toLocaleString()} fewer`;

  return (
    <div className="card px-4 py-3 flex flex-col gap-1">
      <span className="flex items-center gap-1.5 text-xs font-semibold text-ink-500 dark:text-ink-400">
        {dot && <span className={`w-2 h-2 rounded-full ${dot}`} />}
        {label}
      </span>
      <span className="flex items-baseline gap-1.5 tabular-nums">
        <span className="text-[15px] font-semibold text-ink-400 dark:text-ink-500">{a.toLocaleString()}</span>
        <span className="text-ink-400 dark:text-ink-500">→</span>
        <span className={`text-2xl font-bold ${b > 0 && color ? color : "text-ink-900 dark:text-ink-50"}`}>{b.toLocaleString()}</span>
      </span>
      <span className={`text-xs font-semibold ${tone}`}>{text}</span>
    </div>
  );
}// Change

function Pill({ change, map }: { change: string; map: Record<string, { label: string; tone: string; title: string }> }) {
  const c = map[change];
  return <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${TONE[c.tone]}`} title={c.title}>{c.label}</span>;
}// Pill

function Delta({ value, sign }: { value: number; sign: "+" | "−" }) {
  if (value === 0) {
    return <span className="text-ink-300 dark:text-ink-600">-</span>;
  }

  return <span className={`font-semibold ${sign === "+" ? "text-critical-fg" : "text-emerald-700 dark:text-emerald-400"}`}>{sign}{value}</span>;
}// Delta

function VulnRow({ row, cols, index, selected, measureRow, onClick }: {
  row: VulnDelta;
  cols: TableColumn<VulnKey>[];
  index: number;
  selected: boolean;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  return (
    <tr ref={measureRow} data-index={index} className={`table-row ${selected ? "!bg-accent-50 dark:!bg-accent-900/30" : ""}`} aria-selected={selected} onClick={onClick}>
      {cols.map((col) => {
        switch (col.key) {
          case "severity": return <td key={col.key} className="table-cell"><SeverityBadge severity={row.severity} size="sm" /></td>;
          case "name":     return <td key={col.key} className="table-cell text-ink-800 dark:text-ink-100"><span className="block truncate" title={row.name}>{row.name}</span></td>;
          case "change":   return <td key={col.key} className="table-cell"><Pill change={row.change} map={VULN_CHANGE} /></td>;
          case "hostsA":   return <td key={col.key} className="table-cell text-center text-ink-500 dark:text-ink-400">{row.hostsA || "-"}</td>;
          case "hostsB":   return <td key={col.key} className="table-cell text-center font-semibold text-ink-800 dark:text-ink-100">{row.hostsB || "-"}</td>;
          case "added":    return <td key={col.key} className="table-cell text-center"><Delta value={row.added} sign="+" /></td>;
          case "fixed":
            return (
              <td key={col.key} className="table-cell text-center whitespace-nowrap">
                {(row.fixed > 0 || row.unverified === 0) && <Delta value={row.fixed} sign="−" />}
                {row.unverified > 0 && (
                  <span className="ml-1.5 text-amber-700 dark:text-amber-400 font-semibold" title={`${row.unverified} gone but not verified: the host was not rescanned or lost its credentials`}>
                    ?{row.unverified}
                  </span>
                )}
              </td>
            );
        }
      })}
    </tr>
  );
}// VulnRow

function HostRow({ row, cols, index, selected, measureRow, onClick }: {
  row: HostDelta;
  cols: TableColumn<HostKey>[];
  index: number;
  selected: boolean;
  measureRow: (el: HTMLTableRowElement | null) => void;
  onClick: () => void;
}) {
  const sev: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  return (
    <tr ref={measureRow} data-index={index} className={`table-row ${selected ? "!bg-accent-50 dark:!bg-accent-900/30" : ""}`} aria-selected={selected} onClick={onClick}>
      {cols.map((col) => {
        switch (col.key) {
          case "host":
            return (
              <td key={col.key} className="table-cell">
                <span className="block text-accent-700 dark:text-accent-400 tabular-nums" title={row.ipA && row.ipB && row.ipA !== row.ipB ? "The same machine at a new IP" : undefined}>
                  {row.ipA && row.ipB && row.ipA !== row.ipB ? `${row.ipA} → ${row.ipB}` : row.ip}
                </span>
                {row.hostname && <span className="block truncate text-xs text-ink-500 dark:text-ink-400">{row.hostname}</span>}
                {row.conflict && (
                  <span className="block truncate text-xs text-amber-700 dark:text-amber-400" title={row.countsA ? "Another machine has this IP in B" : "Another machine had this IP in A"}>
                    {row.countsA ? "Another machine in B" : "Another machine in A"}: {row.conflict}
                  </span>
                )}
              </td>
            );
          case "change": return <td key={col.key} className="table-cell"><Pill change={row.change} map={HOST_CHANGE} /></td>;
          case "by":
            return (
              <td key={col.key} className={`table-cell ${row.by === "ip" ? "text-amber-700 dark:text-amber-400" : "text-ink-600 dark:text-ink-300"}`} title={row.by ? MATCHED_BY[row.by].title : "Only in one of the scans"}>
                {row.by ? MATCHED_BY[row.by].label : <span className="text-ink-300 dark:text-ink-600">-</span>}
              </td>
            );
          case "added":  return <td key={col.key} className="table-cell text-center"><Delta value={row.added} sign="+" /></td>;
          case "fixed":  return <td key={col.key} className="table-cell text-center"><Delta value={row.fixed} sign="−" /></td>;
          default: {
            const a = row.countsA?.[col.key];
            const b = row.countsB?.[col.key];
            if (!a && !b) {
              return <td key={col.key} className="table-cell text-center text-ink-300 dark:text-ink-600">-</td>;
            }
            const color = b !== undefined && a !== undefined && b !== a
              ? (b > a ? "text-critical-fg" : "text-emerald-700 dark:text-emerald-400")
              : b ? SEVERITY_COLORS[sev[col.key]].text : "text-ink-400 dark:text-ink-500";
            return (
              <td key={col.key} className="table-cell text-center whitespace-nowrap tabular-nums">
                <span className="text-ink-400 dark:text-ink-500">{a ?? "–"}</span>
                <span className="mx-1 text-ink-300 dark:text-ink-600">→</span>
                <span className={`font-semibold ${color}`}>{b ?? "–"}</span>
              </td>
            );
          }
        }
      })}
    </tr>
  );
}// HostRow
