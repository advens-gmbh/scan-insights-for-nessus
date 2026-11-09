import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { severityCounts } from "../types/nessus";
import type { NessusFile, SeverityCounts } from "../types/nessus";
import { formatDuration, formatScanStart, scanWindow } from "../utils/dashboard";
import { byScanDate, defaultTrendSelection, fileStart, previousRuns, runChanges, sameScan } from "../utils/trends";
import type { TableColumn } from "../utils/tableColumns";
import TableHead from "../components/common/TableHead";
import { useTableColumns } from "../hooks/useTableColumns";
import { useTableSort } from "../hooks/useTableSort";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import Segmented from "../components/common/Segmented";
import TrendChart from "../components/charts/TrendChart";
import type { TrendPoint } from "../components/charts/TrendChart";
import EmptyFilesNotice from "./EmptyFilesNotice";

const LEVELS: { key: keyof SeverityCounts; label: string; fg: string; dot: string }[] = [
  { key: "critical", label: "Critical", fg: "text-critical-fg", dot: "bg-critical" },
  { key: "high",     label: "High",     fg: "text-high-fg",     dot: "bg-high" },
  { key: "medium",   label: "Medium",   fg: "text-medium-fg",   dot: "bg-medium" },
  { key: "low",      label: "Low",      fg: "text-low-fg",      dot: "bg-low" },
  { key: "info",     label: "Info",     fg: "text-info-fg",     dot: "bg-info" },
];

type RunKey = "file" | "scanned" | "hosts" | "critical" | "high" | "medium" | "low" | "info" | "added" | "fixed" | "compared";

const RUN_COLUMNS: TableColumn<RunKey>[] = [
  { key: "file",     label: "File",          width: 190, stretch: true, required: true },
  { key: "scanned",  label: "Scanned",       width: 140 },
  { key: "hosts",    label: "Hosts",         width: 70,  align: "center" },
  { key: "critical", label: "Critical",      width: 88,  align: "center", dot: "bg-critical" },
  { key: "high",     label: "High",          width: 80,  align: "center", dot: "bg-high" },
  { key: "medium",   label: "Medium",        width: 88,  align: "center", dot: "bg-medium" },
  { key: "low",      label: "Low",           width: 76,  align: "center", dot: "bg-low" },
  { key: "info",     label: "Info",          width: 80,  align: "center", dot: "bg-info" },
  { key: "added",    label: "New",           width: 64,  align: "center" },
  { key: "fixed",    label: "Fixed",         width: 64,  align: "center" },
  { key: "compared", label: "Compared with", width: 160, sortable: false },
];// RUN_COLUMNS
const RUN_COLUMNS_NO_INFO = RUN_COLUMNS.filter((c) => c.key !== "info");

export default function Trends() {
  const files = useScanStore((s) => s.files);
  const showInfo = useUiStore((s) => s.showInfo);
  const storedIds = useUiStore((s) => s.trendFileIds);
  const setIds = useUiStore((s) => s.setTrendFileIds);
  const chart = useUiStore((s) => s.trendChart);
  const setChart = useUiStore((s) => s.setTrendChart);
  const openFilePanel = useUiStore((s) => s.openFilePanel);
  const navigate = useNavigate();

  const sorted = useMemo(() => byScanDate(files), [files]);
  const selectedIds = useMemo(
    () => new Set((storedIds ?? defaultTrendSelection(files)).filter((id) => files.some((f) => f.id === id))),
    [storedIds, files]
  );
  const runs = useMemo(() => sorted.filter((f) => selectedIds.has(f.id)), [sorted, selectedIds]);

  const label = useMemo(() => {
    const day = (f: NessusFile) => formatScanStart(new Date(fileStart(f))).slice(0, 10);
    const days = runs.map(day);

    return (f: NessusFile) => {
      const d = day(f);
      return days.filter((x) => x === d).length > 1 ? formatScanStart(new Date(fileStart(f))) : d;
    };
  }, [runs]);

  const points: TrendPoint[] = useMemo(
    () => runs.map((f) => ({ id: f.id, date: label(f), filename: f.filename, ...severityCounts(f.hosts) })),
    [runs, label]
  );

  const rows = useMemo(() => {
    const previous = previousRuns(runs);
    return runs.map((f) => {
      const before = previous.get(f.id) ?? null;
      return {
        file: f,
        start: fileStart(f),
        counts: severityCounts(f.hosts),
        window: scanWindow(f.hosts),
        previous: before,
        countsBefore: before ? severityCounts(before.file.hosts) : null,
        changes: before ? runChanges(before.file, f, showInfo) : null,
      };
    });
  }, [runs, showInfo]);

  const mixed = useMemo(() => {
    const newest = runs[runs.length - 1];
    return runs.some((f) => f !== newest && !sameScan(f, newest));
  }, [runs]);

  const table = useTableColumns("trends", showInfo ? RUN_COLUMNS : RUN_COLUMNS_NO_INFO);
  const { sortKey, sortDir, toggleSort } = useTableSort(table.visible, "scanned", "desc", ["file"]);
  const sortedRows = useMemo(() => {
    const value = (r: (typeof rows)[number]): number | string => {
      switch (sortKey) {
        case "file":    return r.file.filename.toLowerCase();
        case "scanned": return r.start;
        case "hosts":   return r.file.hosts.length;
        case "added":   return r.changes?.added ?? -1;
        case "fixed":   return r.changes?.fixed ?? -1;
        case "compared": return 0;
        default:        return r.counts[sortKey];
      }
    };
    const sorted = [...rows].sort((a, b) => {
      const x = value(a);
      const y = value(b);
      return typeof x === "string" ? x.localeCompare(y as string) : x - (y as number);
    });

    return sortDir === "desc" ? sorted.reverse() : sorted;
  }, [rows, sortKey, sortDir]);

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  const toggle = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setIds([...next]);
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Files */}
      <section className="card p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Scan files</h2>
          <span className="text-[13px] text-ink-500 dark:text-ink-400">{runs.length} of {files.length} selected</span>
          <span className="ml-auto flex gap-1">
            <button onClick={() => setIds(files.map((f) => f.id))} className="btn-ghost h-7 px-2 text-xs">Select all</button>
            <button onClick={() => setIds([])} className="btn-ghost h-7 px-2 text-xs">Clear</button>
          </span>
        </div>
        <ul className="max-h-56 overflow-y-auto -mx-1">
          {[...sorted].reverse().map((f) => {
            const start = scanWindow(f.hosts).start;
            return (
              <li key={f.id}>
                <label className="grid grid-cols-[auto_minmax(0,2fr)_minmax(0,1.5fr)_9rem_5rem] items-center gap-3 px-1 py-1.5 rounded-md cursor-pointer hover:bg-ink-50 dark:hover:bg-ink-700/50 text-sm">
                  <input type="checkbox" checked={selectedIds.has(f.id)} onChange={() => toggle(f.id)} className="rounded accent-accent-600" />
                  <span className="truncate font-medium text-ink-800 dark:text-ink-100" title={f.filename}>{f.filename.replace(/\.nessus$/i, "")}</span>
                  <span className="truncate text-ink-500 dark:text-ink-400" title={f.report_name}>{f.report_name}</span>
                  <span className="tabular-nums text-ink-500 dark:text-ink-400">{start ? formatScanStart(start) : "-"}</span>
                  <span className="tabular-nums text-right text-ink-500 dark:text-ink-400">{f.hosts.length} hosts</span>
                </label>
              </li>
            );
          })}
        </ul>
        {mixed && (
          <p className="flex items-center gap-2 text-[13px] text-amber-800 dark:text-amber-300">
            <AlertTriangle size={14} className="shrink-0" />
            Some of these files scanned different targets or hosts, so the chart mixes different scans.
          </p>
        )}
      </section>

      {/* Chart */}
      <section className="card p-4 flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Findings per run</h2>
          <span className="text-xs text-ink-500 dark:text-ink-400">Each finding counted once per host{chart === "bars" ? ", total above each bar" : ""}</span>
          <span className="ml-auto flex items-center gap-3">
            <ShowInfoCheckbox />
            <Segmented label="Chart" value={chart} onChange={setChart} options={[{ value: "lines", label: "Lines" }, { value: "bars", label: "Bars" }]} />
          </span>
        </div>
        {runs.length < 2 ? (
          <p className="py-16 text-center text-ink-500 dark:text-ink-400">Select at least two scan files to see a trend.</p>
        ) : (
          <TrendChart data={points} mode={chart} showInfo={showInfo} />
        )}
      </section>

      {/* Runs */}
      {runs.length > 0 && (
        <section className="card overflow-hidden">
          <div className="px-4 pt-4 pb-3 flex flex-wrap items-baseline gap-3">
            <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Runs</h2>
            <span className="text-xs text-ink-500 dark:text-ink-400">▲ ▼, New and Fixed compare each file with the earlier run of the same scan in the last column</span>
          </div>
          <div className="overflow-x-auto">
            <table style={table.style}>
              <TableHead table={table} sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
              <tbody>
                {sortedRows.map(({ file, counts, window, previous, countsBefore, changes }) => {
                  const versus = previous ? `Compared with ${previous.file.filename.replace(/\.nessus$/i, "")} (${previous.reason})` : "No earlier run of this scan is selected";
                  return (
                    <tr key={file.id} className="table-row" onClick={() => openFilePanel(file.id)}>
                      {table.visible.map((col) => {
                        switch (col.key) {
                          case "file":
                            return (
                              <td key={col.key} className="table-cell py-2.5 overflow-hidden">
                                <span className="block truncate font-medium text-accent-700 dark:text-accent-400" title={file.filename}>{file.filename.replace(/\.nessus$/i, "")}</span>
                                <span className="block truncate text-xs text-ink-500 dark:text-ink-400" title={file.report_name}>{file.report_name}</span>
                              </td>
                            );
                          case "scanned":
                            return (
                              <td key={col.key} className="table-cell py-2.5 whitespace-nowrap overflow-hidden">
                                <span className="block text-ink-800 dark:text-ink-100">{window.start ? formatScanStart(window.start) : "-"}</span>
                                {window.durationMs !== null && <span className="block text-xs text-ink-500 dark:text-ink-400">ran for {formatDuration(window.durationMs)}</span>}
                              </td>
                            );
                          case "hosts":
                            return <td key={col.key} className="table-cell text-center">{file.hosts.length}</td>;
                          case "added":
                            return <td key={col.key} className="table-cell text-center" title={versus}>{changes ? <Count value={changes.added} sign="+" /> : <Dash />}</td>;
                          case "fixed":
                            return <td key={col.key} className="table-cell text-center" title={versus}>{changes ? <Count value={changes.fixed} sign="−" /> : <Dash />}</td>;
                          case "compared":
                            return (
                              <td key={col.key} className="table-cell py-2.5 overflow-hidden">
                                {previous ? (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      navigate("/compare", { state: { pair: [previous.file.id, file.id] } });
                                    }}
                                    className="block max-w-full text-left"
                                    title={`Open in Compare: ${previous.file.filename}`}
                                  >
                                    <span className="block truncate font-medium text-accent-700 dark:text-accent-400 hover:underline">{previous.file.filename.replace(/\.nessus$/i, "")}</span>
                                    <span className="block truncate text-xs text-ink-500 dark:text-ink-400">{previous.reason}</span>
                                  </button>
                                ) : <Dash />}
                              </td>
                            );
                          default: {
                            const level = LEVELS.find((l) => l.key === col.key)!;
                            const n = counts[level.key];
                            return (
                              <td key={col.key} className="table-cell text-center whitespace-nowrap" title={countsBefore ? `${versus}: ${countsBefore[level.key]} then` : versus}>
                                <span className={`font-semibold ${n > 0 ? level.fg : "text-ink-400 dark:text-ink-500"}`}>{n}</span>
                                {countsBefore && <Step value={n - countsBefore[level.key]} />}
                              </td>
                            );
                          }
                        }
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}// Trends

function Step({ value }: { value: number }) {
  if (value === 0) {
    return null;
  }

  return (
    <span className={`ml-1 text-[11px] font-semibold ${value > 0 ? "text-critical-fg" : "text-emerald-700 dark:text-emerald-400"}`}>
      {value > 0 ? `▲${value}` : `▼${-value}`}
    </span>
  );
}// Step

function Dash() {
  return <span className="text-ink-300 dark:text-ink-600">-</span>;
}// Dash

function Count({ value, sign }: { value: number; sign: "+" | "−" }) {
  if (value === 0) {
    return <span className="text-ink-300 dark:text-ink-600">0</span>;
  }

  return <span className={`font-semibold ${sign === "+" ? "text-critical-fg" : "text-emerald-700 dark:text-emerald-400"}`}>{sign}{value}</span>;
}// Count
