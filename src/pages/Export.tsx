import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { AlertCircle, Check, Download, FileSpreadsheet, FileText, X } from "lucide-react";
import { fileNameOf, useScanStore } from "../stores/scanStore";
import { usePageState } from "../stores/pageStore";
import { useNotificationStore } from "../stores/notificationStore";
import { useUiStore } from "../stores/uiStore";
import type { ExportFormat, ExportRequest, NessusFile } from "../types/nessus";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "../types/nessus";
import { formatScanStart, scanWindow } from "../utils/dashboard";
import { byScanDate } from "../utils/trends";
import { folderOf, timeAgo } from "../utils/format";
import { explainExportError, exportErrorOf, needsAnotherPlace } from "../utils/exportResult";
import type { ExportResult } from "../utils/exportResult";
import SeverityPills from "../components/common/SeverityPills";
import FileExt from "../components/common/FileExt";
import EmptyFilesNotice from "./EmptyFilesNotice";

const SAVE_FILTER: Record<ExportFormat, { name: string; extensions: string[] }> = {
  xlsx: { name: "Excel Workbook", extensions: ["xlsx"] },
  csv: { name: "CSV Files", extensions: ["csv"] },
  nessus: { name: "Nessus Files", extensions: ["nessus"] },
};

const SEVERITY_COUNT_CLASS: Record<number, string> = {
  4: "text-critical-fg",
  3: "text-high-fg",
  2: "text-medium-fg",
  1: "text-low-fg",
  0: "text-info-fg",
};

function countsOf(file: NessusFile): Record<number, number> {
  const counts: Record<number, number> = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 };
  for (const host of file.hosts) {
    for (const item of host.items) {
      counts[item.severity]++;
    }
  }

  return counts;
}// countsOf

export default function Export() {
  const files = useScanStore((s) => s.files);
  const notify = useNotificationStore((s) => s.add);
  const { exportExcludedIds, setExportExcludedIds, exportSeverities: severities, setExportSeverities } = useUiStore();
  const [exporting, setExporting] = useState<ExportFormat | null>(null);
  const [result, setResult] = usePageState<ExportResult | null>("export:result", null);

  const sorted = useMemo(() => byScanDate(files).reverse(), [files]);
  const perFile = useMemo(() => new Map(files.map((f) => [f.id, countsOf(f)])), [files]);

  if (files.length === 0) {
    return <EmptyFilesNotice page="export" />;
  }

  const excludedIds = new Set(exportExcludedIds);
  const selected = files.filter((f) => !excludedIds.has(f.id));
  const totals: Record<number, number> = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 };
  for (const f of selected) {
    for (const sev of SEVERITY_ORDER) {
      totals[sev] += perFile.get(f.id)![sev];
    }
  }
  const findings = severities.reduce((sum, sev) => sum + totals[sev], 0);
  const canExport = selected.length > 0 && findings > 0 && exporting === null;

  const toggleFile = (id: string) =>
    setExportExcludedIds(excludedIds.has(id) ? exportExcludedIds.filter((x) => x !== id) : [...exportExcludedIds, id]);

  const toggleSeverity = (sev: number) =>
    setExportSeverities(severities.includes(sev) ? severities.filter((s) => s !== sev) : [...severities, sev]);

  // the same file again (Try again)
  const doExport = async (format: ExportFormat, to?: string) => {
    const outputPath = to ?? await save({
      filters: [SAVE_FILTER[format]],
      defaultPath: result?.format === format ? result.path : `scan-export.${format}`,
    });
    if (!outputPath) {
      return;
    }

    setExporting(format);
    try {
      const req: ExportRequest = { file_ids: selected.map((f) => f.id), severities, output_path: outputPath, format };
      await invoke("export_data", { req });
      setResult({ ok: true, path: outputPath, format, findings, files: selected.length, at: new Date().toISOString() });
    } catch (e) {
      setResult({ ok: false, path: outputPath, format, ...exportErrorOf(e) });
    } finally {
      setExporting(null);
    }
  };

  const openResult = (command: "open_export" | "show_export", path: string) =>
    invoke(command, { path }).catch(() => notify(`Couldn't open ${fileNameOf(path)}. It may have been moved or deleted.`, "error"));

  return (
    <div className="flex flex-col gap-4">
      {/* Files */}
      <section className="card p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100">Scan files</h2>
          <span className="text-small text-ink-500 dark:text-ink-400">{selected.length} of {files.length} selected</span>
          <span className="ml-auto flex gap-1">
            <button onClick={() => setExportExcludedIds([])} className="btn-ghost h-7 px-2 text-caption">Select all</button>
            <button onClick={() => setExportExcludedIds(files.map((f) => f.id))} className="btn-ghost h-7 px-2 text-caption">Clear</button>
          </span>
        </div>
        <div className="-mx-1 overflow-x-auto">
          <table className="w-full text-body">
            <tbody>
              {sorted.map((f) => {
                const start = scanWindow(f.hosts).start;
                const counts = perFile.get(f.id)!;
                return (
                  <tr key={f.id} onClick={() => toggleFile(f.id)} className="cursor-pointer hover:bg-ink-50 dark:hover:bg-ink-700/50">
                    <td className="pl-1 pr-3 py-1.5 w-6">
                      <input
                        type="checkbox"
                        checked={!excludedIds.has(f.id)}
                        onChange={() => toggleFile(f.id)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={`Include ${f.filename}`}
                        className="rounded accent-accent-600 align-middle"
                      />
                    </td>
                    <td className="pr-3 py-1.5 w-[32%] max-w-0 truncate font-medium text-ink-800 dark:text-ink-100" title={f.filename}>{f.filename.replace(/\.nessus$/i, "")}</td>
                    <td className="pr-3 py-1.5 w-[22%] max-w-0 truncate text-ink-500 dark:text-ink-400" title={f.report_name}>{f.report_name}</td>
                    <td className="pr-3 py-1.5 whitespace-nowrap tabular-nums text-ink-500 dark:text-ink-400">{start ? formatScanStart(start) : "-"}</td>
                    <td className="pr-3 py-1.5 whitespace-nowrap tabular-nums text-right text-ink-500 dark:text-ink-400">{f.hosts.length.toLocaleString()} {f.hosts.length === 1 ? "host" : "hosts"}</td>
                    {SEVERITY_ORDER.map((sev) => (
                      <td
                        key={sev}
                        title={`${counts[sev].toLocaleString()} ${SEVERITY_LABELS[sev]}`}
                        className={`pl-3 py-1.5 last:pr-1 whitespace-nowrap tabular-nums text-right text-small font-semibold ${counts[sev] > 0 && severities.includes(sev) ? SEVERITY_COUNT_CLASS[sev] : "text-ink-300 dark:text-ink-600"}`}
                      >
                        {counts[sev].toLocaleString()}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* What goes in, and the export */}
      <section className="card p-4 flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100">Include</h2>
          <SeverityPills counts={totals} selected={severities} onToggle={toggleSeverity} />
          <span className="ml-auto text-small text-ink-500 dark:text-ink-400 tabular-nums">
            {findings.toLocaleString()} {findings === 1 ? "finding" : "findings"} from {selected.length} {selected.length === 1 ? "file" : "files"}
          </span>
        </div>
        {selected.length > 1 && (
          <p className="-mt-2 text-caption text-ink-500 dark:text-ink-400">
            Counted per file, as the export writes them, so a host scanned in two files counts twice. The Dashboard counts each host once.
          </p>
        )}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <ExportOption
            icon={<FileSpreadsheet size={16} />}
            label="Export Excel"
            busy={exporting === "xlsx"}
            disabled={!canExport}
            onClick={() => doExport("xlsx")}
            text={<>One row per finding on each host in an Excel <FileExt ext=".xlsx" /> file.</>}
          />
          <ExportOption
            icon={<FileText size={16} />}
            label="Export CSV"
            busy={exporting === "csv"}
            disabled={!canExport}
            onClick={() => doExport("csv")}
            text={<>One row per finding on each host in a text <FileExt ext=".csv" /> file.</>}
          />
          <ExportOption
            icon={<Download size={16} />}
            label="Export .nessus"
            busy={exporting === "nessus"}
            disabled={!canExport}
            onClick={() => doExport("nessus")}
            text={<>The selected files will be merged into one <FileExt /> scan file and the duplicates will be removed.</>}
          />
        </div>
        {result && (
          <ResultLine
            result={result}
            onOpen={() => openResult("open_export", result.path)}
            onShow={() => openResult("show_export", result.path)}
            onRetry={() => doExport(result.format, !result.ok && needsAnotherPlace(result.reason) ? undefined : result.path)}
            onClose={() => setResult(null)}
            busy={exporting !== null}
          />
        )}
        {!canExport && exporting === null && (
          <p className="text-small text-ink-500 dark:text-ink-400">
            {selected.length === 0 ? "Select at least one scan file." : "Select at least one severity with findings."}
          </p>
        )}
      </section>
    </div>
  );
}// Export

function ExportOption({ icon, label, text, busy, disabled, onClick }: {
  icon: React.ReactNode;
  label: string;
  text: React.ReactNode;
  busy: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <div className="flex items-center gap-4 rounded-md border border-ink-200 dark:border-ink-700 p-3">
      <button onClick={onClick} disabled={disabled} className="btn-primary h-9 px-4 shrink-0 disabled:opacity-50 disabled:cursor-not-allowed">
        {icon}
        {busy ? "Exporting…" : label}
      </button>
      <p className="text-small text-ink-500 dark:text-ink-400">{text}</p>
    </div>
  );
}// ExportOption

function ResultLine({ result, onOpen, onShow, onRetry, onClose, busy }: {
  result: ExportResult;
  onOpen: () => void;
  onShow: () => void;
  onRetry: () => void;
  onClose: () => void;
  busy: boolean;
}) {
  const [details, setDetails] = useState(false);
  const name = fileNameOf(result.path);
  const close = (
    <button onClick={onClose} className="btn-ghost h-8 w-8 p-0 justify-center" aria-label="Close" title="Close">
      <X size={15} />
    </button>
  );
  const icon = "w-5 h-5 rounded-full bg-white dark:bg-ink-800 flex items-center justify-center shrink-0";

  if (result.ok) {
    return (
      <div role="status" className="flex flex-wrap items-center gap-3 rounded-lg px-4 py-3 bg-emerald-50 dark:bg-emerald-900/20">
        <span className={`${icon} text-emerald-700 dark:text-emerald-400`}><Check size={13} strokeWidth={3} /></span>
        <div className="flex-1 min-w-[12rem]">
          <div className="text-body">
            <span className="font-bold text-ink-900 dark:text-ink-50">Saved {name}</span>
            <span className="text-ink-600 dark:text-ink-300"> · {result.findings.toLocaleString()} {result.findings === 1 ? "finding" : "findings"} from {result.files} {result.files === 1 ? "file" : "files"} · {timeAgo(result.at)}</span>
          </div>
          <div className="text-caption text-ink-500 dark:text-ink-400 truncate" title={result.path}>{folderOf(result.path)}</div>
        </div>
        <button onClick={onOpen} className="btn-secondary h-8 text-small">Open</button>
        <button onClick={onShow} className="btn-secondary h-8 text-small">Show in folder</button>
        {close}
      </div>
    );
  }

  const another = needsAnotherPlace(result.reason);
  return (
    <div role="alert" className="flex flex-wrap items-center gap-3 rounded-lg px-4 py-3 bg-critical/5 dark:bg-critical/10 border border-critical/30">
      <span className={`${icon} text-critical-fg`}><AlertCircle size={14} /></span>
      <div className="flex-1 min-w-[12rem] text-body">
        <div className="font-bold text-ink-900 dark:text-ink-50">Couldn't save {name}</div>
        <div className="text-ink-700 dark:text-ink-200">{explainExportError(result.reason)}</div>
      </div>
      <button onClick={onRetry} disabled={busy} className="btn-secondary h-8 text-small disabled:opacity-50">{another ? "Choose another folder…" : "Try again"}</button>
      <button onClick={() => setDetails(!details)} className="btn-ghost h-8 text-small">{details ? "Hide details" : "Details"}</button>
      {close}
      {details && (
        <div className="basis-full font-mono text-tiny leading-[17px] text-ink-700 dark:text-ink-200 bg-white/70 dark:bg-ink-900 border border-ink-100 dark:border-ink-700 rounded-md px-2.5 py-2 [overflow-wrap:anywhere] select-text">
          {result.path}
          <br />
          {result.detail}
        </div>
      )}
    </div>
  );
}// ResultLine
