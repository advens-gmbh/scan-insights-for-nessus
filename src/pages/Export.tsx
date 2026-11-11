import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { Download, FileSpreadsheet, FileText } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useNotificationStore } from "../stores/notificationStore";
import { useUiStore } from "../stores/uiStore";
import type { ExportFormat, ExportRequest, NessusFile } from "../types/nessus";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "../types/nessus";
import { formatScanStart, scanWindow } from "../utils/dashboard";
import { byScanDate } from "../utils/trends";
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

  const doExport = async (format: ExportFormat) => {
    const outputPath = await save({
      filters: [SAVE_FILTER[format]],
      defaultPath: `scan-export.${format}`,
    });
    if (!outputPath) {
      return;
    }

    setExporting(format);
    try {
      const req: ExportRequest = { file_ids: selected.map((f) => f.id), severities, output_path: outputPath, format };
      await invoke("export_data", { req });
      notify(`Exported to ${outputPath}`);
    } catch (e) {
      notify(`Export failed: ${String(e)}`, "error");
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Files */}
      <section className="card p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Scan files</h2>
          <span className="text-[13px] text-ink-500 dark:text-ink-400">{selected.length} of {files.length} selected</span>
          <span className="ml-auto flex gap-1">
            <button onClick={() => setExportExcludedIds([])} className="btn-ghost h-7 px-2 text-xs">Select all</button>
            <button onClick={() => setExportExcludedIds(files.map((f) => f.id))} className="btn-ghost h-7 px-2 text-xs">Clear</button>
          </span>
        </div>
        <div className="-mx-1 overflow-x-auto">
          <table className="w-full text-sm">
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
                        className={`pl-3 py-1.5 last:pr-1 whitespace-nowrap tabular-nums text-right text-[13px] font-semibold ${counts[sev] > 0 && severities.includes(sev) ? SEVERITY_COUNT_CLASS[sev] : "text-ink-300 dark:text-ink-600"}`}
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
          <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Include</h2>
          <SeverityPills counts={totals} selected={severities} onToggle={toggleSeverity} />
          <span className="ml-auto text-[13px] text-ink-500 dark:text-ink-400 tabular-nums">
            {findings.toLocaleString()} {findings === 1 ? "finding" : "findings"} from {selected.length} {selected.length === 1 ? "file" : "files"}
          </span>
        </div>
        {selected.length > 1 && (
          <p className="-mt-2 text-xs text-ink-500 dark:text-ink-400">
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
        {!canExport && exporting === null && (
          <p className="text-[13px] text-ink-500 dark:text-ink-400">
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
      <p className="text-[13px] text-ink-500 dark:text-ink-400">{text}</p>
    </div>
  );
}// ExportOption
