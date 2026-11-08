import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { Download, FileText } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import type { ExportRequest } from "../types/nessus";
import { SEVERITY_ORDER, SEVERITY_LABELS, SEVERITY_COLORS } from "../types/nessus";
import SeverityDonut from "../components/charts/SeverityDonut";
import { severityCounts } from "../types/nessus";
import EmptyFilesNotice from "./EmptyFilesNotice";

export default function Export() {
  const files = useScanStore((s) => s.files);
  const [excludedIds, setExcludedIds] = useState<Set<string>>(new Set());
  const [severities, setSeverities] = useState<Set<number>>(new Set([4, 3, 2, 1, 0]));
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  const selectedIds = files.filter((f) => !excludedIds.has(f.id)).map((f) => f.id);

  const toggleFile = (id: string) =>
    setExcludedIds((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });

  const toggleSeverity = (sev: number) =>
    setSeverities((prev) => {
      const n = new Set(prev);
      n.has(sev) ? n.delete(sev) : n.add(sev);
      return n;
    });

  const doExport = async (format: "csv" | "nessus") => {
    setError(null);
    setSuccess(null);

    const filters =
      format === "csv"
        ? [{ name: "CSV Files", extensions: ["csv"] }]
        : [{ name: "Nessus Files", extensions: ["nessus"] }];

    const outputPath = await save({
      filters,
      defaultPath: `scan-export.${format}`,
    });

    if (!outputPath) {
      return;
    }

    setExporting(true);
    try {
      const req: ExportRequest = {
        file_ids: selectedIds,
        severities: [...severities],
        output_path: outputPath,
        format,
      };
      await invoke("export_data", { req });
      setSuccess(`Exported to ${outputPath}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-5">
      <div>
        <h2 className="font-semibold text-ink-700 dark:text-ink-200">Export</h2>
        <p className="text-xs text-ink-400">Combine and filter scan files for export.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Files to export */}
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-ink-600 dark:text-ink-300">Files to Export</h3>
          <div className="space-y-2">
            {files.map((f) => {
              const checked = !excludedIds.has(f.id);
              const counts = severityCounts(f.hosts);
              return (
                <label
                  key={f.id}
                  className="flex items-center gap-3 p-3 rounded-lg cursor-pointer hover:bg-ink-50 dark:hover:bg-ink-700/50 transition-colors border border-ink-100 dark:border-ink-700"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleFile(f.id)}
                    className="w-4 h-4 rounded accent-accent-600"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-ink-700 dark:text-ink-300 truncate">
                      {f.filename}
                    </p>
                    <p className="text-xs text-ink-400">
                      {f.hosts.length} hosts · {f.hosts.reduce((s, h) => s + h.items.length, 0).toLocaleString()} findings
                    </p>
                  </div>
                  <SeverityDonut counts={counts} size={48} />
                </label>
              );
            })}
          </div>
        </div>

        {/* Severity filter */}
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-ink-600 dark:text-ink-300">Severity Filter</h3>
          <p className="text-xs text-ink-400">Only include findings with these severity levels.</p>
          <div className="space-y-2">
            {SEVERITY_ORDER.map((sev) => {
              const checked = severities.has(sev);
              const color = SEVERITY_COLORS[sev];
              return (
                <label
                  key={sev}
                  className="flex items-center gap-3 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleSeverity(sev)}
                    className="w-4 h-4 rounded accent-accent-600"
                  />
                  <span
                    className="pill text-xs font-semibold"
                    style={{ backgroundColor: color.hex + "22", color: color.hex }}
                  >
                    {SEVERITY_LABELS[sev]}
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      </div>

      {/* Status */}
      {error && (
        <div className="card p-3 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800">
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}
      {success && (
        <div className="card p-3 bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800">
          <p className="text-sm text-emerald-600 dark:text-emerald-400">{success}</p>
        </div>
      )}

      {/* Export buttons */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={() => doExport("csv")}
          disabled={exporting || selectedIds.length === 0 || severities.size === 0}
          className="btn-secondary disabled:opacity-50 flex-1 justify-center"
        >
          <FileText size={15} />
          Export CSV
        </button>
        <button
          onClick={() => doExport("nessus")}
          disabled={exporting || selectedIds.length === 0 || severities.size === 0}
          className="btn-secondary disabled:opacity-50 flex-1 justify-center"
        >
          <Download size={15} />
          {exporting ? "Exporting…" : "Export .nessus"}
        </button>
      </div>

      <p className="text-xs text-ink-400 text-center">
        {selectedIds.length} file(s) selected · {severities.size} severity level(s) included
      </p>
    </div>
  );
}// Export
