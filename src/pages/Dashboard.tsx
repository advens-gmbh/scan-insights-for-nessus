import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FolderOpen, Trash2, ShieldAlert, Server, Clock, FileX } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { severityCounts, buildHostEntries, visibleCounts } from "../types/nessus";
import { useUiStore } from "../stores/uiStore";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import ScanName from "../components/common/ScanName";
import type { NessusFile } from "../types/nessus";
import { formatDate } from "../utils/format";
import SeverityDonut from "../components/charts/SeverityDonut";
import TopHostsBar from "../components/charts/TopHostsBar";
import FileDetailPanel from "../panels/FileDetailPanel";
import logo from "../../src-tauri/icons/128x128.png";

export default function Dashboard() {
  const { files, recentFiles, openFiles, loadFile, unloadFile } = useScanStore();
  const navigate = useNavigate();
  const showInfo = useUiStore((s) => s.showInfo);
  const [detailFile, setDetailFile] = useState<NessusFile | null>(null);

  const allHosts = useMemo(() => buildHostEntries(files), [files]);
  const combinedCounts = useMemo(() => severityCounts(allHosts), [allHosts]);

  if (files.length === 0) {
    return <EmptyState openFiles={openFiles} recentFiles={recentFiles} loadFile={loadFile} />;
  }

  return (
    <div className="space-y-5">
      <div className="flex justify-end">
        <ShowInfoCheckbox />
      </div>

      {/* File card grid - auto-fill so cards fill available width at any screen size */}
      <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))" }}>
        {files.map((file) => {
          const counts = severityCounts(file.hosts);
          const hosts = file.hosts.length;
          return (
            <div key={file.id} className="card p-5 flex flex-col gap-4 hover:shadow-md transition-shadow">
              {/* Title row */}
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="pill bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 text-[10px]">
                      Loaded
                    </span>
                  </div>
                  <p
                    className="font-semibold text-slate-800 dark:text-slate-100 truncate mt-1 cursor-pointer hover:text-violet-600 dark:hover:text-violet-400 transition-colors"
                    title="Click to view file details"
                    onClick={() => setDetailFile(file)}
                  >
                    {file.filename}
                  </p>
                  <ScanName file={file} />
                  <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-1">
                    <Clock size={11} />
                    {formatDate(file.loaded_at)}
                  </p>
                </div>
              </div>

              {/* Stats + donut */}
              <div className="flex items-center gap-4">
                <SeverityDonut counts={visibleCounts(counts, showInfo)} size={110} emptyText={counts.info > 0 ? "Only Info findings" : undefined} />
                <div className="flex flex-col gap-1.5 text-sm">
                  <div className="flex items-center gap-2">
                    <Server size={13} className="text-slate-400" />
                    <span className="text-slate-600 dark:text-slate-400 w-16">Hosts:</span>
                    <strong className="text-slate-800 dark:text-slate-200">{hosts}</strong>
                  </div>
                  <SeverityRow label="Critical" value={counts.critical} color="text-critical" />
                  <SeverityRow label="High"     value={counts.high}     color="text-high" />
                  <SeverityRow label="Medium"   value={counts.medium}   color="text-medium" />
                  <SeverityRow label="Low"      value={counts.low}      color="text-low" />
                  <SeverityRow label="Info"     value={showInfo ? counts.info : 0} color="text-info" />
                </div>
              </div>

              {/* Actions - always at card bottom */}
              <div className="flex gap-2 pt-1 mt-auto border-t border-slate-100 dark:border-slate-700">
                <button
                  onClick={() => navigate("/vulnerabilities", { state: { fileFilter: file.id } })}
                  className="btn-secondary flex-1 text-xs justify-center"
                >
                  <ShieldAlert size={13} /> View Vulns
                </button>
                <button
                  onClick={() => navigate("/hosts", { state: { fileFilter: file.id } })}
                  className="btn-secondary flex-1 text-xs justify-center"
                >
                  <Server size={13} /> View Hosts
                </button>
                <button
                  onClick={() => unloadFile(file.id)}
                  className="btn-danger text-xs"
                  title="Unload this file"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          );
        })}

        {/* Add file card */}
        <button
          onClick={openFiles}
          className="card p-5 flex flex-col items-center justify-center gap-3 border-dashed border-slate-300 dark:border-slate-600 hover:border-violet-400 dark:hover:border-violet-500 hover:bg-violet-50/50 dark:hover:bg-violet-900/10 transition-colors text-slate-400 dark:text-slate-500 hover:text-violet-500 dark:hover:text-violet-400 min-h-48"
        >
          <FolderOpen size={28} />
          <span className="text-sm font-medium">Add .nessus file</span>
        </button>
      </div>

      {/* Aggregate overview */}
      {files.length > 1 && (
        <div className="card overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-100 dark:border-slate-700">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
              Combined Overview ({files.length} files)
            </span>
          </div>
          <div className="px-5 pb-5 pt-4 flex flex-col lg:flex-row gap-6 items-start">
            <div className="shrink-0">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Severity Distribution
              </h3>
              <SeverityDonut counts={visibleCounts(combinedCounts, showInfo)} size={150} showLegend emptyText={combinedCounts.info > 0 ? "Only Info findings" : undefined} />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Top 15 Vulnerable Hosts
              </h3>
              <TopHostsBar hosts={allHosts} showInfo={showInfo} />
            </div>
          </div>
        </div>
      )}

      {detailFile && (
        <FileDetailPanel file={detailFile} onClose={() => setDetailFile(null)} />
      )}
    </div>
  );
}// Dashboard

function SeverityRow({ label, value, color }: { label: string; value: number; color: string }) {
  if (value === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-2">
      <span className={`w-[13px] h-[13px] rounded-full shrink-0 ${color.replace("text-", "bg-")}`} />
      <span className="text-slate-500 dark:text-slate-400 w-16">{label}:</span>
      <strong className={`${color}`}>{value}</strong>
    </div>
  );
}// SeverityRow

function EmptyState({openFiles, recentFiles, loadFile,}: {
  openFiles: () => void;
  recentFiles: { path: string; filename: string; last_opened: string }[];
  loadFile: (path: string) => Promise<unknown>;
}) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] gap-6">
      <div className="flex flex-col items-center gap-3 text-center">
        <img src={logo} alt="" className="w-16 h-16 rounded-2xl" />
        <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">
          Scan Insights for Nessus
        </h1>
        <p className="text-slate-500 dark:text-slate-400 max-w-sm">
          Load one or more <code className="bg-slate-100 dark:bg-slate-700 px-1 rounded">.nessus</code> scan
          files to start analyzing vulnerabilities.
        </p>
        <button onClick={openFiles} className="btn-primary mt-2 px-5 py-2.5">
          <FolderOpen size={16} /> Open .nessus File
        </button>
      </div>

      {recentFiles.length > 0 && (
        <div className="w-full max-w-md">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
            <Clock size={12} /> Recent Files
          </h2>
          <div className="card divide-y divide-slate-100 dark:divide-slate-700">
            {recentFiles.slice(0, 5).map((f) => (
              <button
                key={f.path}
                onClick={() => loadFile(f.path)}
                className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 text-left transition-colors"
              >
                <FileX size={14} className="text-slate-400 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-slate-700 dark:text-slate-300 truncate">{f.filename}</p>
                  <p className="text-xs text-slate-400 truncate">{f.path}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}// EmptyState
