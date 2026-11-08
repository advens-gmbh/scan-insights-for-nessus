import { useMemo } from "react";
import { Sun, Moon, FolderOpen, Trash2 } from "lucide-react";
import { useUiStore } from "../../stores/uiStore";
import { useScanStore } from "../../stores/scanStore";
import { severityCounts, totalFindings, buildHostEntries } from "../../types/nessus";

export default function TopBar() {
  const { theme, toggleTheme, showInfo } = useUiStore();
  const { files, loading, openFiles, unloadAll } = useScanStore();

  // merged across files, so a host or finding present in two scans counts only once
  const hosts = useMemo(() => buildHostEntries(files), [files]);
  const totalHosts = hosts.length;
  const totalVulns = useMemo(
    () => totalFindings(hosts) - (showInfo ? 0 : severityCounts(hosts).info),
    [hosts, showInfo]
  );

  return (
    <header className="h-14 px-5 flex items-center gap-4 border-b border-ink-200 dark:border-ink-700/50 bg-white dark:bg-ink-900 shrink-0">
      {/* stats */}
      {files.length > 0 && (
        <div className="flex items-center gap-4 text-sm text-ink-500 dark:text-ink-400">
          <Stat label="files" value={files.length} />
          <span className="text-ink-300 dark:text-ink-600">·</span>
          <Stat label="hosts" value={totalHosts} />
          <span className="text-ink-300 dark:text-ink-600">·</span>
          <Stat label="findings" value={totalVulns} />
        </div>
      )}

      <div className="flex-1" />

      {/* open button */}
      <button
        onClick={openFiles}
        disabled={loading}
        className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <FolderOpen size={15} />
        {loading ? "Loading…" : "Open File"}
      </button>

      {/* theme toggle */}
      <button
        onClick={toggleTheme}
        className="btn-ghost w-8 h-8 p-0 flex items-center justify-center rounded-lg"
        title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      >
        {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
      </button>

      {/* unload all */}
      {files.length > 1 && (
        <button
          onClick={unloadAll}
          className="btn-danger text-sm"
          title="Unload all files"
        >
          <Trash2 size={14} /> Unload All
        </button>
      )}
    </header>
  );
}// TopBar

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <span>
      <strong className="text-ink-700 dark:text-ink-200 font-semibold">
        {value.toLocaleString()}
      </strong>{" "}
      {label}
    </span>
  );
}// Stat
