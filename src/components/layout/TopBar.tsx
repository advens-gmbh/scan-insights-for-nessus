import { useCallback, useMemo, useState } from "react";
import { Sun, Moon, FolderOpen, ChevronDown } from "lucide-react";
import { useUiStore } from "../../stores/uiStore";
import { useScanStore } from "../../stores/scanStore";
import { severityCounts, totalFindings, buildHostEntries } from "../../types/nessus";
import FilesMenu from "./FilesMenu";

export default function TopBar() {
  const { theme, toggleTheme, showInfo } = useUiStore();
  const files = useScanStore((s) => s.files);
  const loading = useScanStore((s) => s.loading);
  const opening = useScanStore((s) => s.opening);
  const batch = useScanStore((s) => s.batch);
  const openFiles = useScanStore((s) => s.openFiles);
  const [menu, setMenu] = useState(false);
  const closeMenu = useCallback(() => setMenu(false), []);

  // merged across files, so a host or finding present in two scans counts only once
  const hosts = useMemo(() => buildHostEntries(files), [files]);
  const totalHosts = hosts.length;
  const totalVulns = useMemo(
    () => totalFindings(hosts) - (showInfo ? 0 : severityCounts(hosts).info),
    [hosts, showInfo]
  );

  const pct = opening?.stage === "receiving" && opening.total > 0 ? Math.floor((opening.hosts / opening.total) * 100) : opening?.stage === "preparing" ? 100 : null;
  const which = batch.total > 1 ? `Opening ${batch.done + 1} of ${batch.total}` : "Opening";

  return (
    <header className="relative h-14 px-5 flex items-center gap-4 border-b border-ink-200 dark:border-ink-700/50 bg-white dark:bg-ink-900 shrink-0">
      {files.length > 0 ? (
        <>
          <div className="relative">
            <button
              data-files-menu-button
              onClick={() => setMenu((m) => !m)}
              aria-expanded={menu}
              aria-haspopup="dialog"
              className={`inline-flex items-center gap-2 h-[34px] pl-3 pr-2.5 rounded-lg border text-body font-semibold transition-colors ${
                menu
                  ? "border-accent-300 bg-accent-50 text-accent-900 dark:border-accent-700 dark:bg-accent-900/30 dark:text-accent-100"
                  : "border-ink-200 dark:border-ink-600 text-ink-700 dark:text-ink-200 hover:bg-ink-50 dark:hover:bg-ink-800"
              }`}
              title="The open files: details, close one or all"
            >
              {files.length} {files.length === 1 ? "file" : "files"} open
              <ChevronDown size={15} className={`transition-transform ${menu ? "rotate-180" : ""}`} />
            </button>
            {menu && <FilesMenu onClose={closeMenu} />}
          </div>
          <div className="flex items-center gap-2 text-body text-ink-500 dark:text-ink-400">
            <Stat label={totalHosts === 1 ? "host" : "hosts"} value={totalHosts} />
            <span className="text-ink-300 dark:text-ink-600">·</span>
            <Stat label={totalVulns === 1 ? "finding" : "findings"} value={totalVulns} />
          </div>
        </>
      ) : (
        <span className="text-body text-ink-500 dark:text-ink-400">{loading ? "Opening files…" : "No scan files open"}</span>
      )}

      <div className="flex-1" />

      <button
        onClick={openFiles}
        disabled={loading}
        className="btn-primary tabular-nums disabled:opacity-60 disabled:cursor-not-allowed"
        title={opening ? `${opening.filename}${opening.total ? `: ${opening.hosts.toLocaleString()} of ${opening.total.toLocaleString()} hosts` : ""}` : "Open .nessus scan files"}
      >
        <FolderOpen size={15} />
        {loading ? `${which}${pct !== null ? ` · ${pct}%` : "…"}` : "Open files"}
      </button>

      <button
        onClick={toggleTheme}
        className="btn-ghost w-8 h-8 p-0 flex items-center justify-center rounded-lg"
        title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      >
        {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
      </button>

      {loading && files.length > 0 && (
        <span aria-hidden="true" className="absolute left-0 right-0 -bottom-px h-[3px] overflow-hidden">
          <span
            className={`block h-full bg-accent-500 transition-[width] duration-300 ease-out ${pct === null ? "animate-pulse" : ""}`}
            style={{ width: pct === null ? "100%" : `${pct}%` }}
          />
        </span>
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
