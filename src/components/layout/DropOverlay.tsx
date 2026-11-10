import { AlertTriangle, Upload } from "lucide-react";
import { fileNameOf } from "../../stores/scanStore";

export const isScanPath = (p: string) => p.toLowerCase().endsWith(".nessus");

// while files are dragged over the window it displays what a drop will open and skip
export default function DropOverlay({ paths, openCount }: { paths: string[]; openCount: number }) {
  const scans = paths.filter(isScanPath);
  const skipped = paths.filter((p) => !isScanPath(p));
  const shown = scans.slice(0, 6);
  return (
    <div className="fixed inset-0 z-[300] bg-ink-950/55 backdrop-blur-[3px] flex items-center justify-center pointer-events-none animate-fade-in" role="status" aria-label="Drop files to open them">
      <div className={`w-[520px] max-w-[calc(100vw-32px)] rounded-[18px] border-2 border-dashed bg-white dark:bg-ink-800 p-7 flex flex-col items-center gap-3 shadow-2xl ${scans.length ? "border-accent-400" : "border-ink-400"}`}>
        <span className="w-14 h-14 rounded-2xl bg-accent-50 dark:bg-accent-900/30 text-accent-600 dark:text-accent-300 flex items-center justify-center"><Upload size={26} /></span>
        <div className="text-[19px] font-bold text-ink-900 dark:text-ink-50 text-center">
          {scans.length === 0 ? "No .nessus files to open" : `Drop to open ${scans.length === 1 ? "1 scan file" : `${scans.length} scan files`}`}
        </div>
        {scans.length > 0 && (
          <div className="text-[13px] text-ink-600 dark:text-ink-300">
            {openCount === 0 ? "They open one after another." : `They're added to the ${openCount === 1 ? "file" : `${openCount} files`} already open.`}
          </div>
        )}
        {shown.length > 0 && (
          <ul className="w-full flex flex-col gap-1.5 mt-1.5">
            {shown.map((p) => <li key={p} className="px-3 py-2 rounded-lg bg-ink-50 dark:bg-ink-900 text-sm font-semibold text-ink-800 dark:text-ink-100 truncate">{fileNameOf(p)}</li>)}
            {scans.length > shown.length && <li className="px-3 text-[13px] text-ink-500 dark:text-ink-400">and {scans.length - shown.length} more</li>}
          </ul>
        )}
        {skipped.length > 0 && (
          <div className="w-full flex items-start gap-2 text-[13px] text-low-fg bg-low/10 border border-low/40 rounded-lg px-3 py-2">
            <AlertTriangle size={15} className="shrink-0 mt-0.5" />
            <span className="[overflow-wrap:anywhere]">
              {skipped.length === 1 ? <><b>{fileNameOf(skipped[0])}</b> isn't a .nessus file and will be skipped.</> : <>{skipped.length} files aren't .nessus files and will be skipped.</>}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}// DropOverlay
