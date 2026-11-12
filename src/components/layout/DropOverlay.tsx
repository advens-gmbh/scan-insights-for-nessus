import { AlertTriangle } from "lucide-react";
import { fileNameOf } from "../../stores/scanStore";

export const isScanPath = (p: string) => p.toLowerCase().endsWith(".nessus");

// while files are dragged over the window it displays what a drop will open and skip
export default function DropOverlay({ paths, openCount }: { paths: string[]; openCount: number }) {
  const scans = paths.filter(isScanPath);
  const skipped = paths.filter((p) => !isScanPath(p));
  const shown = scans.slice(0, 6);
  return (
    <div
      className="fixed inset-0 z-[300] pointer-events-none animate-fade-in bg-ink-950/[0.14] dark:bg-black/[0.28] shadow-[inset_0_0_0_3px_theme(colors.accent.400)] dark:shadow-[inset_0_0_0_3px_theme(colors.accent.500)]"
      role="status"
      aria-label="Drop files to open them"
    >
      <div className="absolute right-4 bottom-4 w-[380px] max-w-[calc(100vw-32px)] rounded-xl border border-ink-200 dark:border-ink-700 bg-white dark:bg-ink-800 px-5 py-4 shadow-2xl">
        <div className="text-[17px] font-bold text-ink-900 dark:text-ink-50">
          {scans.length === 0 ? "No .nessus files to open" : `Drop to open ${scans.length === 1 ? "1 scan file" : `${scans.length} scan files`}`}
        </div>
        {scans.length > 0 && openCount > 0 && (
          <div className="mt-0.5 text-[13px] text-ink-600 dark:text-ink-300">
            {scans.length === 1 ? "It's" : "They're"} added to the {openCount === 1 ? "file" : `${openCount} files`} already open.
          </div>
        )}
        {shown.length > 0 && (
          <ul className="mt-3 border-t border-ink-100 dark:border-ink-700">
            {shown.map((p) => <li key={p} className="py-2 border-b border-ink-100 dark:border-ink-700 text-sm font-semibold text-ink-800 dark:text-ink-100 truncate">{fileNameOf(p)}</li>)}
            {scans.length > shown.length && <li className="py-2 text-[13px] text-ink-500 dark:text-ink-400">and {scans.length - shown.length} more</li>}
          </ul>
        )}
        {skipped.length > 0 && (
          <div className="mt-3 flex items-start gap-2 text-[13px] text-low-fg bg-low/10 border border-low/40 rounded-lg px-3 py-2">
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
