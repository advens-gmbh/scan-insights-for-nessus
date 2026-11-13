import { useEffect, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, X } from "lucide-react";
import { useScanStore } from "../../stores/scanStore";
import { useUiStore } from "../../stores/uiStore";
import { displayScanName } from "../../types/nessus";
import type { ScanFile, SeverityCounts } from "../../types/nessus";
import { formatScanStart } from "../../utils/format";
import { fileWindow } from "../../utils/fileFacts";

const BAR = [
  { key: "critical", className: "bg-critical" },
  { key: "high", className: "bg-high" },
  { key: "medium", className: "bg-medium" },
  { key: "low", className: "bg-low" },
  { key: "info", className: "bg-info" },
] as const;

export default function FilesMenu({ onClose }: { onClose: () => void }) {
  const files = useScanStore((s) => s.files);
  const openFiles = useScanStore((s) => s.openFiles);
  const unloadFile = useScanStore((s) => s.unloadFile);
  const unloadAll = useScanStore((s) => s.unloadAll);
  const openFilePanel = useUiStore((s) => s.openFilePanel);
  const showInfo = useUiStore((s) => s.showInfo);
  const navigate = useNavigate();
  const box = useRef<HTMLDivElement>(null);

  // newest scan first
  const rows = useMemo(() => files.map((file) => ({ file, start: fileWindow(file).start, counts: file.counts }))
    .sort((a, b) => (b.start?.getTime() ?? 0) - (a.start?.getTime() ?? 0)), [files]);

  useEffect(() => {
    const away = (e: MouseEvent) => {
      const opener = (e.target as HTMLElement).closest("[data-files-menu-button]");
      if (box.current && !box.current.contains(e.target as Node) && !opener) {
        onClose();
      }
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  const act = (fn: () => unknown) => () => {
    onClose();
    fn();
  };

  return (
    <div ref={box} role="dialog" aria-label="Open files" className="card absolute left-0 top-[calc(100%+6px)] z-[150] w-[560px] max-w-[calc(100vw-280px)] overflow-hidden shadow-2xl animate-fade-in">
      <div className="flex items-baseline gap-2 px-3.5 pt-3 pb-2.5">
        <span className="text-body font-bold text-ink-900 dark:text-ink-50">Open files</span>
        <span className="text-caption text-ink-500 dark:text-ink-400">newest scan first</span>
      </div>
      <ul className="max-h-[60vh] overflow-y-auto">
        {rows.map(({ file, start, counts }) => <Row key={file.id} file={file} start={start} counts={counts} showInfo={showInfo} onDetails={act(() => openFilePanel(file.id))} onClose={() => unloadFile(file.id)} />)}
      </ul>
      <div className="flex items-center gap-1 px-2 py-2 border-t border-ink-200 dark:border-ink-700 bg-ink-50 dark:bg-ink-900/40">
        <button onClick={act(openFiles)} className="btn-ghost h-8 text-small font-semibold text-accent-700 dark:text-accent-400"><Plus size={14} /> Open more files</button>
        <button onClick={act(() => navigate("/projects"))} className="btn-ghost h-8 text-small font-semibold text-accent-700 dark:text-accent-400">Save as project</button>
        <button onClick={act(unloadAll)} className="btn-ghost h-8 text-small font-semibold text-critical-fg dark:text-critical-fg ml-auto">Close all files</button>
      </div>
    </div>
  );
}// FilesMenu

function Row({ file, start, counts, showInfo, onDetails, onClose }: {
  file: ScanFile;
  start: Date | null;
  counts: SeverityCounts;
  showInfo: boolean;
  onDetails: () => void;
  onClose: () => void;
}) {
  const name = displayScanName(file);
  const shown = BAR.filter((b) => counts[b.key] > 0 && (showInfo || b.key !== "info"));
  return (
    <li className="flex items-center gap-2.5 px-3.5 py-2.5 border-t border-ink-100 dark:border-ink-700/50">
      <div className="min-w-0 flex-1">
        <button onClick={onDetails} className="block max-w-full truncate text-left text-body font-semibold text-accent-700 dark:text-accent-400 hover:underline" title={`${file.path}
Show the scan file's details`}>{file.filename}</button>
        <div className="text-caption text-ink-500 dark:text-ink-400 truncate">
          {[name, `${file.host_count.toLocaleString()} ${file.host_count === 1 ? "host" : "hosts"}`, start ? `scanned ${formatScanStart(start)}` : null].filter(Boolean).join(" · ")}
        </div>
      </div>
      <span className="flex gap-0.5 h-1.5 w-[70px] rounded-full overflow-hidden bg-ink-100 dark:bg-ink-700 shrink-0" title={shown.map((b) => `${counts[b.key].toLocaleString()} ${b.key}`).join(", ") || (showInfo ? "No findings" : "No findings above Info")}>
        {shown.map((b) => <i key={b.key} className={b.className} style={{ flex: counts[b.key] }} />)}
      </span>
      <button onClick={onClose} className="btn-ghost h-8 w-8 p-0 justify-center" aria-label={`Close ${file.filename}`} title="Close this file"><X size={15} /></button>
    </li>
  );
}// Row
