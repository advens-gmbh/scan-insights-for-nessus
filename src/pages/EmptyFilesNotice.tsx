import { FolderOpen } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { timeAgo } from "../utils/format";
import type { TableColumn } from "../utils/tableColumns";
import FileExt from "../components/common/FileExt";

export type EmptyPage = "vulnerabilities" | "hosts" | "services" | "topology" | "compare" | "trends" | "export";

const PAGES: Record<EmptyPage, { title?: string; text?: string; shows?: string }> = {
  vulnerabilities: { shows: "see its findings" },
  hosts:           { shows: "see its hosts" },
  services:        { shows: "see its services" },
  topology:        { shows: "see its network map" },
  compare:         { title: "Compare needs two scans", text: "Open an earlier and a later run of the same scan." },
  trends:          { title: "Trends need several scans", text: "Open runs of the same scan from different dates." },
  export:          { shows: "export its findings" },
};

const RECENT_SHOWN = 3;
const SEVERITIES = ["Critical", "High", "Medium", "Low"];

// a table page without a scan (its filters and column headers, empty, with the message inside the table)
interface Props {
  page: EmptyPage;
  columns?: TableColumn[];
  search?: string;
}// Props

export default function EmptyFilesNotice({ page, columns, search }: Props) {
  const openFiles = useScanStore((s) => s.openFiles);
  const loadFile = useScanStore((s) => s.loadFile);
  const recentFiles = useScanStore((s) => s.recentFiles);
  const fileCount = useScanStore((s) => s.files.length);
  const { title, text, shows } = PAGES[page];
  const second = page === "compare" && fileCount === 1;
  const shown = columns?.filter((c) => !c.defaultHidden && !c.info);

  return (
    <div className="flex flex-col gap-3.5">
      {search && (
        <div className="flex items-center gap-2 select-none" aria-hidden="true">
          {SEVERITIES.map((s) => <span key={s} className="px-3 py-1 rounded-full bg-ink-100 dark:bg-ink-800 text-body font-medium text-ink-400 dark:text-ink-500">{s}</span>)}
          <span className="flex-1 min-w-48 h-9 px-3 flex items-center rounded-lg border border-ink-200 dark:border-ink-700 bg-white dark:bg-ink-800 text-body text-ink-400 dark:text-ink-500">{search}</span>
        </div>
      )}
      <div className="card overflow-hidden">
        {shown && (
          <table className="w-full table-fixed" aria-hidden="true">
            <colgroup>{shown.map((c) => <col key={c.key} style={{ width: c.width }} />)}</colgroup>
            <thead>
              <tr className="text-caption font-semibold text-ink-500 dark:text-ink-400 bg-ink-50 dark:bg-ink-900/40 border-b border-ink-200 dark:border-ink-700">
                {shown.map((c) => <th key={c.key} className={`px-4 py-3 truncate ${c.align === "center" ? "text-center" : "text-left"}`}>{c.label}</th>)}
              </tr>
            </thead>
          </table>
        )}
        <div className="px-7 pt-7 pb-6">
          <h1 className="text-heading font-bold text-ink-900 dark:text-ink-50">{second ? "Compare needs a second scan" : title ?? "No scan open"}</h1>
          <p className="mt-1.5 text-body text-ink-700 dark:text-ink-200">
            {second ? "Open another run of the same scan." : text ?? <>Open or drop a <FileExt /> file to {shows}.</>}
          </p>
          <button onClick={openFiles} className="btn-primary h-9 mt-4"><FolderOpen size={15} /> Open files…</button>
          {recentFiles.length > 0 && (
            <div className="mt-6 max-w-3xl">
              <h2 className="pb-1 text-caption font-semibold text-ink-500 dark:text-ink-400">Recent files</h2>
              {recentFiles.slice(0, RECENT_SHOWN).map((r) => (
                <div key={r.path} className="flex items-center gap-4 py-2 border-t border-ink-100 dark:border-ink-700/60 first-of-type:border-t-0 text-body">
                  <button onClick={() => loadFile(r.path)} title={r.path} className="min-w-0 truncate text-left font-semibold text-accent-700 dark:text-accent-400 hover:underline">{r.filename}</button>
                  <span className="ml-auto w-56 shrink-0 truncate text-ink-600 dark:text-ink-300">{r.report_name ?? ""}</span>
                  <span className="w-28 shrink-0 text-right text-ink-500 dark:text-ink-400">{timeAgo(r.last_opened)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}// EmptyFilesNotice
