import { useNavigate } from "react-router-dom";
import { Download, FolderOpen, GitCompare, Layers, Network, Server, ShieldAlert, TrendingUp } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { timeAgo } from "../utils/format";
import NessusExt from "../components/common/NessusExt";

export type EmptyPage = "vulnerabilities" | "hosts" | "services" | "topology" | "compare" | "trends" | "export";

const PAGES: Record<EmptyPage, { icon: LucideIcon; title?: string; text?: string }> = {
  vulnerabilities: { icon: ShieldAlert },
  hosts:           { icon: Server },
  services:        { icon: Layers },
  topology:        { icon: Network },
  compare:         { icon: GitCompare, title: "Compare needs two scans", text: "Open an earlier and a later run of the same scan." },
  trends:          { icon: TrendingUp, title: "Trends need several scans", text: "Open runs of the same scan from different dates." },
  export:          { icon: Download },
};

const RECENT_SHOWN = 3;

export default function EmptyFilesNotice({ page }: { page: EmptyPage }) {
  const openFiles = useScanStore((s) => s.openFiles);
  const loadFile = useScanStore((s) => s.loadFile);
  const recentFiles = useScanStore((s) => s.recentFiles);
  const fileCount = useScanStore((s) => s.files.length);
  const navigate = useNavigate();
  const { icon: Icon, title, text } = PAGES[page];
  const second = page === "compare" && fileCount === 1;
  return (
    <div className="min-h-[70vh] flex items-center justify-center">
      <div className="w-[440px] max-w-full flex flex-col items-center gap-3.5 text-center">
        <span className="w-16 h-16 rounded-[18px] bg-accent-50 dark:bg-accent-900/30 text-accent-600 dark:text-accent-300 flex items-center justify-center"><Icon size={30} /></span>
        <h1 className="text-xl font-bold text-ink-900 dark:text-ink-50">{second ? "Compare needs a second scan" : title ?? "No scan open"}</h1>
        <p className="text-sm leading-[21px] text-ink-600 dark:text-ink-300">
          {second ? "Open another run of the same scan." : text ?? <>Open a <NessusExt /> file, or drop one anywhere in this window.</>}
        </p>
        <div className="flex flex-wrap justify-center gap-2.5 mt-1">
          <button onClick={openFiles} className="btn-primary h-9"><FolderOpen size={15} /> Open files</button>
          {fileCount === 0 && <button onClick={() => navigate("/")} className="btn-secondary h-9">Go to the start screen</button>}
        </div>
        {recentFiles.length > 0 && (
          <div className="w-full mt-4 text-left">
            <div className="px-3 pb-1 text-xs font-semibold text-ink-500 dark:text-ink-400">Recent files</div>
            {recentFiles.slice(0, RECENT_SHOWN).map((r) => (
              <button
                key={r.path}
                onClick={() => loadFile(r.path)}
                title={r.path}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left text-[13.5px] font-semibold text-accent-700 dark:text-accent-400 hover:bg-ink-100 dark:hover:bg-ink-800"
              >
                <span className="min-w-0 truncate">{r.filename}</span>
                <span className="ml-auto shrink-0 text-xs font-normal text-ink-500 dark:text-ink-400">{timeAgo(r.last_opened)}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}// EmptyFilesNotice
