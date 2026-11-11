import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { FileText, FolderOpen, Upload, X } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useProjectStore } from "../stores/projectStore";
import type { Project, RecentFile } from "../types/nessus";
import { folderOf, formatBytes, timeAgo } from "../utils/format";
import FileExt from "../components/common/FileExt";
import logo from "../../src-tauri/icons/128x128.png";

const PROJECTS_SHOWN = 3;
const RECENT_ROWS = 8;
const ROW_H = 49;

// start screen (previously opened files)
export default function Welcome() {
  const recentFiles = useScanStore((s) => s.recentFiles);
  const openFiles = useScanStore((s) => s.openFiles);
  const loadFiles = useScanStore((s) => s.loadFiles);
  const forgetRecent = useScanStore((s) => s.forgetRecent);
  const clearRecent = useScanStore((s) => s.clearRecent);
  const projects = useProjectStore((s) => s.projects);
  const [picked, setPicked] = useState<string[]>([]);
  // size per path; null when the file isn't there any more, missing while unknown
  const [sizes, setSizes] = useState<Record<string, number | null>>({});

  const paths = useMemo(() => recentFiles.map((r) => r.path), [recentFiles]);
  useEffect(() => {
    if (paths.length === 0) {
      return;
    }
    let live = true;
    invoke<(number | null)[]>("file_sizes", { paths })
      .then((found) => live && Array.isArray(found) && setSizes(Object.fromEntries(paths.map((p, i) => [p, found[i] ?? null]))))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [paths]);

  const missing = (p: string) => sizes[p] === null;
  const chosen = picked.filter((p) => paths.includes(p) && !missing(p));
  const toggle = (p: string) => setPicked((now) => (now.includes(p) ? now.filter((x) => x !== p) : [...now, p]));
  const openable = paths.filter((p) => !missing(p));
  const allPicked = openable.length > 0 && openable.every((p) => chosen.includes(p));

  if (recentFiles.length === 0) {
    return <FirstRun openFiles={openFiles} projects={projects} loadFiles={loadFiles} />;
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="card flex flex-wrap items-center gap-4 px-5 py-4">
        <img src={logo} alt="" className="w-11 h-11 rounded-xl" />
        <div className="min-w-0">
          <h1 className="text-[19px] font-bold text-ink-900 dark:text-ink-50">Pick up where you left off</h1>
          <p className="mt-0.5 text-[13px] text-ink-600 dark:text-ink-300">Tick files to open them together, or drop new <FileExt /> files anywhere.</p>
        </div>
        <span className="flex-1" />
        <button onClick={openFiles} className="btn-secondary h-9">Choose other files…</button>
        <button onClick={() => loadFiles(chosen)} disabled={chosen.length === 0} className="btn-primary h-9 disabled:opacity-50 disabled:cursor-not-allowed">
          {chosen.length === 0 ? "Open selected" : `Open ${chosen.length} selected`}
        </button>
      </section>

      <section className="flex flex-col gap-2.5">
        <div className="flex items-baseline gap-2">
          <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Recent files</h2>
          <span className="text-xs text-ink-500 dark:text-ink-400">double-click one to open it</span>
          <span className="flex-1" />
          <button onClick={clearRecent} className="btn-ghost h-7 text-xs">Clear list</button>
        </div>
        <div className="card overflow-auto" style={{ maxHeight: 41 + RECENT_ROWS * ROW_H + 2 }}>
          <table className="w-full table-fixed text-[13.5px]">
            <colgroup>
              <col className="w-11" />
              <col className="w-[34%]" />
              <col className="w-[20%]" />
              <col />
              <col className="w-24" />
              <col className="w-32" />
              <col className="w-12" />
            </colgroup>
            <thead className="sticky top-0 z-10">
              <tr className="text-left text-xs font-semibold text-ink-500 dark:text-ink-400 bg-ink-50 dark:bg-[color-mix(in_srgb,theme(colors.ink.900)_50%,theme(colors.ink.800))] shadow-[inset_0_-1px_0_theme(colors.ink.200)] dark:shadow-[inset_0_-1px_0_theme(colors.ink.700)]">
                <th className="pl-4 py-2.5">
                  <input type="checkbox" checked={allPicked} onChange={() => setPicked(allPicked ? [] : openable)} aria-label="Select every file" className="w-4 h-4 accent-accent-600 align-middle" />
                </th>
                <th className="px-3 py-2.5">File</th>
                <th className="px-3 py-2.5">Scan</th>
                <th className="px-3 py-2.5">Folder</th>
                <th className="px-3 py-2.5 text-right">Size</th>
                <th className="px-3 py-2.5 text-right">Opened</th>
                <th className="pr-3 py-2.5"><span className="sr-only">Remove</span></th>
              </tr>
            </thead>
            <tbody>
              {recentFiles.map((r) => (
                <RecentRow
                  key={r.path}
                  file={r}
                  size={sizes[r.path]}
                  picked={chosen.includes(r.path)}
                  onToggle={() => toggle(r.path)}
                  onOpen={() => loadFiles([r.path])}
                  onRemove={() => forgetRecent(r.path)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {projects.length > 0 && <Projects projects={projects} loadFiles={loadFiles} />}
    </div>
  );
}// Welcome

function FileIcon({ dim = false }: { dim?: boolean }) {
  return (
    <span className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${dim ? "bg-ink-100 dark:bg-ink-700 text-ink-400" : "bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300"}`}>
      <FileText size={16} />
    </span>
  );
}// FileIcon

function RecentRow({ file, size, picked, onToggle, onOpen, onRemove }: {
  file: RecentFile;
  size: number | null | undefined;
  picked: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onRemove: () => void;
}) {
  const gone = size === null;
  const folder = folderOf(file.path);
  return (
    <tr
      onClick={gone ? undefined : onToggle}
      onDoubleClick={gone ? undefined : onOpen}
      className={`group border-t border-ink-100 dark:border-ink-700/50 first:border-t-0 select-none ${
        gone ? "text-ink-400 dark:text-ink-500" : `cursor-pointer ${picked ? "bg-accent-50 dark:bg-accent-900/20" : "hover:bg-ink-50 dark:hover:bg-ink-700/40"}`
      }`}
    >
      <td className="pl-4 py-2">
        <input
          type="checkbox"
          checked={picked}
          disabled={gone}
          onChange={onToggle}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${file.filename}`}
          className="w-4 h-4 accent-accent-600 align-middle"
        />
      </td>
      <td className="px-3 py-2">
        <span className="flex items-center gap-2.5 min-w-0">
          <FileIcon dim={gone} />
          <span className={`truncate font-semibold ${gone ? "" : "text-ink-800 dark:text-ink-100"}`} title={file.filename}>{file.filename}</span>
        </span>
      </td>
      <td className={`px-3 py-2 truncate ${gone ? "" : "text-ink-700 dark:text-ink-200"}`} title={gone ? undefined : file.report_name ?? undefined}>
        {gone ? "not found: moved or deleted" : file.report_name ?? <span className="text-ink-400">-</span>}
      </td>
      <td className="px-3 py-2 truncate text-ink-500 dark:text-ink-400" title={folder}>{folder}</td>
      <td className="px-3 py-2 text-right tabular-nums whitespace-nowrap text-ink-600 dark:text-ink-300">{typeof size === "number" ? formatBytes(size) : ""}</td>
      <td className="px-3 py-2 text-right whitespace-nowrap text-ink-600 dark:text-ink-300">{timeAgo(file.last_opened)}</td>
      <td className="pr-3 py-2 text-right">
        <button
          onClick={(e) => { e.stopPropagation(); onRemove(); }}
          onDoubleClick={(e) => e.stopPropagation()}
          title="Remove from the list"
          aria-label={`Remove ${file.filename} from the list`}
          className={`w-7 h-7 inline-flex items-center justify-center rounded-md text-ink-400 hover:text-ink-700 hover:bg-ink-100 dark:hover:text-ink-100 dark:hover:bg-ink-700 focus-visible:opacity-100 ${gone ? "" : "opacity-0 group-hover:opacity-100"}`}
        >
          <X size={15} />
        </button>
      </td>
    </tr>
  );
}// RecentRow

const lastUsed = (p: Project) => p.last_opened ?? p.created_at;

function Projects({ projects, loadFiles }: { projects: Project[]; loadFiles: (paths: string[]) => Promise<unknown> }) {
  const markOpened = useProjectStore((s) => s.markOpened);
  // the ones used most recently first
  const shown = [...projects].sort((a, b) => lastUsed(b).localeCompare(lastUsed(a))).slice(0, PROJECTS_SHOWN);
  return (
    <section className="flex flex-col gap-2.5">
      <div className="flex items-baseline gap-2">
        <h2 className="text-[15px] font-semibold text-ink-800 dark:text-ink-100">Projects</h2>
        <span className="flex-1" />
        <Link to="/projects" className="text-[13px] font-semibold text-accent-700 dark:text-accent-400 hover:underline">{projects.length > PROJECTS_SHOWN ? `All ${projects.length} projects` : "Manage projects"}</Link>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {shown.map((p) => {
          const names = p.file_paths.map((f) => (f.filename || f.path.split(/[\\/]/).pop() || f.path).replace(/\.nessus$/i, ""));
          return (
            <div key={p.id} className="card px-4 py-3.5 flex flex-col gap-2 min-w-0">
              <div className="flex items-center gap-3 min-w-0">
                <span className="w-8 h-8 rounded-lg bg-ink-100 dark:bg-ink-700 text-ink-700 dark:text-ink-200 flex items-center justify-center shrink-0"><FolderOpen size={16} /></span>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-ink-800 dark:text-ink-100 truncate" title={p.name}>{p.name}</div>
                  <div className="text-xs text-ink-500 dark:text-ink-400 truncate">
                    {p.file_paths.length} {p.file_paths.length === 1 ? "file" : "files"} · {p.last_opened ? `opened ${timeAgo(p.last_opened)}` : `created ${timeAgo(p.created_at)}`}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1.5 min-w-0">
                {names.slice(0, 2).map((n) => <span key={n} className="px-1.5 rounded bg-ink-100 dark:bg-ink-700 text-[11px] font-semibold text-ink-700 dark:text-ink-200 truncate max-w-[9rem]" title={n}>{n}</span>)}
                {names.length > 2 && <span className="px-1.5 rounded bg-ink-100 dark:bg-ink-700 text-[11px] font-semibold text-ink-700 dark:text-ink-200">+{names.length - 2}</span>}
                <span className="flex-1" />
                <button
                  onClick={() => {
                    markOpened(p.id);
                    loadFiles(p.file_paths.map((f) => f.path));
                  }}
                  disabled={p.file_paths.length === 0}
                  className="btn-ghost h-8 px-3 border border-ink-200 dark:border-ink-600 text-[13px] font-semibold text-accent-700 dark:text-accent-400 disabled:opacity-50"
                >
                  Open
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}// Projects

function FirstRun({ openFiles, projects, loadFiles }: { openFiles: () => void; projects: Project[]; loadFiles: (paths: string[]) => Promise<unknown> }) {
  return (
    <div className="flex flex-col gap-7">
      <div className="flex items-center gap-4">
        <img src={logo} alt="" className="w-[52px] h-[52px] rounded-[14px]" />
        <div>
          <h1 className="text-2xl font-bold text-ink-900 dark:text-ink-50">Scan Insights for Nessus</h1>
          <p className="mt-1 text-sm text-ink-600 dark:text-ink-300">Your scans stay on this computer.</p>
        </div>
      </div>
      <section aria-label="Open files" className="rounded-2xl border-2 border-dashed border-accent-300 dark:border-accent-700 bg-accent-50 dark:bg-accent-900/20 min-h-[230px] flex flex-col items-center justify-center gap-3 text-center px-6 py-8">
        <span className="w-14 h-14 rounded-2xl bg-white dark:bg-ink-800 text-accent-600 dark:text-accent-300 flex items-center justify-center shadow-sm"><Upload size={26} /></span>
        <div className="text-lg font-semibold text-ink-900 dark:text-ink-50">Drop <FileExt /> files here</div>
        <div className="flex items-center gap-3 text-sm text-ink-600 dark:text-ink-300">or <button onClick={openFiles} className="btn-primary h-9">Choose files</button></div>
      </section>
      {projects.length > 0 && <Projects projects={projects} loadFiles={loadFiles} />}
    </div>
  );
}// FirstRun
