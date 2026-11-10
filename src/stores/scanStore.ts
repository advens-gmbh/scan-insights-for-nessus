import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import type { NessusFile, RecentFile, ReportHost } from "../types/nessus";
import { useNotificationStore } from "./notificationStore";

// load_nessus_file returns the file without its hosts
type LoadedFile = Omit<NessusFile, "hosts"> & { host_count: number; finding_count: number; size: number };
interface HostPage { hosts: ReportHost[]; next: number }

// the file being opened, step by step
export interface Opening {
  path: string;
  filename: string;
  stage: "reading" | "receiving" | "preparing";
  size: number | null;
  hosts: number;         // received so far
  total: number;         // hosts in the file
  findings: number;
  readMs: number | null; // how long reading the file took
}// Opening

// a file that couldn't be opened, stays on screen until dismissed
export interface LoadFailure {
  id: string;
  path: string;
  filename: string;
  kind: string;          // missing, unreadable, not_nessus, old_format, truncated, damaged, no_hosts, other
  message: string;       // the original text, for the details
}// LoadFailure

export const fileNameOf = (path: string) => path.split(/[\\/]/).pop() ?? path;
export const samePath = (a: string, b: string) => a.replace(/\\/g, "/").toLowerCase() === b.replace(/\\/g, "/").toLowerCase();

function sameScanFile(open: NessusFile, filename: string, size: number | undefined, hostCount: number): boolean {
  return open.filename.toLowerCase() === filename.toLowerCase() && open.hosts.length === hostCount && (open.size === undefined || size === undefined || open.size === size);
}// sameScanFile

// lets the page paint "Preparing the pages" before the heavy first draw
const nextFrame = () => new Promise<void>((resolve) =>
  typeof requestAnimationFrame === "function" ? requestAnimationFrame(() => setTimeout(resolve, 0)) : setTimeout(resolve, 0));

function failureOf(e: unknown): { kind: string; message: string } {
  if (e && typeof e === "object" && "kind" in e && "message" in e) {
    return { kind: String(e.kind), message: String(e.message) };
  }
  return { kind: "other", message: e instanceof Error ? e.message : String(e) };
}// failureOf

let failureId = 0;
// files open one after another; each call adds its files to the end
let chain: Promise<unknown> = Promise.resolve();

interface ScanStore {
  files: NessusFile[];
  recentFiles: RecentFile[];
  loading: boolean;                      // a file is being opened, or waits for it
  opening: Opening | null;
  queue: string[];                       // paths waiting to be opened
  batch: { done: number; total: number }; // "file 2 of 3" since the app was last idle
  failures: LoadFailure[];
  openFiles: () => Promise<void>;
  loadFiles: (paths: string[]) => Promise<NessusFile[]>;
  loadFile: (path: string) => Promise<NessusFile | null>;
  retry: (id: string) => Promise<void>;
  dismissFailure: (id: string) => void;
  unloadFile: (id: string) => Promise<void>;
  unloadAll: () => Promise<void>;
  loadRecentFiles: () => Promise<void>;
  forgetRecent: (path: string) => Promise<void>;
  clearRecent: () => Promise<void>;
}// ScanStore

export const useScanStore = create<ScanStore>((set, get) => {
  const saveRecent = async (files: RecentFile[]) => {
    set({ recentFiles: files });
    try {
      await invoke("save_recent_files", { files });
    } catch {
      // the list still works for this session
    }
  };

  // files of one batch wait here and join `files` together when the batch ends
  let arrived: NessusFile[] = [];

  const openOne = async (path: string): Promise<NessusFile | null> => {
    const filename = fileNameOf(path);
    const update = (o: Partial<Opening>) => set((s) => ({ opening: s.opening && { ...s.opening, ...o } }));
    set((s) => ({
      queue: s.queue.filter((q) => q !== path),
      opening: { path, filename, stage: "reading", size: null, hosts: 0, total: 0, findings: 0, readMs: null },
    }));
    const started = Date.now();
    invoke<(number | null)[]>("file_sizes", { paths: [path] })
      .then((sizes) => Array.isArray(sizes) && typeof sizes[0] === "number" && update({ size: sizes[0] }))
      .catch(() => {});
    try {
      const { host_count, finding_count, size, ...head } = await invoke<LoadedFile>("load_nessus_file", { path });
      const twin = [...get().files, ...arrived].find((f) => sameScanFile(f, head.filename, size, host_count));
      if (twin) {
        await invoke("unload_file", { id: head.id }).catch(() => {});
        useNotificationStore.getState().add(`"${head.filename}" is already open${samePath(twin.path, path) ? "" : ` from ${twin.path}`}`, "info");
        return null;
      }
      update({ stage: "receiving", size: size ?? null, total: host_count, findings: finding_count ?? 0, readMs: Date.now() - started });
      const hosts: ReportHost[] = [];
      while (hosts.length < host_count) {
        const page = await invoke<HostPage>("file_hosts", { id: head.id, start: hosts.length });
        if (page.hosts.length === 0) {
          throw new Error(`Only ${hosts.length} of ${host_count} hosts arrived.`);
        }
        for (const h of page.hosts) {
          hosts.push(h);
        }
        update({ hosts: hosts.length });
      }
      update({ stage: "preparing" });
      await nextFrame();
      const file: NessusFile = { ...head, hosts, size };
      arrived = [...arrived.filter((f) => !samePath(f.path, file.path)), file];
      const recent: RecentFile = { path: file.path, filename: file.filename, last_opened: new Date().toISOString(), report_name: file.report_name || null };
      await saveRecent([recent, ...get().recentFiles.filter((r) => r.path !== file.path)].slice(0, 20));
      return file;
    } catch (e) {
      const failure: LoadFailure = { id: `f${++failureId}`, path, filename, ...failureOf(e) };
      set((s) => ({ failures: [...s.failures.filter((f) => f.path !== path), failure] }));
      return null;
    } finally {
      set((s) => {
        const idle = s.queue.length === 0;
        if (!idle) {
          return { opening: null, batch: { ...s.batch, done: s.batch.done + 1 } };
        }
        const joined = arrived;
        arrived = [];
        const files = joined.length ? [...s.files.filter((f) => !joined.some((j) => j.id === f.id || samePath(j.path, f.path))), ...joined] : s.files;
        return { opening: null, loading: false, batch: { done: 0, total: 0 }, files };
      });
    }
  };

  return {
    files: [],
    recentFiles: [],
    loading: false,
    opening: null,
    queue: [],
    batch: { done: 0, total: 0 },
    failures: [],

    openFiles: async () => {
      const selected = await open({
        multiple: true,
        filters: [{ name: "Nessus Scan Files", extensions: ["nessus"] }],
      });
      if (!selected) return;
      await get().loadFiles(Array.isArray(selected) ? selected : [selected]);
    },

    loadFiles: (paths: string[]) => {
      const s = get();
      const waiting = [...s.queue, ...(s.opening ? [s.opening.path] : [])];
      const fresh: string[] = [];
      for (const p of paths) {
        if ([...s.files, ...arrived].some((f) => samePath(f.path, p))) {
          useNotificationStore.getState().add(`"${fileNameOf(p)}" is already open`, "info");
        } else if (!waiting.some((w) => samePath(w, p)) && !fresh.some((f) => samePath(f, p))) {
          fresh.push(p);
        }
      }
      if (fresh.length === 0) {
        return Promise.resolve([]);
      }
      set({
        queue: [...s.queue, ...fresh],
        loading: true,
        batch: { done: s.loading ? s.batch.done : 0, total: (s.loading ? s.batch.total : 0) + fresh.length },
        failures: s.failures.filter((f) => !fresh.includes(f.path)),
      });
      const runs = fresh.map((p) => {
        const run = chain.then(() => openOne(p));
        chain = run.catch(() => null);
        return run;
      });
      return Promise.all(runs).then((files) => files.filter((f): f is NessusFile => f !== null));
    },

    loadFile: async (path: string) => {
      const [file] = await get().loadFiles([path]);
      return file ?? null;
    },

    retry: async (id: string) => {
      const failure = get().failures.find((f) => f.id === id);
      if (failure) {
        await get().loadFile(failure.path);
      }
    },

    dismissFailure: (id: string) => set((s) => ({ failures: s.failures.filter((f) => f.id !== id) })),

    unloadFile: async (id: string) => {
      await invoke("unload_file", { id });
      set((s) => ({ files: s.files.filter((f) => f.id !== id) }));
    },

    unloadAll: async () => {
      await invoke("unload_all_files");
      set({ files: [] });
    },

    loadRecentFiles: async () => {
      try {
        const files = await invoke<RecentFile[]>("load_recent_files");
        set({ recentFiles: files });
      } catch {
        // ignore (first run)
      }
    },

    forgetRecent: (path: string) => saveRecent(get().recentFiles.filter((r) => r.path !== path)),

    clearRecent: () => saveRecent([]),
  };
});// useScanStore
