import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import type { RecentFile, ScanFile } from "../types/nessus";
import { useNotificationStore } from "./notificationStore";

// the file being read
export interface Opening {
  path: string;
  filename: string;
  size: number | null;
  percent: number;       // how much of it the backend has read
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

function sameScanFile(open: ScanFile, file: ScanFile): boolean {
  return open.filename.toLowerCase() === file.filename.toLowerCase() && open.host_count === file.host_count && open.size === file.size;
}// sameScanFile

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
  files: ScanFile[];
  recentFiles: RecentFile[];
  loading: boolean;                      // a file is being opened, or waits for it
  opening: Opening | null;
  queue: string[];                       // paths waiting to be opened
  batch: { done: number; total: number }; // "file 2 of 3" since the app was last idle
  failures: LoadFailure[];
  openFiles: () => Promise<void>;
  loadFiles: (paths: string[]) => Promise<ScanFile[]>;
  loadFile: (path: string) => Promise<ScanFile | null>;
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

  // how far the backend has read the file being opened
  let listening = false;
  const follow = () => {
    if (listening) {
      return;
    }
    listening = true;
    listen<{ path: string; percent: number }>("load-progress", (e) => {
      set((s) => (s.opening && s.opening.path === e.payload.path && s.opening.percent !== e.payload.percent
        ? { opening: { ...s.opening, percent: e.payload.percent } }
        : s));
    }).catch(() => {
      listening = false;
    });
  };

  const openOne = async (path: string): Promise<ScanFile | null> => {
    const filename = fileNameOf(path);
    follow();
    set((s) => ({
      queue: s.queue.filter((q) => q !== path),
      opening: { path, filename, size: null, percent: 0 },
    }));
    invoke<(number | null)[]>("file_sizes", { paths: [path] })
      .then((sizes) => Array.isArray(sizes) && typeof sizes[0] === "number" && set((s) => ({ opening: s.opening?.path === path ? { ...s.opening, size: sizes[0] } : s.opening })))
      .catch(() => {});
    try {
      const file = await invoke<ScanFile>("load_nessus_file", { path });
      const twin = get().files.find((f) => !samePath(f.path, file.path) && sameScanFile(f, file));
      if (twin) {
        await invoke("unload_file", { id: file.id }).catch(() => {});
        useNotificationStore.getState().add(`"${file.filename}" is already open from ${twin.path}`, "info");
        return null;
      }
      const compliance = file.compliance_skipped ?? 0;
      if (compliance > 0) {
        useNotificationStore.getState().add(
          `"${file.filename}" has ${compliance.toLocaleString()} compliance check ${compliance === 1 ? "result" : "results"}. The app doesn't show compliance results yet.`,
          "warning",
        );
      }
      // shown at once; the pages ask the backend for their lists again
      set((s) => ({ files: [...s.files.filter((f) => f.id !== file.id && !samePath(f.path, file.path)), file] }));
      const recent: RecentFile = { path: file.path, filename: file.filename, last_opened: new Date().toISOString(), report_name: file.report_name || null };
      await saveRecent([recent, ...get().recentFiles.filter((r) => r.path !== file.path)].slice(0, 20));
      return file;
    } catch (e) {
      const failure: LoadFailure = { id: `f${++failureId}`, path, filename, ...failureOf(e) };
      set((s) => ({ failures: [...s.failures.filter((f) => f.path !== path), failure] }));
      return null;
    } finally {
      set((s) => (s.queue.length === 0
        ? { opening: null, loading: false, batch: { done: 0, total: 0 } }
        : { opening: null, batch: { ...s.batch, done: s.batch.done + 1 } }));
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
        if (s.files.some((f) => samePath(f.path, p))) {
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
      return Promise.all(runs).then((files) => files.filter((f): f is ScanFile => f !== null));
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
