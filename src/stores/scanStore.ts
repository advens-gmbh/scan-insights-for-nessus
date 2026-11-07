import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import type { NessusFile, RecentFile } from "../types/nessus";
import { useNotificationStore } from "./notificationStore";

interface ScanStore {
  files: NessusFile[];
  recentFiles: RecentFile[];
  loading: boolean;
  error: string | null;
  openFiles: () => Promise<void>;
  loadFile: (path: string) => Promise<NessusFile | null>;
  unloadFile: (id: string) => Promise<void>;
  unloadAll: () => Promise<void>;
  loadRecentFiles: () => Promise<void>;
  clearError: () => void;
}

export const useScanStore = create<ScanStore>((set, get) => ({
  files: [],
  recentFiles: [],
  loading: false,
  error: null,

  openFiles: async () => {
    const selected = await open({
      multiple: true,
      filters: [{ name: "Nessus Scan Files", extensions: ["nessus"] }],
    });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];
    for (const p of paths) {
      await get().loadFile(p);
    }
  },

  loadFile: async (path: string) => {
    const filename = path.split(/[\\/]/).pop() ?? path;
    if (get().files.some((f) => f.path === path)) {
      useNotificationStore.getState().add(`"${filename}" is already loaded`, "warning");
      return null;
    }
    set({ loading: true, error: null });
    try {
      const file = await invoke<NessusFile>("load_nessus_file", { path });
      set((s) => {
        const without = s.files.filter((f) => f.id !== file.id);
        return { files: [...without, file], loading: false };
      });
      // update recent files
      const recent: RecentFile = {
        path: file.path,
        filename: file.filename,
        last_opened: new Date().toISOString(),
      };
      const existing = get().recentFiles.filter((r) => r.path !== path);
      const updated = [recent, ...existing].slice(0, 20);
      set({ recentFiles: updated });
      await invoke("save_recent_files", { files: updated });
      return file;
    } catch (e) {
      const msg = String(e).replace(/^.*?Error[:\s]*/i, "").trim() || String(e);
      useNotificationStore.getState().add(`Failed to load "${filename}": ${msg}`, "error");
      set({ error: String(e), loading: false });
      return null;
    }
  },

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

  clearError: () => set({ error: null }),
}));// useScanStore
