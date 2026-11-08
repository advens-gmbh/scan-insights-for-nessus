import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { AppSettings } from "../types/nessus";

interface UiStore {
  theme: "light" | "dark";
  sidebarCollapsed: boolean;
  // Panels
  vulnPanelId: number | null;       // plugin_id
  vulnPanelFileId: string | null;   // null = show all files
  hostPanelIp: string | null;
  hostPanelFileId: string | null;   // null = show merged across all files
  openVulnPanel: (pluginId: number, fileId?: string) => void;
  openHostPanel: (ip: string, fileId?: string) => void;
  closeVulnPanel: () => void;
  closeHostPanel: () => void;
  // info findings are mostly noise, unchecked by default
  showInfo: boolean;
  toggleShowInfo: () => void;
  groupHostFindings: boolean;
  toggleGroupHostFindings: () => void;
  // Theme
  toggleTheme: () => void;
  setTheme: (t: "light" | "dark") => void;
  // Sidebar
  toggleSidebar: () => void;
  setSidebarCollapsed: (v: boolean) => void;
  // Persistence
  loadSettings: () => Promise<void>;
  saveSettings: () => Promise<void>;
}// UiStore

export const useUiStore = create<UiStore>((set, get) => ({
  theme: "dark",
  sidebarCollapsed: false,
  vulnPanelId: null,
  vulnPanelFileId: null,
  hostPanelIp: null,
  hostPanelFileId: null,
  showInfo: false,

  toggleShowInfo: () => set((s) => ({ showInfo: !s.showInfo })),
  groupHostFindings: false,
  toggleGroupHostFindings: () => set((s) => ({ groupHostFindings: !s.groupHostFindings })),

  openVulnPanel: (pluginId, fileId) => set({ vulnPanelId: pluginId, vulnPanelFileId: fileId ?? null, hostPanelIp: null }),
  openHostPanel: (ip, fileId) => set({ hostPanelIp: ip, hostPanelFileId: fileId ?? null, vulnPanelId: null }),
  closeVulnPanel: () => set({ vulnPanelId: null, vulnPanelFileId: null }),
  closeHostPanel: () => set({ hostPanelIp: null, hostPanelFileId: null }),

  toggleTheme: () => {
    const next = get().theme === "dark" ? "light" : "dark";
    set({ theme: next });
    document.documentElement.classList.toggle("dark", next === "dark");
    get().saveSettings();
  },

  setTheme: (t) => {
    set({ theme: t });
    document.documentElement.classList.toggle("dark", t === "dark");
  },

  toggleSidebar: () => {
    const next = !get().sidebarCollapsed;
    set({ sidebarCollapsed: next });
    get().saveSettings();
  },

  setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),

  loadSettings: async () => {
    try {
      const s = await invoke<AppSettings>("load_settings");
      const theme = (s.theme === "light" ? "light" : "dark") as "light" | "dark";
      set({ theme, sidebarCollapsed: s.sidebar_collapsed });
      document.documentElement.classList.toggle("dark", theme === "dark");
    } catch {
      // defaults
      document.documentElement.classList.add("dark");
    }
  },

  saveSettings: async () => {
    const { theme, sidebarCollapsed } = get();
    try {
      await invoke("save_settings", {
        settings: { theme, sidebar_collapsed: sidebarCollapsed },
      });
    } catch {
      // ignore persistence errors
    }
  },
}));// useUiStore
