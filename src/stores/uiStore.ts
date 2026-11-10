import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { AppSettings } from "../types/nessus";

// a panel that was open, so it can be gone back to
export type PanelEntry =
  | { kind: "vuln"; id: number; fileId: string | null }
  | { kind: "host"; ip: string; fileId: string | null }
  | { kind: "service"; key: string; fileId: string | null }
  | { kind: "file"; id: string };

const NO_PANEL = { vulnPanelId: null, vulnPanelFileId: null, hostPanelIp: null, hostPanelFileId: null, servicePanelKey: null, servicePanelFileId: null, filePanelId: null };

function openPanel(s: UiStore): PanelEntry | null {
  if (s.vulnPanelId !== null) {
    return { kind: "vuln", id: s.vulnPanelId, fileId: s.vulnPanelFileId };
  }
  if (s.hostPanelIp !== null) {
    return { kind: "host", ip: s.hostPanelIp, fileId: s.hostPanelFileId };
  }
  if (s.servicePanelKey !== null) {
    return { kind: "service", key: s.servicePanelKey, fileId: s.servicePanelFileId };
  }
  return s.filePanelId !== null ? { kind: "file", id: s.filePanelId } : null;
}// openPanel

function show(entry: PanelEntry) {
  switch (entry.kind) {
    case "vuln": return { ...NO_PANEL, vulnPanelId: entry.id, vulnPanelFileId: entry.fileId };
    case "host": return { ...NO_PANEL, hostPanelIp: entry.ip, hostPanelFileId: entry.fileId };
    case "service": return { ...NO_PANEL, servicePanelKey: entry.key, servicePanelFileId: entry.fileId };
    case "file": return { ...NO_PANEL, filePanelId: entry.id };
  }
}// show

function opening(s: UiStore, entry: PanelEntry) {
  const current = openPanel(s);
  const history = current && current.kind !== entry.kind ? [...s.panelHistory, current] : s.panelHistory;
  return { ...show(entry), panelHistory: current ? history : [] };
}// opening

interface UiStore {
  theme: "light" | "dark";
  sidebarCollapsed: boolean;
  // Panels
  vulnPanelId: number | null;       // plugin_id
  vulnPanelFileId: string | null;   // null = show all files
  hostPanelIp: string | null;
  hostPanelFileId: string | null;   // null = show merged across all files
  servicePanelKey: string | null;   // port/protocol
  servicePanelFileId: string | null;
  openServicePanel: (key: string, fileId?: string) => void;
  closeServicePanel: () => void;
  filePanelId: string | null;
  openFilePanel: (fileId: string) => void;
  closeFilePanel: () => void;
  openVulnPanel: (pluginId: number, fileId?: string) => void;
  openHostPanel: (ip: string, fileId?: string) => void;
  closeVulnPanel: () => void;
  closeHostPanel: () => void;
  panelHistory: PanelEntry[];
  goBack: () => void;
  closePanels: () => void;
  // info findings are mostly noise, unchecked by default
  showInfo: boolean;
  toggleShowInfo: () => void;
  groupHostFindings: boolean;
  toggleGroupHostFindings: () => void;
  groupServiceFindings: boolean;
  toggleGroupServiceFindings: () => void;
  groupServices: boolean;
  toggleGroupServices: () => void;
  trendFileIds: string[] | null;    // null = the default selection
  setTrendFileIds: (ids: string[]) => void;
  trendChart: "lines" | "bars";
  exportExcludedIds: string[];
  setExportExcludedIds: (ids: string[]) => void;
  exportSeverities: number[];
  setExportSeverities: (severities: number[]) => void;
  setTrendChart: (chart: "lines" | "bars") => void;
  topologyMoved: Record<string, { x: number; y: number }>; // boxes dragged on the map
  moveTopologyNode: (id: string, by: { x: number; y: number }) => void;
  resetTopologyLayout: () => void;
  topologyPanel: boolean;
  toggleTopologyPanel: () => void;
  topologyOpen: string[];               // address blocks unfolded on the map
  toggleTopologyBlock: (id: string) => void;
  topologyTarget: string | null;        // the network the way is shown to
  setTopologyTarget: (target: string | null) => void;
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
  servicePanelKey: null,
  servicePanelFileId: null,
  filePanelId: null,
  showInfo: false,

  toggleShowInfo: () => set((s) => ({ showInfo: !s.showInfo })),
  groupHostFindings: false,
  toggleGroupHostFindings: () => set((s) => ({ groupHostFindings: !s.groupHostFindings })),
  groupServiceFindings: false,
  toggleGroupServiceFindings: () => set((s) => ({ groupServiceFindings: !s.groupServiceFindings })),
  groupServices: false,
  toggleGroupServices: () => set((s) => ({ groupServices: !s.groupServices })),
  trendFileIds: null,
  setTrendFileIds: (ids) => set({ trendFileIds: ids }),
  trendChart: "lines",
  exportExcludedIds: [],
  setExportExcludedIds: (ids) => set({ exportExcludedIds: ids }),
  exportSeverities: [4, 3, 2, 1, 0],
  setExportSeverities: (severities) => set({ exportSeverities: severities }),
  setTrendChart: (chart) => set({ trendChart: chart }),
  topologyMoved: {},
  moveTopologyNode: (id, by) => set((s) => ({ topologyMoved: { ...s.topologyMoved, [id]: by } })),
  resetTopologyLayout: () => set({ topologyMoved: {} }),
  topologyPanel: true,
  toggleTopologyPanel: () => set((s) => ({ topologyPanel: !s.topologyPanel })),
  topologyOpen: [],
  toggleTopologyBlock: (id) => set((s) => ({ topologyOpen: s.topologyOpen.includes(id) ? s.topologyOpen.filter((x) => x !== id) : [...s.topologyOpen, id] })),
  topologyTarget: null,
  setTopologyTarget: (target) => set({ topologyTarget: target }),

  openVulnPanel: (pluginId, fileId) => set((s) => opening(s, { kind: "vuln", id: pluginId, fileId: fileId ?? null })),
  openHostPanel: (ip, fileId) => set((s) => opening(s, { kind: "host", ip, fileId: fileId ?? null })),
  openServicePanel: (key, fileId) => set((s) => opening(s, { kind: "service", key, fileId: fileId ?? null })),
  openFilePanel: (fileId) => set((s) => opening(s, { kind: "file", id: fileId })),
  closeServicePanel: () => set({ ...NO_PANEL, panelHistory: [] }),
  closeFilePanel: () => set({ ...NO_PANEL, panelHistory: [] }),
  closeVulnPanel: () => set({ ...NO_PANEL, panelHistory: [] }),
  closeHostPanel: () => set({ ...NO_PANEL, panelHistory: [] }),
  panelHistory: [],
  goBack: () => set((s) => {
    const previous = s.panelHistory[s.panelHistory.length - 1];
    return previous ? { ...show(previous), panelHistory: s.panelHistory.slice(0, -1) } : {};
  }),
  closePanels: () => set({ ...NO_PANEL, panelHistory: [] }),

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
