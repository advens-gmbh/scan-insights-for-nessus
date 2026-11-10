import { Suspense, useEffect } from "react";
import { Outlet } from "react-router-dom";
import { getCurrentWindow } from "@tauri-apps/api/window";
import Sidebar from "./Sidebar";
import TopBar from "./TopBar";
import Notifications from "./Notifications";
import VulnDetail from "../../panels/VulnDetail";
import HostDetail from "../../panels/HostDetail";
import ServiceDetail from "../../panels/ServiceDetail";
import FileDetailPanel from "../../panels/FileDetailPanel";
import { useUiStore } from "../../stores/uiStore";
import { useScanStore } from "../../stores/scanStore";
import { useNotificationStore } from "../../stores/notificationStore";

export default function Layout() {
  const { vulnPanelId, hostPanelIp, servicePanelKey, filePanelId, closePanels } = useUiStore();
  const panelOpen = vulnPanelId !== null || hostPanelIp !== null || servicePanelKey !== null || filePanelId !== null;
  const loadFile = useScanStore((s) => s.loadFile);

  // lives here so files can be dropped on any page
  useEffect(() => {
    const promise = getCurrentWindow().onDragDropEvent(async (event) => {
      if (event.payload.type !== "drop") {
        return;
      }

      const paths = event.payload.paths;
      const scans = paths.filter((p) => p.toLowerCase().endsWith(".nessus"));
      if (scans.length < paths.length) {
        useNotificationStore.getState().add("Only .nessus files can be loaded", "warning");
      }

      for (const path of scans) {
        await loadFile(path);
      }
    });
    return () => { promise.then((unlisten) => unlisten()); };
  }, [loadFile]);

  return (
    <div className="flex h-screen overflow-hidden bg-ink-50 dark:bg-ink-950">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-5">
          <Suspense fallback={null}>
            <Outlet />
          </Suspense>
        </main>
      </div>

      {/* Global slide-in panels */}
      {panelOpen && <div className="panel-overlay" onClick={closePanels} aria-hidden="true" />}
      {vulnPanelId !== null && <VulnDetail pluginId={vulnPanelId} />}
      {hostPanelIp !== null && <HostDetail ip={hostPanelIp} />}
      {servicePanelKey !== null && <ServiceDetail serviceKey={servicePanelKey} />}
      {filePanelId !== null && <FileDetailPanel fileId={filePanelId} />}

      {/* Toast notifications */}
      <Notifications />
    </div>
  );
}// Layout
