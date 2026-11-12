import { Suspense, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { getCurrentWindow } from "@tauri-apps/api/window";
import Sidebar from "./Sidebar";
import TopBar from "./TopBar";
import Notifications from "./Notifications";
import DropOverlay, { isScanPath } from "./DropOverlay";
import { FailureCard, OpeningCard, OpeningToast } from "./LoadStatus";
import VulnDetail from "../../panels/VulnDetail";
import HostDetail from "../../panels/HostDetail";
import ServiceDetail from "../../panels/ServiceDetail";
import FileDetailPanel from "../../panels/FileDetailPanel";
import { useUiStore } from "../../stores/uiStore";
import { usePanelClickAway } from "./usePanelClickAway";
import { useScanStore } from "../../stores/scanStore";
import { useNotificationStore } from "../../stores/notificationStore";

export default function Layout() {
  const { vulnPanelId, hostPanelIp, servicePanelKey, filePanelId } = useUiStore();
  const panelOpen = vulnPanelId !== null || hostPanelIp !== null || servicePanelKey !== null || filePanelId !== null;
  usePanelClickAway(panelOpen);
  const loadFiles = useScanStore((s) => s.loadFiles);
  const fileCount = useScanStore((s) => s.files.length);
  const loading = useScanStore((s) => s.loading);
  const failures = useScanStore((s) => s.failures);
  // the files being dragged over the window
  const [dragging, setDragging] = useState<string[] | null>(null);

  // lives here so files can be dropped on any page
  useEffect(() => {
    const promise = getCurrentWindow().onDragDropEvent((event) => {
      const p = event.payload;
      if (p.type === "enter") {
        setDragging(p.paths.length ? p.paths : null);
      } else if (p.type === "leave") {
        setDragging(null);
      } else if (p.type === "drop") {
        setDragging(null);
        const scans = p.paths.filter(isScanPath);
        if (scans.length < p.paths.length) {
          const skipped = p.paths.length - scans.length;
          useNotificationStore.getState().add(`${skipped === 1 ? "1 file was" : `${skipped} files were`} skipped: only .nessus files can be opened`, "warning");
        }
        loadFiles(scans);
      }
    });
    return () => { promise.then((unlisten) => unlisten()); };
  }, [loadFiles]);

  return (
    <div className="flex h-screen overflow-hidden bg-ink-50 dark:bg-ink-950">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-5">
          {/* the first file opening takes the page. later ones will be shown in the corner */}
          {fileCount === 0 && loading ? (
            <OpeningCard />
          ) : (
            <Suspense fallback={null}>
              <Outlet />
            </Suspense>
          )}
        </main>
      </div>

      {/* Global slide-in panels */}
      {/* only dims; clicks go through to the page (usePanelClickAway) */}
      {panelOpen && <div className="panel-overlay" aria-hidden="true" />}
      {vulnPanelId !== null && <VulnDetail pluginId={vulnPanelId} />}
      {hostPanelIp !== null && <HostDetail ip={hostPanelIp} />}
      {servicePanelKey !== null && <ServiceDetail serviceKey={servicePanelKey} />}
      {filePanelId !== null && <FileDetailPanel fileId={filePanelId} />}

      <div data-keeps-panel className="fixed bottom-4 right-4 z-[200] flex flex-col items-end gap-2 max-w-[calc(100vw-32px)] pointer-events-none">
        {failures.map((f) => <FailureCard key={f.id} failure={f} />)}
        {fileCount > 0 && <OpeningToast />}
        <Notifications />
      </div>

      {dragging && <DropOverlay paths={dragging} openCount={fileCount} />}
    </div>
  );
}// Layout
