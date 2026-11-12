import { useEffect } from "react";
import { useUiStore } from "../../stores/uiStore";

// what is shown in the panels, to tell whether a click changed it
function shown(s: ReturnType<typeof useUiStore.getState>) {
  return [s.vulnPanelId, s.vulnPanelFileId, s.hostPanelIp, s.hostPanelFileId, s.servicePanelKey, s.servicePanelFileId, s.filePanelId].join("|");
}// shown

// while a panel is open, the page behind it stays usable
export function usePanelClickAway(panelOpen: boolean) {
  useEffect(() => {
    if (!panelOpen) {
      return;
    }
    let down: { x: number; y: number; inside: boolean } | null = null;

    const onDown = (e: PointerEvent) => {
      const target = e.target instanceof Element ? e.target : null;
      down = { x: e.clientX, y: e.clientY, inside: !!target?.closest(".panel-drawer, [data-keeps-panel]") };
    };
    const onClick = (e: MouseEvent) => {
      const start = down;
      down = null;
      if (!start || start.inside || Math.hypot(e.clientX - start.x, e.clientY - start.y) > 5) {
        return;
      }
      const before = shown(useUiStore.getState());
      setTimeout(() => {
        const s = useUiStore.getState();
        if (shown(s) === before) {
          s.closePanels();
        } else {
          useUiStore.setState({ panelHistory: [] });
        }
      }, 0);
    };

    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("click", onClick, true);

    return () => {
      document.removeEventListener("pointerdown", onDown, true);
      document.removeEventListener("click", onClick, true);
    };
  }, [panelOpen]);
}// usePanelClickAway
