import { useMemo, useRef } from "react";
import type { MouseEvent as ReactMouseEvent } from "react";
import { useTableStore } from "../stores/tableStore";
import {
  columnWidth,
  defaultLayout,
  dragColumn,
  resetColumnWidth,
  tableStyle,
  toggleColumn,
  visibleColumns,
} from "../utils/tableColumns";
import type { TableColumn } from "../utils/tableColumns";

export function useTableColumns<K extends string>(tableId: string, columns: TableColumn<K>[], showInfo = false) {
  const stored = useTableStore((s) => s.layouts[tableId]);
  const setLayout = useTableStore((s) => s.setLayout);
  const clearLayout = useTableStore((s) => s.clearLayout);
  const dragged = useRef(false);

  const layout = useMemo(() => stored ?? defaultLayout(columns), [stored, columns]);
  const visible = useMemo(() => visibleColumns(columns, layout, showInfo), [columns, layout, showInfo]);
  const pickable = useMemo(() => columns.filter((c) => !c.info), [columns]);
  const style = useMemo(() => tableStyle(visible, layout), [visible, layout]);

  const latestLayout = () => useTableStore.getState().layouts[tableId] ?? defaultLayout(columns);

  const startResize = (key: K, e: ReactMouseEvent) => {
    const cells = e.currentTarget.closest("tr")?.querySelectorAll("th");
    if (!cells) {
      return;
    }

    const rendered: Record<string, number> = {};
    visible.forEach((c, i) => { rendered[c.key] = cells[i].getBoundingClientRect().width; });
    const startX = e.clientX;

    const onMove = (ev: MouseEvent) => {
      if (ev.clientX === startX && !dragged.current) {
        return;
      }

      dragged.current = true;
      setLayout(tableId, dragColumn(latestLayout(), rendered, key, rendered[key] + ev.clientX - startX));
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      setTimeout(() => { dragged.current = false; }, 0);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  };

  return {
    columns: pickable,
    visible,
    style,
    isVisible: (key: K) => !layout.hidden.includes(key),
    widthOf: (column: TableColumn<K>) => columnWidth(column, layout),
    startResize,
    wasDragged: () => dragged.current,
    resetWidth: (key: K) => setLayout(tableId, resetColumnWidth(columns, latestLayout(), key)),
    toggle: (key: K) => setLayout(tableId, toggleColumn(columns, latestLayout(), key)),
    resetAll: () => clearLayout(tableId),
  };
}// useTableColumns

export type TableColumnsApi<K extends string> = ReturnType<typeof useTableColumns<K>>;
