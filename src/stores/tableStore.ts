import { create } from "zustand";
import type { TableLayout } from "../utils/tableColumns";

interface TableStore {
  layouts: Record<string, TableLayout>;
  setLayout: (tableId: string, layout: TableLayout) => void;
  clearLayout: (tableId: string) => void;
}// TableStore

export const useTableStore = create<TableStore>((set) => ({
  layouts: {},
  setLayout: (tableId, layout) => set((s) => ({ layouts: { ...s.layouts, [tableId]: layout } })),
  clearLayout: (tableId) =>
    set((s) => {
      const layouts = { ...s.layouts };
      delete layouts[tableId];
      return { layouts };
    }),
}));// useTableStore
