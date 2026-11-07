import { create } from "zustand";

interface SeverityStore {
  selections: Record<string, number[]>;
  setSelection: (pageId: string, selected: number[]) => void;
}// SeverityStore

export const useSeverityStore = create<SeverityStore>((set) => ({
  selections: {},
  setSelection: (pageId, selected) => set((s) => ({ selections: { ...s.selections, [pageId]: selected } })),
}));// useSeverityStore
