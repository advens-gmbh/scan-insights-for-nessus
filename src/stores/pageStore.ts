import { useCallback } from "react";
import { create } from "zustand";

// what a page was showing (search, filters, sort order), kept until the app closes
interface PageStore {
  values: Record<string, unknown>;
  set: (key: string, value: unknown) => void;
}// PageStore

export const usePageStore = create<PageStore>((set) => ({
  values: {},
  set: (key, value) => set((s) => ({ values: { ...s.values, [key]: value } })),
}));// usePageStore

// like useState, but the value survives switching pages
export function usePageState<T>(key: string, initial: T): [T, (next: T | ((prev: T) => T)) => void] {
  const stored = usePageStore((s) => s.values[key]) as T | undefined;
  const value = stored === undefined ? initial : stored;
  const setValue = useCallback((next: T | ((prev: T) => T)) => {
    const store = usePageStore.getState();
    const prev = key in store.values ? (store.values[key] as T) : initial;
    store.set(key, typeof next === "function" ? (next as (p: T) => T)(prev) : next);
  }, [key, initial]);

  return [value, setValue];
}// usePageState
