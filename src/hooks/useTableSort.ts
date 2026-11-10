import { usePageState } from "../stores/pageStore";

export type SortDir = "asc" | "desc";

// falls back to the default sort while the sorted column is hidden
export function useTableSort<K extends string>(
  tableId: string,
  visible: { key: K }[],
  defaultKey: K,
  defaultDir: SortDir,
  ascendingFirst: K[],
) {
  const [chosen, setChosen] = usePageState<{ key: K; dir: SortDir }>(`sort:${tableId}`, { key: defaultKey, dir: defaultDir });
  const active = visible.some((c) => c.key === chosen.key) ? chosen : { key: defaultKey, dir: defaultDir };

  const toggleSort = (key: K) => {
    if (key === active.key) {
      setChosen({ key, dir: active.dir === "asc" ? "desc" : "asc" });
    } else {
      setChosen({ key, dir: ascendingFirst.includes(key) ? "asc" : "desc" });
    }
  };

  return { sortKey: active.key, sortDir: active.dir, toggleSort };
}// useTableSort
