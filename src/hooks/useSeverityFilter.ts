import { useCallback } from "react";
import { useSeverityStore } from "../stores/severityStore";
import { matchesSeverities, toggleSeverity } from "../utils/severityFilter";

const NONE: number[] = [];

export function useSeverityFilter(pageId: string, initial: readonly number[] = NONE) {
  const selected = useSeverityStore((s) => s.selections[pageId] ?? initial);
  const setSelection = useSeverityStore((s) => s.setSelection);

  const toggle = useCallback(
    (sev: number) => setSelection(pageId, toggleSeverity(useSeverityStore.getState().selections[pageId] ?? initial, sev)),
    [pageId, initial, setSelection]
  );
  const matches = useCallback((rowSeverities: readonly number[]) => matchesSeverities(rowSeverities, selected), [selected]);

  return { selected, toggle, matches };
}// useSeverityFilter
