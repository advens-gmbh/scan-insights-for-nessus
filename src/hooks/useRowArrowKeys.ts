import { useEffect, useLayoutEffect, useRef } from "react";

interface Rows {
  count: number;
  current: () => number;               // the row whose panel is open, -1 when it isn't in the table
  selectable?: (index: number) => boolean;  // rows the keys stop on (all of them when left out)
  go: (index: number) => void;         // opens that row's panel
  scrollToIndex: (index: number, options: { align: "auto" }) => void;
}// Rows

// while a row's panel is open, up and down open the previous and next row in the table's order
export function useRowArrowKeys(active: boolean, rows: Rows) {
  const latest = useRef(rows);
  useLayoutEffect(() => {
    latest.current = rows;
  });

  useEffect(() => {
    if (!active) {
      return;
    }

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") {
        return;
      }
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) {
        return;
      }

      const { count, current: find, selectable = () => true, go, scrollToIndex } = latest.current;
      const current = find();
      // from a row that isn't in the table, the first one is next
      const step = current === -1 ? 1 : e.key === "ArrowDown" ? 1 : -1;
      let next = current === -1 ? 0 : current + step;
      while (next >= 0 && next < count && !selectable(next)) {
        next += step;
      }
      if (next < 0 || next >= count) {
        return;
      }

      e.preventDefault();
      go(next);
      scrollToIndex(next, { align: "auto" });
    };
    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, [active]);
}// useRowArrowKeys
