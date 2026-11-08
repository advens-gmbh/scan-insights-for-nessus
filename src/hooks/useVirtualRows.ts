import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

// renders only the table rows near the viewport, so large scans stay responsive
export function useVirtualRows(count: number, estimatedRowHeight = 44) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => estimatedRowHeight,
    overscan: 12,
  });
  const rows = virtualizer.getVirtualItems();
  const paddingTop = rows.length > 0 ? rows[0].start : 0;
  const paddingBottom = rows.length > 0 ? virtualizer.getTotalSize() - rows[rows.length - 1].end : 0;
  
  return { scrollRef, rows, paddingTop, paddingBottom, measureRow: virtualizer.measureElement, scrollToIndex: virtualizer.scrollToIndex };
}// useVirtualRows
