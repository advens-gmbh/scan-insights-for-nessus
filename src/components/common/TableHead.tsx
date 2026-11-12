import { ChevronDown, ChevronUp } from "lucide-react";
import type { TableColumnsApi } from "../../hooks/useTableColumns";
import type { SortDir } from "../../hooks/useTableSort";

interface Props<K extends string> {
  table: TableColumnsApi<K>;
  sortKey: K;
  sortDir: SortDir;
  onSort: (key: K) => void;
}// Props

const DARK_HEADER = "dark:bg-[color-mix(in_srgb,theme(colors.ink.900)_50%,theme(colors.ink.800))]";
const DARK_ACTIVE = "dark:bg-[color-mix(in_srgb,theme(colors.accent.900)_20%,theme(colors.ink.800))]";

// column widths and sortable, resizable header of a table
export default function TableHead<K extends string>({ table, sortKey, sortDir, onSort }: Props<K>) {
  return (
    <>
      <colgroup>
        {table.visible.map((col) => <col key={col.key} style={{ width: table.widthOf(col) }} />)}
      </colgroup>
      <thead className="sticky top-0 z-10">
        <tr>
          {table.visible.map((col) => {
            const sortable = col.sortable !== false;
            const active = sortable && col.key === sortKey;
            const centered = col.align === "center";
            return (
              <th
                key={col.key}
                className={`relative px-4 py-3 text-small select-none transition-colors overflow-hidden ${sortable ? "cursor-pointer" : ""} ${
                  centered ? "text-center" : "text-left"
                } ${
                  active
                    ? `bg-accent-50 ${DARK_ACTIVE} text-accent-700 dark:text-accent-300 font-bold`
                    : `bg-ink-50 ${DARK_HEADER} text-ink-500 dark:text-ink-400 font-semibold hover:text-ink-700 dark:hover:text-ink-200`
                }`}
                onClick={() => {
                  if (sortable && !table.wasDragged()) {
                    onSort(col.key);
                  }
                }}
              >
                <span className={`flex items-center gap-1 whitespace-nowrap ${centered ? "justify-center" : ""}`}>
                  {col.dot && <span className={`w-2 h-2 rounded-full shrink-0 ${col.dot}`} aria-hidden="true" />}
                  {col.label}
                  {sortable && (active
                    ? (sortDir === "desc" ? <ChevronDown size={12} /> : <ChevronUp size={12} />)
                    : <ChevronDown size={12} className="opacity-30" />)}
                </span>
                <div
                  className="absolute right-0 top-0 bottom-0 w-3 flex items-center justify-center cursor-col-resize group z-10"
                  title="Drag to resize, double-click to reset"
                  onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); table.startResize(col.key, e); }}
                  onClick={(e) => e.stopPropagation()}
                  onDoubleClick={(e) => { e.stopPropagation(); table.resetWidth(col.key); }}
                >
                  <div className="w-px h-4 rounded-full bg-ink-300 dark:bg-ink-600 group-hover:bg-accent-500 group-hover:w-0.5 transition-all" />
                </div>
              </th>
            );
          })}
        </tr>
      </thead>
    </>
  );
}// TableHead
