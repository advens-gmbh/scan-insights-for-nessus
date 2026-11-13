import type { ReactNode } from "react";
import type { TableColumnsApi } from "../../hooks/useTableColumns";
import type { SortDir } from "../../hooks/useTableSort";
import { useVirtualRows } from "../../hooks/useVirtualRows";
import { useRowArrowKeys } from "../../hooks/useRowArrowKeys";
import SpacerRow from "./SpacerRow";
import TableHead from "./TableHead";

interface Props<K extends string> {
  table: TableColumnsApi<K>;
  sort: { sortKey: K; sortDir: SortDir; toggleSort: (key: K) => void };
  count: number;
  row: (index: number, measure: (el: HTMLTableRowElement | null) => void) => ReactNode;
  empty: string | null;  // shown when there are no rows; null while they are still loading
  // while a row's panel is open, up and down open the previous and next row
  keys?: {
    open: boolean;
    current: () => number;  // the open row, -1 when it isn't in the table
    selectable?: (index: number) => boolean;
    go: (index: number) => void;
  };
}// Props

const NO_KEYS = { open: false, current: () => -1, go: () => {} };

export default function DataTable<K extends string>({ table, sort, count, row, empty, keys = NO_KEYS }: Props<K>) {
  const { scrollRef, rows, paddingTop, paddingBottom, measureRow, scrollToIndex } = useVirtualRows(count);
  useRowArrowKeys(keys.open, { count, current: keys.current, selectable: keys.selectable, go: keys.go, scrollToIndex });
  const columns = table.visible.length;

  return (
    <div className="card min-h-0 flex flex-col overflow-hidden">
      <div ref={scrollRef} className="overflow-auto flex-1 min-h-0">
        <table style={table.style}>
          <TableHead table={table} sortKey={sort.sortKey} sortDir={sort.sortDir} onSort={sort.toggleSort} />
          <tbody className="divide-y divide-ink-100 dark:divide-ink-700/50">
            <SpacerRow height={paddingTop} colSpan={columns} />
            {rows.map((r) => row(r.index, measureRow))}
            <SpacerRow height={paddingBottom} colSpan={columns} />
            {count === 0 && empty !== null && (
              <tr>
                <td colSpan={columns} className="table-cell text-center text-ink-500 py-10">{empty}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}// DataTable
