import type { ReactNode } from "react";
import { useScanStore } from "../../stores/scanStore";
import type { TableColumnsApi } from "../../hooks/useTableColumns";
import ColumnPicker from "./ColumnPicker";
import SearchBar from "./SearchBar";
import Select, { fileOption } from "./Select";

interface Props<K extends string> {
  pills: ReactNode;
  search: { value: string; onChange: (v: string) => void; placeholder: string };
  file: { value: string; onChange: (id: string) => void; ariaLabel: string };
  table: TableColumnsApi<K>;
  tools?: ReactNode;  // the page's own, between Columns and the count
  count: string;
}// Props

// Line 1 holds the filter pills, line 2 search and file, with the table's tools on the right
export default function TableToolbar<K extends string>({ pills, search, file, table, tools, count }: Props<K>) {
  const files = useScanStore((s) => s.files);
  return (
    <div className="flex flex-col gap-3 shrink-0">
      <div className="flex flex-wrap items-center gap-3">{pills}</div>

      <div className="flex items-center gap-3">
        <SearchBar value={search.value} onChange={search.onChange} placeholder={search.placeholder} className="flex-[1_1_15rem] min-w-40" />
        {files.length > 1 && (
          <Select value={file.value} onChange={file.onChange} options={[{ value: "all", label: "All files" }, ...files.map(fileOption)]} ariaLabel={file.ariaLabel} className="flex-[0_1_15rem] min-w-[9.5rem]" />
        )}
        <div className="ml-auto flex items-center gap-3 shrink-0">
          <ColumnPicker table={table} />
          {tools}
          <span className="text-caption text-ink-500">{count}</span>
        </div>
      </div>
    </div>
  );
}// TableToolbar
