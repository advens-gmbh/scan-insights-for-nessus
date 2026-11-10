import { useEffect, useRef, useState } from "react";
import { Check, RotateCcw, SlidersHorizontal } from "lucide-react";
import type { TableColumnsApi } from "../../hooks/useTableColumns";

const MENU_W = 176;

export default function ColumnPicker<K extends string>({ table }: { table: TableColumnsApi<K> }) {
  const [open, setOpen] = useState(false);
  // opens toward whichever side has room inside the page
  const [rightward, setRightward] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }

    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);

    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const page = e.currentTarget.closest("main")?.getBoundingClientRect();
          setRightward(r.right - MENU_W < (page?.left ?? 0) + 8);
          setOpen((v) => !v);
        }}
        title="Choose columns"
        className={`btn-ghost h-8 px-2.5 flex items-center gap-1.5 text-xs font-medium transition-colors ${
          open ? "bg-ink-100 dark:bg-ink-700 text-ink-700 dark:text-ink-200" : ""
        }`}
      >
        <SlidersHorizontal size={13} />
        Columns
      </button>
      {open && (
        <div className={`absolute ${rightward ? "left-0" : "right-0"} top-full mt-1 z-50 card p-1.5 w-44 shadow-xl max-h-[70vh] overflow-y-auto`}>
          {table.columns.map((col) => {
            const visible = table.isVisible(col.key);
            return (
              <button
                key={col.key}
                onClick={() => table.toggle(col.key)}
                disabled={col.required}
                className={`w-full flex items-center gap-2.5 px-2 py-1.5 rounded text-sm text-left transition-colors ${
                  col.required
                    ? "opacity-40 cursor-not-allowed"
                    : "hover:bg-ink-50 dark:hover:bg-ink-700/50 cursor-pointer"
                }`}
              >
                <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                  visible ? "bg-accent-500 border-accent-500" : "border-ink-300 dark:border-ink-600"
                }`}>
                  {visible && <Check size={10} className="text-white" strokeWidth={3} />}
                </div>
                <span className="text-ink-700 dark:text-ink-300">{col.label}</span>
              </button>
            );
          })}
          <div className="my-1 border-t border-ink-100 dark:border-ink-700" />
          <button
            onClick={table.resetAll}
            className="w-full flex items-center gap-2.5 px-2 py-1.5 rounded text-sm text-left text-ink-500 dark:text-ink-400 hover:bg-ink-50 dark:hover:bg-ink-700/50 transition-colors"
          >
            <RotateCcw size={13} className="shrink-0 mx-px" />
            Reset columns
          </button>
        </div>
      )}
    </div>
  );
}// ColumnPicker
