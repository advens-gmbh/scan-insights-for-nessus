import { useLayoutEffect } from "react";
import type { KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { ChevronDown } from "lucide-react";
import type { ScanFile } from "../../types/nessus";
import { fileOption } from "./Select";
import { useFloatingList } from "../../hooks/useFloatingList";

interface Props {
  files: ScanFile[];
  picked: string[];                   // the ids shown; all of them means "All files", none is allowed
  onChange: (ids: string[]) => void;
  ariaLabel: string;
  className?: string;
}// Props

// like Select, but with a tick box per file, to check/uncheck several files
export default function FileChecklist({ files, picked, onChange, ariaLabel, className = "" }: Props) {
  const { open, place, wrap, trigger, list, listId, show, close } = useFloatingList(360);
  const all = picked.length === files.length;
  const label = all ? "All files" : picked.length === 0 ? "No files" : `${picked.length} of ${files.length} files`;

  useLayoutEffect(() => {
    if (open && place) list.current?.querySelector("input")?.focus();
  }, [open, place, list]);

  const toggle = (id: string) =>
    onChange(picked.includes(id) ? picked.filter((p) => p !== id) : files.map((f) => f.id).filter((f) => f === id || picked.includes(f)));

  const onListKey = (e: KeyboardEvent) => {
    const boxes = [...(list.current?.querySelectorAll("input") ?? [])];
    const at = boxes.indexOf(document.activeElement as HTMLInputElement);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      boxes[Math.min(Math.max(at + (e.key === "ArrowDown" ? 1 : -1), 0), boxes.length - 1)]?.focus();
    } else if (e.key === "Escape") {
      // only the list closes, not the panel it sits in
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key === "Tab") {
      close(false);
    }
  };

  const row = "flex items-center gap-2.5 pl-2 pr-3 py-1.5 rounded-lg cursor-pointer hover:bg-ink-100 dark:hover:bg-ink-700 focus-within:bg-ink-100 dark:focus-within:bg-ink-700";
  return (
    <div ref={wrap} className={`relative min-w-0 ${className}`}>
      <button
        ref={trigger}
        type="button"
        onClick={() => (open ? close() : show())}
        onKeyDown={(e) => {
          if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
            e.preventDefault();
            show();
          }
        }}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-label={ariaLabel}
        className="w-full h-8 flex items-center gap-2 pl-3 pr-2 rounded-lg border border-ink-200 dark:border-ink-600 bg-white dark:bg-ink-800 text-left text-caption font-medium text-ink-800 dark:text-ink-100 hover:border-ink-300 dark:hover:border-ink-500"
      >
        <span className="min-w-0 truncate">{label}</span>
        <ChevronDown size={14} className={`ml-auto shrink-0 text-ink-500 dark:text-ink-400 transition-transform ${open ? "rotate-180" : ""}`} aria-hidden="true" />
      </button>
      {open && place && createPortal(
        <div
          ref={list}
          id={listId}
          role="dialog"
          aria-label={ariaLabel}
          onKeyDown={onListKey}
          data-keeps-panel
          style={place}
          className="z-[60] w-max max-w-[min(26rem,calc(100vw-2rem))] overflow-y-auto p-1.5 rounded-xl border border-ink-200 dark:border-ink-700 bg-white dark:bg-ink-800 shadow-xl"
        >
          <label className={row}>
            <input type="checkbox" checked={all} onChange={() => onChange(all ? [] : files.map((f) => f.id))} className="w-[15px] h-[15px] rounded accent-accent-600" />
            <span className="text-body font-semibold text-ink-800 dark:text-ink-100">All files</span>
          </label>
          <div className="my-1 border-t border-ink-100 dark:border-ink-700" />
          {files.map((f) => {
            const o = fileOption(f);
            return (
              <label key={f.id} className={row} title={f.path}>
                <input type="checkbox" checked={picked.includes(f.id)} onChange={() => toggle(f.id)} className="w-[15px] h-[15px] rounded accent-accent-600" />
                <span className="min-w-0">
                  <span className="block truncate text-body font-semibold text-ink-800 dark:text-ink-100">{o.label}</span>
                  {o.sub && <span className="block truncate text-caption text-ink-500 dark:text-ink-400">{o.sub}</span>}
                </span>
              </label>
            );
          })}
        </div>,
        document.body,
      )}
    </div>
  );
}// FileChecklist
