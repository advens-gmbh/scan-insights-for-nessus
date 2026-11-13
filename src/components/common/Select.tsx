import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown } from "lucide-react";
import type { ScanFile } from "../../types/nessus";
import { fileWindow } from "../../utils/fileFacts";
import { formatScanStart } from "../../utils/format";
import { useFloatingList } from "../../hooks/useFloatingList";

export interface SelectOption {
  value: string;
  label: string;
  sub?: string;    // a second line, e.g. the scan name and date of a file
  group?: string;  // options with the same group are listed under one heading
}// SelectOption

interface Props {
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;       // shown while no option has the value
  size?: "xs" | "sm" | "md";  // panel, toolbar, Compare's pickers
  id?: string;
  ariaLabel?: string;
  title?: string;
  className?: string;
}// Props

const TRIGGER: Record<NonNullable<Props["size"]>, string> = {
  xs: "h-7 text-caption",
  sm: "h-8 text-caption",
  md: "h-9 text-body",
};

// a file as an option: its name, and the scan name and date below it
export function fileOption(f: ScanFile): SelectOption {
  const start = fileWindow(f).start;
  return { value: f.id, label: f.filename.replace(/\.nessus$/i, ""), sub: [f.report_name, start && formatScanStart(start)].filter(Boolean).join(" · ") };
}// fileOption

// the app's own dropdown: the list follows the theme, and arrows, Enter, Esc and typing work like a native one
export default function Select({ value, options, onChange, placeholder = "", size = "sm", id, ariaLabel, title, className = "" }: Props) {
  const { open, place, wrap, trigger, list, listId, show: showList, close } = useFloatingList(320);
  const [active, setActive] = useState(0);
  const typed = useRef({ text: "", at: 0 });
  const chosen = options.findIndex((o) => o.value === value);

  const show = () => {
    setActive(Math.max(chosen, 0));
    showList();
  };
  const pick = (i: number) => {
    const o = options[i];
    if (o) onChange(o.value);
    close();
  };

  // the list takes the keys while it's open
  useLayoutEffect(() => {
    if (open && place) list.current?.focus();
  }, [open, place, list]);

  useEffect(() => {
    if (open) document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [open, active, listId]);

  // typing jumps to the next option starting with the typed letters
  const typeAhead = (key: string, now: number) => {
    typed.current = { text: now - typed.current.at < 600 ? typed.current.text + key.toLowerCase() : key.toLowerCase(), at: now };
    const text = typed.current.text;
    const from = text.length === 1 ? active + 1 : active;
    for (let n = 0; n < options.length; n++) {
      const i = (from + n) % options.length;
      if (options[i].label.toLowerCase().startsWith(text)) return i;
    }
    return -1;
  };

  const onTriggerKey = (e: KeyboardEvent) => {
    if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
      e.preventDefault();
      show();
    }
  };

  const onListKey = (e: KeyboardEvent) => {
    const last = options.length - 1;
    const move = (i: number) => { e.preventDefault(); setActive(Math.min(Math.max(i, 0), last)); };
    switch (e.key) {
      case "ArrowDown": return move(active + 1);
      case "ArrowUp": return move(active - 1);
      case "Home": return move(0);
      case "End": return move(last);
      case "PageDown": return move(active + 8);
      case "PageUp": return move(active - 8);
      case "Enter":
      case " ":
        e.preventDefault();
        return pick(active);
      case "Escape":
        // only the list closes, not the panel it sits in
        e.preventDefault();
        e.stopPropagation();
        return close();
      case "Tab":
        return close(false);
    }
    if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const i = typeAhead(e.key, e.timeStamp);
      if (i >= 0) setActive(i);
    }
  };

  const current = options[chosen];
  return (
    <div ref={wrap} className={`relative min-w-0 ${className}`}>
      <button
        ref={trigger}
        id={id}
        type="button"
        onClick={() => (open ? close() : show())}
        onKeyDown={onTriggerKey}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-label={ariaLabel}
        title={title}
        className={`w-full flex items-center gap-2 pl-3 pr-2 rounded-lg border border-ink-200 dark:border-ink-600 bg-white dark:bg-ink-800 text-left font-medium hover:border-ink-300 dark:hover:border-ink-500 ${TRIGGER[size]} ${current ? "text-ink-800 dark:text-ink-100" : "text-ink-500 dark:text-ink-400"}`}
      >
        <span className="min-w-0 truncate">{current ? current.label : placeholder}</span>
        <ChevronDown size={14} className={`ml-auto shrink-0 text-ink-500 dark:text-ink-400 transition-transform ${open ? "rotate-180" : ""}`} aria-hidden="true" />
      </button>
      {open && place && createPortal(
        <div
          ref={list}
          id={listId}
          role="listbox"
          tabIndex={-1}
          aria-activedescendant={`${listId}-${active}`}
          onKeyDown={onListKey}
          data-keeps-panel
          style={place}
          className="z-[60] w-max max-w-[min(26rem,calc(100vw-2rem))] overflow-y-auto p-1.5 rounded-xl border border-ink-200 dark:border-ink-700 bg-white dark:bg-ink-800 shadow-xl focus:outline-none"
        >
          {options.map((o, i) => (
            <div key={o.value}>
              {o.group && o.group !== options[i - 1]?.group && (
                <div className={`px-2.5 pt-2 pb-1 text-caption font-semibold text-ink-500 dark:text-ink-400 ${i > 0 ? "mt-1 border-t border-ink-100 dark:border-ink-700" : ""}`}>{o.group}</div>
              )}
              <div
                id={`${listId}-${i}`}
                role="option"
                aria-selected={i === chosen}
                data-value={o.value}
                onMouseEnter={() => setActive(i)}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(i)}
                className={`flex items-center gap-2 pl-1.5 pr-3 py-1.5 rounded-lg cursor-pointer ${i === active ? "bg-ink-100 dark:bg-ink-700" : ""}`}
              >
                <span className="w-4 shrink-0 text-accent-700 dark:text-accent-400">{i === chosen && <Check size={14} strokeWidth={2.6} aria-hidden="true" />}</span>
                <span className="min-w-0">
                  <span className="block truncate text-body font-semibold text-ink-800 dark:text-ink-100">{o.label}</span>
                  {o.sub && <span className="block truncate text-caption text-ink-500 dark:text-ink-400">{o.sub}</span>}
                </span>
              </div>
            </div>
          ))}
        </div>,
        document.body,
      )}
    </div>
  );
}// Select
