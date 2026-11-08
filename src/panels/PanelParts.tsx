import { useEffect } from "react";
import type { ReactNode } from "react";
import CopyButton from "../components/common/CopyButton";

export function Section({ title, copy, actions, children }: { title: string; copy?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="pt-4 border-t border-ink-200 dark:border-ink-700 first:pt-0 first:border-t-0">
      <div className="flex items-center justify-between gap-2 mb-2">
        <h3 className="text-[15px] font-semibold text-ink-900 dark:text-ink-50">{title}</h3>
        {copy && <CopyButton text={copy} label={`Copy ${title.replace(/ \(\d+\)$/, "").toLowerCase()}`} variant="icon" />}
        {actions}
      </div>
      <div className="text-sm leading-relaxed text-ink-700 dark:text-ink-200">{children}</div>
    </section>
  );
}// Section

export function Tag({ danger = false, children }: { danger?: boolean; children: ReactNode }) {
  return (
    <span className={`px-1.5 py-px rounded text-[11px] font-semibold bg-ink-100 dark:bg-ink-700 ${danger ? "text-critical-fg" : "text-ink-700 dark:text-ink-200"}`}>
      {children}
    </span>
  );
}// Tag

export function useEscape(onEscape: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onEscape();
      }
    };
    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, [onEscape]);
}// useEscape
