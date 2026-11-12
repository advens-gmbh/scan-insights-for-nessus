import { useEffect } from "react";
import type { ReactNode } from "react";
import { ArrowLeft, X, Zap } from "lucide-react";
import CopyButton from "../components/common/CopyButton";
import { useUiStore } from "../stores/uiStore";
import type { PanelEntry } from "../stores/uiStore";

const BACK_TO: Record<PanelEntry["kind"], (e: PanelEntry) => string> = {
  vuln: () => "Back to the finding",
  host: (e) => `Back to ${e.kind === "host" ? e.ip : "the host"}`,
  service: (e) => `Back to ${e.kind === "service" ? e.key : "the service"}`,
  file: () => "Back to the scan file",
};

export function PanelButtons({ onClose }: { onClose: () => void }) {
  const previous = useUiStore((s) => s.panelHistory[s.panelHistory.length - 1]);
  const goBack = useUiStore((s) => s.goBack);
  return (
    <div className="ml-auto flex items-center gap-1 shrink-0">
      {previous && (
        <button onClick={goBack} className="btn-ghost h-8 px-2 text-caption gap-1" title={BACK_TO[previous.kind](previous)} aria-label="Back">
          <ArrowLeft size={15} /> Back
        </button>
      )}
      <button onClick={onClose} className="btn-ghost w-8 h-8 p-0 justify-center" title="Close (Esc)" aria-label="Close">
        <X size={16} />
      </button>
    </div>
  );
}// PanelButtons

export function Section({ title, copy, actions, children }: { title: string; copy?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="pt-4 border-t border-ink-200 dark:border-ink-700 first:pt-0 first:border-t-0">
      <div className="flex items-center justify-between gap-2 mb-2">
        <h3 className="text-heading font-semibold text-ink-900 dark:text-ink-50">{title}</h3>
        {copy && <CopyButton text={copy} label={`Copy ${title.replace(/ \(\d+\)$/, "").toLowerCase()}`} variant="icon" />}
        {actions}
      </div>
      <div className="text-body leading-relaxed text-ink-700 dark:text-ink-200">{children}</div>
    </section>
  );
}// Section

export function Tag({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <span title={title} className="inline-flex items-center gap-1 px-1.5 py-px rounded text-tiny font-semibold bg-ink-100 dark:bg-ink-700 text-ink-700 dark:text-ink-200">
      {children}
    </span>
  );
}// Tag

export function ExploitTag({ children = "Exploit" }: { children?: ReactNode }) {
  return <Tag><Zap size={11} strokeWidth={2.6} aria-hidden="true" />{children}</Tag>;
}// ExploitTag

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
