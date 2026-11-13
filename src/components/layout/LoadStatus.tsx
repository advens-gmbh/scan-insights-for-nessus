import { useState } from "react";
import { AlertCircle, ChevronDown, ChevronUp, FileText, X } from "lucide-react";
import { useScanStore, fileNameOf } from "../../stores/scanStore";
import type { LoadFailure, Opening } from "../../stores/scanStore";
import { formatBytes } from "../../utils/format";
import CopyButton from "../common/CopyButton";

export function Spinner({ size = 18 }: { size?: number }) {
  return (
    <span
      aria-hidden="true"
      className="inline-block shrink-0 rounded-full border-[3px] border-accent-200 border-t-accent-600 dark:border-accent-900 dark:border-t-accent-400 animate-spin"
      style={{ width: size, height: size }}
    />
  );
}// Spinner

type Batch = { done: number; total: number };

// one file being read (name, size and how far it has got)
function ReadingRow({ o, big }: { o: Opening; big: boolean }) {
  return (
    <li className={`flex flex-col gap-1.5 border-t border-ink-100 dark:border-ink-700/50 ${big ? "py-2.5" : "py-2"}`} title={o.path}>
      <div className="flex items-baseline gap-3 min-w-0">
        <span className={`min-w-0 truncate font-semibold text-ink-800 dark:text-ink-100 ${big ? "text-body" : "text-small"}`}>{o.filename.replace(/\.nessus$/i, "")}</span>
        <span className="ml-auto shrink-0 text-caption tabular-nums text-ink-500 dark:text-ink-400">{o.size !== null ? `${formatBytes(o.size)} · ` : ""}{o.percent}%</span>
      </div>
      <div className="h-1.5 rounded-full bg-ink-100 dark:bg-ink-700 overflow-hidden">
        <div className="h-full rounded-full bg-accent-600 transition-[width] duration-300 ease-out" style={{ width: `${o.percent}%` }} />
      </div>
    </li>
  );
}// ReadingRow

function Title({ batch, big }: { batch: Batch; big: boolean }) {
  return (
    <div className="min-w-0 flex-1">
      <div className={`font-bold text-ink-900 dark:text-ink-50 ${big ? "text-heading" : "text-body"}`}>{batch.total > 1 ? `Opening ${batch.total} files` : "Opening"}</div>
      {batch.total > 1 && <div className="text-caption tabular-nums text-ink-500 dark:text-ink-400">{batch.done} done</div>}
    </div>
  );
}// Title

function Next({ queue }: { queue: string[] }) {
  return queue.length > 0 ? (
    <div className="text-caption text-ink-500 dark:text-ink-400 truncate" title={queue.map(fileNameOf).join("\n")}>
      Next: {fileNameOf(queue[0]).replace(/\.nessus$/i, "")}{queue.length > 1 ? ` and ${queue.length - 1} more` : ""}
    </div>
  ) : null;
}// Next

// shown in the middle of the page while nothing is open yet
export function OpeningCard() {
  const reading = useScanStore((s) => s.reading);
  const queue = useScanStore((s) => s.queue);
  const batch = useScanStore((s) => s.batch);
  if (reading.length === 0) {
    return null;
  }
  return (
    <div className="min-h-[70vh] flex items-center justify-center">
      <section role="status" aria-label="Opening a file" className="card w-[560px] max-w-full p-6 flex flex-col gap-4 shadow-sm">
        <div className="flex items-center gap-3">
          <span className="w-10 h-10 rounded-xl bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300 flex items-center justify-center shrink-0"><FileText size={20} /></span>
          <Title batch={batch} big />
        </div>
        <ul>
          {reading.map((o) => <ReadingRow key={o.path} o={o} big />)}
        </ul>
        <Next queue={queue} />
      </section>
    </div>
  );
}// OpeningCard

// the same in the corner while other files are open, and it can be folded away
export function OpeningToast() {
  const reading = useScanStore((s) => s.reading);
  const queue = useScanStore((s) => s.queue);
  const batch = useScanStore((s) => s.batch);
  const [hidden, setHidden] = useState(false);
  if (reading.length === 0) {
    return null;
  }
  return (
    <section role="status" aria-label="Opening a file" className="card pointer-events-auto w-[380px] p-4 flex flex-col gap-2.5 shadow-xl">
      <div className="flex items-center gap-2.5">
        <Spinner />
        <Title batch={batch} big={false} />
        <button onClick={() => setHidden((h) => !h)} className="btn-ghost h-7 w-7 p-0 justify-center" aria-label={hidden ? "Show details" : "Hide details"} title={hidden ? "Show details" : "Hide details"}>
          {hidden ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </button>
      </div>
      {!hidden && (
        <>
          <ul>
            {reading.map((o) => <ReadingRow key={o.path} o={o} big={false} />)}
          </ul>
          <Next queue={queue} />
        </>
      )}
    </section>
  );
}// OpeningToast

// what went wrong, in plain words, and what to do about it
export function explainFailure(f: Pick<LoadFailure, "kind" | "message">): string {
  switch (f.kind) {
    case "missing":
      return "The file isn't there any more: it was moved, renamed or deleted.";
    case "unreadable":
      return "The file couldn't be read. Another program may be using it, or you may not have permission to open it.";
    case "not_nessus":
      return /<html>/i.test(f.message)
        ? "This isn't a Nessus scan export: it looks like an HTML report saved with a .nessus name. In Nessus, export the scan with the format Nessus."
        : "This isn't a Nessus scan export. In Nessus, export the scan with the format Nessus.";
    case "old_format":
      return "This is the old .nessus v1 format. Export the scan again from a current Nessus, which writes the newer format.";
    case "truncated":
      return "The file is cut off: it ends in the middle of the scan data, so it was probably not copied or downloaded completely. Copy it again, then try once more.";
    case "damaged":
      return "Part of the file isn't valid, so it may be damaged. Export or copy it again, then try once more.";
    case "no_hosts":
      return "It holds a scan policy, but no scanned hosts. Export the finished scan instead: in Nessus, open the scan's results and use Export › Nessus.";
    default:
      return f.message;
  }
}// explainFailure

export function FailureCard({ failure: f }: { failure: LoadFailure }) {
  const retry = useScanStore((s) => s.retry);
  const dismiss = useScanStore((s) => s.dismissFailure);
  const forgetRecent = useScanStore((s) => s.forgetRecent);
  const inRecent = useScanStore((s) => s.recentFiles.some((r) => r.path === f.path));
  const [details, setDetails] = useState(false);
  const explained = explainFailure(f);
  return (
    <section role="alert" className="card pointer-events-auto w-[420px] p-4 flex flex-col gap-2 shadow-xl border-critical/40">
      <div className="flex items-start gap-2.5">
        <span className="w-7 h-7 rounded-lg bg-critical/10 text-critical-fg flex items-center justify-center shrink-0"><AlertCircle size={16} /></span>
        <div className="min-w-0 flex-1 text-body font-bold leading-[19px] text-ink-900 dark:text-ink-50">
          Couldn't open <span className="text-critical-fg [overflow-wrap:anywhere]" title={f.path}>{f.filename}</span>
        </div>
        <button onClick={() => dismiss(f.id)} className="btn-ghost h-7 w-7 p-0 justify-center shrink-0" aria-label="Dismiss" title="Dismiss"><X size={15} /></button>
      </div>
      <p className="text-small leading-[19px] text-ink-700 dark:text-ink-200">{explained}</p>
      {details && (
        <div className="font-mono text-tiny leading-[17px] text-ink-700 dark:text-ink-200 bg-ink-50 dark:bg-ink-900 border border-ink-100 dark:border-ink-700 rounded-lg px-2.5 py-2 [overflow-wrap:anywhere] select-text">
          {f.path}
          <br />
          {f.message}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {f.kind === "missing" && inRecent ? (
          <button onClick={() => { forgetRecent(f.path); dismiss(f.id); }} className="btn-secondary h-8 text-small">Remove from recent files</button>
        ) : (
          <button onClick={() => retry(f.id)} className="btn-secondary h-8 text-small">Try again</button>
        )}
        {details && <CopyButton text={`${f.path}\n${f.message}`} label="Copy details" />}
        {explained !== f.message && (
          <button onClick={() => setDetails((d) => !d)} className="btn-ghost h-8 text-small ml-auto">{details ? "Hide details" : "Show details"}</button>
        )}
      </div>
    </section>
  );
}// FailureCard
