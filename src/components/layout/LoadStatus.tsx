import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertCircle, Check, ChevronDown, ChevronUp, FileText, X } from "lucide-react";
import { useScanStore, fileNameOf } from "../../stores/scanStore";
import type { LoadFailure, Opening } from "../../stores/scanStore";
import { folderOf, formatBytes } from "../../utils/format";
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

// seconds since the file started, ticking while it is read
function useElapsed(running: boolean) {
  const [started] = useState(() => Date.now());
  const [now, setNow] = useState(started);
  useEffect(() => {
    if (!running) {
      return;
    }
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, [running]);
  return (now - started) / 1000;
}// useElapsed

// the size of each waiting file
function useSizes(paths: string[]) {
  const [sizes, setSizes] = useState<Record<string, number | null>>({});
  useEffect(() => {
    if (paths.length === 0) {
      return;
    }
    let live = true;
    invoke<(number | null)[]>("file_sizes", { paths })
      .then((found) => live && Array.isArray(found) && setSizes((s) => ({ ...s, ...Object.fromEntries(paths.map((p, i) => [p, found[i] ?? null])) })))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [paths]);
  return sizes;
}// useSizes

const seconds = (s: number) => `${s < 10 ? s.toFixed(1) : Math.round(s)} s`;

function Bar({ value }: { value: number }) {
  return (
    <div className="h-2 rounded-full bg-ink-100 dark:bg-ink-700 overflow-hidden">
      <div className="h-full rounded-full bg-accent-600 transition-[width] duration-300 ease-out" style={{ width: `${value}%` }} />
    </div>
  );
}// Bar

type StepState = "done" | "now" | "later";

function Step({ state, title, text, right, children }: { state: StepState; title: string; text?: string; right?: string; children?: React.ReactNode }) {
  return (
    <li className="grid grid-cols-[24px_1fr_auto] gap-3 items-start">
      {state === "done" ? (
        <span className="w-6 h-6 rounded-full bg-accent-600 text-white flex items-center justify-center"><Check size={14} strokeWidth={3} /></span>
      ) : state === "now" ? (
        <span className="w-6 h-6 flex items-center justify-center"><Spinner size={22} /></span>
      ) : (
        <span className="w-6 h-6 rounded-full border-2 border-ink-300 dark:border-ink-600" />
      )}
      <div className="min-w-0">
        <div className={`text-body font-semibold ${state === "later" ? "text-ink-500 dark:text-ink-400" : "text-ink-800 dark:text-ink-100"}`}>{title}</div>
        {text && <div className="mt-0.5 text-caption text-ink-600 dark:text-ink-300">{text}</div>}
        {children}
      </div>
      <span className="text-caption tabular-nums text-ink-500 dark:text-ink-400 whitespace-nowrap">{right}</span>
    </li>
  );
}// Step

// the first file is displayed in the middle of the page, while nothing else is open
export function OpeningCard() {
  const opening = useScanStore((s) => s.opening);
  const queue = useScanStore((s) => s.queue);
  const batch = useScanStore((s) => s.batch);
  if (!opening) {
    return null;
  }
  return <OpeningCardBody key={opening.path} opening={opening} queue={queue} batch={batch} />;
}// OpeningCard

function OpeningCardBody({ opening: o, queue, batch }: { opening: Opening; queue: string[]; batch: { done: number; total: number } }) {
  const elapsed = useElapsed(true);
  const sizes = useSizes(queue);
  return (
    <div className="min-h-[70vh] flex items-center justify-center">
      <section role="status" aria-label="Opening a file" className="card w-[560px] max-w-full p-6 flex flex-col gap-5 shadow-sm">
        <div className="flex items-center gap-3">
          <span className="w-10 h-10 rounded-xl bg-accent-50 dark:bg-accent-900/30 text-accent-700 dark:text-accent-300 flex items-center justify-center shrink-0"><FileText size={20} /></span>
          <div className="min-w-0">
            <div className="text-caption font-semibold text-ink-500 dark:text-ink-400">{batch.total > 1 ? `Opening file ${batch.done + 1} of ${batch.total}` : "Opening"}</div>
            <div className="text-heading font-bold text-ink-900 dark:text-ink-50 truncate" title={o.path}>{o.filename}</div>
            <div className="text-caption text-ink-500 dark:text-ink-400 truncate">{[o.size !== null ? formatBytes(o.size) : null, folderOf(o.path)].filter(Boolean).join(" · ")}</div>
          </div>
        </div>
        <ol className="flex flex-col gap-4">
          <Step state="now" title="Reading the file" text={`${o.percent}%`} right={seconds(elapsed)}>
            <div className="mt-2"><Bar value={o.percent} /></div>
          </Step>
        </ol>
        {queue.length > 0 && (
          <div>
            <div className="text-caption font-semibold text-ink-500 dark:text-ink-400 mb-0.5">Next</div>
            <ul className="text-small text-ink-700 dark:text-ink-200">
              {queue.map((p) => (
                <li key={p} className="flex gap-3 py-1.5 border-t border-ink-100 dark:border-ink-700/50" title={p}>
                  <span className="min-w-0 truncate">{fileNameOf(p)}</span>
                  <span className="ml-auto shrink-0 text-caption tabular-nums text-ink-500 dark:text-ink-400">{typeof sizes[p] === "number" ? formatBytes(sizes[p]!) : ""}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </div>
  );
}// OpeningCardBody

// small card in the corner
export function OpeningToast() {
  const opening = useScanStore((s) => s.opening);
  const queue = useScanStore((s) => s.queue);
  const batch = useScanStore((s) => s.batch);
  const [hidden, setHidden] = useState(false);
  if (!opening) {
    return null;
  }
  return <OpeningToastBody key={opening.path} opening={opening} queue={queue} batch={batch} hidden={hidden} onHide={() => setHidden((h) => !h)} />;
}// OpeningToast

function OpeningToastBody({ opening: o, queue, batch, hidden, onHide }: { opening: Opening; queue: string[]; batch: { done: number; total: number }; hidden: boolean; onHide: () => void }) {
  const elapsed = useElapsed(true);
  const label = batch.total > 1 ? `Opening file ${batch.done + 1} of ${batch.total}` : "Opening";
  return (
    <section role="status" aria-label="Opening a file" className="card pointer-events-auto w-[380px] p-4 flex flex-col gap-2.5 shadow-xl">
      <div className="flex items-center gap-2.5">
        <Spinner />
        <div className="min-w-0 flex-1">
          <div className="text-caption font-semibold text-ink-500 dark:text-ink-400">{label}</div>
          <div className="text-body font-bold text-ink-900 dark:text-ink-50 truncate" title={o.path}>{o.filename}</div>
        </div>
        <button onClick={onHide} className="btn-ghost h-7 w-7 p-0 justify-center" aria-label={hidden ? "Show details" : "Hide details"} title={hidden ? "Show details" : "Hide details"}>
          {hidden ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </button>
      </div>
      {!hidden && (
        <>
          <div className="text-caption text-ink-600 dark:text-ink-300 tabular-nums">Reading the file: {o.percent}% · {seconds(elapsed)}</div>
          <Bar value={o.percent} />
          <div className="flex gap-3 text-caption text-ink-500 dark:text-ink-400">
            {queue.length > 0 && <span className="min-w-0 truncate">Next: {fileNameOf(queue[0])}{queue.length > 1 ? ` and ${queue.length - 1} more` : ""}</span>}
            <span className="ml-auto shrink-0">Keep working meanwhile</span>
          </div>
        </>
      )}
    </section>
  );
}// OpeningToastBody

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
