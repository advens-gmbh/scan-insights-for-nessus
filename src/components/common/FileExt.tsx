// shows a file extension on a code background
export default function FileExt({ ext = ".nessus" }: { ext?: string }) {
  return <code className="px-1 rounded bg-ink-100 dark:bg-ink-700 text-[0.92em] text-ink-800 dark:text-ink-100">{ext}</code>;
}// FileExt
