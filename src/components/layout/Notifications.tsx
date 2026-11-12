import { X, AlertCircle, AlertTriangle, Info } from "lucide-react";
import { useNotificationStore } from "../../stores/notificationStore";

export default function Notifications() {
  const { notifications, remove } = useNotificationStore();

  if (notifications.length === 0) {
    return null;
  }

  return (
    <div className="flex flex-col items-end gap-2 w-[380px] max-w-full">
      {notifications.map((n) => {
        const styles = {
          error:   "bg-bad-50    dark:bg-bad-950/90   border-bad-200   dark:border-bad-800   text-bad-700   dark:text-bad-300",
          warning: "bg-warn-50  dark:bg-warn-950/90 border-warn-200 dark:border-warn-800 text-warn-700 dark:text-warn-300",
          info:    "bg-white     dark:bg-ink-800    border-ink-200 dark:border-ink-700 text-ink-700 dark:text-ink-200",
        }[n.type];
        const Icon = { error: AlertCircle, warning: AlertTriangle, info: Info }[n.type];
        return (
          <div
            key={n.id}
            className={`pointer-events-auto w-full flex items-start gap-3 px-4 py-3 rounded-xl shadow-xl border text-body ${styles}`}
          >
            <Icon size={16} className="shrink-0 mt-0.5 opacity-80" />
            <span className="flex-1 min-w-0 leading-snug [overflow-wrap:anywhere]">{n.message}</span>
            <button
              onClick={() => remove(n.id)}
              className="shrink-0 opacity-50 hover:opacity-100 transition-opacity mt-0.5"
              aria-label="Dismiss"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}// Notifications
