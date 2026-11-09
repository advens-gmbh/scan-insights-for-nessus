import { X, AlertCircle, AlertTriangle, Info } from "lucide-react";
import { useNotificationStore } from "../../stores/notificationStore";

export default function Notifications() {
  const { notifications, remove } = useNotificationStore();

  if (notifications.length === 0) {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 z-[200] flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {notifications.map((n) => {
        const styles = {
          error:   "bg-red-50    dark:bg-red-950/90   border-red-200   dark:border-red-800   text-red-700   dark:text-red-300",
          warning: "bg-amber-50  dark:bg-amber-950/90 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300",
          info:    "bg-white     dark:bg-ink-800    border-ink-200 dark:border-ink-700 text-ink-700 dark:text-ink-200",
        }[n.type];
        const Icon = { error: AlertCircle, warning: AlertTriangle, info: Info }[n.type];
        return (
          <div
            key={n.id}
            className={`pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-xl shadow-xl border text-sm ${styles}`}
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
