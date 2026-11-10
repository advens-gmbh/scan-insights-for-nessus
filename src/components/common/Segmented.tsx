export default function Segmented<T extends string>({ label, value, onChange, options }: {
  label: string;
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string; count?: number }[];
}) {
  return (
    <div className="inline-flex rounded-md border border-ink-200 dark:border-ink-700 overflow-hidden" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
          className={`px-3 h-8 text-[13px] border-l first:border-l-0 border-ink-200 dark:border-ink-700 ${
            value === o.value
              ? "bg-accent-600 text-white font-semibold"
              : "bg-white dark:bg-ink-800 text-ink-600 dark:text-ink-300 hover:bg-ink-50 dark:hover:bg-ink-700"
          }`}
        >
          {o.label}
          {o.count !== undefined && <span className="ml-1.5 tabular-nums opacity-80">{o.count.toLocaleString()}</span>}
        </button>
      ))}
    </div>
  );
}// Segmented
