import { SEVERITY_LABELS, SEVERITY_ORDER } from "../../types/nessus";

interface Props {
  counts: Record<number, number>;
  selected: readonly number[];
  onToggle: (sev: number) => void;
  // given on pages where nothing selected shows everything: then every pill is filled, and "Show all" resets a pick
  onClear?: () => void;
}// Props

const FILLED: Record<number, string> = {
  4: "bg-critical text-critical-on",
  3: "bg-high text-high-on",
  2: "bg-medium text-medium-on",
  1: "bg-low text-low-on",
  0: "bg-info text-info-on",
};

const FADED = "bg-transparent text-ink-500 dark:text-ink-400 ring-1 ring-inset ring-ink-200 dark:ring-ink-600 hover:text-ink-800 dark:hover:text-ink-100";

// filled pills are the levels shown
export default function SeverityPills({ counts, selected, onToggle, onClear }: Props) {
  const all = onClear !== undefined && selected.length === 0;
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {SEVERITY_ORDER.map((sev) => {
        const count = counts[sev] ?? 0;
        const active = selected.includes(sev);
        // a selected pill stays visible so it can still be switched off
        if (count === 0 && !active) {
          return null;
        }

        return (
          <button
            key={sev}
            onClick={() => onToggle(sev)}
            aria-pressed={active}
            title={all ? `Show only ${SEVERITY_LABELS[sev]}` : undefined}
            className={`pill px-3 py-1 text-body font-semibold cursor-pointer transition-colors ${all || active ? FILLED[sev] : FADED}`}
          >
            {SEVERITY_LABELS[sev]} {count.toLocaleString()}
          </button>
        );
      })}
      {onClear && selected.length > 0 && (
        <button onClick={onClear} className="px-1.5 py-1 text-body font-semibold text-accent-700 dark:text-accent-400 hover:underline">
          Show all
        </button>
      )}
    </div>
  );
}// SeverityPills
