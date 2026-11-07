import { SEVERITY_LABELS, SEVERITY_ORDER } from "../../types/nessus";

interface Props {
  counts: Record<number, number>;
  selected: readonly number[];
  onToggle: (sev: number) => void;
}// Props

const COLORS: Record<number, { on: string; off: string }> = {
  4: { on: "bg-critical text-white", off: "bg-critical/10 text-critical" },
  3: { on: "bg-high text-white",     off: "bg-high/10 text-high" },
  2: { on: "bg-medium text-white",   off: "bg-medium/10 text-medium" },
  1: { on: "bg-low text-white",      off: "bg-low/10 text-low" },
  0: { on: "bg-info text-white",     off: "bg-info/10 text-info" },
};

// row filter: nothing selected shows everything, selected pills narrow it down
export default function SeverityPills({ counts, selected, onToggle }: Props) {
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
            className={`pill px-3 py-1 text-sm font-semibold cursor-pointer transition-colors ${active ? COLORS[sev].on : COLORS[sev].off}`}
          >
            {SEVERITY_LABELS[sev]} {count}
          </button>
        );
      })}
    </div>
  );
}// SeverityPills
