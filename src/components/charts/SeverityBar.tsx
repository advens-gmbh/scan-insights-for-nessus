import type { SeverityCounts } from "../../types/nessus";

const SEGMENTS = [
  { key: "critical", label: "Critical", fill: "bg-critical text-critical-on" },
  { key: "high",     label: "High",     fill: "bg-high text-high-on" },
  { key: "medium",   label: "Medium",   fill: "bg-medium text-medium-on" },
  { key: "low",      label: "Low",      fill: "bg-low text-low-on" },
  { key: "info",     label: "Info",     fill: "bg-info text-info-on" },
] as const;

interface Props {
  counts: SeverityCounts;
  max: number;          // the total that fills the whole track, so bars in one list compare
  numbers?: boolean;    // counts inside segments wide enough to hold them
  className?: string;
}// Props

export default function SeverityBar({ counts, max, numbers = true, className = "h-5" }: Props) {
  return (
    <div className={`flex rounded-sm overflow-hidden bg-ink-100 dark:bg-ink-700 text-[11px] font-bold tabular-nums ${className}`}>
      {max > 0 && SEGMENTS.map((s) => {
        const value = counts[s.key];
        if (value === 0) {
          return null;
        }

        const share = value / max;
        const label = value.toLocaleString();
        const minWidth = numbers ? `${label.length * 0.45 + 0.6}rem` : "3px";
        return (
          <div
            key={s.key}
            className={`flex items-center justify-center ${s.fill}`}
            style={{ flex: `0 1 ${share * 100}%`, minWidth }}
            title={`${s.label}: ${label}`}
          >
            {numbers && label}
          </div>
        );
      })}
    </div>
  );
}// SeverityBar
