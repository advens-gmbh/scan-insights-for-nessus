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
    <div className={`flex rounded-sm overflow-hidden bg-ink-100 dark:bg-ink-700 text-tiny font-bold tabular-nums ${className}`}>
      {SEGMENTS.map((s) => {
        const value = max > 0 ? counts[s.key] : 0;
        const share = max > 0 ? value / max : 0;
        const label = value.toLocaleString();
        const minWidth = value === 0 ? "0px" : numbers ? `${label.length * 0.45 + 0.6}rem` : "3px";
        return (
          <div
            key={s.key}
            className={`flex items-center justify-center overflow-hidden transition-[flex-basis,min-width] duration-500 ease-out ${s.fill}`}
            style={{ flexGrow: 0, flexShrink: 1, flexBasis: `${share * 100}%`, minWidth }}
            title={value > 0 ? `${s.label}: ${label}` : undefined}
          >
            {numbers && value > 0 && label}
          </div>
        );
      })}
    </div>
  );
}// SeverityBar
