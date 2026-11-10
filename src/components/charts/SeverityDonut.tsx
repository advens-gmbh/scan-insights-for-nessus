import { memo } from "react";
import { PieChart, Pie, Tooltip, ResponsiveContainer } from "recharts";
import type { SeverityCounts } from "../../types/nessus";
import { severity } from "../../theme/colors";

const SLICES = [
  { key: "critical", label: "Critical", color: severity.critical.fill },
  { key: "high",     label: "High",     color: severity.high.fill },
  { key: "medium",   label: "Medium",   color: severity.medium.fill },
  { key: "low",      label: "Low",      color: severity.low.fill },
  { key: "info",     label: "Info",     color: severity.info.fill },
] as const;

function DonutTooltip({ active, payload }: any) {
  if (!active || !payload?.length) {
    return null;
  }

  const entry = payload[0];
  return (
    <div className="bg-white dark:bg-ink-800 border border-ink-200 dark:border-ink-700 rounded-lg shadow-lg px-3 py-1.5 text-xs">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full shrink-0" style={{ background: entry.payload.color }} />
        <span className="text-ink-600 dark:text-ink-300">{entry.name}:</span>
        <strong className="text-ink-900 dark:text-white">{entry.value.toLocaleString()}</strong>
      </div>
    </div>
  );
}// DonutTooltip

interface Props {
  counts: SeverityCounts;
  size?: number;
  showLegend?: boolean;
  emptyText?: string;
}// Props

function SeverityDonut({ counts, size = 160, showLegend = false, emptyText = "No data" }: Props) {
  const data = SLICES.map((s) => ({ ...s, fill: s.color, value: counts[s.key] })).filter((s) => s.value > 0);
  const total = data.reduce((s, d) => s + d.value, 0);

  if (total === 0) {
    return (
      <div className="flex items-center justify-center text-center text-ink-400 text-xs" style={{ width: size, height: size }}>
        {emptyText}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-4">
      <div style={{ width: size, height: size }} className="relative shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius="60%"
              outerRadius="85%"
              dataKey="value"
              nameKey="label"
              strokeWidth={2}
              stroke="transparent"
              animationBegin={0}
              animationDuration={800}
            />
            <Tooltip
              content={<DonutTooltip />}
              allowEscapeViewBox={{ x: true, y: true }}
              wrapperStyle={{ zIndex: 50 }}
            />
          </PieChart>
        </ResponsiveContainer>
        {size >= 80 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="font-bold text-ink-800 dark:text-ink-100" style={{ fontSize: Math.max(12, Math.min(size * 0.14, (size * 0.51 * 0.92) / (total.toLocaleString().length * 0.62))) }}>
              {total.toLocaleString()}
            </span>
            <span className="text-ink-500 dark:text-ink-400" style={{ fontSize: Math.max(10, size * 0.10) }}>findings</span>
          </div>
        )}
      </div>

      {showLegend && (
        <div className="flex flex-col gap-1.5">
          {SLICES.map((s) => {
            const v = counts[s.key];
            if (v === 0) return null;
            return (
              <div key={s.key} className="flex items-center gap-2 text-xs">
                <div className="w-[13px] h-[13px] rounded-full shrink-0" style={{ background: s.color }} />
                <span className="text-ink-600 dark:text-ink-400 w-14">{s.label}</span>
                <span className="font-semibold" style={{ color: s.color }}>{v.toLocaleString()}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}// SeverityDonut

// recharts restarts the animation on every render, so only re-render when something shown changes
const sameCounts = (a: SeverityCounts, b: SeverityCounts) =>
  a.critical === b.critical && a.high === b.high && a.medium === b.medium && a.low === b.low && a.info === b.info;

export default memo(SeverityDonut, (prev, next) =>
  sameCounts(prev.counts, next.counts) && prev.size === next.size && prev.showLegend === next.showLegend && prev.emptyText === next.emptyText
);
