import { PieChart, Pie, Tooltip, ResponsiveContainer } from "recharts";
import type { SeverityCounts } from "../../types/nessus";

const SLICES = [
  { key: "critical", label: "Critical", color: "#dc2626" },
  { key: "high",     label: "High",     color: "#f97316" },
  { key: "medium",   label: "Medium",   color: "#eab308" },
  { key: "low",      label: "Low",      color: "#22c55e" },
  { key: "info",     label: "Info",     color: "#3b82f6" },
] as const;

function DonutTooltip({ active, payload }: any) {
  if (!active || !payload?.length) {
    return null;
  }

  const entry = payload[0];
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg px-3 py-1.5 text-xs">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full shrink-0" style={{ background: entry.payload.color }} />
        <span className="text-slate-600 dark:text-slate-300">{entry.name}:</span>
        <strong className="text-slate-900 dark:text-white">{entry.value.toLocaleString()}</strong>
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

export default function SeverityDonut({ counts, size = 160, showLegend = false, emptyText = "No data" }: Props) {
  const data = SLICES.map((s) => ({ ...s, fill: s.color, value: counts[s.key] })).filter((s) => s.value > 0);
  const total = data.reduce((s, d) => s + d.value, 0);

  if (total === 0) {
    return (
      <div className="flex items-center justify-center text-center text-slate-400 text-xs" style={{ width: size, height: size }}>
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
            <span className="font-bold text-slate-800 dark:text-slate-100" style={{ fontSize: Math.max(12, size * 0.14) }}>
              {total.toLocaleString()}
            </span>
            <span className="text-slate-500 dark:text-slate-400" style={{ fontSize: Math.max(10, size * 0.10) }}>findings</span>
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
                <span className="text-slate-600 dark:text-slate-400 w-14">{s.label}</span>
                <span className="font-semibold" style={{ color: s.color }}>{v.toLocaleString()}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}// SeverityDonut
