import { useMemo } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,} from "recharts";

export interface TrendPoint {
  label: string;
  date: string;
  filename: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}// TrendPoint

const LINE_COLORS: Record<string, string> = {
  Total: "#a78bfa",
  Critical: "#dc2626",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Info: "#3b82f6",
};// LINE_COLORS

function TrendTooltip({ active, payload, coordinate, viewBox }: any) {
  if (!active || !payload?.length) {
    return null;
  }

  const d = payload[0].payload as TrendPoint;
  const flipLeft = coordinate && viewBox && coordinate.x > viewBox.width * 0.55;
  const sevRows = payload.filter((p: any) => p.name !== "Total");
  const hasTotal = payload.some((p: any) => p.name === "Total");
  const visibleTotal = sevRows.reduce((sum: number, p: any) => sum + (p.value ?? 0), 0);

  return (
    <div
      className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg px-3 py-2 text-xs"
      style={{ transform: flipLeft ? "translateX(-110%)" : undefined }}
    >
      <p className="font-semibold text-slate-700 dark:text-slate-200 truncate">{d.filename}</p>
      <p className="text-slate-400 text-[10px] mb-1.5">{d.date}</p>
      {sevRows.map((p: any) => (
        <div key={p.name} className="flex items-center gap-2 py-0.5">
          <div className="w-2 h-2 rounded-full shrink-0" style={{ background: LINE_COLORS[p.name] ?? p.stroke }} />
          <span className="text-slate-500 dark:text-slate-400 w-14">{p.name}:</span>
          <strong className="text-slate-800 dark:text-slate-100">{p.value}</strong>
        </div>
      ))}
      {hasTotal && (
        <div className="border-t border-slate-100 dark:border-slate-700 mt-1.5 pt-1.5 flex items-center gap-2">
          <div className="w-2 h-2 rounded-full shrink-0" style={{ background: LINE_COLORS["Total"] }} />
          <span className="text-slate-500 dark:text-slate-400 w-14">Total:</span>
          <strong className="text-slate-800 dark:text-slate-100">{visibleTotal}</strong>
        </div>
      )}
    </div>
  );
}// TrendTooltip

interface Props {
  data: TrendPoint[];
  height?: number;
  showInfo?: boolean;
}// Props

export default function TrendLine({ data, height = 220, showInfo = false }: Props) {
  const displayData = useMemo(
    () => data.map((d) => ({ ...d, total: showInfo ? d.total : d.total - d.info })),
    [data, showInfo]
  );

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={displayData} margin={{ top: 5, right: 20, left: -10, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.2)" />
        <XAxis dataKey="date" tick={{ fontSize: 11 }} />
        <YAxis tick={{ fontSize: 11 }} />
        <Tooltip content={<TrendTooltip />} allowEscapeViewBox={{ x: true, y: true }} wrapperStyle={{ zIndex: 50 }} />
        <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 13 }} />
        <Line type="monotone" dataKey="total"    stroke="#a78bfa" strokeWidth={2} dot={{ r: 4 }} name="Total" />
        <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={2} dot={{ r: 4 }} name="Critical" />
        <Line type="monotone" dataKey="high"     stroke="#f97316" strokeWidth={2} dot={{ r: 4 }} name="High" />
        <Line type="monotone" dataKey="medium"   stroke="#eab308" strokeWidth={2} dot={{ r: 4 }} name="Medium" />
        <Line type="monotone" dataKey="low"      stroke="#22c55e" strokeWidth={2} dot={{ r: 4 }} name="Low" />
        {showInfo && (
          <Line type="monotone" dataKey="info"   stroke="#3b82f6" strokeWidth={2} dot={{ r: 4 }} name="Info" />
        )}
      </LineChart>
    </ResponsiveContainer>
  );
}// TrendLine
