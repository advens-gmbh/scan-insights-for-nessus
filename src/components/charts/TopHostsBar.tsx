import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,} from "recharts";
import type { HostEntry } from "../../types/nessus";
import { useUiStore } from "../../stores/uiStore";

interface Props {
  hosts: HostEntry[];
  limit?: number;
  showInfo?: boolean;
}// Props

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

function BarTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) {
    return null;
  }

  const visible = [...payload.filter((p: any) => p.value > 0)].sort(
    (a, b) => SEV_ORDER.indexOf(a.name) - SEV_ORDER.indexOf(b.name)
  );

  const total = visible.reduce((s: number, p: any) => s + p.value, 0);

  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg px-3 py-2 text-xs">
      <p className="font-semibold text-slate-700 dark:text-slate-200 mb-1.5">{label}</p>
      {visible.map((p: any) => (
        <div key={p.name} className="flex items-center gap-2 py-0.5">
          <div className="w-2 h-2 rounded-full shrink-0" style={{ background: p.fill }} />
          <span className="text-slate-500 dark:text-slate-400 w-14">{p.name}:</span>
          <strong className="text-slate-800 dark:text-slate-100">{p.value}</strong>
        </div>
      ))}
      <div className="border-t border-slate-100 dark:border-slate-700 mt-1.5 pt-1.5 flex items-center gap-2">
        <div className="w-2 h-2 shrink-0" />
        <span className="text-slate-500 dark:text-slate-400 w-14">Total:</span>
        <strong className="text-slate-800 dark:text-slate-100">{total}</strong>
      </div>
    </div>
  );
}// BarTooltip

export default function TopHostsBar({ hosts, limit = 15, showInfo = false }: Props) {
  const openHostPanel = useUiStore((s) => s.openHostPanel);

  const data = hosts
    // without Info, a host with nothing else would only be an empty row
    .filter((h) => showInfo || h.items.some((i) => i.severity > 0))
    .sort((a, b) => {
      const totalA = a.severity_counts.critical * 1000 + a.severity_counts.high * 100 + a.severity_counts.medium * 10 + a.severity_counts.low;
      const totalB = b.severity_counts.critical * 1000 + b.severity_counts.high * 100 + b.severity_counts.medium * 10 + b.severity_counts.low;
      return totalB - totalA;
    })
    .slice(0, limit)
    .map((h) => ({
      ip: h.ip,
      Critical: h.severity_counts.critical,
      High: h.severity_counts.high,
      Medium: h.severity_counts.medium,
      Low: h.severity_counts.low,
      Info: h.severity_counts.info,
    }));

  if (data.length === 0) {
    return null;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}
        onClick={(d) => d?.activePayload?.[0] && openHostPanel((d.activePayload[0].payload as { ip: string }).ip)}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.2)" />
        <XAxis dataKey="ip" tick={{ fontSize: 11 }} />
        <YAxis tick={{ fontSize: 11 }} />
        <Tooltip content={<BarTooltip />} cursor={false} />
        {showInfo && <Bar dataKey="Info"   stackId="a" fill="#3b82f6" />}
        <Bar dataKey="Low"    stackId="a" fill="#22c55e" />
        <Bar dataKey="Medium" stackId="a" fill="#eab308" />
        <Bar dataKey="High"   stackId="a" fill="#f97316" />
        <Bar dataKey="Critical" stackId="a" fill="#dc2626" radius={[3, 3, 0, 0]}>
          {data.map((_, i) => <Cell key={i} cursor="pointer" />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}// TopHostsBar
