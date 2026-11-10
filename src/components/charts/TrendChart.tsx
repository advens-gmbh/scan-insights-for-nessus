import { memo } from "react";
import { Bar, BarChart, CartesianGrid, DefaultZIndexes, LabelList, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, ZIndexLayer, usePlotArea } from "recharts";
import { ink, severity } from "../../theme/colors";
import { useUiStore } from "../../stores/uiStore";

export interface TrendPoint {
  id: string;
  date: string;
  filename: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}// TrendPoint

type Level = "critical" | "high" | "medium" | "low" | "info";
type Series = { key: Level; name: string };

const SERIES: Series[] = [
  { key: "critical", name: "Critical" },
  { key: "high",     name: "High" },
  { key: "medium",   name: "Medium" },
  { key: "low",      name: "Low" },
  { key: "info",     name: "Info" },
];

const DURATION = 500;
const AFTER_ANIMATION = { animation: `fadeIn 0.2s ease-out ${DURATION}ms both` };

function TrendTooltip({ active, payload, coordinate }: any) {
  const plotArea = usePlotArea();
  if (!active || !payload?.length) {
    return null;
  }

  const d = payload[0].payload as TrendPoint;
  const flipLeft = coordinate && plotArea && coordinate.x > plotArea.width * 0.55;
  const rows = SERIES.filter((s) => payload.some((p: any) => p.dataKey === s.key));
  const total = rows.reduce((sum, s) => sum + d[s.key], 0);

  return (
    <div
      className="bg-white dark:bg-ink-800 border border-ink-200 dark:border-ink-700 rounded-lg shadow-lg px-3 py-2 text-xs tabular-nums"
      style={{ transform: flipLeft ? "translateX(-110%)" : undefined }}
    >
      <p className="font-semibold text-ink-800 dark:text-ink-100 truncate">{d.filename}</p>
      <p className="text-ink-500 dark:text-ink-400 mb-1.5">{d.date}</p>
      {rows.map((s) => (
        <div key={s.key} className="flex items-center gap-2 py-0.5">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: severity[s.key].fill }} />
          <span className="text-ink-500 dark:text-ink-400 w-14">{s.name}</span>
          <strong className="ml-auto text-ink-800 dark:text-ink-100">{d[s.key].toLocaleString()}</strong>
        </div>
      ))}
      <div className="border-t border-ink-100 dark:border-ink-700 mt-1.5 pt-1.5 flex items-center gap-2">
        <span className="text-ink-500 dark:text-ink-400 w-14 ml-4">Total</span>
        <strong className="ml-auto text-ink-800 dark:text-ink-100">{total.toLocaleString()}</strong>
      </div>
    </div>
  );
}// TrendTooltip

interface Props {
  data: TrendPoint[];
  mode: "lines" | "bars";
  showInfo: boolean;
  height?: number;
}// Props

function TrendChart({ data, mode, showInfo, height = 300 }: Props) {
  const dark = useUiStore((s) => s.theme) === "dark";
  const surface = dark ? ink[800] : "#ffffff";
  const muted = dark ? ink[400] : ink[500];
  const text = dark ? ink[100] : ink[800];
  const series = SERIES.filter((s) => showInfo || s.key !== "info");
  const total = (d: TrendPoint) => series.reduce((sum, s) => sum + d[s.key], 0);
  const top = niceMax(Math.max(5, ...data.map((d) => (mode === "bars" ? total(d) : Math.max(...series.map((s) => d[s.key]))))));
  // a new key restarts the fade of the numbers whenever the data changes
  const version = `${mode}|${showInfo}|${data.map((d) => d.id).join(",")}`;

  const axes = (
    <>
      <CartesianGrid vertical={false} stroke={dark ? ink[700] : ink[200]} />
      <XAxis dataKey="date" tick={{ fontSize: 12, fill: muted }} tickLine={false} axisLine={{ stroke: dark ? ink[600] : ink[300] }} />
      <YAxis tick={{ fontSize: 12, fill: muted }} tickLine={false} axisLine={false} allowDecimals={false} width={Math.max(44, top.toLocaleString().length * 7.5 + 10)} tickFormatter={(v: number) => v.toLocaleString()} domain={[0, top]} ticks={[0, 1, 2, 3, 4, 5].map((i) => (top * i) / 5)} />
      <Tooltip content={<TrendTooltip />} allowEscapeViewBox={{ x: true, y: true }} wrapperStyle={{ zIndex: 50 }} cursor={mode === "bars" ? { fill: dark ? ink[700] : ink[100] } : { stroke: muted }} />
      <Legend
        iconType="circle"
        iconSize={10}
        wrapperStyle={{ fontSize: 13 }}
        itemSorter={(item: any) => SERIES.findIndex((s) => s.key === item.dataKey)}
        formatter={(value: string) => <span style={{ color: muted }}>{value}</span>}
      />
    </>
  );

  if (mode === "bars") {
    return (
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 24, right: 16, left: 0, bottom: 4 }}>
          {axes}
          {[...series].reverse().map((s) => (
            <Bar key={s.key} dataKey={s.key} name={s.name} stackId="runs" fill={severity[s.key].fill} stroke={surface} strokeWidth={2} maxBarSize={64} animationDuration={DURATION}>
              <LabelList
                dataKey={s.key}
                content={(p: any) =>
                  p.value > 0 && p.height >= 14 && p.width >= Number(p.value).toLocaleString().length * 7 + 4 ? (
                    <text x={p.x + p.width / 2} y={p.y + p.height / 2 + 4} textAnchor="middle" fontSize={11} fontWeight={700} fill={severity[s.key].on}>
                      {Number(p.value).toLocaleString()}
                    </text>
                  ) : null}
              />
            </Bar>
          ))}
          <BarTotals key={version} data={data} total={total} top={top} color={text} />
        </BarChart>
      </ResponsiveContainer>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 12, right: 16, left: 0, bottom: 4 }}>
        {axes}
        {series.map((s) => (
          <Line
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.name}
            stroke={severity[s.key].fill}
            strokeWidth={2}
            dot={{ r: 4.5, fill: severity[s.key].fill, stroke: surface, strokeWidth: 2 }}
            activeDot={{ r: 6, stroke: surface, strokeWidth: 2 }}
            animationDuration={DURATION}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}// TrendChart

export default memo(TrendChart);

// an axis top a bit above the highest value, on a round number
function niceMax(value: number): number {
  const step = 10 ** Math.floor(Math.log10(value));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (value <= m * step) {
      return m * step;
    }
  }

  return 10 * step;
}// niceMax

// the total of each stacked bar, above it
function BarTotals({ data, total, top, color }: { data: TrendPoint[]; total: (d: TrendPoint) => number; top: number; color: string }) {
  const area = usePlotArea();
  if (!area || data.length === 0) {
    return null;
  }

  const band = area.width / data.length;
  if (band < 22) {
    return null;
  }

  // the label layer is above the hover highlight, which would hide them
  return (
    <ZIndexLayer zIndex={DefaultZIndexes.label}>
      <g style={AFTER_ANIMATION}>
        {data.map((d, i) => (
          <text key={d.id} x={area.x + band * (i + 0.5)} y={area.y + area.height * (1 - total(d) / top) - 6} textAnchor="middle" fontSize={12} fontWeight={600} fill={color}>
            {total(d).toLocaleString()}
          </text>
        ))}
      </g>
    </ZIndexLayer>
  );
}// BarTotals
