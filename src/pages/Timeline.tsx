import { useMemo, useState } from "react";
import { FileText, Server, Clock } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { severityCounts, SEVERITY_COLORS, visibleCounts } from "../types/nessus";
import { useUiStore } from "../stores/uiStore";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import ScanName from "../components/common/ScanName";
import type { NessusFile } from "../types/nessus";
import TrendLine, { type TrendPoint } from "../components/charts/TrendLine";
import SeverityDonut from "../components/charts/SeverityDonut";
import FileDetailPanel from "../panels/FileDetailPanel";
import EmptyFilesNotice from "./EmptyFilesNotice";
import { formatDate, formatDateShort } from "../utils/format";
import { accent, ink } from "../theme/colors";

function getFileDate(f: NessusFile): number {
  const hostStart = f.hosts[0]?.host_start;
  if (hostStart) {
    const d = new Date(hostStart);
    if (!isNaN(d.getTime())) {
      return d.getTime();
    }
  }
  return new Date(f.loaded_at).getTime();
}// getFileDate

function worstSeverityColor(f: NessusFile): string {
  const c = severityCounts(f.hosts);
  if (c.critical > 0) 
    return SEVERITY_COLORS[4].hex;
  if (c.high > 0) 
    return SEVERITY_COLORS[3].hex;
  if (c.medium > 0) 
    return SEVERITY_COLORS[2].hex;
  if (c.low > 0) 
    return SEVERITY_COLORS[1].hex;
  if (c.info > 0) 
    return SEVERITY_COLORS[0].hex;

  return ink[500];
}// worstSeverityColor

function SeverityRow({ label, value, color }: { label: string; value: number; color: string }) {
  if (value === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-2">
      <span className={`w-[13px] h-[13px] rounded-full shrink-0 ${color.replace("text-", "bg-").replace("-fg", "")}`} />
      <span className="text-ink-500 dark:text-ink-400 w-16">{label}:</span>
      <strong className={color}>{value}</strong>
    </div>
  );
}// SeverityRow

export default function Timeline() {
  const files = useScanStore((s) => s.files);
  const [selected, setSelected] = useState<string | null>(null);
  const [detailFile, setDetailFile] = useState<NessusFile | null>(null);
  const showInfo = useUiStore((s) => s.showInfo);

  const sortedFiles = useMemo(
    () => [...files].sort((a, b) => getFileDate(a) - getFileDate(b)),
    [files]
  );

  const duplicateDates = useMemo(() => {
    const counts = new Map<string, number>();
    for (const f of sortedFiles) {
      const d = formatDateShort(new Date(getFileDate(f)).toISOString());
      counts.set(d, (counts.get(d) ?? 0) + 1);
    }
    return new Set([...counts.entries()].filter(([, n]) => n > 1).map(([d]) => d));
  }, [sortedFiles]);

  const scanLabel = (f: NessusFile): string => {
    const ts = new Date(getFileDate(f));
    const short = formatDateShort(ts.toISOString());
    if (duplicateDates.has(short)) {
      const p = (n: number) => String(n).padStart(2, "0");
      return `${short} ${p(ts.getHours())}:${p(ts.getMinutes())}`;
    }

    return short;
  };

  const trendData: TrendPoint[] = useMemo(() => {
    return sortedFiles.map((f) => {
      const c = severityCounts(f.hosts);
      return {
        label:    f.filename.replace(/\.nessus$/i, "").slice(0, 20),
        date:     scanLabel(f),
        filename: f.filename,
        critical: c.critical,
        high:     c.high,
        medium:   c.medium,
        low:      c.low,
        info:     c.info,
        total:    c.critical + c.high + c.medium + c.low + c.info,
      };
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sortedFiles, duplicateDates]);

  const selectedFile = sortedFiles.find((f) => f.id === selected) ?? sortedFiles[0] ?? null;

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  if (files.length < 2) {
    return (
      <div className="space-y-4">
        <p className="text-ink-400 text-sm">Load at least 2 scan files to see a trend.</p>
        <EmptyFilesNotice />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="font-semibold text-ink-700 dark:text-ink-200 mb-1">Timeline & Trend Analysis</h2>
        <p className="text-xs text-ink-400">Vulnerability counts across all loaded scans, sorted by scan date.</p>
      </div>

      {/* Trend chart */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-ink-600 dark:text-ink-300">Vulnerability Severity Trend</h3>
          <ShowInfoCheckbox />
        </div>
        <TrendLine data={trendData} height={260} showInfo={showInfo} />
      </div>

      {/* Timeline file icons - alternating above / below the line */}
      <div className="card p-5 overflow-x-auto">
        <h3 className="text-sm font-semibold text-ink-600 dark:text-ink-300 mb-2">Scan Files</h3>
        {/* Each item is a flex-column: [top-half] · [dot] · [bottom-half].
            Even indices show icon+label in top-half; odd indices in bottom-half.
            Both halves are always rendered (for consistent height), but the
            "unused" half is invisible so the dot stays vertically centered. */}
        <div className="relative flex items-stretch min-w-max">
          {/* Horizontal rule sits at 50% - behind the items */}
          <div className="absolute inset-x-0 top-1/2 h-px bg-ink-200 dark:bg-ink-700 -translate-y-1/2" />

          {sortedFiles.map((f, i) => {
            const above = i % 2 === 0;
            const isSelected = selected ? f.id === selected : i === 0;
            const sevColor = worstSeverityColor(f);
            const name = f.filename.replace(/\.nessus$/i, "");
            const scanDate = scanLabel(f);

            const label = (
              <div className="text-center">
                <p className={`text-[10px] font-medium whitespace-nowrap ${isSelected ? "text-accent-700 dark:text-accent-400" : "text-ink-500 dark:text-ink-400"}`}>
                  {name}
                </p>
                <p className="text-[9px] text-ink-400">{scanDate}</p>
              </div>
            );
            const icon = <FileText size={32} style={{ color: sevColor }} />;

            return (
              <div
                key={f.id}
                className="flex flex-col items-center px-5 cursor-pointer group relative z-10"
                onClick={() => setSelected(f.id)}
              >
                {/* Top half */}
                <div className={`flex flex-col items-center justify-end gap-1 pb-2.5 h-24 ${above ? "" : "invisible"}`}>
                  {label}
                  {icon}
                </div>

                {/* Dot on line */}
                <div
                  className="w-2.5 h-2.5 rounded-full shrink-0 transition-transform group-hover:scale-125"
                  style={{
                    backgroundColor: isSelected ? accent[400] : sevColor,
                    boxShadow: isSelected ? `0 0 0 2px ${accent[400]}` : "none",
                    transform: isSelected ? "scale(1.2)" : undefined,
                  }}
                />

                {/* Bottom half */}
                <div className={`flex flex-col items-center justify-start gap-1 pt-2.5 h-24 ${above ? "invisible" : ""}`}>
                  {icon}
                  {label}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected scan detail - matches Dashboard card layout */}
      {selectedFile && (() => {
        const counts = severityCounts(selectedFile.hosts);
        return (
          <div className="card p-5 flex flex-col gap-4">
            {/* Title row */}
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="pill bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 text-[10px]">
                    Selected
                  </span>
                </div>
                <p
                  className="font-semibold text-ink-800 dark:text-ink-100 truncate cursor-pointer hover:text-accent-700 dark:hover:text-accent-400 transition-colors"
                  title="Click to view file details"
                  onClick={() => setDetailFile(selectedFile)}
                >
                  {selectedFile.filename}
                </p>
                <ScanName file={selectedFile} />
                <p className="text-xs text-ink-400 mt-0.5 flex items-center gap-1">
                  <Clock size={11} />
                  {formatDate(new Date(getFileDate(selectedFile)).toISOString())}
                </p>
              </div>
            </div>

            {/* Stats + donut */}
            <div className="flex items-center gap-4">
              <SeverityDonut counts={visibleCounts(counts, showInfo)} size={110} emptyText={counts.info > 0 ? "Only Info findings" : undefined} />
              <div className="flex flex-col gap-1.5 text-sm">
                <div className="flex items-center gap-2">
                  <Server size={13} className="text-ink-400" />
                  <span className="text-ink-600 dark:text-ink-400 w-16">Hosts:</span>
                  <strong className="text-ink-800 dark:text-ink-200">{selectedFile.hosts.length}</strong>
                </div>
                <SeverityRow label="Critical" value={counts.critical} color="text-critical-fg" />
                <SeverityRow label="High"     value={counts.high}     color="text-high-fg" />
                <SeverityRow label="Medium"   value={counts.medium}   color="text-medium-fg" />
                <SeverityRow label="Low"      value={counts.low}      color="text-low-fg" />
                <SeverityRow label="Info"     value={showInfo ? counts.info : 0} color="text-info-fg" />
              </div>
            </div>
          </div>
        );
      })()}

      {detailFile && (
        <FileDetailPanel file={detailFile} onClose={() => setDetailFile(null)} />
      )}
    </div>
  );
}// Timeline
