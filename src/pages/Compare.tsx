import { useMemo, useState } from "react";
import { ArrowRight, Plus, Minus, Equal, Server, CircleHelp } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { useUiStore } from "../stores/uiStore";
import { severityCounts, visibleCounts } from "../types/nessus";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import ScanName from "../components/common/ScanName";
import type { NessusFile } from "../types/nessus";
import { compareScans, type DeltaItem } from "../utils/compare";
import { compareHosts } from "../utils/ip";
import SeverityBadge from "../components/common/SeverityBadge";
import SeverityDonut from "../components/charts/SeverityDonut";
import SpacerRow from "../components/common/SpacerRow";
import TableHead from "../components/common/TableHead";
import { useTableColumns } from "../hooks/useTableColumns";
import { useTableSort } from "../hooks/useTableSort";
import { useVirtualRows } from "../hooks/useVirtualRows";
import type { TableColumn } from "../utils/tableColumns";
import FileDetailPanel from "../panels/FileDetailPanel";
import EmptyFilesNotice from "./EmptyFilesNotice";

export default function Compare() {
  const files = useScanStore((s) => s.files);
  const { openVulnPanel, showInfo } = useUiStore();

  const [scanA, setScanA] = useState<string>("");
  const [scanB, setScanB] = useState<string>("");
  const [detailFile, setDetailFile] = useState<NessusFile | null>(null);

  const fileA = files.find((f) => f.id === scanA);
  const fileB = files.find((f) => f.id === scanB);

  const delta = useMemo(() => {
    if (!fileA || !fileB) {
      return { newItems: [], resolvedItems: [], persistedItems: [], unverifiedItems: [] };
    }

    return compareScans(fileA, fileB);
  }, [fileA, fileB]);

  const itemMap = useMemo(() => {
    const m = new Map<number, { name: string; severity: number }>();
    for (const f of [fileA, fileB]) {
      if (!f) {
        continue;
      }

      for (const host of f.hosts) {
        for (const item of host.items) {
          const known = m.get(item.plugin_id);
          if (!known || item.severity > known.severity) {
            m.set(item.plugin_id, { name: item.plugin_name, severity: item.severity });
          }
        }
      }
    }

    return m;
  }, [fileA, fileB]);

  const { newItems, resolvedItems, persistedItems, unverifiedItems } = useMemo(() => {
    const keep = (items: DeltaItem[]) =>
      showInfo ? items : items.filter((i) => (itemMap.get(i.pluginId)?.severity ?? 0) > 0);

    return {
      newItems: keep(delta.newItems),
      resolvedItems: keep(delta.resolvedItems),
      persistedItems: keep(delta.persistedItems),
      unverifiedItems: keep(delta.unverifiedItems),
    };
  }, [delta, itemMap, showInfo]);

  if (files.length < 2) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <div className="text-center text-ink-400">
          <p className="text-lg font-medium mb-2">Load at least 2 scan files to compare.</p>
          <EmptyFilesNotice />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Scan selector */}
      <div className="flex items-center gap-4">
        <div className="flex-1">
          <label className="text-xs font-medium text-ink-500 dark:text-ink-400 mb-1 block">Scan A (baseline)</label>
          <select
            value={scanA}
            onChange={(e) => setScanA(e.target.value)}
            className="input"
          >
            <option value="">- Select scan -</option>
            {files.filter((f) => f.id !== scanB).map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
        </div>
        <ArrowRight size={20} className="text-ink-400 mt-5 shrink-0" />
        <div className="flex-1">
          <label className="text-xs font-medium text-ink-500 dark:text-ink-400 mb-1 block">Scan B (comparison)</label>
          <select
            value={scanB}
            onChange={(e) => setScanB(e.target.value)}
            className="input"
          >
            <option value="">- Select scan -</option>
            {files.filter((f) => f.id !== scanA).map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
        </div>
      </div>

      {fileA && fileB && (
        <>
          <div className="flex justify-end">
            <ShowInfoCheckbox />
          </div>

          {/* Side-by-side summary */}
          <div className="grid grid-cols-2 gap-4">
            <ScanSummaryCard file={fileA} label="Scan A" onFileClick={setDetailFile} />
            <ScanSummaryCard file={fileB} label="Scan B" onFileClick={setDetailFile} />
          </div>

          {/* Delta stats */}
          <div className="grid grid-cols-4 gap-4">
            <DeltaCard
              icon={<Plus size={16} />}
              label="New"
              count={newItems.length}
              desc="In B but not in A"
              color="text-red-500"
              bg="bg-red-50 dark:bg-red-900/10"
            />
            <DeltaCard
              icon={<Minus size={16} />}
              label="Resolved"
              count={resolvedItems.length}
              desc="In A, and host rescanned in B without it"
              color="text-emerald-500"
              bg="bg-emerald-50 dark:bg-emerald-900/10"
            />
            <DeltaCard
              icon={<CircleHelp size={16} />}
              label="Not verified"
              count={unverifiedItems.length}
              desc="In A, but B can't confirm a fix"
              color="text-amber-500"
              bg="bg-amber-50 dark:bg-amber-900/10"
            />
            <DeltaCard
              icon={<Equal size={16} />}
              label="Persisted"
              count={persistedItems.length}
              desc="In both scans"
              color="text-ink-500"
              bg="bg-ink-50 dark:bg-ink-800/50"
            />
          </div>

          <p className="text-xs text-ink-400">
            Findings are matched by plugin, host, port and protocol. A different scan policy between
            the two scans can still hide a finding, so check that both used the same one.
          </p>

          {/* Delta tables */}
          {newItems.length > 0 && (
            <DeltaTable
              title="New Vulnerabilities"
              items={newItems}
              itemMap={itemMap}
              rowClass="bg-red-50/50 dark:bg-red-900/5 hover:bg-red-50 dark:hover:bg-red-900/10"
              onOpen={openVulnPanel}
            />
          )}
          {resolvedItems.length > 0 && (
            <DeltaTable
              title="Resolved Vulnerabilities"
              items={resolvedItems}
              itemMap={itemMap}
              rowClass="bg-emerald-50/50 dark:bg-emerald-900/5 hover:bg-emerald-50 dark:hover:bg-emerald-900/10"
              onOpen={openVulnPanel}
            />
          )}
          {unverifiedItems.length > 0 && (
            <DeltaTable
              title="Not Verified: Could Not Be Confirmed Fixed"
              items={unverifiedItems}
              itemMap={itemMap}
              rowClass="bg-amber-50/50 dark:bg-amber-900/5 hover:bg-amber-50 dark:hover:bg-amber-900/10"
              onOpen={openVulnPanel}
            />
          )}
          {persistedItems.length > 0 && (
            <DeltaTable
              title="Persisted Vulnerabilities"
              items={persistedItems}
              itemMap={itemMap}
              rowClass="table-row"
              onOpen={openVulnPanel}
            />
          )}
        </>
      )}

      {(!fileA || !fileB) && (
        <div className="card p-8 text-center text-ink-400">
          Select two scan files above to compare them.
        </div>
      )}

      {detailFile && (
        <FileDetailPanel file={detailFile} onClose={() => setDetailFile(null)} />
      )}
    </div>
  );
}// Compare

function ScanSummaryCard({ file, label, onFileClick }: { file: NessusFile; label: string; onFileClick: (f: NessusFile) => void }) {
  const showInfo = useUiStore((s) => s.showInfo);
  const counts = severityCounts(file.hosts);

  return (
    <div className="card p-5">
      <p className="text-xs font-semibold uppercase tracking-wider text-ink-400 mb-1">{label}</p>
      <div className="mb-3">
        <h3
          className="font-semibold text-ink-800 dark:text-ink-100 truncate cursor-pointer hover:text-accent-700 dark:hover:text-accent-400 transition-colors"
          title="Click to view file details"
          onClick={() => onFileClick(file)}
        >
          {file.filename}
        </h3>
        <ScanName file={file} />
      </div>
      <div className={`flex items-center gap-4 ${showInfo ? "min-h-[150px]" : "min-h-[124px]"}`}>
        <SeverityDonut counts={visibleCounts(counts, showInfo)} size={110} emptyText={counts.info > 0 ? "Only Info findings" : undefined} />
        <div className="flex flex-col gap-1.5 text-sm">
          <div className="flex items-center gap-2">
            <Server size={13} className="text-ink-400" />
            <span className="text-ink-600 dark:text-ink-400 w-16">Hosts:</span>
            <strong className="text-ink-800 dark:text-ink-200">{file.hosts.length}</strong>
          </div>
          <CompareSeverityRow label="Critical" value={counts.critical} color="text-critical-fg" />
          <CompareSeverityRow label="High"     value={counts.high}     color="text-high-fg" />
          <CompareSeverityRow label="Medium"   value={counts.medium}   color="text-medium-fg" />
          <CompareSeverityRow label="Low"      value={counts.low}      color="text-low-fg" />
          <CompareSeverityRow label="Info"     value={showInfo ? counts.info : 0} color="text-info-fg" />
        </div>
      </div>
    </div>
  );
}// ScanSummaryCard

function CompareSeverityRow({ label, value, color }: { label: string; value: number; color: string }) {
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
}// CompareSeverityRow

function DeltaCard({ icon, label, count, desc, color, bg }: {icon: React.ReactNode; label: string; count: number; desc: string; color: string; bg: string;}) {
  return (
    <div className={`card p-5 ${bg}`}>
      <div className={`flex items-center gap-2 ${color} mb-1`}>
        {icon}
        <span className="font-semibold">{label}</span>
      </div>
      <p className={`text-3xl font-bold ${color}`}>{count.toLocaleString()}</p>
      <p className="text-xs text-ink-400 mt-1">{desc}</p>
    </div>
  );
}// DeltaCard

type DeltaSortKey = "severity" | "name" | "ip";

const DELTA_COLUMNS: TableColumn<DeltaSortKey>[] = [
  { key: "severity", label: "Severity",    width: 112, required: true },
  { key: "name",     label: "Plugin Name", width: 200, stretch: true, required: true },
  { key: "ip",       label: "Host IP",     width: 208, required: true },
];// DELTA_COLUMNS

function DeltaTable({ title, items, itemMap, rowClass, onOpen }: {title: string; items: DeltaItem[]; itemMap: Map<number, { name: string; severity: number }>; rowClass: string; onOpen: (id: number) => void;}) {
  const table = useTableColumns("compare", DELTA_COLUMNS);
  const { sortKey, sortDir, toggleSort } = useTableSort(table.visible, "severity", "desc", ["name", "ip"]);

  const sorted = useMemo(() => {
    return [...items].sort((a, b) => {
      const ia = itemMap.get(a.pluginId);
      const ib = itemMap.get(b.pluginId);
      let cmp = 0;

      if (sortKey === "severity") {
        cmp = (ia?.severity ?? -1) - (ib?.severity ?? -1);
      }
      else if (sortKey === "name") {
        cmp = (ia?.name ?? "").localeCompare(ib?.name ?? "");
      }
      else if (sortKey === "ip") {
        cmp = compareHosts(a.ip, b.ip) || a.port - b.port;
      }
      return sortDir === "desc" ? -cmp : cmp;
    });
  }, [items, itemMap, sortKey, sortDir]);

  const { scrollRef, rows, paddingTop, paddingBottom, measureRow } = useVirtualRows(sorted.length, 41);

  return (
    <div className="card overflow-hidden">
      <div className="px-5 py-3 border-b border-ink-100 dark:border-ink-700">
        <h3 className="font-semibold text-ink-700 dark:text-ink-300 text-sm">
          {title} ({items.length})
        </h3>
      </div>
      <div ref={scrollRef} className="overflow-x-auto max-h-72 overflow-y-auto">
        <table style={table.style}>
          <TableHead table={table} sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
          <tbody className="divide-y divide-ink-100 dark:divide-ink-700/50">
            <SpacerRow height={paddingTop} colSpan={3} />
            {rows.map((row) => {
              const item = sorted[row.index];
              const info = itemMap.get(item.pluginId);
              return (
                <tr
                  key={`${item.pluginId}|${item.ip}|${item.port}|${item.protocol}`}
                  ref={measureRow}
                  data-index={row.index}
                  className={`${rowClass} cursor-pointer transition-colors`}
                  onClick={() => onOpen(item.pluginId)}
                >
                  <td className="table-cell">
                    {info && <SeverityBadge severity={info.severity} size="sm" />}
                  </td>
                  <td className="table-cell text-sm text-ink-700 dark:text-ink-300">
                    <span className="truncate block">{info?.name ?? `Plugin #${item.pluginId}`}</span>
                    {item.note && (
                      <span className="block text-[10px] text-amber-600 dark:text-amber-400">{item.note}</span>
                    )}
                  </td>
                  <td className="table-cell text-accent-700 dark:text-accent-400">
                    {item.ip}
                    {item.port > 0 && (
                      <span className="text-xs text-ink-400"> {item.port}/{item.protocol}</span>
                    )}
                  </td>
                </tr>
              );
            })}
            <SpacerRow height={paddingBottom} colSpan={3} />
          </tbody>
        </table>
      </div>
    </div>
  );
}// DeltaTable
