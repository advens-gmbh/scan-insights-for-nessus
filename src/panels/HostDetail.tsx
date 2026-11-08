import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { X, ChevronDown, ChevronRight, AlertTriangle } from "lucide-react";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import { buildHostEntries, ratedScore, SEVERITY_COLORS } from "../types/nessus";
import type { ReportItem } from "../types/nessus";
import { formatDuration, formatScanStart, scanWindow } from "../utils/dashboard";
import { groupByPort, openPorts, sortFindings } from "../utils/hostFindings";
import type { PortGroup } from "../utils/hostFindings";
import SeverityBadge from "../components/common/SeverityBadge";
import CopyButton from "../components/common/CopyButton";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import { Section, Tag, useEscape } from "./PanelParts";

const COUNTS = [
  { sev: 4, label: "Critical", key: "critical" },
  { sev: 3, label: "High",     key: "high" },
  { sev: 2, label: "Medium",   key: "medium" },
  { sev: 1, label: "Low",      key: "low" },
  { sev: 0, label: "Info",     key: "info" },
] as const;

const CHIP: Record<number, string> = {
  4: "bg-critical text-critical-on",
  3: "bg-high text-high-on",
  2: "bg-medium text-medium-on",
  1: "bg-low text-low-on",
  0: "bg-info text-info-on",
};

interface Props {
  ip: string;
}// Props

export default function HostDetail({ ip }: Props) {
  const closeHostPanel = useUiStore((s) => s.closeHostPanel);
  useEscape(closeHostPanel);

  return (
    <aside className="panel-drawer border-l border-ink-200 dark:border-ink-700" aria-label="Host details">
      <HostContent key={ip} ip={ip} onClose={closeHostPanel} />
    </aside>
  );
}// HostDetail

function HostContent({ ip, onClose }: { ip: string; onClose: () => void }) {
  const hostPanelFileId = useUiStore((s) => s.hostPanelFileId);
  const showInfo = useUiStore((s) => s.showInfo);
  const grouped = useUiStore((s) => s.groupHostFindings);
  const toggleGrouped = useUiStore((s) => s.toggleGroupHostFindings);
  const files = useScanStore((s) => s.files);

  const [fileScope, setFileScope] = useState(hostPanelFileId ?? "all");

  const acrossFiles = useMemo(() => buildHostEntries(files).find((h) => h.ip === ip), [files, ip]);
  const scopedFiles = useMemo(
    () => (fileScope === "all" ? files : files.filter((f) => f.id === fileScope)),
    [files, fileScope]
  );
  const scoped = useMemo(() => buildHostEntries(scopedFiles).find((h) => h.ip === ip), [scopedFiles, ip]);

  if (!acrossFiles) {
    return null;
  }

  const host = scoped ?? acrossFiles;
  const scopeFileId = fileScope === "all" ? undefined : fileScope;
  const findings = host.items.filter((i) => showInfo || i.severity > 0);
  const { tcp, udp } = openPorts(host.items);
  const osValues = host.os ? host.os.split(/\n+/).map((o) => o.trim()).filter(Boolean) : [];
  const macs = host.mac ? host.mac.split(/[\n,]+/).map((m) => m.trim()).filter(Boolean) : [];
  const scan = scanWindow([host]);
  const multiFile = acrossFiles.file_ids.length > 1;

  return (
    <>
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-ink-200 dark:border-ink-700 flex flex-col gap-2.5">
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-semibold tabular-nums text-ink-900 dark:text-ink-50">{host.ip}</h2>
          <CopyButton text={host.ip} variant="icon" label="Copy IP" />
          {host.credentialed_scan && <Tag>Credentialed</Tag>}
          {multiFile && <Tag>{acrossFiles.file_ids.length} files</Tag>}
          <button onClick={onClose} className="btn-ghost w-8 h-8 p-0 ml-auto justify-center shrink-0" title="Close (Esc)" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        {(host.hostname || host.netbios || osValues.length > 0) && (
          <p className="text-[13px] text-ink-500 dark:text-ink-400 truncate">
            {[host.hostname ?? host.netbios, osValues[0]].filter(Boolean).join(" · ")}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          {COUNTS.map((c) => {
            const n = host.severity_counts[c.key];
            return (
              <div key={c.sev} className="flex flex-col gap-0.5 min-w-[4.5rem] px-2.5 py-1.5 rounded-md border border-ink-200 dark:border-ink-700">
                <span className={`text-lg font-bold leading-tight tabular-nums ${n > 0 ? SEVERITY_COLORS[c.sev].text : "text-ink-300 dark:text-ink-600"}`}>{n}</span>
                <span className="text-[11px] font-semibold text-ink-500 dark:text-ink-400">{c.label}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-4">
        {acrossFiles.conflicts.length > 0 && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-md bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/40">
            <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
            <p className="text-[13px] text-amber-800 dark:text-amber-300 leading-relaxed">
              <span className="font-semibold">Possible identity conflict: </span>
              {acrossFiles.conflicts.join(" and ")} differ{acrossFiles.conflicts.length > 1 ? "" : "s"} across scan files.
              This IP may be different machines.
            </p>
          </div>
        )}

        <Section title="Details">
          <dl className="grid grid-cols-[auto_minmax(0,1fr)_auto] gap-x-6 gap-y-1 items-baseline">
            <Detail label="Hostname" value={host.hostname} copy />
            <Detail label="Other names" value={host.alt_hostnames.length ? host.alt_hostnames.join("\n") : null} copy />
            <Detail label="Operating system" value={osValues.length ? osValues.join("\n") : null} copy />
            <Detail label="Domain" value={host.domain} />
            <Detail label="NetBIOS name" value={host.netbios} />
            <Detail label="MAC address" value={macs.length ? macs.join("\n") : null} copy />
            <Detail label="System type" value={host.system_type} />
            {scan.start && (
              <Detail
                label="Scanned"
                value={`${formatScanStart(scan.start)}${scan.durationMs !== null ? `, ran for ${formatDuration(scan.durationMs)}` : ""}`}
              />
            )}
            <dt className="text-ink-500 dark:text-ink-400">{multiFile ? "Scan files" : "Scan file"}</dt>
            <dd className="col-span-2 min-w-0">
              {multiFile ? (
                <div className="flex flex-wrap gap-1.5 py-0.5" role="group" aria-label="Show this host from">
                  <FileChip active={fileScope === "all"} onClick={() => setFileScope("all")} title="Findings merged from every file">
                    All files
                  </FileChip>
                  {acrossFiles.file_ids.map((id, i) => (
                    <FileChip key={id} active={fileScope === id} onClick={() => setFileScope(id)} title={acrossFiles.filenames[i]}>
                      {acrossFiles.filenames[i].replace(/\.nessus$/i, "")}
                    </FileChip>
                  ))}
                </div>
              ) : (
                <span className="block truncate" title={acrossFiles.filename}>{acrossFiles.filename.replace(/\.nessus$/i, "")}</span>
              )}
            </dd>
          </dl>
        </Section>

        {(tcp.length > 0 || udp.length > 0) && (
          <Section
            title={`Open ports (${tcp.length + udp.length})`}
            actions={
              <div className="flex items-center gap-1">
                {tcp.length > 0 && <CopyButton text={tcp.join(", ")} label="Copy TCP" />}
                {udp.length > 0 && <CopyButton text={udp.join(", ")} label="Copy UDP" />}
                {tcp.length > 0 && udp.length > 0 && (
                  <CopyButton text={`TCP: ${tcp.join(", ")}\nUDP: ${udp.join(", ")}`} label="Copy all" />
                )}
              </div>
            }
          >
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 tabular-nums">
              {tcp.length > 0 && <><dt className="font-semibold text-ink-500 dark:text-ink-400">TCP</dt><dd>{tcp.join(", ")}</dd></>}
              {udp.length > 0 && <><dt className="font-semibold text-ink-500 dark:text-ink-400">UDP</dt><dd>{udp.join(", ")}</dd></>}
            </dl>
          </Section>
        )}

        <Section
          title={`Vulnerabilities (${findings.length})`}
          actions={
            <div className="flex items-center gap-3">
              <ShowInfoCheckbox />
              <label className="flex items-center gap-1.5 text-xs text-ink-500 dark:text-ink-400 cursor-pointer select-none shrink-0">
                <input type="checkbox" checked={grouped} onChange={toggleGrouped} className="rounded accent-accent-600" />
                Group by port
              </label>
            </div>
          }
        >
          {findings.length === 0 ? (
            <p className="text-ink-500 dark:text-ink-400 text-center py-4">No findings above Info on this host.</p>
          ) : grouped ? (
            <PortGroups groups={groupByPort(findings)} fileId={scopeFileId} showInfo={showInfo} />
          ) : (
            <FindingList items={sortFindings(findings)} fileId={scopeFileId} />
          )}
        </Section>
      </div>
    </>
  );
}// HostContent

function Detail({ label, value, copy = false }: { label: string; value: string | null; copy?: boolean }) {
  if (!value) {
    return null;
  }

  return (
    <>
      <dt className="text-ink-500 dark:text-ink-400">{label}</dt>
      <dd className="min-w-0 whitespace-pre-line break-words">{value}</dd>
      <dd className="-my-1">{copy && <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} variant="icon" />}</dd>
    </>
  );
}// Detail

function FileChip({ active, onClick, title, children }: { active: boolean; onClick: () => void; title: string; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      title={title}
      aria-pressed={active}
      className={`max-w-full truncate px-2 py-0.5 rounded-md border text-[13px] transition-colors ${
        active
          ? "border-accent-600 bg-accent-50 text-accent-800 dark:border-accent-500 dark:bg-accent-900/40 dark:text-accent-200 font-medium"
          : "border-ink-200 dark:border-ink-600 text-ink-700 dark:text-ink-200 hover:bg-ink-100 dark:hover:bg-ink-700"
      }`}
    >
      {children}
    </button>
  );
}// FileChip

function itemScore(i: ReportItem) {
  return ratedScore({ cvss4: i.cvss4_base_score, cvss3: i.cvss3_base_score, cvss2: i.cvss_base_score, severity: i.severity });
}// itemScore

function Cvss({ item }: { item: ReportItem }) {
  const cvss = itemScore(item);
  if (!cvss) {
    return <span className="text-ink-300 dark:text-ink-600">-</span>;
  }

  return (
    <span className="whitespace-nowrap">
      <span className={`${SEVERITY_COLORS[item.severity].text} ${item.severity >= 3 ? "font-semibold" : ""}`}>
        {cvss.score.toFixed(1)}
      </span>
      <span className="ml-1 text-[10px] text-ink-400" title={`CVSS v${cvss.version}`}>v{cvss.version}</span>
    </span>
  );
}// Cvss

function FindingList({ items, fileId }: { items: ReportItem[]; fileId?: string }) {
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);

  return (
    <div className="card overflow-hidden">
      <table className="w-full table-fixed text-sm tabular-nums">
        <colgroup>
          <col className="w-[5.5rem]" />
          <col />
          <col className="w-[6.5rem]" />
          <col className="w-[5.5rem]" />
        </colgroup>
        <thead>
          <tr className="bg-ink-100 dark:bg-ink-700/60 text-[13px] text-left text-ink-500 dark:text-ink-300">
            <th className="px-3 py-2 font-semibold">Severity</th>
            <th className="px-3 py-2 font-semibold">Name</th>
            <th className="px-3 py-2 font-semibold">Port</th>
            <th className="px-3 py-2 font-semibold text-right">CVSS</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={`${item.plugin_id}-${item.port}-${item.protocol}`}
              onClick={() => openVulnPanel(item.plugin_id, fileId)}
              className="border-t border-ink-100 dark:border-ink-700 cursor-pointer hover:bg-ink-50 dark:hover:bg-ink-800"
            >
              <td className="px-3 py-1.5"><SeverityBadge severity={item.severity} size="sm" /></td>
              <td className="px-3 py-1.5 truncate">
                <FindingName item={item} fileId={fileId} />
              </td>
              <td className="px-3 py-1.5 truncate text-ink-500 dark:text-ink-400">{item.port > 0 ? `${item.port}/${item.protocol}` : "-"}</td>
              <td className="px-3 py-1.5 text-right"><Cvss item={item} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}// FindingList

function FindingName({ item, fileId }: { item: ReportItem; fileId?: string }) {
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);

  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        openVulnPanel(item.plugin_id, fileId);
      }}
      title={item.plugin_name}
      className="max-w-full truncate text-left text-ink-800 dark:text-ink-100 hover:underline"
    >
      {item.plugin_name}
    </button>
  );
}// FindingName

function PortGroups({ groups, fileId, showInfo }: { groups: PortGroup[]; fileId?: string; showInfo: boolean }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set(groups.filter((g) => g.worst >= 3).map((g) => g.key)));
  const allOpen = groups.every((g) => open.has(g.key));

  const toggle = (key: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }

      return next;
    });
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between text-[13px] text-ink-500 dark:text-ink-400">
        <span>{groups.length} {groups.length === 1 ? "port" : "ports"}</span>
        <button onClick={() => setOpen(allOpen ? new Set() : new Set(groups.map((g) => g.key)))} className="btn-ghost h-7 px-2 text-xs">
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
      </div>
      {groups.map((g) => {
        const expanded = open.has(g.key);
        return (
          <div key={g.key} className="rounded-md border border-ink-200 dark:border-ink-700 overflow-hidden">
            <button
              onClick={() => toggle(g.key)}
              aria-expanded={expanded}
              className="w-full grid grid-cols-[6rem_minmax(0,1fr)_auto_1rem] items-center gap-3 px-3 py-2 text-left bg-ink-50 dark:bg-ink-800 hover:bg-ink-100 dark:hover:bg-ink-700/70"
            >
              <span className="font-semibold tabular-nums text-ink-900 dark:text-ink-50">{g.port > 0 ? `${g.port}/${g.protocol}` : "General"}</span>
              <span className="truncate text-ink-500 dark:text-ink-400">{g.port > 0 ? g.service : "not tied to a port"}</span>
              <span className="flex gap-1 tabular-nums text-xs font-semibold">
                {COUNTS.filter((c) => showInfo || c.sev > 0).map((c) => (
                  <span key={c.sev} className={`w-7 py-0.5 rounded text-center ${g.counts[c.sev] > 0 ? CHIP[c.sev] : ""}`} title={g.counts[c.sev] > 0 ? `${g.counts[c.sev]} ${c.label}` : undefined}>
                    {g.counts[c.sev] > 0 ? g.counts[c.sev] : ""}
                  </span>
                ))}
              </span>
              {expanded ? <ChevronDown size={14} className="text-ink-500" /> : <ChevronRight size={14} className="text-ink-500" />}
            </button>
            {expanded && (
              <ul>
                {g.items.map((item) => (
                  <li
                    key={`${item.plugin_id}-${item.port}-${item.protocol}`}
                    className="grid grid-cols-[4.25rem_minmax(0,1fr)_4rem] items-center gap-3 px-3 py-1.5 border-t border-ink-100 dark:border-ink-700 hover:bg-ink-50 dark:hover:bg-ink-800"
                  >
                    <SeverityBadge severity={item.severity} size="sm" />
                    <span className="truncate"><FindingName item={item} fileId={fileId} /></span>
                    <span className="text-right tabular-nums"><Cvss item={item} /></span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}
    </div>
  );
}// PortGroups
