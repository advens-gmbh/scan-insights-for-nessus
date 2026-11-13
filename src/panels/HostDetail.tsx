import { useState } from "react";
import { AlertTriangle } from "lucide-react";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import { osGuesses } from "../types/nessus";
import type { FindingRow, HostRow } from "../types/nessus";
import { useQuery } from "../data/query";
import { formatDuration, formatScanStart } from "../utils/format";
import { fileStart } from "../utils/fileFacts";

const FILES_SHOWN = 3;
import { groupByPort, sortFindings } from "../utils/hostFindings";
import SeverityBadge from "../components/common/SeverityBadge";
import CopyButton from "../components/common/CopyButton";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import Select, { fileOption } from "../components/common/Select";
import { PanelButtons, Section, Tag, useEscape } from "./PanelParts";
import { CountBoxes, Cvss, FindingGroups, FindingName, itemScore } from "./FindingParts";

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
  const openFilePanel = useUiStore((s) => s.openFilePanel);

  const [fileScope, setFileScope] = useState(hostPanelFileId ?? "all");

  const [allFiles, setAllFiles] = useState(false);
  const detail = useQuery<{ host: HostRow; findings: FindingRow[]; tcp: number[]; udp: number[] } | null>("host_detail", { ip, file: fileScope === "all" ? null : fileScope });

  if (!detail) {
    return null;
  }

  const acrossFiles = detail.host;
  const host = acrossFiles;
  const scopeFileId = fileScope === "all" ? undefined : fileScope;
  const findings = detail.findings.filter((i) => showInfo || i.severity > 0);
  const { tcp, udp } = detail;
  const osValues = osGuesses(host.os);
  const macs = host.mac ? host.mac.split(/[\n,]+/).map((m) => m.trim()).filter(Boolean) : [];
  const multiFile = acrossFiles.file_ids.length > 1;
  // newest scan first, with its date
  const scanFiles = acrossFiles.file_ids.map((id, i) => {
    const f = files.find((x) => x.id === id);
    const start = f ? fileStart(f) : null;
    return { id, filename: acrossFiles.filenames[i], start, date: start !== null ? formatScanStart(new Date(start)).slice(0, 10) : "" };
  }).sort((a, b) => (b.start ?? 0) - (a.start ?? 0));

  return (
    <>
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-ink-200 dark:border-ink-700 flex flex-col gap-2.5">
        <div className="flex items-center gap-2">
          <h2 className="text-title font-semibold tabular-nums text-ink-900 dark:text-ink-50">{host.ip}</h2>
          <CopyButton text={host.ip} variant="icon" label="Copy IP" />
          {host.credentialed_scan && <Tag>Credentialed</Tag>}
          {host.os_unsupported && <Tag title="The vendor no longer supports this operating system">Unsupported OS</Tag>}
          {multiFile && <Tag>{acrossFiles.file_ids.length} files</Tag>}
          <PanelButtons onClose={onClose} />
        </div>
        {(host.hostname || host.netbios || osValues.length > 0) && (
          <p className="text-small text-ink-500 dark:text-ink-400 truncate">
            {[host.hostname ?? host.netbios, osValues[0]].filter(Boolean).join(" · ")}
          </p>
        )}
        <CountBoxes counts={host.severity_counts} />
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-4">
        {acrossFiles.conflicts.length > 0 && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-warn-50 dark:bg-warn-900/20 border border-warn-200 dark:border-warn-700/40">
            <AlertTriangle size={14} className="shrink-0 mt-0.5 text-warn-600 dark:text-warn-400" />
            <p className="text-small text-warn-800 dark:text-warn-300 leading-relaxed">
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
            {multiFile ? (
              scanFiles[0]?.start != null && <Detail label="Last scanned" value={formatScanStart(new Date(scanFiles[0].start))} />
            ) : host.start !== null && (
              <Detail
                label="Scanned"
                value={`${formatScanStart(new Date(host.start))}${host.duration_ms !== null ? `, ran for ${formatDuration(host.duration_ms)}` : ""}`}
              />
            )}
            <dt className="text-ink-500 dark:text-ink-400">{multiFile ? "Scan files" : "Scan file"}</dt>
            <dd className="col-span-2 min-w-0">
              <div className="flex flex-col items-start gap-0.5">
                {(allFiles ? scanFiles : scanFiles.slice(0, FILES_SHOWN)).map((f) => (
                  <span key={f.id} className="max-w-full flex items-baseline gap-1.5 min-w-0">
                    <button
                      onClick={() => openFilePanel(f.id)}
                      title={`${f.filename}\nShow the scan file`}
                      className="min-w-0 truncate text-left text-accent-700 dark:text-accent-400 hover:underline"
                    >
                      {f.filename.replace(/\.nessus$/i, "")}
                    </button>
                    {f.date && <span className="shrink-0 text-small text-ink-500 dark:text-ink-400 tabular-nums">· {f.date}</span>}
                  </span>
                ))}
                {scanFiles.length > FILES_SHOWN && (
                  <button onClick={() => setAllFiles(!allFiles)} className="mt-0.5 text-small font-semibold text-accent-700 dark:text-accent-400 hover:underline">
                    {allFiles ? "Show fewer" : `Show all ${scanFiles.length}`}
                  </button>
                )}
              </div>
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
              {multiFile && (
                <Select
                  value={fileScope}
                  onChange={setFileScope}
                  size="xs"
                  ariaLabel="Show the findings from"
                  title="Show the findings from one scan file, or merged from all of them"
                  className="w-44"
                  options={[{ value: "all", label: "All files" }, ...acrossFiles.file_ids.map((id, i) => {
                    const f = files.find((x) => x.id === id);
                    return f ? fileOption(f) : { value: id, label: acrossFiles.filenames[i].replace(/\.nessus$/i, "") };
                  })]}
                />
              )}
              <ShowInfoCheckbox />
              <label className="flex items-center gap-1.5 text-caption text-ink-500 dark:text-ink-400 cursor-pointer select-none shrink-0">
                <input type="checkbox" checked={grouped} onChange={toggleGrouped} className="rounded accent-accent-600" />
                Group by port
              </label>
            </div>
          }
        >
          {findings.length === 0 ? (
            <p className="text-ink-500 dark:text-ink-400 text-center py-4">No findings above Info on this host.</p>
          ) : grouped ? (
            <FindingGroups
              groups={groupByPort(findings)}
              noun={["port", "ports"]}
              fileId={scopeFileId}
              showInfo={showInfo}
              header={(g) => (
                <>
                  <span className="w-20 shrink-0 font-semibold tabular-nums text-ink-900 dark:text-ink-50">{g.port > 0 ? `${g.port}/${g.protocol}` : "General"}</span>
                  <span className="truncate text-ink-500 dark:text-ink-400">{g.port > 0 ? g.service : "not tied to a port"}</span>
                </>
              )}
            />
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

function FindingList({ items, fileId }: { items: FindingRow[]; fileId?: string }) {
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);

  return (
    <div className="card overflow-hidden">
      <table className="w-full table-fixed text-body tabular-nums">
        <colgroup>
          <col className="w-[5.5rem]" />
          <col />
          <col className="w-[6.5rem]" />
          <col className="w-[5.5rem]" />
        </colgroup>
        <thead>
          <tr className="bg-ink-100 dark:bg-ink-700/60 text-small text-left text-ink-500 dark:text-ink-300">
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
                <FindingName pluginId={item.plugin_id} name={item.plugin_name} fileId={fileId} />
              </td>
              <td className="px-3 py-1.5 truncate text-ink-500 dark:text-ink-400">{item.port > 0 ? `${item.port}/${item.protocol}` : "-"}</td>
              <td className="px-3 py-1.5 text-right"><Cvss score={itemScore(item)} severity={item.severity} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}// FindingList
