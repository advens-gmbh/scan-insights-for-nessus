import { useMemo, useState } from "react";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import { buildHostEntries, buildServiceEntries, buildVulnEntries, isHttps, isPlainHttp, ratedScore } from "../types/nessus";
import { groupByHost } from "../utils/hostFindings";
import { httpUrl, httpsUrl } from "../utils/webUrls";
import SeverityBadge from "../components/common/SeverityBadge";
import IpLink from "../components/common/IpLink";
import CopyButton from "../components/common/CopyButton";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";
import { PanelButtons, Section, Tag, useEscape } from "./PanelParts";
import { CountBoxes, Cvss, FindingGroups, FindingName } from "./FindingParts";

const ROWS_PAGE = 200;
const HOSTS_COLLAPSED = 24; // 6 rows of 4 at the panel's full width

export default function ServiceDetail({ serviceKey }: { serviceKey: string }) {
  const closeServicePanel = useUiStore((s) => s.closeServicePanel);
  useEscape(closeServicePanel);

  return (
    <aside className="panel-drawer border-l border-ink-200 dark:border-ink-700" aria-label="Service details">
      <ServiceContent key={serviceKey} serviceKey={serviceKey} onClose={closeServicePanel} />
    </aside>
  );
}// ServiceDetail

function ServiceContent({ serviceKey, onClose }: { serviceKey: string; onClose: () => void }) {
  const fileId = useUiStore((s) => s.servicePanelFileId) ?? undefined;
  const showInfo = useUiStore((s) => s.showInfo);
  const grouped = useUiStore((s) => s.groupServiceFindings);
  const toggleGrouped = useUiStore((s) => s.toggleGroupServiceFindings);
  const allFiles = useScanStore((s) => s.files);

  const [showAllHosts, setShowAllHosts] = useState(false);
  const [visibleFindings, setVisibleFindings] = useState(ROWS_PAGE);

  const files = useMemo(() => (fileId ? allFiles.filter((f) => f.id === fileId) : allFiles), [allFiles, fileId]);
  const service = useMemo(() => buildServiceEntries(files).find((s) => s.key === serviceKey), [files, serviceKey]);
  const hosts = buildHostEntries(files);
  const hostnames = useMemo(() => new Map(hosts.map((h) => [h.ip, h.hostname ?? h.netbios])), [hosts]);
  const scores = useMemo(() => new Map(buildVulnEntries(files).map((v) => [v.plugin_id, ratedScore(v)])), [files]);

  if (!service) {
    return null;
  }

  const { port, protocol } = service;
  const names = service.svc_names.join(" ");
  const findings = showInfo ? service.findings : service.findings.filter((f) => f.severity > 0);
  const hostIps = showAllHosts ? service.host_ips : service.host_ips.slice(0, HOSTS_COLLAPSED);
  const httpUrls = isPlainHttp(port, names) ? service.host_ips.map((ip) => httpUrl(ip, port)) : [];
  const httpsUrls = isHttps(port, names) ? service.host_ips.map((ip) => httpsUrl(ip, port)) : [];
  const seenIn = files.filter((f) => f.hosts.some((h) => h.items.some((i) => i.port === port && i.protocol === protocol))).length;
  const subtitle = [
    service.svc_names.join(", "),
    `${service.host_ips.length} ${service.host_ips.length === 1 ? "host" : "hosts"}`,
    allFiles.length > 1 && !fileId ? `seen in ${seenIn} ${seenIn === 1 ? "file" : "files"}` : null,
  ].filter(Boolean).join(" · ");

  return (
    <>
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-ink-200 dark:border-ink-700 flex flex-col gap-2.5">
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-semibold tabular-nums text-ink-900 dark:text-ink-50">{service.key}</h2>
          {service.exploit_available && <Tag danger>Exploit available</Tag>}
          <PanelButtons onClose={onClose} />
        </div>
        <p className="text-[13px] text-ink-500 dark:text-ink-400 truncate" title={subtitle}>{subtitle}</p>
        <CountBoxes counts={service.severity_counts} />
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-4">
        <Section title={`Hosts (${service.host_ips.length})`}>
          <div className="flex flex-wrap items-center gap-1 mb-3">
            <CopyButton text={service.host_ips.join("\n")} label="Copy IPs" />
            <CopyButton text={service.host_ips.map((ip) => `${ip}:${port}`).join("\n")} label="Copy IP:port" />
            {httpUrls.length > 0 && <CopyButton text={httpUrls.join("\n")} label="Copy HTTP URLs" />}
            {httpsUrls.length > 0 && <CopyButton text={httpsUrls.join("\n")} label="Copy HTTPS URLs" />}
          </div>
          <div className="grid gap-x-3 gap-y-1.5 tabular-nums" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))" }}>
            {hostIps.map((ip) => (
              <div key={ip} title={hostnames.get(ip) ?? undefined}>
                <IpLink ip={ip} fileId={fileId} className="text-left break-all" />
              </div>
            ))}
          </div>
          {service.host_ips.length > HOSTS_COLLAPSED && (
            <button onClick={() => setShowAllHosts((v) => !v)} className="btn-ghost w-full justify-center text-xs mt-2">
              {showAllHosts ? "Show less" : `Show all ${service.host_ips.length}`}
            </button>
          )}
        </Section>

        <Section
          title={`Findings (${findings.length})`}
          actions={
            <div className="flex items-center gap-3">
              <ShowInfoCheckbox />
              <label className="flex items-center gap-1.5 text-xs text-ink-500 dark:text-ink-400 cursor-pointer select-none shrink-0">
                <input type="checkbox" checked={grouped} onChange={toggleGrouped} className="rounded accent-accent-600" />
                Group by host
              </label>
            </div>
          }
        >
          {findings.length === 0 ? (
            <p className="text-ink-500 dark:text-ink-400 text-center py-4">No findings above Info on this port.</p>
          ) : grouped ? (
            <FindingGroups
              groups={groupByHost(hosts, port, protocol, (i) => showInfo || i.severity > 0)}
              noun={["host", "hosts"]}
              fileId={fileId}
              showInfo={showInfo}
              header={(g) => (
                <>
                  <span className="w-28 shrink-0" onClick={(e) => e.stopPropagation()}><IpLink ip={g.ip} fileId={fileId} className="text-left font-medium" /></span>
                  <span className="truncate text-ink-500 dark:text-ink-400">{g.hostname}</span>
                </>
              )}
            />
          ) : (
            <div className="card overflow-hidden">
              <table className="w-full table-fixed text-sm tabular-nums">
                <colgroup>
                  <col className="w-[5.5rem]" />
                  <col />
                  <col className="w-[4.5rem]" />
                  <col className="w-[5.5rem]" />
                </colgroup>
                <thead>
                  <tr className="bg-ink-100 dark:bg-ink-700/60 text-[13px] text-left text-ink-500 dark:text-ink-300">
                    <th className="px-3 py-2 font-semibold">Severity</th>
                    <th className="px-3 py-2 font-semibold">Name</th>
                    <th className="px-3 py-2 font-semibold text-right">Hosts</th>
                    <th className="px-3 py-2 font-semibold text-right">CVSS</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.slice(0, visibleFindings).map((f) => (
                    <FindingRow key={f.plugin_id} pluginId={f.plugin_id} name={f.plugin_name} severity={f.severity} hostCount={f.host_count} fileId={fileId}>
                      <Cvss score={scores.get(f.plugin_id) ?? null} severity={f.severity} />
                    </FindingRow>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!grouped && findings.length > visibleFindings && (
            <button onClick={() => setVisibleFindings((n) => n + ROWS_PAGE)} className="btn-ghost w-full justify-center text-xs mt-2">
              Show {Math.min(ROWS_PAGE, findings.length - visibleFindings)} more of {findings.length - visibleFindings} remaining
            </button>
          )}
        </Section>
      </div>
    </>
  );
}// ServiceContent

function FindingRow({ pluginId, name, severity, hostCount, fileId, children }: {
  pluginId: number;
  name: string;
  severity: number;
  hostCount: number;
  fileId?: string;
  children: React.ReactNode;
}) {
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);

  return (
    <tr onClick={() => openVulnPanel(pluginId, fileId)} className="border-t border-ink-100 dark:border-ink-700 cursor-pointer hover:bg-ink-50 dark:hover:bg-ink-800">
      <td className="px-3 py-1.5"><SeverityBadge severity={severity} size="sm" /></td>
      <td className="px-3 py-1.5 truncate"><FindingName pluginId={pluginId} name={name} fileId={fileId} /></td>
      <td className="px-3 py-1.5 text-right text-ink-700 dark:text-ink-200">{hostCount}</td>
      <td className="px-3 py-1.5 text-right">{children}</td>
    </tr>
  );
}// FindingRow
