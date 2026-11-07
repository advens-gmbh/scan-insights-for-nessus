import { useMemo } from "react";
import { X, Monitor, Cpu, Server, Shield, Clock, Wifi, FileText, Globe, Link, Network, AlertTriangle } from "lucide-react";
import { formatDate } from "../utils/format";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import { buildHostEntries } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import CopyButton from "../components/common/CopyButton";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";

interface Props {
  ip: string;
}// Props

export default function HostDetail({ ip }: Props) {
  const { closeHostPanel, openVulnPanel, hostPanelFileId, showInfo } = useUiStore();
  const files = useScanStore((s) => s.files);

  const relevantFiles = useMemo(
    () => hostPanelFileId ? files.filter((f) => f.id === hostPanelFileId) : files,
    [files, hostPanelFileId]
  );
  const allHosts = useMemo(() => buildHostEntries(relevantFiles), [relevantFiles]);
  const host = allHosts.find((h) => h.ip === ip);

  if (!host) {
    return null;
  }

  const sortedItems = host.items.filter((i) => showInfo || i.severity > 0).sort((a, b) => b.severity - a.severity || a.plugin_name.localeCompare(b.plugin_name));
  const macAddresses = host.mac ? host.mac.split(/[\n,]+/).map((m) => m.trim()).filter(Boolean) : [];
  const osValues     = host.os  ? host.os.split(/\n+/).map((o) => o.trim()).filter(Boolean) : [];

  const tcpPorts = [...new Set(
    host.items.filter((i) => i.port > 0 && i.protocol === "tcp").map((i) => i.port)
  )].sort((a, b) => a - b);
  const udpPorts = [...new Set(
    host.items.filter((i) => i.port > 0 && i.protocol === "udp").map((i) => i.port)
  )].sort((a, b) => a - b);
  const allPortsText = [
    tcpPorts.length > 0 ? `TCP: ${tcpPorts.join(", ")}` : "",
    udpPorts.length > 0 ? `UDP: ${udpPorts.join(", ")}` : "",
  ].filter(Boolean).join("\n");

  return (
    <>
      <div className="panel-overlay" onClick={closeHostPanel} />
      <div className="panel-drawer">
        {/* Header */}
        <div className="px-5 pt-5 pb-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Monitor size={18} className="text-violet-500 shrink-0" />
                <h2 className="font-mono font-bold text-xl text-slate-900 dark:text-slate-100">{host.ip}</h2>
                <CopyButton text={host.ip} variant="icon" label="Copy IP" />
              </div>
              {host.file_ids.length > 1 ? (
                <div className="mt-1 space-y-0.5">
                  {host.filenames.map((name, i) => (
                    <p key={i} className="text-xs text-slate-400 flex items-center gap-1">
                      <FileText size={11} className="shrink-0" />
                      {name}
                    </p>
                  ))}
                  <p className="text-[10px] text-slate-400 dark:text-slate-500 italic pl-4">
                    findings deduplicated across {host.file_ids.length} files
                  </p>
                </div>
              ) : (
                <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-1">
                  <FileText size={11} className="shrink-0" />
                  {host.filename}
                </p>
              )}
            </div>
            <button onClick={closeHostPanel} className="btn-ghost w-8 h-8 p-0 flex items-center justify-center">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Conflict warning */}
          {host.conflicts.length > 0 && (
            <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/40">
              <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
              <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed">
                <span className="font-semibold">Possible identity conflict - </span>
                {host.conflicts.join(" and ")} differ{host.conflicts.length > 1 ? "" : "s"} across scan files.
                This IP may represent different machines.
              </p>
            </div>
          )}

          {/* Host properties */}
          <div className="grid grid-cols-2 gap-3">
            {host.hostname && (
              <InfoCard icon={<Globe size={14} />} label="Hostname" value={host.hostname} />
            )}
            {host.domain && (
              <InfoCard icon={<Network size={14} />} label="Domain" value={host.domain} />
            )}
            {host.alt_hostnames.length > 0 && (
              <div className="card p-3">
                <div className="flex items-center justify-between gap-1.5 text-xs text-slate-400 dark:text-slate-500 mb-1">
                  <div className="flex items-center gap-1.5">
                    <Link size={14} />
                    <span>Alt. Hostnames{host.alt_hostnames.length > 1 ? ` (${host.alt_hostnames.length})` : ""}</span>
                  </div>
                  <CopyButton text={host.alt_hostnames.join("\n")} variant="icon" label="Copy" />
                </div>
                {host.alt_hostnames.map((name, i) => (
                  <p key={i} className="text-sm text-slate-700 dark:text-slate-200 font-medium leading-5">
                    {name}
                  </p>
                ))}
              </div>
            )}
            {osValues.length > 0 && (
              <div className="card p-3">
                <div className="flex items-center justify-between gap-1.5 text-xs text-slate-400 dark:text-slate-500 mb-1">
                  <div className="flex items-center gap-1.5">
                    <Cpu size={14} />
                    <span>Operating System{osValues.length > 1 ? ` (${osValues.length})` : ""}</span>
                  </div>
                  <CopyButton text={host.os!} variant="icon" label="Copy OS" />
                </div>
                {osValues.map((os, i) => (
                  <p key={i} className="text-sm text-slate-700 dark:text-slate-200 font-medium leading-5">
                    {os}
                  </p>
                ))}
              </div>
            )}
            {host.system_type && (
              <InfoCard icon={<Server size={14} />} label="System Type" value={host.system_type} />
            )}
            {macAddresses.length > 0 && (
              <div className="card p-3">
                <div className="flex items-center justify-between gap-1.5 text-xs text-slate-400 dark:text-slate-500 mb-1">
                  <div className="flex items-center gap-1.5">
                    <Wifi size={14} />
                    <span>MAC Address</span>
                  </div>
                  <CopyButton text={macAddresses.join("\n")} variant="icon" label="Copy MAC" />
                </div>
                {macAddresses.map((m, i) => (
                  <p key={i} className="text-sm text-slate-700 dark:text-slate-200 font-medium font-mono leading-5">
                    {m}
                  </p>
                ))}
              </div>
            )}
            {host.netbios && (
              <InfoCard icon={<Monitor size={14} />} label="NetBIOS Name" value={host.netbios} />
            )}
            <InfoCard
              icon={<Shield size={14} />}
              label="Credentialed Scan"
              value={host.credentialed_scan ? "Yes" : "No"}
            />
            {host.host_start && (
              <InfoCard icon={<Clock size={14} />} label="Scan Start" value={formatDate(host.host_start)} />
            )}
            {host.host_end && (
              <InfoCard icon={<Clock size={14} />} label="Scan End" value={formatDate(host.host_end)} />
            )}
          </div>

          {/* Open ports */}
          {(tcpPorts.length > 0 || udpPorts.length > 0) && (
            <div className="card p-3">
              <div className="flex items-center justify-between gap-1.5 text-xs text-slate-400 dark:text-slate-500 mb-2">
                <span className="font-semibold uppercase tracking-wider">
                  Open Ports ({tcpPorts.length + udpPorts.length})
                </span>
                <div className="flex items-center gap-1">
                  {tcpPorts.length > 0 && <CopyButton text={tcpPorts.join(", ")} label="TCP" />}
                  {udpPorts.length > 0 && <CopyButton text={udpPorts.join(", ")} label="UDP" />}
                  <CopyButton text={allPortsText} label="All" />
                </div>
              </div>
              {tcpPorts.length > 0 && (
                <div className="mb-1.5">
                  <span className="text-[10px] font-bold uppercase text-slate-400 mr-1.5">TCP</span>
                  <span className="text-xs font-mono text-slate-700 dark:text-slate-200 leading-relaxed">
                    {tcpPorts.join(", ")}
                  </span>
                </div>
              )}
              {udpPorts.length > 0 && (
                <div>
                  <span className="text-[10px] font-bold uppercase text-slate-400 mr-1.5">UDP</span>
                  <span className="text-xs font-mono text-slate-700 dark:text-slate-200 leading-relaxed">
                    {udpPorts.join(", ")}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Severity summary */}
          <div className="flex gap-2">
            {[
              { label: "Critical", value: host.severity_counts.critical, sev: 4 },
              { label: "High",     value: host.severity_counts.high,     sev: 3 },
              { label: "Medium",   value: host.severity_counts.medium,   sev: 2 },
              { label: "Low",      value: host.severity_counts.low,      sev: 1 },
              { label: "Info",     value: host.severity_counts.info,     sev: 0 },
            ]
              .filter((x) => x.value > 0 && (showInfo || x.sev > 0))
              .map((x) => (
                <div key={x.sev} className="flex-1 card p-2 text-center">
                  <div className="text-lg font-bold">{x.value}</div>
                  <SeverityBadge severity={x.sev} size="sm" />
                </div>
              ))}
          </div>

          {/* Vulnerabilities */}
          <div>
            <div className="flex items-center justify-between gap-3 mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Vulnerabilities ({sortedItems.length})
              </h3>
              <ShowInfoCheckbox />
            </div>
            <div className="space-y-1">
              {sortedItems.length === 0 && (
                <p className="text-sm text-slate-400 px-3 py-2">No findings above Info on this host.</p>
              )}
              {sortedItems.map((item, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
                  onClick={() => openVulnPanel(item.plugin_id, hostPanelFileId ?? undefined)}
                >
                  <SeverityBadge severity={item.severity} size="sm" />
                  <span className="text-sm text-slate-700 dark:text-slate-300 flex-1 min-w-0 truncate">
                    {item.plugin_name}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}// HostDetail

function InfoCard({icon, label, value,}: {icon: React.ReactNode; label: string; value: string;}) {
  return (
    <div className="card p-3">
      <div className="flex items-center justify-between gap-1.5 text-xs text-slate-400 dark:text-slate-500 mb-1">
        <div className="flex items-center gap-1.5">
          {icon}
          <span>{label}</span>
        </div>
        <CopyButton text={value} variant="icon" label="Copy" />
      </div>
      <p className="text-sm text-slate-700 dark:text-slate-200 font-medium truncate" title={value}>
        {value}
      </p>
    </div>
  );
}// InfoCard
