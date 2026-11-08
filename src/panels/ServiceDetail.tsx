import { useMemo, useState } from "react";
import { X } from "lucide-react";
import { useUiStore } from "../stores/uiStore";
import { buildHostEntries } from "../types/nessus";
import type { NessusFile, ServiceEntry } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import IpLink from "../components/common/IpLink";
import CopyButton from "../components/common/CopyButton";
import ShowInfoCheckbox from "../components/common/ShowInfoCheckbox";

const ROWS_PAGE = 200;
const HOSTS_COLLAPSED = 24; // 6 rows of 4 at the panel's full width

interface Props {
  service: ServiceEntry;
  files: NessusFile[];
  fileId?: string; // keeps the host and finding panels on the file being viewed
  onClose: () => void;
}// Props

export default function ServiceDetail({ service, files, fileId, onClose }: Props) {
  const { openVulnPanel, showInfo } = useUiStore();
  const [showAllHosts, setShowAllHosts] = useState(false);
  const [visibleFindings, setVisibleFindings] = useState(ROWS_PAGE);

  const hostnames = useMemo(
    () => new Map(buildHostEntries(files).map((h) => [h.ip, h.hostname ?? h.netbios])),
    [files]
  );

  const findings = showInfo ? service.findings : service.findings.filter((f) => f.severity > 0);
  const hostIps = showAllHosts ? service.host_ips : service.host_ips.slice(0, HOSTS_COLLAPSED);

  return (
    <>
      <div className="panel-overlay" onClick={onClose} />
      <div className="panel-drawer">
        {/* Header */}
        <div className="px-5 pt-5 pb-4 border-b border-ink-200 dark:border-ink-700">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="font-mono font-bold text-xl text-ink-900 dark:text-ink-100 line-clamp-2 break-all" title={service.key}>{service.key}</h2>
              {service.svc_names.length > 0 && (
                <p className="text-sm text-ink-500 dark:text-ink-400 mt-0.5 line-clamp-2 break-all" title={service.svc_names.join(", ")}>{service.svc_names.join(", ")}</p>
              )}
            </div>
            <button onClick={onClose} className="btn-ghost w-8 h-8 p-0 flex items-center justify-center shrink-0">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Hosts */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-400 dark:text-ink-500 mb-2">
              Hosts ({service.host_ips.length})
            </h3>
            <div className="flex flex-wrap gap-1.5 mb-3">
              <CopyButton text={service.host_ips.join("\n")} label="Copy All IPs" />
              <CopyButton text={service.host_ips.map((ip) => `${ip}:${service.port}`).join("\n")} label="Copy All IP:Ports" />
            </div>
            <div className="grid gap-x-3 gap-y-2 px-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))" }}>
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
          </div>

          {/* Findings */}
          <div>
            <div className="flex items-center justify-between gap-3 mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-400 dark:text-ink-500">
                Findings ({findings.length})
              </h3>
              <ShowInfoCheckbox />
            </div>
            <div className="space-y-0.5">
              {findings.length === 0 && (
                <p className="text-sm text-ink-400 px-3 py-2">No findings above Info on this port.</p>
              )}
              {findings.slice(0, visibleFindings).map((f) => (
                <button
                  key={f.plugin_id}
                  onClick={() => openVulnPanel(f.plugin_id, fileId)}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left hover:bg-ink-50 dark:hover:bg-ink-700/50 transition-colors"
                >
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="text-sm text-ink-700 dark:text-ink-300 flex-1 min-w-0 truncate">{f.plugin_name}</span>
                  <span className="text-xs text-ink-400 shrink-0">
                    {f.host_count} {f.host_count === 1 ? "host" : "hosts"}
                  </span>
                </button>
              ))}
              <ShowMore shown={visibleFindings} total={findings.length} onClick={() => setVisibleFindings((n) => n + ROWS_PAGE)} />
            </div>
          </div>
        </div>
      </div>
    </>
  );
}// ServiceDetail

function ShowMore({ shown, total, onClick }: { shown: number; total: number; onClick: () => void }) {
  if (total <= shown) {
    return null;
  }

  return (
    <button onClick={onClick} className="btn-ghost w-full justify-center text-xs">
      Show {Math.min(ROWS_PAGE, total - shown)} more of {total - shown} remaining
    </button>
  );
}// ShowMore
