import { useMemo } from "react";
import { TriangleAlert } from "lucide-react";
import { useScanStore } from "../stores/scanStore";
import { buildHostEntries, SEVERITY_ORDER, SEVERITY_LABELS, SEVERITY_COLORS } from "../types/nessus";
import NetworkGraph from "../components/topology/NetworkGraph";
import SeverityPills from "../components/common/SeverityPills";
import { useSeverityFilter } from "../hooks/useSeverityFilter";
import { countBySeverity, severitiesOf } from "../utils/severityFilter";
import EmptyFilesNotice from "./EmptyFilesNotice";

const ALL_SEVERITIES = new Set<number>(SEVERITY_ORDER);
// hosts with only info findings would bury the rest of the graph
const START_SELECTED = [4, 3, 2, 1];

export default function Topology() {
  const files = useScanStore((s) => s.files);
  const { selected, toggle } = useSeverityFilter("topology", START_SELECTED);
  const hosts = useMemo(() => buildHostEntries(files), [files]);
  const shown = useMemo(() => (selected.length === 0 ? ALL_SEVERITIES : new Set(selected)), [selected]);
  const severityCounts = useMemo(() => countBySeverity(hosts.map((h) => severitiesOf(h.severity_counts))), [hosts]);

  if (files.length === 0) {
    return <EmptyFilesNotice />;
  }

  return (
    <div className="flex flex-col gap-4 h-full" style={{ height: "calc(100vh - 100px)" }}>
      {/* Controls */}
      <div className="flex items-center gap-4 flex-wrap shrink-0">
        <h2 className="font-semibold text-slate-700 dark:text-slate-200">Network Topology</h2>
        <p className="text-xs text-slate-400">
          Subnet-inferred topology - hosts grouped by /24 subnet, colored by worst severity.
        </p>
        <div className="ml-auto">
          <SeverityPills counts={severityCounts} selected={selected} onToggle={toggle} />
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 flex-wrap text-xs text-slate-500 dark:text-slate-400 shrink-0">
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: SEVERITY_COLORS[sev]?.hex }} />
            {SEVERITY_LABELS[sev]}
          </span>
        ))}
        <span className="flex items-center gap-1.5" title="Virtual grouping node - represents a /24 subnet, not a real host">
          <span className="w-8 h-3.5 rounded shrink-0 bg-slate-200 dark:bg-slate-700 border border-slate-400 dark:border-slate-500" />
          Subnet hub
        </span>
        <span className="flex items-center gap-1.5" title="Two subnets appeared in the same scan file - a connection exists somewhere, but the routing host is unknown">
          <span className="w-8 h-0 shrink-0" style={{ borderTop: "2px dashed #64748b" }} />
          Inter-subnet link
        </span>
        <span className="flex items-center gap-1.5" title="Confirmed routing path - the gateway was identified via traceroute data (plugin 10287) and is known to route traffic between these two subnets">
          <span className="w-8 h-0 shrink-0" style={{ borderTop: "2px solid rgb(20,184,166)" }} />
          Gateway link
        </span>
        <span className="flex items-center gap-1.5" title="Host identified as a network router via traceroute (plugin 10287) - connected to both subnet hubs with teal lines">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
            stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
            className="shrink-0">
            <circle cx="8" cy="8" r="3" />
            <line x1="8" y1="5" x2="8" y2="1.5" /><polyline points="6.5,3 8,1.5 9.5,3" />
            <line x1="11" y1="8" x2="14.5" y2="8" /><polyline points="13,6.5 14.5,8 13,9.5" />
            <line x1="8" y1="11" x2="8" y2="14.5" /><polyline points="6.5,13 8,14.5 9.5,13" />
            <line x1="5" y1="8" x2="1.5" y2="8" /><polyline points="3,6.5 1.5,8 3,9.5" />
          </svg>
          Gateway
        </span>
        <span className="flex items-center gap-1.5" title="Same MAC address or NetBIOS name seen on IPs in multiple /24 subnets - likely a firewall, router, or dual-NIC server">
          <span className="w-3 h-3 rounded-full shrink-0 border-2"
            style={{ borderStyle: "dashed", borderColor: "rgb(20,184,166)" }} />
          Multi-homed
        </span>
      </div>

      {/* Multi-file reliability warning */}
      {files.length > 1 && (
        <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/50 text-xs text-amber-800 dark:text-amber-300 shrink-0">
          <TriangleAlert size={14} className="shrink-0 mt-0.5" />
          <span>
            Topology connections are inferred from IP addresses only - no physical device identity is verified.
            If the loaded scan files are from <strong>different, unrelated environments</strong>, hosts or gateways
            sharing the same IP (e.g. <span className="font-mono">10.0.0.1</span>) will be incorrectly shown as connected.
            This view is only reliable when all files come from the <strong>same network environment</strong>.
          </span>
        </div>
      )}

      {/* Graph */}
      <div className="card flex-1 overflow-hidden">
        <NetworkGraph
          key={selected.join(",")}
          hosts={hosts}
          files={files}
          severityFilter={shown}
        />
      </div>

      <p className="text-xs text-slate-400 text-center shrink-0">
        {hosts.length} hosts across {new Set(hosts.map((h) => h.ip.split(".").slice(0, 3).join("."))).size} subnets.
        Click any host node to view details.
      </p>
    </div>
  );
}// Topology
