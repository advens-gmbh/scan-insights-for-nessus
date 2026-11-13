import { useMemo, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import type { ScanFile } from "../types/nessus";
import { useQuery } from "../data/query";
import { formatDuration, formatScanStart } from "../utils/dashboard";
import { fileWindow } from "../utils/fileFacts";
import { splitTargets, targetCoverage } from "../utils/fileTargets";
import type { TargetCoverage } from "../utils/fileTargets";
import IpLink from "../components/common/IpLink";
import CopyButton from "../components/common/CopyButton";
import { PanelButtons, Section, useEscape } from "./PanelParts";
import { CountBoxes } from "./FindingParts";

const HOSTS_COLLAPSED = 24; // 6 rows of 4 at the panel's full width
const TARGETS_COLLAPSED = 10;

// a host of the file, as file_host_list answers it (sorted by address)
interface BriefHost {
  ip: string;
  name: string;
  hostname: string | null;
  credentialed_scan: boolean;
}// BriefHost

const NO_HOSTS: BriefHost[] = [];

export default function FileDetailPanel({ fileId }: { fileId: string }) {
  const closeFilePanel = useUiStore((s) => s.closeFilePanel);
  const file = useScanStore((s) => s.files.find((f) => f.id === fileId));
  useEscape(closeFilePanel);

  if (!file) {
    return null;
  }

  return (
    <aside className="panel-drawer border-l border-ink-200 dark:border-ink-700" aria-label="Scan file details">
      <FileContent key={file.id} file={file} onClose={closeFilePanel} />
    </aside>
  );
}// FileDetailPanel

function FileContent({ file, onClose }: { file: ScanFile; onClose: () => void }) {
  const listed = useQuery<BriefHost[]>("file_host_list", { id: file.id });
  const hosts = listed ?? NO_HOSTS;
  // nothing counts as missed until the hosts are here
  const coverage = useMemo(() => (listed ? targetCoverage(splitTargets(file.target), listed) : []), [file.target, listed]);
  const missed = coverage.filter((t) => t.ips.length === 0);
  const scan = fileWindow(file);
  const credentialed = file.credentialed;
  const withoutCredentials = credentialed > 0 ? hosts.filter((h) => !h.credentialed_scan) : [];
  const name = file.filename.replace(/\.nessus$/i, "");
  const scanned = scan.start ? `${formatScanStart(scan.start)}${scan.durationMs !== null ? `, ran for ${formatDuration(scan.durationMs)}` : ""}` : null;

  return (
    <>
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-ink-200 dark:border-ink-700 flex flex-col gap-2.5">
        <div className="flex items-center gap-2 min-w-0">
          <h2 className="text-title font-semibold text-ink-900 dark:text-ink-50 truncate" title={file.filename}>{name}</h2>
          <PanelButtons onClose={onClose} />
        </div>
        <p className="text-small text-ink-500 dark:text-ink-400 truncate">
          {[file.report_name, `${file.host_count} ${file.host_count === 1 ? "host" : "hosts"}`].filter(Boolean).join(" · ")}
        </p>
        <CountBoxes counts={file.counts} />
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-4">
        {(file.compliance_skipped ?? 0) > 0 && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-warn-50 dark:bg-warn-900/20 border border-warn-200 dark:border-warn-700/40">
            <AlertTriangle size={14} className="shrink-0 mt-0.5 text-warn-600 dark:text-warn-400" />
            <p className="text-small text-warn-800 dark:text-warn-300 leading-relaxed">
              <span className="font-semibold">{file.compliance_skipped!.toLocaleString()} compliance check {file.compliance_skipped === 1 ? "result" : "results"} left out.</span>{" "}
              The app doesn't show compliance results yet. The vulnerabilities in this file are all here.
            </p>
          </div>
        )}

        <Section title="Details">
          <dl className="grid grid-cols-[auto_minmax(0,1fr)_auto] gap-x-6 gap-y-1 items-baseline">
            {file.report_name && <Detail label="Scan name" value={file.report_name} />}
            {scanned && <Detail label="Scanned" value={scanned} />}
            <Detail
              label="Credentialed"
              value={
                credentialed === 0 ? "No"
                  : credentialed === file.host_count ? `Yes, all ${file.host_count} hosts`
                  : `${credentialed} of ${file.host_count} hosts`
              }
            />
            <Detail label="File" value={file.path} copy />
          </dl>
        </Section>

        <Section
          title={`Targets (${coverage.length})${missed.length > 0 ? ` · ${missed.length} not reached` : ""}`}
          actions={coverage.length > 0 && (
            <div className="flex items-center gap-1">
              {missed.length > 0 && missed.length < coverage.length && (
                <CopyButton text={coverage.filter((t) => t.ips.length > 0).map((t) => t.target).join("\n")} label="Copy reached" />
              )}
              {missed.length > 0 && <CopyButton text={missed.map((t) => t.target).join("\n")} label="Copy not reached" />}
              <CopyButton text={coverage.map((t) => t.target).join("\n")} label="Copy all" />
            </div>
          )}
        >
          {coverage.length === 0 ? (
            <p className="text-ink-500 dark:text-ink-400">The scan file doesn't list its targets.</p>
          ) : (
            <TargetList coverage={coverage} fileId={file.id} />
          )}
        </Section>

        <IpSection
          title={`Hosts (${file.host_count})`}
          hosts={hosts}
          fileId={file.id}
          empty="No hosts in this scan file."
        />

        {withoutCredentials.length > 0 && (
          <IpSection
            title={`Without working credentials (${withoutCredentials.length})`}
            note="Local checks didn't run on these hosts, so their findings may be incomplete."
            hosts={withoutCredentials}
            fileId={file.id}
          />
        )}
      </div>
    </>
  );
}// FileContent

function TargetList({ coverage, fileId }: { coverage: TargetCoverage[]; fileId: string }) {
  const [showAll, setShowAll] = useState(false);
  const ordered = [...coverage.filter((t) => t.ips.length === 0), ...coverage.filter((t) => t.ips.length > 0)];
  const shown = showAll ? ordered : ordered.slice(0, TARGETS_COLLAPSED);

  return (
    <>
      <ul className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-6 gap-y-1 tabular-nums">
        {shown.map((t) => (
          <li key={t.target} className="contents">
            <span className="truncate" title={t.target}>{t.target}</span>
            {t.ips.length === 0 ? (
              <span className="flex items-center gap-1 text-warn-700 dark:text-warn-400">
                <AlertTriangle size={13} /> not reached
              </span>
            ) : t.size !== null ? (
              <span className="text-ink-500 dark:text-ink-400">{t.ips.length} of {t.size.toLocaleString()} answered</span>
            ) : t.ips[0] !== t.target ? (
              <span className="text-ink-500 dark:text-ink-400" title="The address the name resolved to during the scan">
                resolved to <IpLink ip={t.ips[0]} fileId={fileId} />
                {t.ips.length > 1 && ` +${t.ips.length - 1}`}
              </span>
            ) : (
              <span className="text-ink-500 dark:text-ink-400">reached</span>
            )}
          </li>
        ))}
      </ul>
      {ordered.length > TARGETS_COLLAPSED && (
        <button onClick={() => setShowAll((v) => !v)} className="btn-ghost w-full justify-center text-caption mt-2">
          {showAll ? "Show less" : `Show all ${ordered.length}`}
        </button>
      )}
    </>
  );
}// TargetList

function Detail({ label, value, copy = false }: { label: string; value: string; copy?: boolean }) {
  return (
    <>
      <dt className="text-ink-500 dark:text-ink-400">{label}</dt>
      <dd className="min-w-0 break-words">{value}</dd>
      <dd className="-my-1">{copy && <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} variant="icon" />}</dd>
    </>
  );
}// Detail

function IpSection({ title, note, hosts, fileId, empty }: {
  title: string;
  note?: string;
  hosts: { ip: string; hostname: string | null }[];
  fileId: string;
  empty?: string;
}) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? hosts : hosts.slice(0, HOSTS_COLLAPSED);

  return (
    <Section title={title}>
      {note && <p className="mb-2 text-ink-500 dark:text-ink-400">{note}</p>}
      {hosts.length === 0 ? (
        <p className="text-ink-500 dark:text-ink-400">{empty}</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-1 mb-3">
            <CopyButton text={hosts.map((h) => h.ip).join("\n")} label="Copy IPs" />
            <CopyButton text={hosts.map((h) => (h.hostname ? `${h.ip} (${h.hostname})` : h.ip)).join("\n")} label="Copy IPs with names" />
          </div>
          <div className="grid gap-x-3 gap-y-1.5 tabular-nums" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))" }}>
            {shown.map((h) => (
              <div key={h.ip} title={h.hostname ?? undefined}>
                <IpLink ip={h.ip} fileId={fileId} className="text-left break-all" />
              </div>
            ))}
          </div>
          {hosts.length > HOSTS_COLLAPSED && (
            <button onClick={() => setShowAll((v) => !v)} className="btn-ghost w-full justify-center text-caption mt-2">
              {showAll ? "Show less" : `Show all ${hosts.length}`}
            </button>
          )}
        </>
      )}
    </Section>
  );
}// IpSection
