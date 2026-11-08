import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { X, ExternalLink, ChevronDown, ChevronRight, AlertTriangle } from "lucide-react";
import { isWebUrl, metasploitSearchUrl, openExternal } from "../utils/openExternal";
import { formatNessusDate } from "../utils/format";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import { buildVulnEntries, cvssSeverity, isPlainHttp, isHttps, ratingDifferences, SEVERITY_COLORS, SEVERITY_LABELS } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import IpLink from "../components/common/IpLink";
import CopyButton from "../components/common/CopyButton";
import SearchBar from "../components/common/SearchBar";
import { Section, Tag, useEscape } from "./PanelParts";

const HOST_ROWS_PAGE = 200;

interface Props {
  pluginId: number;
}// Props

export default function VulnDetail({ pluginId }: Props) {
  const closeVulnPanel = useUiStore((s) => s.closeVulnPanel);

  useEscape(closeVulnPanel);

  return (
    <aside className="panel-drawer border-l border-ink-200 dark:border-ink-700" aria-label="Finding details">
      <VulnContent key={pluginId} pluginId={pluginId} onClose={closeVulnPanel} />
    </aside>
  );
}// VulnDetail

function VulnContent({ pluginId, onClose }: { pluginId: number; onClose: () => void }) {
  const vulnPanelFileId = useUiStore((s) => s.vulnPanelFileId);
  const files = useScanStore((s) => s.files);

  const [fileFilter, setFileFilter] = useState(vulnPanelFileId ?? "all");
  const [ipSearch, setIpSearch] = useState("");
  const [hiddenOutput, setHiddenOutput] = useState<Set<number>>(new Set());
  const [visibleRows, setVisibleRows] = useState(HOST_ROWS_PAGE);

  const allVulns = useMemo(() => buildVulnEntries(files), [files]);
  const filteredFiles = useMemo(
    () => (fileFilter === "all" ? files : files.filter((f) => f.id === fileFilter)),
    [files, fileFilter]
  );
  const filteredVulns = useMemo(() => buildVulnEntries(filteredFiles), [filteredFiles]);

  const acrossFiles = allVulns.find((v) => v.plugin_id === pluginId);
  if (!acrossFiles) {
    return null;
  }

  // With one file selected, the rating and details are that file's own, as in the table.
  const vuln = filteredVulns.find((v) => v.plugin_id === pluginId) ?? acrossFiles;
  const differences = ratingDifferences(acrossFiles);

  const hosts = acrossFiles.affected_hosts.filter((h) =>
    (fileFilter === "all" || h.file_id === fileFilter) && (!ipSearch || h.ip.includes(ipSearch))
  );

  // Lists to copy are de-duplicated (same host and port can be present in multiple files)
  const ips = [...new Set(hosts.map((h) => h.ip))];
  const ipPorts = [...new Set(hosts.map((h) => `${h.ip}:${h.port}`))];
  const httpUrls = [...new Set(hosts.filter((h) => isPlainHttp(h.port, h.svc_name)).map((h) => httpUrl(h.ip, h.port)))];
  const httpsUrls = [...new Set(hosts.filter((h) => isHttps(h.port, h.svc_name)).map((h) => httpsUrl(h.ip, h.port)))];
  const withOutput = hosts.filter((h) => h.plugin_output);
  const allHidden = withOutput.length > 0 && withOutput.every((h) => hiddenOutput.has(h.id));

  const toggleOutput = (id: number) => {
    setHiddenOutput((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }

      return next;
    });
  };

  const showFile = files.length > 1;
  const columns = 4;
  const hasScores = vuln.cvss4 !== null || vuln.cvss3 !== null || vuln.cvss2 !== null || vuln.vpr !== null || vuln.epss !== null;

  return (
    <>
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-ink-200 dark:border-ink-700 flex flex-col gap-2.5">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={vuln.severity} />
          {vuln.exploit_available && <Tag danger>Exploit</Tag>}
          {vuln.metasploit_available && <Tag>Metasploit</Tag>}
          <button onClick={onClose} className="btn-ghost w-8 h-8 p-0 ml-auto justify-center shrink-0" title="Close (Esc)" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <h2 className="text-lg font-semibold leading-snug text-ink-900 dark:text-ink-50">{vuln.plugin_name}</h2>
        <p className="text-[13px] text-ink-500 dark:text-ink-400">
          Plugin {vuln.plugin_id} · {vuln.plugin_family}
        </p>
        {hasScores && (
          <div className="flex flex-wrap gap-2">
            {vuln.cvss4 !== null && <Score label="CVSS v4" value={vuln.cvss4.toFixed(1)} sev={cvssSeverity(vuln.cvss4, 4)} />}
            {vuln.cvss3 !== null && <Score label="CVSS v3" value={vuln.cvss3.toFixed(1)} sev={cvssSeverity(vuln.cvss3, 3)} />}
            {vuln.cvss2 !== null && <Score label="CVSS v2" value={vuln.cvss2.toFixed(1)} sev={cvssSeverity(vuln.cvss2, 2)} />}
            {vuln.vpr !== null && <Score label="VPR" value={vuln.vpr.toFixed(1)} sev={cvssSeverity(vuln.vpr, 3)} />}
            {vuln.epss !== null && <Score label="EPSS" value={String(vuln.epss)} />}
          </div>
        )}
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-4">
        {differences.length > 0 && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-md bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/40">
            <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
            <div className="text-[13px] text-amber-800 dark:text-amber-300 leading-relaxed min-w-0">
              <p className="font-semibold">Scan files rate this differently</p>
              {differences.map((d) => (
                <p key={d.severity} className="break-words" title={d.filenames.join("\n")}>
                  {SEVERITY_LABELS[d.severity]} in {d.filenames.slice(0, 2).join(", ")}
                  {d.filenames.length > 2 ? ` +${d.filenames.length - 2} more` : ""}
                </p>
              ))}
              <p className="mt-1">With all files shown, the worst rating is used.</p>
            </div>
          </div>
        )}

        {vuln.synopsis && (
          <Section title="Synopsis" copy={vuln.synopsis}>
            <p className="whitespace-pre-wrap">{vuln.synopsis}</p>
          </Section>
        )}

        <Section title="Description" copy={vuln.description || undefined}>
          <p className="whitespace-pre-wrap">{vuln.description || "No description available."}</p>
        </Section>

        <Section title="Solution" copy={vuln.solution || undefined}>
          <p className="whitespace-pre-wrap">{vuln.solution || "No solution available."}</p>
        </Section>

        {(vuln.vuln_publication_date || vuln.patch_publication_date) && (
          <Section title="Dates">
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 tabular-nums">
              {vuln.vuln_publication_date && (
                <>
                  <dt className="text-ink-500 dark:text-ink-400">Vulnerability published</dt>
                  <dd>{formatNessusDate(vuln.vuln_publication_date)}</dd>
                </>
              )}
              {vuln.patch_publication_date && (
                <>
                  <dt className="text-ink-500 dark:text-ink-400">Patch released</dt>
                  <dd>{formatNessusDate(vuln.patch_publication_date)}</dd>
                </>
              )}
            </dl>
          </Section>
        )}

        {vuln.metasploit_name && (
          <Section title="Metasploit module" copy={vuln.metasploit_name}>
            <ExtLink onClick={() => openExternal(metasploitSearchUrl(vuln.metasploit_name!))} title="Search for this module on rapid7.com">
              {vuln.metasploit_name}
            </ExtLink>
          </Section>
        )}

        {vuln.cve.length > 0 && (
          <Section title={`CVEs (${vuln.cve.length})`} copy={vuln.cve.join("\n")}>
            {/* equal columns sized to the longest ID, so the list lines up */}
            <div
              className="grid gap-x-4 gap-y-1 tabular-nums"
              style={{ gridTemplateColumns: `repeat(auto-fill, minmax(${Math.max(...vuln.cve.map((c) => c.length)) + 2.5}ch, 1fr))` }}
            >
              {vuln.cve.map((c) => (
                <ExtLink key={c} onClick={() => openExternal(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`)} title="Open on nvd.nist.gov">
                  {c}
                </ExtLink>
              ))}
            </div>
          </Section>
        )}

        {vuln.cwe.length > 0 && (
          <Section title="CWEs">
            <div className="flex flex-wrap gap-x-4 gap-y-1 tabular-nums">
              {vuln.cwe.map((c) => {
                const id = /\d+/.exec(c)?.[0];
                return id
                  ? <ExtLink key={c} onClick={() => openExternal(`https://cwe.mitre.org/data/definitions/${id}.html`)} title="Open on cwe.mitre.org">CWE-{id}</ExtLink>
                  : <span key={c}>{c}</span>;
              })}
            </div>
          </Section>
        )}

        {vuln.see_also.length > 0 && (
          <Section title="References">
            <ul className="flex flex-col gap-1">
              {vuln.see_also.map((url, i) => (
                <li key={i} className="text-[13px] break-all">
                  {isWebUrl(url)
                    ? <button onClick={() => openExternal(url)} className="text-left text-accent-700 dark:text-accent-400 hover:underline">{url}</button>
                    : <span className="text-ink-500 dark:text-ink-400">{url}</span>}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {/* Affected hosts */}
        <Section title={`Affected hosts · ${ips.length} ${ips.length === 1 ? "host" : "hosts"}${hosts.length !== ips.length ? `, ${hosts.length} instances` : ""}`}>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            {showFile && (
              <select value={fileFilter} onChange={(e) => setFileFilter(e.target.value)} className="input h-8 py-0 text-sm w-auto max-w-56">
                <option value="all">All files</option>
                {files.map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
              </select>
            )}
            <SearchBar value={ipSearch} onChange={setIpSearch} placeholder="Filter IPs…" className="flex-1 min-w-36" />
          </div>
          <div className="flex flex-wrap items-center gap-1 mb-3">
            <CopyButton text={ips.join("\n")} label="Copy IPs" />
            <CopyButton text={ipPorts.join("\n")} label="Copy IP:port" />
            {httpUrls.length > 0 && <CopyButton text={httpUrls.join("\n")} label="Copy HTTP URLs" />}
            {httpsUrls.length > 0 && <CopyButton text={httpsUrls.join("\n")} label="Copy HTTPS URLs" />}
            {withOutput.length > 0 && (
              <button
                onClick={() => setHiddenOutput(allHidden ? new Set() : new Set(withOutput.map((h) => h.id)))}
                className="btn-ghost h-7 px-2 text-xs ml-auto"
              >
                {allHidden ? "Show all output" : "Hide all output"}
              </button>
            )}
          </div>

          {hosts.length === 0 ? (
            <p className="text-sm text-ink-500 dark:text-ink-400 text-center py-4">No hosts match the filter.</p>
          ) : (
            <div className="card overflow-x-auto">
              {/* fixed layout: the host column takes what's left, so the table never needs a sideways scrollbar */}
              <table className="w-full table-fixed text-sm tabular-nums">
                <colgroup>
                  <col />
                  <col className="w-[6.5rem]" />
                  <col className="w-[5.5rem]" />
                  <col className="w-[13rem]" />
                </colgroup>
                <thead>
                  <tr className="bg-ink-100 dark:bg-ink-700/60 text-[13px] text-left text-ink-500 dark:text-ink-300">
                    <th className="px-3 py-2 font-semibold">Host</th>
                    <th className="px-3 py-2 font-semibold">Port</th>
                    <th className="px-3 py-2 font-semibold">Service</th>
                    <th className="px-3 py-2"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.slice(0, visibleRows).map((h) => {
                    const web = isPlainHttp(h.port, h.svc_name) ? httpUrl(h.ip, h.port) : isHttps(h.port, h.svc_name) ? httpsUrl(h.ip, h.port) : null;
                    const open = h.plugin_output && !hiddenOutput.has(h.id);
                    return (
                      <HostRows key={h.id} open={!!open} columns={columns} output={h.plugin_output}>
                        <td className="px-3 py-1.5">
                          <IpLink ip={h.ip} className="text-left" />
                          {showFile && (
                            <div className="truncate text-xs text-ink-500 dark:text-ink-400" title={h.filename}>{h.filename.replace(/\.nessus$/i, "")}</div>
                          )}
                        </td>
                        <td className="px-3 py-1.5 truncate text-ink-700 dark:text-ink-200">{h.port}/{h.protocol}</td>
                        <td className="px-3 py-1.5 truncate text-ink-500 dark:text-ink-400" title={h.svc_name || undefined}>{h.svc_name || "-"}</td>
                        <td className="px-2 py-1.5 text-right whitespace-nowrap">
                          <CopyButton text={h.ip} label="IP" className="!px-1.5" />
                          <CopyButton text={`${h.ip}:${h.port}`} label="IP:port" className="!px-1.5" />
                          {web && <CopyButton text={web} label="URL" className="!px-1.5" />}
                          {h.plugin_output ? (
                            <button
                              onClick={() => toggleOutput(h.id)}
                              className="btn-ghost h-7 w-7 p-0 justify-center"
                              title={open ? "Hide plugin output" : "Show plugin output"}
                              aria-label={open ? "Hide plugin output" : "Show plugin output"}
                              aria-expanded={!!open}
                            >
                              {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </button>
                          ) : <span className="inline-block w-7" />}
                        </td>
                      </HostRows>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {hosts.length > visibleRows && (
            <button onClick={() => setVisibleRows((n) => n + HOST_ROWS_PAGE)} className="btn-ghost w-full justify-center text-xs mt-2">
              Show {Math.min(HOST_ROWS_PAGE, hosts.length - visibleRows)} more of {hosts.length - visibleRows} remaining
            </button>
          )}
        </Section>
      </div>
    </>
  );
}// VulnContent

function httpUrl(ip: string, port: number): string {
  return `http://${ip}${port !== 80 ? `:${port}` : ""}`;
}// httpUrl

function httpsUrl(ip: string, port: number): string {
  return `https://${ip}${port !== 443 ? `:${port}` : ""}`;
}// httpsUrl

// a host's row, and its plugin output underneath when open
function HostRows({ open, columns, output, children }: { open: boolean; columns: number; output: string | null; children: ReactNode }) {
  return (
    <>
      <tr className="border-t border-ink-100 dark:border-ink-700">{children}</tr>
      {open && output && (
        <tr>
          <td colSpan={columns} className="px-3 pb-2.5">
            <pre className="m-0 px-3 py-2 max-h-48 overflow-y-auto rounded-md border border-ink-200 dark:border-ink-700 bg-ink-50 dark:bg-ink-900 text-xs leading-relaxed whitespace-pre-wrap font-mono text-ink-700 dark:text-ink-200">
              {output}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}// HostRows

function ExtLink({ onClick, title, children }: { onClick: () => void; title: string; children: ReactNode }) {
  return (
    <button onClick={onClick} title={title} className="inline-flex items-center gap-1 text-left font-medium text-accent-700 dark:text-accent-400 hover:underline break-words">
      {children} <ExternalLink size={11} className="shrink-0" />
    </button>
  );
}// ExtLink

function Score({ label, value, sev }: { label: string; value: string; sev?: number }) {
  const color = sev === undefined ? "text-ink-900 dark:text-ink-50" : SEVERITY_COLORS[sev].text;

  return (
    <div className="flex flex-col gap-0.5 min-w-[4.5rem] px-2.5 py-1.5 rounded-md border border-ink-200 dark:border-ink-700">
      <span className={`text-lg font-bold leading-tight tabular-nums ${color}`}>{value}</span>
      <span className="text-[11px] font-semibold text-ink-500 dark:text-ink-400">{label}</span>
    </div>
  );
}// Score
