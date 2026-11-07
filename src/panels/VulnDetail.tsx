import { useMemo, useState } from "react";
import { X, ExternalLink, ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";
import { isWebUrl, metasploitSearchUrl, openExternal } from "../utils/openExternal";
import { formatNessusDate } from "../utils/format";
import { useUiStore } from "../stores/uiStore";
import { useScanStore } from "../stores/scanStore";
import { buildVulnEntries, cvssSeverity, isPlainHttp, isHttps, ratingDifferences, SEVERITY_COLORS, SEVERITY_LABELS,} from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";
import IpLink from "../components/common/IpLink";
import CopyButton from "../components/common/CopyButton";
import SearchBar from "../components/common/SearchBar";

const HOST_ROWS_PAGE = 200;

interface Props {
  pluginId: number;
}// Props

export default function VulnDetail({ pluginId }: Props) {
  const { closeVulnPanel, vulnPanelFileId } = useUiStore();
  const files = useScanStore((s) => s.files);

  const [fileFilter, setFileFilter] = useState(vulnPanelFileId ?? "all");
  const [ipSearch, setIpSearch] = useState("");
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
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

  const colors = SEVERITY_COLORS[vuln.severity] ?? SEVERITY_COLORS[0];

  const allHosts = acrossFiles.affected_hosts.filter((h) => {
    if (fileFilter !== "all" && h.file_id !== fileFilter) {
      return false;
    }

    if (ipSearch && !h.ip.includes(ipSearch)) {
      return false;
    }

    return true;
  });

  // Lists to copy are de-duplicated (same host and port can be present in multiple files)
  const allIps = [...new Set(allHosts.map((h) => h.ip))];
  const allIpPorts = [...new Set(allHosts.map((h) => `${h.ip}:${h.port}`))];
  const httpHosts = allHosts.filter((h) => isPlainHttp(h.port, h.svc_name));
  const httpsHosts = allHosts.filter((h) => isHttps(h.port, h.svc_name));
  const httpUrls = [...new Set(httpHosts.map((h) => `http://${h.ip}${h.port !== 80 ? `:${h.port}` : ""}`))];
  const httpsUrls = [...new Set(httpsHosts.map((h) => `https://${h.ip}${h.port !== 443 ? `:${h.port}` : ""}`))];

  const toggleCollapse = (id: number) => {
    setCollapsed((prev) => {
      const n = new Set(prev);
      if (n.has(id)) {
        n.delete(id);
      }
      else {
        n.add(id);
      }

      return n;
    });
  };

  const collapseAll = () => setCollapsed(new Set(allHosts.map((h) => h.id)));
  const expandAll = () => setCollapsed(new Set());

  return (
    <>
      <div className="panel-overlay" onClick={closeVulnPanel} />
      <div className="panel-drawer">
        {/* Header */}
        <div className={`px-5 pt-5 pb-4 border-b border-slate-200 dark:border-slate-700 ${colors.bg}`}>
          <div className="flex items-start gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-2">
                <SeverityBadge severity={vuln.severity} />
                {vuln.exploit_available && (
                  <span className="pill bg-red-600 text-white text-xs">EXPLOIT</span>
                )}
                {vuln.metasploit_available && (
                  <span className="pill bg-purple-600 text-white text-xs">METASPLOIT</span>
                )}
              </div>
              <h2 className="font-semibold text-slate-900 dark:text-slate-100 leading-snug">
                {vuln.plugin_name}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Plugin ID: {vuln.plugin_id} · {vuln.plugin_family}
              </p>
            </div>
            <button onClick={closeVulnPanel} className="btn-ghost w-8 h-8 p-0 flex items-center justify-center shrink-0">
              <X size={16} />
            </button>
          </div>

          {/* CVSS scores */}
          {(vuln.cvss2 !== null || vuln.cvss3 !== null || vuln.cvss4 !== null || vuln.vpr !== null || vuln.epss !== null) && (
            <div className="flex flex-wrap gap-3 mt-3">
              {vuln.cvss4 !== null && <CvssScore label="CVSS v4" score={vuln.cvss4} version={4} />}
              {vuln.cvss3 !== null && <CvssScore label="CVSS v3" score={vuln.cvss3} version={3} />}
              {vuln.cvss2 !== null && <CvssScore label="CVSS v2" score={vuln.cvss2} version={2} />}
              {vuln.vpr !== null && <CvssScore label="VPR" score={vuln.vpr} version={3} />}
              {vuln.epss !== null && (
                <div className="flex items-baseline gap-1.5">
                  <span className="text-2xl font-bold tabular-nums text-slate-700 dark:text-slate-200">{vuln.epss}</span>
                  <span className="text-xs text-slate-500">EPSS</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Files disagreeing about the rating */}
          {differences.length > 0 && (
            <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/40">
              <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
              <div className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed min-w-0">
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

          {/* Description */}
          <Section title="Description">
            {vuln.synopsis && (
              <p className="text-sm font-medium text-slate-800 dark:text-slate-200 whitespace-pre-wrap leading-relaxed mb-2">
                {vuln.synopsis}
              </p>
            )}
            <div className="flex items-start justify-between gap-2">
              <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed flex-1">
                {vuln.description || "No description available."}
              </p>
              {vuln.description && <CopyButton text={vuln.description} label="Copy" variant="icon" />}
            </div>
          </Section>

          {/* Solution */}
          <Section title="Solution">
            <div className="flex items-start justify-between gap-2">
              <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed flex-1">
                {vuln.solution || "No solution available."}
              </p>
              {vuln.solution && <CopyButton text={vuln.solution} label="Copy" variant="icon" />}
            </div>
            {vuln.patch_publication_date && (
              <p className="text-sm text-slate-700 dark:text-slate-300 mt-2">
                Patch released: {formatNessusDate(vuln.patch_publication_date)}
              </p>
            )}
          </Section>

          {/* Metasploit */}
          {vuln.metasploit_name && (
            <Section title="Metasploit Module">
              <div className="flex items-center justify-between gap-2">
                <button
                  onClick={() => openExternal(metasploitSearchUrl(vuln.metasploit_name!))}
                  title="Search for this module on rapid7.com"
                  className="text-sm text-violet-600 dark:text-violet-400 hover:underline break-words text-left min-w-0"
                >
                  {vuln.metasploit_name} <ExternalLink size={11} className="inline" />
                </button>
                <CopyButton text={vuln.metasploit_name} label="Copy module name" variant="icon" />
              </div>
            </Section>
          )}

          {/* CVEs */}
          {vuln.cve.length > 0 && (
            <Section title="CVEs">
              {/* equal-width columns sized to the longest ID, so the list lines up with no spare gap */}
              <div
                className="grid gap-1.5"
                style={{ gridTemplateColumns: `repeat(auto-fill, min(${Math.max(...vuln.cve.map((c) => c.length)) / 2 + 2.125}rem, 100%))` }}
              >
                {vuln.cve.map((c) => (
                  <button
                    key={c}
                    onClick={() => openExternal(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`)}
                    className="pill justify-between tabular-nums break-all bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 hover:bg-violet-100 dark:hover:bg-violet-900/30 hover:text-violet-700 dark:hover:text-violet-300 transition-colors cursor-pointer"
                  >
                    {c} <ExternalLink size={10} className="inline" />
                  </button>
                ))}
              </div>
            </Section>
          )}

          {/* CWEs */}
          {vuln.cwe.length > 0 && (
            <Section title="CWEs">
              <div className="flex flex-wrap gap-1.5">
                {vuln.cwe.map((c) => (
                  <span key={c} className="pill bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                    {c}
                  </span>
                ))}
              </div>
            </Section>
          )}

          {/* References */}
          {vuln.see_also.length > 0 && (
            <Section title="References">
              <ul className="space-y-1">
                {vuln.see_also.map((url, i) => (
                  <li key={i}>
                    {isWebUrl(url) ? (
                      <button
                        onClick={() => openExternal(url)}
                        className="text-xs text-violet-600 dark:text-violet-400 hover:underline break-all text-left"
                      >
                        {url}
                      </button>
                    ) : (
                      <span className="text-xs text-slate-500 dark:text-slate-400 break-all">{url}</span>
                    )}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {/* Affected Hosts */}
          <Section
            title={`Affected Hosts (${allIps.length})${ allHosts.length !== allIps.length ? ` · ${allHosts.length} instances` : "" }`}
          >
            {/* Controls */}
            <div className="flex flex-wrap items-center gap-2 mb-3">
              {files.length > 1 && (
                <select
                  value={fileFilter}
                  onChange={(e) => setFileFilter(e.target.value)}
                  className="input h-7 py-0 text-xs w-auto"
                >
                  <option value="all">All files</option>
                  {files.map((f) => (
                    <option key={f.id} value={f.id}>{f.filename}</option>
                  ))}
                </select>
              )}
              <SearchBar value={ipSearch} onChange={setIpSearch} placeholder="Filter IPs…" className="flex-1 min-w-28" />
            </div>

            {/* Bulk copy buttons */}
            <div className="flex flex-wrap gap-1.5 mb-3">
              <button onClick={collapseAll} className="btn-ghost h-7 text-xs">
                <ChevronUp size={12} /> Fold All
              </button>
              <button onClick={expandAll} className="btn-ghost h-7 text-xs">
                <ChevronDown size={12} /> Expand All
              </button>
              <CopyButton text={allIps.join("\n")} label="Copy All IPs" />
              <CopyButton text={allIpPorts.join("\n")} label="Copy All IP:Ports" />
              {httpUrls.length > 0 && <CopyButton text={httpUrls.join("\n")} label="Copy All HTTP" />}
              {httpsUrls.length > 0 && <CopyButton text={httpsUrls.join("\n")} label="Copy All HTTPS" />}
            </div>

            {/* Host list */}
            <div className="space-y-1.5">
              {allHosts.slice(0, visibleRows).map((h) => {
                const isCollapsed = collapsed.has(h.id);
                const httpUrl = isPlainHttp(h.port, h.svc_name) ? `http://${h.ip}${h.port !== 80 ? `:${h.port}` : ""}` : null;
                const httpsUrl = isHttps(h.port, h.svc_name) ? `https://${h.ip}${h.port !== 443 ? `:${h.port}` : ""}` : null;

                return (
                  <div key={h.id} className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 overflow-hidden">
                    <div
                      className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-700/50"
                      onClick={() => toggleCollapse(h.id)}
                    >
                      <IpLink ip={h.ip} />
                      <span className="text-xs text-slate-500 font-mono">{h.port}/{h.protocol}</span>
                      <span className="text-xs text-slate-500">{h.svc_name}</span>
                      {files.length > 1 && (
                        <span className="pill bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 ml-auto text-[10px] max-w-32 truncate">
                          {h.filename}
                        </span>
                      )}
                      <div className="flex items-center gap-1 ml-auto">
                        <CopyButton text={h.ip} label="Copy IP" />
                        <CopyButton text={`${h.ip}:${h.port}`} label="IP:Port" />
                        {httpUrl && <CopyButton text={httpUrl} label="HTTP" />}
                        {httpsUrl && <CopyButton text={httpsUrl} label="HTTPS" />}
                      </div>
                    </div>
                    {!isCollapsed && h.plugin_output && (
                      <div className="px-3 pb-2 border-t border-slate-200 dark:border-slate-700">
                        <pre className="text-xs text-slate-600 dark:text-slate-400 mt-1.5 whitespace-pre-wrap font-mono leading-relaxed max-h-40 overflow-y-auto">
                          {h.plugin_output}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
              {allHosts.length > visibleRows && (
                <button
                  onClick={() => setVisibleRows((n) => n + HOST_ROWS_PAGE)}
                  className="btn-ghost w-full justify-center text-xs"
                >
                  Show {Math.min(HOST_ROWS_PAGE, allHosts.length - visibleRows)} more of {allHosts.length - visibleRows} remaining
                </button>
              )}
              {allHosts.length === 0 && (
                <p className="text-sm text-slate-400 text-center py-4">No hosts match the filter.</p>
              )}
            </div>
          </Section>
        </div>
      </div>
    </>
  );
}// VulnDetail

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">
        {title}
      </h3>
      {children}
    </div>
  );
}// Section

function CvssScore({ label, score, version }: { label: string; score: number; version: 2 | 3 | 4 }) {
  const color = SEVERITY_COLORS[cvssSeverity(score, version)].text;

  return (
    <div className="flex items-baseline gap-1.5">
      <span className={`text-2xl font-bold tabular-nums ${color}`}>{score.toFixed(1)}</span>
      <span className="text-xs text-slate-500">{label}</span>
    </div>
  );
}// CvssScore
