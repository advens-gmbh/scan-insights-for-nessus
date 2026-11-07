import { X, Target, Server } from "lucide-react";
import type { NessusFile } from "../types/nessus";
import CopyButton from "../components/common/CopyButton";

interface Props {
  file: NessusFile;
  onClose: () => void;
}// Props

export default function FileDetailPanel({ file, onClose }: Props) {
  const targets = file.target ? file.target.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean) : [];
  const hosts = file.hosts.map((h) => ({
    ip: h.ip,
    hostname: h.hostname,
  }));

  const allTargetsText = targets.join("\n");
  const allIpsText = hosts.map((h) => h.ip).join("\n");
  const allWithNamesText = hosts
    .map((h) => (h.hostname ? `${h.ip} (${h.hostname})` : h.ip))
    .join("\n");

  return (
    <>
      <div className="panel-overlay" onClick={onClose} />
      <div className="panel-drawer">
        {/* Header */}
        <div className="px-5 pt-5 pb-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs text-slate-400 mb-0.5">Scan File Details</p>
              <h2
                className="font-semibold text-slate-900 dark:text-slate-100 truncate"
                title={file.filename}
              >
                {file.filename}
              </h2>
              {file.report_name && (
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                  {file.report_name}
                </p>
              )}
            </div>
            <button
              onClick={onClose}
              className="btn-ghost w-8 h-8 p-0 flex items-center justify-center shrink-0"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-6">

          {/* Configured Targets */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-1.5">
                <Target size={14} className="text-violet-500" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Configured Targets
                  {targets.length > 0 && (
                    <span className="ml-1.5 normal-case font-normal text-slate-400">
                      ({targets.length})
                    </span>
                  )}
                </h3>
              </div>
              {targets.length > 0 && <CopyButton text={allTargetsText} label="Copy All" />}
            </div>

            {targets.length === 0 ? (
              <p className="text-xs text-slate-400 italic">
                Target information not found in this scan file's policy section.
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {targets.map((t, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-1 pl-2.5 pr-1 py-1 rounded-md border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 font-mono text-xs text-slate-700 dark:text-slate-200"
                  >
                    {t}
                    <CopyButton text={t} variant="icon" label="Copy" />
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Reached Hosts */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-1.5">
                <Server size={14} className="text-violet-500" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Reached Hosts
                  <span className="ml-1.5 normal-case font-normal text-slate-400">
                    ({hosts.length})
                  </span>
                </h3>
              </div>
              {hosts.length > 0 && (
                <div className="flex items-center gap-1">
                  <CopyButton text={allIpsText} label="IPs" />
                  <CopyButton text={allWithNamesText} label="IPs+Names" />
                </div>
              )}
            </div>

            {hosts.length === 0 ? (
              <p className="text-xs text-slate-400 italic">No hosts in this scan file.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {hosts.map((h) => (
                  <div
                    key={h.ip}
                    className="flex items-center gap-1 pl-2.5 pr-1 py-1 rounded-md border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 font-mono text-xs text-slate-700 dark:text-slate-200"
                  >
                    <span>{h.ip}</span>
                    {h.hostname && (
                      <span className="font-sans text-slate-400 ml-0.5 text-[10px]">({h.hostname})</span>
                    )}
                    <CopyButton text={h.ip} variant="icon" label="Copy IP" />
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </div>
    </>
  );
}// FileDetailPanel
