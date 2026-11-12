import { useState } from "react";
import type { ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useUiStore } from "../stores/uiStore";
import { ratedScore, SEVERITY_COLORS } from "../types/nessus";
import type { CvssScore, ReportItem, SeverityCounts } from "../types/nessus";
import SeverityBadge from "../components/common/SeverityBadge";

export const COUNTS = [
  { sev: 4, label: "Critical", key: "critical", dot: "bg-critical" },
  { sev: 3, label: "High",     key: "high",     dot: "bg-high" },
  { sev: 2, label: "Medium",   key: "medium",   dot: "bg-medium" },
  { sev: 1, label: "Low",      key: "low",      dot: "bg-low" },
  { sev: 0, label: "Info",     key: "info",     dot: "bg-info" },
] as const;

const GROUPS_PAGE = 100;
// groups with high or critical findings start open, up to this many
const OPEN_AT_START = 10;

const CHIP: Record<number, string> = {
  4: "bg-critical text-critical-on",
  3: "bg-high text-high-on",
  2: "bg-medium text-medium-on",
  1: "bg-low text-low-on",
  0: "bg-info text-info-on",
};

export interface FindingGroup {
  key: string;
  counts: number[]; // indexed by severity
  worst: number;
  items: ReportItem[];
}// FindingGroup

export function CountBoxes({ counts }: { counts: SeverityCounts }) {
  return (
    <div className="grid grid-cols-5 gap-px rounded-lg border border-ink-200 dark:border-ink-700 bg-ink-100 dark:bg-ink-700/70 overflow-hidden">
      {COUNTS.map((c) => {
        const n = counts[c.key];
        return (
          <div key={c.sev} className="min-w-0 flex flex-col gap-1 px-3 py-2 bg-white dark:bg-ink-900">
            <span className={`text-lg font-bold leading-tight tabular-nums ${n > 0 ? SEVERITY_COLORS[c.sev].text : "text-ink-300 dark:text-ink-600"}`}>{n.toLocaleString()}</span>
            <span className="flex items-center gap-1.5 text-[11px] font-semibold text-ink-500 dark:text-ink-400"><span className={`w-[7px] h-[7px] rounded-full ${c.dot}`} />{c.label}</span>
          </div>
        );
      })}
    </div>
  );
}// CountBoxes

export function itemScore(i: ReportItem): CvssScore | null {
  return ratedScore({ cvss4: i.cvss4_base_score, cvss3: i.cvss3_base_score, cvss2: i.cvss_base_score, severity: i.severity });
}// itemScore

export function Cvss({ score, severity }: { score: CvssScore | null; severity: number }) {
  if (!score) {
    return <span className="text-ink-300 dark:text-ink-600">-</span>;
  }

  return (
    <span className="whitespace-nowrap">
      <span className={`${SEVERITY_COLORS[severity].text} ${severity >= 3 ? "font-semibold" : ""}`}>
        {score.score.toFixed(1)}
      </span>
      <span className="ml-1 text-[10px] text-ink-400" title={`CVSS v${score.version}`}>v{score.version}</span>
    </span>
  );
}// Cvss

export function FindingName({ pluginId, name, fileId }: { pluginId: number; name: string; fileId?: string }) {
  const openVulnPanel = useUiStore((s) => s.openVulnPanel);

  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        openVulnPanel(pluginId, fileId);
      }}
      title={name}
      className="max-w-full truncate text-left text-ink-800 dark:text-ink-100 hover:underline"
    >
      {name}
    </button>
  );
}// FindingName

export function SeverityChips({ counts, showInfo }: { counts: number[]; showInfo: boolean }) {
  return (
    <span className="flex gap-1 tabular-nums text-xs font-semibold">
      {COUNTS.filter((c) => showInfo || c.sev > 0).map((c) => (
        <span key={c.sev} className={`w-7 py-0.5 rounded text-center ${counts[c.sev] > 0 ? CHIP[c.sev] : ""}`} title={counts[c.sev] > 0 ? `${counts[c.sev]} ${c.label}` : undefined}>
          {counts[c.sev] > 0 ? counts[c.sev] : ""}
        </span>
      ))}
    </span>
  );
}// SeverityChips

// collapsible groups of findings, the ones with Critical or High findings start open
export function FindingGroups<G extends FindingGroup>({ groups, noun, header, fileId, showInfo }: {
  groups: G[];
  noun: [string, string];
  header: (group: G) => ReactNode;
  fileId?: string;
  showInfo: boolean;
}) {
  const [open, setOpen] = useState<Set<string>>(() => new Set(groups.filter((g) => g.worst >= 3).slice(0, OPEN_AT_START).map((g) => g.key)));
  const [shown, setShown] = useState(GROUPS_PAGE);
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
        <span>{groups.length.toLocaleString()} {groups.length === 1 ? noun[0] : noun[1]}</span>
        <button onClick={() => setOpen(allOpen ? new Set() : new Set(groups.map((g) => g.key)))} className="btn-ghost h-7 px-2 text-xs">
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
      </div>
      {groups.slice(0, shown).map((g) => {
        const expanded = open.has(g.key);
        return (
          <div key={g.key} className="rounded-md border border-ink-200 dark:border-ink-700 overflow-hidden">
            <div
              onClick={() => toggle(g.key)}
              className="grid grid-cols-[minmax(0,1fr)_auto_1.75rem] items-center gap-3 pl-3 pr-1 py-1 cursor-pointer bg-ink-50 dark:bg-ink-800 hover:bg-ink-100 dark:hover:bg-ink-700/70"
            >
              <div className="min-w-0 flex items-center gap-3">{header(g)}</div>
              <SeverityChips counts={g.counts} showInfo={showInfo} />
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  toggle(g.key);
                }}
                aria-expanded={expanded}
                aria-label={expanded ? "Collapse" : "Expand"}
                className="btn-ghost h-7 w-7 p-0 justify-center"
              >
                {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </button>
            </div>
            {expanded && (
              <ul>
                {g.items.map((item) => (
                  <li
                    key={`${item.plugin_id}-${item.port}-${item.protocol}`}
                    className="grid grid-cols-[4.25rem_minmax(0,1fr)_4rem] items-center gap-3 px-3 py-1.5 border-t border-ink-100 dark:border-ink-700 hover:bg-ink-50 dark:hover:bg-ink-800"
                  >
                    <SeverityBadge severity={item.severity} size="sm" />
                    <span className="truncate"><FindingName pluginId={item.plugin_id} name={item.plugin_name} fileId={fileId} /></span>
                    <span className="text-right tabular-nums"><Cvss score={itemScore(item)} severity={item.severity} /></span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}
      {groups.length > shown && (
        <button onClick={() => setShown((n) => n + GROUPS_PAGE)} className="btn-ghost w-full justify-center text-xs">
          Show {Math.min(GROUPS_PAGE, groups.length - shown)} more of {(groups.length - shown).toLocaleString()} remaining
        </button>
      )}
    </div>
  );
}// FindingGroups
