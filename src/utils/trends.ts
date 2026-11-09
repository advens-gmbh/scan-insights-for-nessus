import type { NessusFile } from "../types/nessus";
import { compareScans, pairHosts } from "./compare";
import { scanWindow } from "./dashboard";
import { splitTargets } from "./fileTargets";

export function fileStart(file: NessusFile): number {
  return scanWindow(file.hosts).start?.getTime() ?? new Date(file.loaded_at).getTime();
}// fileStart

export function byScanDate(files: NessusFile[]): NessusFile[] {
  return [...files].sort((a, b) => fileStart(a) - fileStart(b));
}// byScanDate

// Two files are runs of the same scan when they list the same targets, or when at least half of all hosts
export function sameScan(a: NessusFile, b: NessusFile): string | null {
  const targetsA = splitTargets(a.target).map((t) => t.toLowerCase()).sort();
  const targetsB = splitTargets(b.target).map((t) => t.toLowerCase()).sort();
  if (targetsA.length > 0 && targetsA.join(",") === targetsB.join(",")) {
    return "same targets";
  }

  const shared = pairHosts(a, b).filter((p) => p.a && p.b).length;
  const all = a.hosts.length + b.hosts.length - shared;

  return shared > 0 && shared * 2 >= all ? `${shared} of ${all} hosts in both` : null;
}// sameScan

// every run of the newest scan, or everything when that scan only ran once
export function defaultTrendSelection(files: NessusFile[]): string[] {
  const sorted = byScanDate(files);
  const newest = sorted[sorted.length - 1];
  if (!newest) {
    return [];
  }

  const runs = sorted.filter((f) => f === newest || sameScan(f, newest));

  return (runs.length >= 2 ? runs : sorted).map((f) => f.id);
}// defaultTrendSelection

export function runChanges(previous: NessusFile, current: NessusFile, showInfo: boolean): { added: number; fixed: number } {
  const severity = new Map<number, number>();
  for (const f of [previous, current]) {
    for (const host of f.hosts) {
      for (const item of host.items) {
        severity.set(item.plugin_id, Math.max(severity.get(item.plugin_id) ?? 0, item.severity));
      }
    }
  }
  const counted = (pluginId: number) => showInfo || (severity.get(pluginId) ?? 0) > 0;
  const delta = compareScans(previous, current);

  return {
    added: delta.newItems.filter((d) => counted(d.pluginId)).length,
    fixed: delta.resolvedItems.filter((d) => counted(d.pluginId)).length,
  };
}// runChanges

export interface PreviousRun {
  file: NessusFile;
  reason: string;
}// PreviousRun

export function previousRuns(runs: NessusFile[]): Map<string, PreviousRun | null> {
  const sorted = byScanDate(runs);
  const previous = new Map<string, PreviousRun | null>();
  sorted.forEach((f, i) => {
    let found: PreviousRun | null = null;
    for (let j = i - 1; j >= 0 && !found; j--) {
      const candidate = sorted[j];
      const reason = fileStart(candidate) < fileStart(f) ? sameScan(candidate, f) : null;
      found = reason ? { file: candidate, reason } : null;
    }
    previous.set(f.id, found);
  });

  return previous;
}// previousRuns
