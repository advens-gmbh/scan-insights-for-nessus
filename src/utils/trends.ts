import type { ScanFile } from "../types/nessus";
import { fileStart } from "./fileFacts";

export { fileCounts, fileStart, fileWindow } from "./fileFacts";

export type SameScans = Map<string, string>;

export function sameScansOf(pairs: { a: string; b: string; reason: string }[]): SameScans {
  const same: SameScans = new Map();
  for (const { a, b, reason } of pairs) {
    same.set(`${a}|${b}`, reason);
    same.set(`${b}|${a}`, reason);
  }
  return same;
}// sameScansOf

export function sameScan(same: SameScans, a: ScanFile, b: ScanFile): string | null {
  return same.get(`${a.id}|${b.id}`) ?? null;
}// sameScan

export function byScanDate(files: ScanFile[]): ScanFile[] {
  return [...files].sort((a, b) => fileStart(a) - fileStart(b));
}// byScanDate

// every run of the newest scan, or everything when that scan only ran once
export function defaultTrendSelection(files: ScanFile[], same: SameScans): string[] {
  const sorted = byScanDate(files);
  const newest = sorted[sorted.length - 1];
  if (!newest) {
    return [];
  }

  const runs = sorted.filter((f) => f === newest || sameScan(same, f, newest));

  return (runs.length >= 2 ? runs : sorted).map((f) => f.id);
}// defaultTrendSelection

export interface PreviousRun {
  file: ScanFile;
  reason: string;
}// PreviousRun

// each run with the latest earlier run of the same scan
export function previousRuns(runs: ScanFile[], same: SameScans): Map<string, PreviousRun | null> {
  const sorted = byScanDate(runs);
  const previous = new Map<string, PreviousRun | null>();
  sorted.forEach((f, i) => {
    let found: PreviousRun | null = null;
    for (let j = i - 1; j >= 0 && !found; j--) {
      const candidate = sorted[j];
      const reason = fileStart(candidate) < fileStart(f) ? sameScan(same, candidate, f) : null;
      found = reason ? { file: candidate, reason } : null;
    }
    previous.set(f.id, found);
  });

  return previous;
}// previousRuns
