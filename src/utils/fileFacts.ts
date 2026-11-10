import type { NessusFile, SeverityCounts } from "../types/nessus";
import { severityCounts } from "../types/nessus";
import { scanWindow } from "./dashboard";

// Each of these reads every host of a file, and stores it while the file is open.

export function rememberPair<V>(cache: WeakMap<NessusFile, WeakMap<NessusFile, V>>, a: NessusFile, b: NessusFile, make: () => V): V {
  let inner = cache.get(a);
  if (!inner) {
    inner = new WeakMap();
    cache.set(a, inner);
  }
  if (!inner.has(b)) {
    inner.set(b, make());
  }
  return inner.get(b)!;
}// rememberPair

const windows = new WeakMap<NessusFile, ReturnType<typeof scanWindow>>();
const starts = new WeakMap<NessusFile, number>();
const counts = new WeakMap<NessusFile, SeverityCounts>();

// when the scan started and how long it ran
export function fileWindow(file: NessusFile): ReturnType<typeof scanWindow> {
  let w = windows.get(file);
  if (!w) {
    w = scanWindow(file.hosts);
    windows.set(file, w);
  }
  return w;
}// fileWindow

export function fileStart(file: NessusFile): number {
  let start = starts.get(file);
  if (start === undefined) {
    start = fileWindow(file).start?.getTime() ?? new Date(file.loaded_at).getTime();
    starts.set(file, start);
  }
  return start;
}// fileStart

// the findings of one file by severity
export function fileCounts(file: NessusFile): SeverityCounts {
  let c = counts.get(file);
  if (!c) {
    c = severityCounts(file.hosts);
    counts.set(file, c);
  }
  return c;
}// fileCounts
