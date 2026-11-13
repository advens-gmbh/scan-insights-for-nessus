import type { ScanFile } from "../types/nessus";

// when the scan started and how long it ran
export function fileWindow(file: ScanFile): { start: Date | null; durationMs: number | null } {
  return { start: file.start !== null ? new Date(file.start) : null, durationMs: file.duration_ms };
}// fileWindow

export function fileStart(file: ScanFile): number {
  return file.start ?? new Date(file.loaded_at).getTime();
}// fileStart
