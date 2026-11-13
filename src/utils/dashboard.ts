const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Nessus writes HOST_START / HOST_END as "Mon Jan  1 10:00:00 2024", which not every webview parses
export function parseNessusTime(value: string | null | undefined): Date | null {
  if (!value) {
    return null;
  }

  const m = /^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})$/.exec(value.trim());
  if (m && MONTHS.includes(m[1])) {
    return new Date(Number(m[6]), MONTHS.indexOf(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
  }

  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}// parseNessusTime

// earliest host start to latest host end
export function scanWindow(hosts: { host_start: string | null; host_end: string | null }[]): { start: Date | null; durationMs: number | null } {
  const starts = hosts.map((h) => parseNessusTime(h.host_start)).filter((d): d is Date => d !== null);
  const ends = hosts.map((h) => parseNessusTime(h.host_end)).filter((d): d is Date => d !== null);
  if (starts.length === 0) {
    return { start: null, durationMs: null };
  }

  const start = new Date(Math.min(...starts.map((d) => d.getTime())));
  const end = ends.length ? Math.max(...ends.map((d) => d.getTime())) : null;

  return { start, durationMs: end !== null && end >= start.getTime() ? end - start.getTime() : null };
}// scanWindow

export function formatScanStart(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}// formatScanStart

export function formatDuration(ms: number): string {
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) {
    return "under 1 min";
  }

  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h === 0) {
    return `${m} min`;
  }

  return m === 0 ? `${h} h` : `${h} h ${m} min`;
}// formatDuration
