import type { SeverityCounts } from "../types/nessus";

export function severitiesOf(counts: SeverityCounts): number[] {
  const out: number[] = [];
  if (counts.critical > 0) out.push(4);
  if (counts.high > 0)     out.push(3);
  if (counts.medium > 0)   out.push(2);
  if (counts.low > 0)      out.push(1);
  if (counts.info > 0)     out.push(0);

  return out;
}// severitiesOf

// no pill selected shows everything
export function matchesSeverities(rowSeverities: readonly number[], selected: readonly number[]): boolean {
  return selected.length === 0 || rowSeverities.some((s) => selected.includes(s));
}// matchesSeverities

// how many rows each pill would show on its own
export function countBySeverity(rows: Iterable<readonly number[]>): Record<number, number> {
  const c: Record<number, number> = { 4: 0, 3: 0, 2: 0, 1: 0, 0: 0 };
  for (const severities of rows) {
    for (const s of new Set(severities)) {
      c[s]++;
    }
  }

  return c;
}// countBySeverity

export function toggleSeverity(selected: readonly number[], sev: number): number[] {
  return selected.includes(sev) ? selected.filter((s) => s !== sev) : [...selected, sev];
}// toggleSeverity
