import type { SeverityCounts } from "../types/nessus";

// what list_counts answers
export interface ListCounts {
  vulnerabilities: number;
  hosts: number;
  services: number;
  findings: SeverityCounts; // merged across files
}// ListCounts
