import { describe, expect, it } from "vitest";
import { cvssSeverity, displayScanName, isHttps, isPlainHttp, ratedScore, ratingDifferences, visibleCounts, vulnScore } from "./nessus";

describe("displayScanName", () => {
  const name = (report_name: string, filename = "a1b2c3d4.nessus") => displayScanName({ report_name, filename });

  it("shows a name that adds something", () => {
    expect(name("Quarterly_DMZ_Scan (scheduled)")).toBe("Quarterly_DMZ_Scan (scheduled)");
    expect(name("  local2  ", "nessus_report_local2.nessus")).toBe("local2");
  });

  it("hides a name that only repeats the filename, or is empty", () => {
    expect(name("manyhosts", "manyhosts.nessus")).toBeNull();
    expect(name("ManyHosts", "manyhosts.NESSUS")).toBeNull();
    expect(name("", "scan.nessus")).toBeNull();
    expect(name("   ", "scan.nessus")).toBeNull();
  });
});

describe("visibleCounts", () => {
  const counts = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

  it("only removes Info", () => {
    expect(visibleCounts(counts, false)).toEqual({ ...counts, info: 0 });
    expect(visibleCounts(counts, true)).toBe(counts);
  });
});

describe("cvssSeverity", () => {
  it.each([
    [10, 2, 4], [9.9, 2, 3], [9.3, 2, 3], [7, 2, 3], [6.9, 2, 2], [4, 2, 2], [3.9, 2, 1], [0.1, 2, 1], [0, 2, 0],
    [10, 3, 4], [9, 3, 4], [8.9, 3, 3], [7, 3, 3], [6.9, 3, 2], [4, 3, 2], [3.9, 3, 1], [0, 3, 0],
    [9, 4, 4], [8.9, 4, 3],
  ] as const)("score %d on CVSS v%d is severity %d", (score, version, severity) => {
    expect(cvssSeverity(score, version)).toBe(severity);
  });
});

// the lists themselves are built and tested in the backend (src-tauri/src/views.rs)
describe("scores", () => {
  it("names the CVSS version of the score it shows", () => {
    const rated = (severity: number, v2: number | null, v3: number | null, v4: number | null) =>
      ratedScore({ severity, cvss2: v2, cvss3: v3, cvss4: v4 } as Parameters<typeof ratedScore>[0]);
    expect(rated(3, 9.3, null, null)).toEqual({ score: 9.3, version: 2 });
    expect(rated(2, 5, 7.5, null)).toEqual({ score: 5, version: 2 });
    expect(rated(3, 7.5, 8.1, null)).toEqual({ score: 8.1, version: 3 });
    expect(rated(4, 10, 9.8, 9.3)).toEqual({ score: 9.3, version: 4 });
    expect(rated(4, null, 8.1, null)).toEqual({ score: 8.1, version: 3 });
    expect(rated(2, null, null, null)).toBeNull();
  });

  it("shows the score behind the finding's severity", () => {
    const score = (severity: number, v2: number | null, v3: number | null) =>
      vulnScore({ severity, cvss2: v2, cvss3: v3, cvss4: null } as Parameters<typeof vulnScore>[0]);
    expect(score(3, 9.3, null)).toBe(9.3);  // v2 only: High up to 9.9
    expect(score(2, 5, 7.5)).toBe(5);       // rated by v2, the newer v3 score would contradict it
    expect(score(3, 7.5, 10)).toBe(7.5);
    expect(score(4, 10, 9.8)).toBe(9.8);    // both agree, so the newest wins
    expect(score(4, null, 8.1)).toBe(8.1);  // no score fits, so show what the file has
  });

  it("prefers the newest CVSS version", () => {
    const entry = (v2: number | null, v3: number | null, v4: number | null) =>
      vulnScore({ cvss2: v2, cvss3: v3, cvss4: v4 } as Parameters<typeof vulnScore>[0]);
    expect(entry(5, 6, 7)).toBe(7);
    expect(entry(5, 6, null)).toBe(6);
    expect(entry(5, null, null)).toBe(5);
    expect(entry(null, null, null)).toBeNull();
  });
});

describe("ratingDifferences", () => {
  const rated = (...ratings: [string, number][]) =>
    ratingDifferences({ file_ratings: ratings.map(([filename, severity]) => ({ file_id: filename, filename, severity })) });

  it("says which file rated a finding how", () => {
    expect(rated(["a.nessus", 1], ["b.nessus", 4], ["c.nessus", 1])).toEqual([
      { severity: 4, filenames: ["b.nessus"] },
      { severity: 1, filenames: ["a.nessus", "c.nessus"] },
    ]);
    expect(rated(["a.nessus", 2], ["b.nessus", 2])).toEqual([]);
    expect(rated(["a.nessus", 2])).toEqual([]);
  });
});

describe("web address kind", () => {
  it.each([
    [80, "www", true, false],
    [8080, "www", true, false],
    [443, "www", false, true],
    [8443, "www", false, true],
    [443, "https?", false, true],
    [5000, "ssl", false, true],
    [22, "ssh", false, false],
  ])("port %i, service %s", (port, svc, http, https) => {
    expect(isPlainHttp(port, svc)).toBe(http);
    expect(isHttps(port, svc)).toBe(https);
  });
});
