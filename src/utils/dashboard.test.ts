import { describe, expect, it } from "vitest";
import { formatDuration, parseNessusTime, rankHosts, scanWindow, topVulnerabilities } from "./dashboard";

describe("parseNessusTime", () => {
  it("reads the format Nessus writes in HOST_START and HOST_END", () => {
    const d = parseNessusTime("Mon Jan  1 10:05:09 2024");
    expect(d && [d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()]).toEqual([2024, 0, 1, 10, 5, 9]);
    expect(parseNessusTime("Tue Oct 28 22:14:03 2025")?.getMonth()).toBe(9);
  });

  it("returns null for nothing or nonsense", () => {
    expect(parseNessusTime(null)).toBeNull();
    expect(parseNessusTime("")).toBeNull();
    expect(parseNessusTime("not a date")).toBeNull();
  });
});

describe("scanWindow", () => {
  it("runs from the earliest host start to the latest host end", () => {
    const w = scanWindow([
      { host_start: "Mon Jan  1 10:30:00 2024", host_end: "Mon Jan  1 11:00:00 2024" },
      { host_start: "Mon Jan  1 10:00:00 2024", host_end: "Mon Jan  1 12:15:00 2024" },
      { host_start: null, host_end: null },
    ]);
    expect(w.start?.getHours()).toBe(10);
    expect(w.start?.getMinutes()).toBe(0);
    expect(w.durationMs).toBe((2 * 60 + 15) * 60 * 1000);
  });

  it("has no duration when the file has no end times", () => {
    const w = scanWindow([{ host_start: "Mon Jan  1 10:00:00 2024", host_end: null }]);
    expect(w.start).not.toBeNull();
    expect(w.durationMs).toBeNull();
  });

  it("is empty when no host has times", () => {
    expect(scanWindow([{ host_start: null, host_end: null }])).toEqual({ start: null, durationMs: null });
  });
});

describe("formatDuration", () => {
  it("shows hours and minutes", () => {
    expect(formatDuration((60 + 48) * 60000)).toBe("1 h 48 min");
    expect(formatDuration(3 * 3600000)).toBe("3 h");
    expect(formatDuration(54 * 60000)).toBe("54 min");
    expect(formatDuration(20000)).toBe("under 1 min");
  });
});

const host = (ip: string, critical: number, high: number, medium: number, low: number, info: number) => ({
  ip,
  severity_counts: { critical, high, medium, low, info },
});

describe("rankHosts", () => {
  const hosts = [host("a", 0, 9, 9, 9, 0), host("b", 1, 0, 0, 0, 0), host("c", 0, 0, 0, 0, 7), host("d", 1, 2, 0, 0, 0)];

  it("puts the worst severity first, then the next one down", () => {
    expect(rankHosts(hosts, true, 10).map((h) => h.ip)).toEqual(["d", "b", "a", "c"]);
  });

  it("ranks one critical above any number of highs", () => {
    expect(rankHosts([host("highs", 0, 20, 0, 0, 0), host("crit", 1, 0, 0, 0, 0)], true, 10).map((h) => h.ip)).toEqual(["crit", "highs"]);
  });

  it("leaves out hosts with only Info findings while Info is hidden", () => {
    expect(rankHosts(hosts, false, 10).map((h) => h.ip)).toEqual(["d", "b", "a"]);
  });

  it("returns at most the limit and leaves the input alone", () => {
    const copy = [...hosts];
    expect(rankHosts(hosts, true, 2)).toHaveLength(2);
    expect(hosts).toEqual(copy);
  });
});

describe("topVulnerabilities", () => {
  const v = (plugin_id: number, severity: number, host_count: number) => ({ plugin_id, severity, host_count });

  it("keeps critical and high, every critical first, each by how many hosts it is on", () => {
    const list = [v(1, 3, 5), v(2, 4, 5), v(3, 2, 99), v(4, 4, 2), v(5, 3, 30)];
    expect(topVulnerabilities(list, 10).map((x) => x.plugin_id)).toEqual([2, 4, 5, 1]);
  });

  it("returns at most the limit", () => {
    expect(topVulnerabilities([v(1, 4, 1), v(2, 4, 2), v(3, 4, 3)], 2).map((x) => x.plugin_id)).toEqual([3, 2]);
  });
});
