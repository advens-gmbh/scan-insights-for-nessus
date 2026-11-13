import { describe, expect, it } from "vitest";
import { formatDuration, parseNessusTime, scanWindow } from "./dashboard";

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
