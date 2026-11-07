import { describe, expect, it } from "vitest";
import { countBySeverity, matchesSeverities, severitiesOf, toggleSeverity } from "./severityFilter";

const counts = (critical: number, high: number, medium: number, low: number, info: number) => ({ critical, high, medium, low, info });

describe("severitiesOf", () => {
  it("lists the severities a row has at least one finding of", () => {
    expect(severitiesOf(counts(2, 0, 1, 0, 5))).toEqual([4, 2, 0]);
    expect(severitiesOf(counts(0, 0, 0, 0, 0))).toEqual([]);
  });
});

describe("matchesSeverities", () => {
  it("shows every row when no pill is selected, info-only rows too", () => {
    expect(matchesSeverities([], [])).toBe(true);
    expect(matchesSeverities([1], [])).toBe(true);
    expect(matchesSeverities([0], [])).toBe(true);
  });

  it("selecting Critical shows only rows with a critical finding", () => {
    expect(matchesSeverities([4, 1], [4])).toBe(true);
    expect(matchesSeverities([3], [4])).toBe(false);
    expect(matchesSeverities([1, 0], [4])).toBe(false);
  });

  it("selecting several pills shows rows with any of them", () => {
    expect(matchesSeverities([3], [4, 3])).toBe(true);
    expect(matchesSeverities([4], [4, 3])).toBe(true);
    expect(matchesSeverities([2, 1], [4, 3])).toBe(false);
  });

  it("selecting Info shows rows with an info finding", () => {
    expect(matchesSeverities([0], [0])).toBe(true);
    expect(matchesSeverities([2, 0], [0])).toBe(true);
    expect(matchesSeverities([2], [0])).toBe(false);
  });
});

describe("countBySeverity", () => {
  it("counts rows that have at least one finding of each severity", () => {
    const rows = [[4, 1], [4], [2, 0], [], [0, 0]];
    expect(countBySeverity(rows)).toEqual({ 4: 2, 3: 0, 2: 1, 1: 1, 0: 2 });
  });
});

describe("toggleSeverity", () => {
  it("adds and removes a pill without changing the original list", () => {
    const start = [4];
    const added = toggleSeverity(start, 3);
    expect([...added].sort()).toEqual([3, 4]);
    expect(toggleSeverity(added, 4)).toEqual([3]);
    expect(start).toEqual([4]);
  });
});
