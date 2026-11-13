import { describe, expect, it } from "vitest";
import type { ScanFile } from "../types/nessus";
import { byScanDate, defaultTrendSelection, previousRuns, sameScansOf } from "./trends";

const run = (id: string, start: string) => ({ id, start: Date.parse(start), loaded_at: "2026-01-01T00:00:00Z" } as ScanFile);

describe("byScanDate", () => {
  it("sorts by when the scan ran, not when the file was loaded", () => {
    expect(byScanDate([run("b", "2026-11-02T22:00:00"), run("a", "2026-10-01T22:00:00")]).map((f) => f.id)).toEqual(["a", "b"]);
  });
});

describe("defaultTrendSelection", () => {
  it("selects the runs of the newest scan", () => {
    const files = [run("lan1", "2026-07-02T21:10:00"), run("dmz", "2026-10-12T20:00:00"), run("lan2", "2026-10-14T21:05:00")];
    expect(defaultTrendSelection(files, sameScansOf([{ a: "lan1", b: "lan2", reason: "same targets" }]))).toEqual(["lan1", "lan2"]);
  });

  it("selects everything when the newest scan ran only once", () => {
    expect(defaultTrendSelection([run("x", "2026-07-02T21:10:00"), run("y", "2026-10-14T21:05:00")], new Map())).toEqual(["x", "y"]);
    expect(defaultTrendSelection([], new Map())).toEqual([]);
  });
});

describe("previousRuns", () => {
  it("pairs each run with the latest earlier run of the same scan, and says why", () => {
    const runs = [
      run("lan1", "2026-07-02T21:10:00"),
      run("dmz1", "2026-07-03T21:10:00"),
      run("lan2", "2026-10-14T21:05:00"),
      run("dmz2", "2026-10-15T21:05:00"),
      run("web", "2026-10-16T21:05:00"),
    ];
    const same = sameScansOf([
      { a: "lan1", b: "lan2", reason: "same targets" },
      { a: "dmz1", b: "dmz2", reason: "3 of 4 hosts in both" },
    ]);
    expect([...previousRuns(runs, same)].map(([id, p]) => `${id}<${p ? `${p.file.id} (${p.reason})` : "-"}`)).toEqual([
      "lan1<-",
      "dmz1<-",
      "lan2<lan1 (same targets)",
      "dmz2<dmz1 (3 of 4 hosts in both)",
      "web<-",
    ]);
  });

  it("does not pair runs that started at the same time", () => {
    const same = sameScansOf([{ a: "a", b: "b", reason: "same targets" }]);
    const prev = previousRuns([run("a", "2022-03-23T14:31:00"), run("b", "2022-03-23T14:31:00")], same);
    expect([...prev.values()]).toEqual([null, null]);
  });
});
