import { describe, expect, it } from "vitest";
import type { NessusFile, ReportItem } from "../types/nessus";
import { byScanDate, defaultTrendSelection, previousRuns, runChanges, sameScan } from "./trends";

const LAN = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"];
const DMZ = ["172.16.0.1", "172.16.0.2", "172.16.0.3"];

const run = (id: string, report_name: string, start: string, ips: string[], target: string | null = null, items: ReportItem[] = []) =>
  ({
    id, report_name, target, loaded_at: "2026-01-01T00:00:00Z",
    hosts: ips.map((ip, i) => ({ ip, host_start: start, host_end: null, items: i === 0 ? items : [] })),
  } as unknown as NessusFile);
const item = (plugin_id: number, severity: number) => ({ plugin_id, severity, port: 80, protocol: "tcp" } as ReportItem);

describe("byScanDate", () => {
  it("sorts by when the scan ran, not when the file was loaded", () => {
    const files = [run("b", "X", "Mon Nov  2 22:00:00 2026", LAN), run("a", "X", "Thu Oct  1 22:00:00 2026", LAN)];
    expect(byScanDate(files).map((f) => f.id)).toEqual(["a", "b"]);
  });
});

describe("sameScan", () => {
  const start = "Thu Oct  1 22:00:00 2026";

  it("matches the same target list, whatever the name and hosts", () => {
    expect(sameScan(run("a", "LAN", start, LAN, "10.0.0.0/24, srv.lab"), run("b", "Renamed", start, DMZ, "SRV.lab,10.0.0.0/24"))).toBe("same targets");
  });

  it("matches when at least half of all hosts are in both", () => {
    expect(sameScan(run("a", "LAN", start, LAN), run("b", "Renamed", start, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"]))).toBe("3 of 5 hosts in both");
    expect(sameScan(run("a", "LAN", start, LAN), run("b", "LAN", start, ["10.0.0.1", "10.0.0.8", "10.0.0.9"]))).toBeNull();
  });

  it("does not match a small scan of a few of the hosts, or unrelated scans with the same name", () => {
    expect(sameScan(run("a", "LAN", start, LAN), run("b", "Web", start, ["10.0.0.1"]))).toBeNull();
    expect(sameScan(run("a", "Weekly", start, LAN), run("b", "Weekly", start, DMZ))).toBeNull();
  });
});

describe("defaultTrendSelection", () => {
  it("selects the runs of the newest scan, even when it was renamed", () => {
    expect(defaultTrendSelection([
      run("lan1", "LAN", "Thu Jul  2 21:10:00 2026", LAN),
      run("dmz", "DMZ", "Mon Oct 12 20:00:00 2026", DMZ),
      run("lan2", "LAN (new name)", "Wed Oct 14 21:05:00 2026", LAN),
    ])).toEqual(["lan1", "lan2"]);
  });

  it("selects everything when the newest scan ran only once", () => {
    expect(defaultTrendSelection([run("x", "X", "Thu Jul  2 21:10:00 2026", LAN), run("y", "Y", "Wed Oct 14 21:05:00 2026", DMZ)])).toEqual(["x", "y"]);
    expect(defaultTrendSelection([])).toEqual([]);
  });
});

describe("runChanges", () => {
  const before = run("a", "X", "Thu Oct  1 22:00:00 2026", ["10.0.0.1"], null, [item(1, 4), item(2, 2), item(3, 0)]);
  const after = run("b", "X", "Mon Nov  2 22:00:00 2026", ["10.0.0.1"], null, [item(2, 2), item(4, 3), item(5, 0)]);

  it("counts what came and went since the previous run", () => {
    expect(runChanges(before, after, false)).toEqual({ added: 1, fixed: 1 });
  });

  it("counts Info only when it is shown", () => {
    expect(runChanges(before, after, true)).toEqual({ added: 2, fixed: 2 });
  });
});

describe("previousRuns", () => {
  it("pairs each run with the latest earlier run of the same scan, and says why", () => {
    const runs = [
      run("lan1", "LAN", "Thu Jul  2 21:10:00 2026", LAN, "10.0.0.0/24"),
      run("dmz1", "DMZ", "Fri Jul  3 21:10:00 2026", DMZ),
      run("lan2", "LAN renamed", "Wed Oct 14 21:05:00 2026", LAN, "10.0.0.0/24"),
      run("dmz2", "DMZ", "Thu Oct 15 21:05:00 2026", [...DMZ, "172.16.0.4"]),
      run("web", "Web", "Fri Oct 16 21:05:00 2026", ["10.0.0.1"]),
    ];
    const prev = previousRuns(runs);
    expect([...prev].map(([id, p]) => `${id}<${p ? `${p.file.id} (${p.reason})` : "-"}`)).toEqual([
      "lan1<-",
      "dmz1<-",
      "lan2<lan1 (same targets)",
      "dmz2<dmz1 (3 of 4 hosts in both)",
      "web<-",
    ]);
  });

  it("does not pair runs that started at the same time", () => {
    const prev = previousRuns([run("a", "X", "Wed Mar 23 14:31:00 2022", LAN), run("b", "X", "Wed Mar 23 14:31:00 2022", LAN)]);
    expect([...prev.values()]).toEqual([null, null]);
  });
});
