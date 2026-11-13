import { describe, expect, it } from "vitest";
import type { ScanFile } from "../types/nessus";
import { defaultPair } from "./compare";

// the comparison itself is tested in the backend (src-tauri/src/compare.rs)
describe("defaultPair", () => {
  const scan = (id: string, report_name: string, start: string) =>
    ({ id, report_name, loaded_at: "2026-01-01T00:00:00Z", start: Date.parse(start) } as ScanFile);

  it("pairs the newest scan with the run of the same scan before it", () => {
    expect(defaultPair([
      scan("lan-q2", "LAN", "2026-07-02T21:10:00"),
      scan("dmz-q3", "DMZ", "2026-10-12T20:00:00"),
      scan("lan-q3", "LAN", "2026-10-14T21:05:00"),
    ])).toEqual(["lan-q2", "lan-q3"]);
  });

  it("falls back to the scan just before the newest", () => {
    expect(defaultPair([scan("x", "X", "2026-07-02T21:10:00"), scan("y", "Y", "2026-10-14T21:05:00")])).toEqual(["x", "y"]);
    expect(defaultPair([scan("x", "X", "2026-07-02T21:10:00")])).toBeNull();
  });
});
