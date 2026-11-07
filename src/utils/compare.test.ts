import { describe, expect, it } from "vitest";
import type { NessusFile, ReportHost, ReportItem } from "../types/nessus";
import { compareScans } from "./compare";

function item(pluginId: number, port = 80): ReportItem {
  return { plugin_id: pluginId, port, protocol: "tcp" } as ReportItem;
}

function host(ip: string, items: ReportItem[], credentialed = false): ReportHost {
  return { ip, items, credentialed_scan: credentialed } as ReportHost;
}

function file(...hosts: ReportHost[]): NessusFile {
  return { hosts } as NessusFile;
}

describe("compareScans", () => {
  it("sorts findings into new, resolved and persisted", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1), item(2)])),
      file(host("10.0.0.1", [item(2), item(3)])),
    );
    expect(d.resolvedItems.map((i) => i.pluginId)).toEqual([1]);
    expect(d.persistedItems.map((i) => i.pluginId)).toEqual([2]);
    expect(d.newItems.map((i) => i.pluginId)).toEqual([3]);
    expect(d.unverifiedItems).toEqual([]);
  });

  it("does not call a finding resolved when its host was not rescanned", () => {
    const d = compareScans(file(host("10.0.0.1", [item(1)])), file(host("10.0.0.2", [])));
    expect(d.resolvedItems).toEqual([]);
    expect(d.unverifiedItems).toEqual([
      { pluginId: 1, ip: "10.0.0.1", port: 80, protocol: "tcp", note: "Host was not in scan B" },
    ]);
  });

  it("does not call a finding resolved when the rescan lost credentials", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1)], true)),
      file(host("10.0.0.1", [], false)),
    );
    expect(d.resolvedItems).toEqual([]);
    expect(d.unverifiedItems[0].note).toBe("Scan B was not credentialed on this host");
  });

  it("calls a finding resolved when the rescan gained credentials", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1)], false)),
      file(host("10.0.0.1", [], true)),
    );
    expect(d.resolvedItems).toHaveLength(1);
  });

  it("matches on port, so a fix on one port is not hidden by another", () => {
    const d = compareScans(
      file(host("10.0.0.1", [item(1, 80), item(1, 443)])),
      file(host("10.0.0.1", [item(1, 443)])),
    );
    expect(d.resolvedItems.map((i) => i.port)).toEqual([80]);
    expect(d.persistedItems.map((i) => i.port)).toEqual([443]);
  });

  it("flags new findings that may only reflect better coverage in B", () => {
    const d = compareScans(
      file(host("10.0.0.1", [], false)),
      file(host("10.0.0.1", [item(1)], true), host("10.0.0.2", [item(2)])),
    );
    expect(d.newItems.map((i) => i.note)).toEqual([
      "Scan A was not credentialed on this host",
      "Host was not in scan A",
    ]);
  });
});
