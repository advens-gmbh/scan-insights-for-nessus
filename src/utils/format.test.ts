import { describe, expect, it } from "vitest";
import { folderOf, formatBytes, portNumbers, timeAgo, formatDuration } from "./format";

describe("formatBytes", () => {
  it("picks a readable unit", () => {
    expect(formatBytes(300)).toBe("1 KB");
    expect(formatBytes(340 * 1024)).toBe("340 KB");
    expect(formatBytes(9.44 * 1024 * 1024)).toBe("9.4 MB");
    expect(formatBytes(517 * 1024 * 1024)).toBe("517 MB");
    expect(formatBytes(1.5 * 1024 * 1024 * 1024)).toBe("1.5 GB");
  });
});

describe("timeAgo", () => {
  const now = new Date(2026, 10, 10, 15, 0);
  const at = (y: number, m: number, d: number, h = 12, min = 0) => new Date(y, m, d, h, min).toISOString();

  it("says it the way people do", () => {
    expect(timeAgo(at(2026, 10, 10, 14, 59, ), now)).toBe("1 min ago");
    expect(timeAgo(new Date(now.getTime() - 20_000).toISOString(), now)).toBe("just now");
    expect(timeAgo(at(2026, 10, 10, 13, 0), now)).toBe("2 hours ago");
    expect(timeAgo(at(2026, 10, 10, 14, 0), now)).toBe("1 hour ago");
    expect(timeAgo(at(2026, 10, 9, 23, 0), now)).toBe("yesterday");
    expect(timeAgo(at(2026, 10, 7), now)).toBe("3 days ago");
    expect(timeAgo(at(2026, 10, 2), now)).toBe("Nov 2");
    expect(timeAgo(at(2025, 5, 30), now)).toBe("Jun 30, 2025");
    expect(timeAgo("not a date", now)).toBe("");
  });
});

describe("folderOf", () => {
  it("keeps the folder as written", () => {
    expect(folderOf("D:\\Scans\\Corp\\a.nessus")).toBe("D:\\Scans\\Corp");
    expect(folderOf("\\\\fileserver\\pentest\\b.nessus")).toBe("\\\\fileserver\\pentest");
    expect(folderOf("/home/me/c.nessus")).toBe("/home/me");
    expect(folderOf("c.nessus")).toBe("");
  });
});

describe("portNumbers", () => {
  it("lists ports in number order, each once", () => {
    expect(portNumbers(["443/tcp", "53/udp", "8080/tcp", "22/tcp", "53/tcp", "445/udp", "445/tcp"])).toEqual([22, 53, 443, 445, 8080]);
  });

  it("skips what isn't a port", () => {
    expect(portNumbers(["general/tcp", "80/tcp"])).toEqual([80]);
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
