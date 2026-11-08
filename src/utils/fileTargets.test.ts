import { describe, expect, it } from "vitest";
import { splitTargets, targetCoverage } from "./fileTargets";

const hosts = [
  { ip: "10.0.0.5", name: "10.0.0.5", hostname: null },
  { ip: "10.0.0.40", name: "10.0.0.40", hostname: "db.corp.example" },
  { ip: "10.0.1.7", name: "web.corp.example", hostname: "web.corp.example" },
  { ip: "192.168.1.1", name: "192.168.1.1", hostname: null },
];

describe("splitTargets", () => {
  it("splits on commas and new lines, without blanks or repeats", () => {
    expect(splitTargets("10.0.0.5, 10.0.0.0/24\n\n10.0.0.5")).toEqual(["10.0.0.5", "10.0.0.0/24"]);
    expect(splitTargets(null)).toEqual([]);
  });
});

describe("targetCoverage", () => {
  const coverage = (t: string) => targetCoverage([t], hosts)[0];

  it("finds the hosts in a subnet", () => {
    expect(coverage("10.0.0.0/24")).toEqual({ target: "10.0.0.0/24", size: 256, ips: ["10.0.0.5", "10.0.0.40"] });
    expect(coverage("10.0.0.0/23").ips).toEqual(["10.0.0.5", "10.0.0.40", "10.0.1.7"]);
  });

  it("finds the hosts in a range, written in full or by the last octet", () => {
    expect(coverage("10.0.0.1-10.0.0.39")).toEqual({ target: "10.0.0.1-10.0.0.39", size: 39, ips: ["10.0.0.5"] });
    expect(coverage("10.0.0.1-40")).toEqual({ target: "10.0.0.1-40", size: 40, ips: ["10.0.0.5", "10.0.0.40"] });
  });

  it("matches a single address", () => {
    expect(coverage("192.168.1.1")).toEqual({ target: "192.168.1.1", size: null, ips: ["192.168.1.1"] });
    expect(coverage("192.168.1.2").ips).toEqual([]);
  });

  it("matches a host name, ignoring case", () => {
    expect(coverage("WEB.corp.example").ips).toEqual(["10.0.1.7"]);
    expect(coverage("db.corp.example").ips).toEqual(["10.0.0.40"]);
    expect(coverage("mail.corp.example").ips).toEqual([]);
  });
});
