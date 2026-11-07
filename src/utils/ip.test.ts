import { describe, expect, it } from "vitest";
import { compareHosts } from "./ip";

describe("compareHosts", () => {
  it("orders IPv4 numerically, then everything else as text", () => {
    const hosts = ["web.example", "10.0.0.10", "fe80::1", "10.0.0.2", "9.255.0.1"];
    expect([...hosts].sort(compareHosts)).toEqual([
      "9.255.0.1",
      "10.0.0.2",
      "10.0.0.10",
      "fe80::1",
      "web.example",
    ]);
  });
});
