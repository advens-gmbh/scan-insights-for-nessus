import { describe, expect, it } from "vitest";
import { spreadsheetCell } from "./spreadsheet";

describe("spreadsheetCell", () => {
  it.each([
    ["=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"],
    ["+1+1", "'+1+1"],
    ["-1+1", "'-1+1"],
    ["@SUM(A1)", "'@SUM(A1)"],
    ["\t=1", "'=1"],
    ["  =1", "'=1"],
  ])("neutralizes %s", (input, expected) => {
    expect(spreadsheetCell(input)).toBe(expected);
  });

  it("keeps a value on one line in one cell", () => {
    expect(spreadsheetCell("Windows\nLinux\tother\r\nend")).toBe("Windows Linux other end");
  });

  it("leaves normal values alone", () => {
    for (const value of ["10.0.0.1", "web.corp.example", "80, 443", "Yes", "3", "a=b", ""]) {
      expect(spreadsheetCell(value)).toBe(value);
    }
  });
});
