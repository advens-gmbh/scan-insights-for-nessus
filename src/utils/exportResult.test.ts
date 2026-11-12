import { describe, expect, it } from "vitest";
import { explainExportError, exportErrorOf, needsAnotherPlace } from "./exportResult";

describe("export errors", () => {
  it("explains each reason in one sentence", () => {
    expect(explainExportError("in_use")).toBe("It's open in another program. Close it and try again.");
    expect(explainExportError("disk_full")).toMatch(/disk is full/);
    expect(explainExportError("something new")).toBe("Something went wrong while saving.");
  });

  it("reads the error from the Rust side, or a plain message", () => {
    expect(exportErrorOf({ reason: "denied", detail: "Access is denied. (os error 5)" })).toEqual({ reason: "denied", detail: "Access is denied. (os error 5)" });
    expect(exportErrorOf("No matching files found for export")).toEqual({ reason: "other", detail: "No matching files found for export" });
  });

  it("asks for another place only when the folder is the problem", () => {
    expect(needsAnotherPlace("denied")).toBe(true);
    expect(needsAnotherPlace("no_folder")).toBe(true);
    expect(needsAnotherPlace("in_use")).toBe(false);
  });
});
