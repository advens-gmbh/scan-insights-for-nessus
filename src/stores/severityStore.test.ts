import { beforeEach, describe, expect, it } from "vitest";
import { useSeverityStore } from "./severityStore";

describe("severityStore", () => {
  beforeEach(() => useSeverityStore.setState({ selections: {} }));

  it("starts with nothing selected on any page", () => {
    expect(useSeverityStore.getState().selections.hosts).toBeUndefined();
  });

  it("keeps each page's selection separately", () => {
    const { setSelection } = useSeverityStore.getState();
    setSelection("hosts", [4]);
    setSelection("services", [3, 0]);
    expect(useSeverityStore.getState().selections).toEqual({ hosts: [4], services: [3, 0] });
  });
});
