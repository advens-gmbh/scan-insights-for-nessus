import { describe, expect, it } from "vitest";
import {
  columnWidth,
  defaultLayout,
  dragColumn,
  MIN_COLUMN_WIDTH,
  resetColumnWidth,
  tableStyle,
  toggleColumn,
  visibleColumns,
} from "./tableColumns";
import type { TableColumn } from "./tableColumns";

const COLUMNS: TableColumn[] = [
  { key: "ip", label: "IP", width: 100, required: true },
  { key: "name", label: "Name", width: 200, stretch: true },
  { key: "os", label: "OS", width: 150 },
  { key: "mac", label: "MAC", width: 120, defaultHidden: true },
];

const RENDERED = { ip: 100, name: 400, os: 150 };

describe("defaultLayout", () => {
  it("hides only the columns that start hidden, and has no custom widths", () => {
    expect(defaultLayout(COLUMNS)).toEqual({ hidden: ["mac"], widths: null, baseline: null });
  });
});

describe("visibleColumns", () => {
  it("leaves out hidden columns and keeps the order", () => {
    const keys = visibleColumns(COLUMNS, defaultLayout(COLUMNS)).map((c) => c.key);
    expect(keys).toEqual(["ip", "name", "os"]);
  });

  it("shows an Info column exactly when Show Info is on, whatever the stored layout says", () => {
    const cols: TableColumn[] = [{ key: "host", label: "Host", width: 100 }, { key: "info", label: "Info", width: 80, info: true }];
    const hiddenBefore = { hidden: ["info"], widths: null, baseline: null };
    expect(visibleColumns(cols, hiddenBefore, true).map((c) => c.key)).toEqual(["host", "info"]);
    expect(visibleColumns(cols, defaultLayout(cols), false).map((c) => c.key)).toEqual(["host"]);
  });
});

describe("toggleColumn", () => {
  it("hides a visible column and shows a hidden one", () => {
    const hidden = toggleColumn(COLUMNS, defaultLayout(COLUMNS), "os");
    expect(hidden.hidden).toContain("os");
    const shown = toggleColumn(COLUMNS, hidden, "mac");
    expect(shown.hidden).not.toContain("mac");
  });

  it("will not hide a required column", () => {
    const layout = defaultLayout(COLUMNS);
    expect(toggleColumn(COLUMNS, layout, "ip")).toBe(layout);
  });
});

describe("columnWidth", () => {
  it("leaves the stretch column free until the first drag", () => {
    const layout = defaultLayout(COLUMNS);
    expect(columnWidth(COLUMNS[1], layout)).toBeUndefined();
    expect(columnWidth(COLUMNS[0], layout)).toBe(100);
  });

  it("gives every column an exact width after a drag", () => {
    const layout = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 200);
    expect(columnWidth(COLUMNS[1], layout)).toBe(400);
    expect(columnWidth(COLUMNS[2], layout)).toBe(200);
  });

  it("uses the default for a column shown after the drag", () => {
    const layout = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 200);
    expect(columnWidth(COLUMNS[3], layout)).toBe(120);
  });
});

describe("dragColumn", () => {
  it("changes only the dragged column", () => {
    const { widths } = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    expect(widths).toEqual({ ip: 100, name: 400, os: 300 });
  });

  it("does not let other columns drift over several drags", () => {
    const first = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    const second = dragColumn(first, { ip: 100, name: 400, os: 300 }, "ip", 180);
    expect(second.widths).toEqual({ ip: 180, name: 400, os: 300 });
  });

  it("keeps the first drag's widths as the baseline", () => {
    const first = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    const second = dragColumn(first, { ip: 100, name: 400, os: 300 }, "ip", 180);
    expect(second.baseline).toEqual(RENDERED);
  });

  it("stops at the minimum width", () => {
    const { widths } = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 3);
    expect(widths?.os).toBe(MIN_COLUMN_WIDTH);
  });
});

describe("tableStyle", () => {
  it("fills the space before any drag, but never squeezes columns below their widths", () => {
    const layout = defaultLayout(COLUMNS);
    expect(tableStyle(visibleColumns(COLUMNS, layout), layout)).toEqual({
      tableLayout: "fixed",
      width: "100%",
      minWidth: 450,
    });
  });

  // Forcing 100% here made the browser re-share space, so other columns shrank during a drag.
  it("is exactly as wide as its columns after a drag", () => {
    const layout = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    expect(tableStyle(visibleColumns(COLUMNS, layout), layout)).toEqual({
      tableLayout: "fixed",
      width: 800,
    });
  });
});

describe("resetColumnWidth", () => {
  it("puts one column back and keeps the other changes", () => {
    const first = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    const second = dragColumn(first, { ip: 100, name: 400, os: 300 }, "ip", 180);
    const { widths } = resetColumnWidth(COLUMNS, second, "os");
    expect(widths).toEqual({ ip: 180, name: 400, os: 150 });
  });

  it("goes back to filling the space once nothing differs", () => {
    const dragged = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    const reset = resetColumnWidth(COLUMNS, dragged, "os");
    expect(reset.widths).toBeNull();
    expect(reset.baseline).toBeNull();
  });

  it("does nothing when no column has been resized", () => {
    const layout = defaultLayout(COLUMNS);
    expect(resetColumnWidth(COLUMNS, layout, "os")).toBe(layout);
  });

  it("uses the default for a column that was hidden during the first drag", () => {
    const dragged = dragColumn(defaultLayout(COLUMNS), RENDERED, "os", 300);
    const moved = dragColumn(dragged, { ip: 100, name: 400, os: 300, mac: 120 }, "mac", 260);
    const { widths } = resetColumnWidth(COLUMNS, moved, "mac");
    expect(widths?.mac).toBe(120);
  });
});
